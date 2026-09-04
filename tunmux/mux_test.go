package tunmux

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/gaissmai/bart"
	"github.com/maisem/tailmix/packetmap"
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/net/packet"
)

func testUDP(src, dst netip.Addr) []byte {
	return packet.Generate(packet.UDP4Header{
		IP4Header: packet.IP4Header{Src: src, Dst: dst},
		SrcPort:   1000,
		DstPort:   2000,
	}, []byte("mux"))
}

func injectTestOutbound(t *testing.T, tun *ChanTUN, pkt []byte) {
	t.Helper()
	if err := tun.InjectOutbound(pkt); err != nil {
		t.Fatal(err)
	}
}

func injectTestInbound(t *testing.T, tun *ChanTUN, pkt []byte) {
	t.Helper()
	owned := tun.pool.copy(pkt)
	ok, err := tun.tryInjectInboundPacket(owned)
	if err != nil || !ok {
		owned.Release()
		t.Fatalf("inject inbound: sent=%v err=%v", ok, err)
	}
}

func takeTestPacket(packet Packet) []byte {
	pkt := append([]byte(nil), packet.Bytes()...)
	packet.Release()
	return pkt
}

func TestMuxRoutesOutboundPacketToSelectedProfileTun(t *testing.T) {
	host := NewChanTUN("host")
	work := NewChanTUN("work")
	hostNAT := netip.MustParseAddr("10.250.0.10")
	effectivePeer := netip.MustParseAddr("100.127.0.1")
	canonicalSelf := netip.MustParseAddr("100.65.0.10")
	canonicalPeer := netip.MustParseAddr("100.64.0.1")
	table := packetmap.Table{
		Destinations: new(bart.Table[packetmap.Destination]),
		Sources: map[packetmap.SourceKey]packetmap.Source{
			{ProfileID: "work"}: {HostIP: hostNAT, CanonicalIP: canonicalSelf},
		},
	}
	table.Destinations.Insert(netip.PrefixFrom(effectivePeer, 32), packetmap.Destination{ProfileID: "work", CanonicalIP: canonicalPeer})
	mux := NewMux(host, map[string]*ChanTUN{"work": work}, packetmap.New(table), nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go mux.Run(ctx)
	injectTestOutbound(t, host, testUDP(hostNAT, effectivePeer))
	select {
	case owned := <-work.outbound:
		got := takeTestPacket(owned)
		var p packet.Parsed
		p.Decode(got)
		if p.Dst.Addr() != canonicalPeer {
			t.Fatalf("profile packet destination = %v, want %v", p.Dst.Addr(), canonicalPeer)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for routed packet")
	}
}

func TestMuxRoutesInboundPacketToHostTun(t *testing.T) {
	host := NewChanTUN("host")
	work := NewChanTUN("work")
	hostNAT := netip.MustParseAddr("10.250.0.10")
	effectivePeer := netip.MustParseAddr("100.127.0.1")
	canonicalSelf := netip.MustParseAddr("100.65.0.10")
	canonicalPeer := netip.MustParseAddr("100.64.0.1")
	inbound := new(bart.Table[netip.Addr])
	inbound.Insert(netip.PrefixFrom(canonicalPeer, 32), effectivePeer)
	mux := NewMux(host, map[string]*ChanTUN{"work": work}, packetmap.New(packetmap.Table{
		InboundPeers: map[string]*bart.Table[netip.Addr]{"work": inbound},
		Sources: map[packetmap.SourceKey]packetmap.Source{
			{ProfileID: "work"}: {HostIP: hostNAT, CanonicalIP: canonicalSelf},
		},
	}), nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go mux.Run(ctx)
	injectTestInbound(t, work, testUDP(canonicalPeer, canonicalSelf))
	select {
	case owned := <-host.inbound:
		got := takeTestPacket(owned)
		var p packet.Parsed
		p.Decode(got)
		if p.Src.Addr() != effectivePeer || p.Dst.Addr() != hostNAT {
			t.Fatalf("host packet = %v > %v, want %v > %v", p.Src.Addr(), p.Dst.Addr(), effectivePeer, hostNAT)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for inbound host packet")
	}
}

type testLocalHandler struct {
	dst      netip.Addr
	handled  chan []byte
	outbound chan []byte
}

func (h *testLocalHandler) HandlePacket(pkt []byte) bool {
	var parsed packet.Parsed
	parsed.Decode(pkt)
	if parsed.Dst.Addr() != h.dst {
		return false
	}
	h.handled <- append([]byte(nil), pkt...)
	return true
}

func (h *testLocalHandler) Outbound() <-chan []byte { return h.outbound }
func (h *testLocalHandler) Err() error              { return nil }

func TestMuxTerminatesLocalServicePackets(t *testing.T) {
	host := NewChanTUN("host")
	work := NewChanTUN("work")
	serviceIP := netip.MustParseAddr("100.100.100.100")
	clientIP := netip.MustParseAddr("100.127.0.10")
	handler := &testLocalHandler{
		dst:      serviceIP,
		handled:  make(chan []byte, 1),
		outbound: make(chan []byte, 1),
	}
	mux := NewMux(host, map[string]*ChanTUN{"work": work}, packetmap.New(packetmap.Table{}), nil)
	mux.SetLocalPacketHandler(handler)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go mux.Run(ctx)

	query := testUDP(clientIP, serviceIP)
	injectTestOutbound(t, host, query)
	select {
	case got := <-handler.handled:
		if string(got) != string(query) {
			t.Fatalf("local handler packet differs from query")
		}
	case owned := <-work.outbound:
		got := takeTestPacket(owned)
		t.Fatalf("local service packet unexpectedly reached profile: %x", got)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for local handler")
	}

	response := testUDP(serviceIP, clientIP)
	handler.outbound <- response
	select {
	case owned := <-host.inbound:
		got := takeTestPacket(owned)
		var parsed packet.Parsed
		parsed.Decode(got)
		if parsed.Src.Addr() != serviceIP || parsed.Dst.Addr() != clientIP {
			t.Fatalf("local response = %v > %v, want %v > %v", parsed.Src.Addr(), parsed.Dst.Addr(), serviceIP, clientIP)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for local response")
	}
}

func TestMuxAddsAndRemovesProfilesWithoutStopping(t *testing.T) {
	host := NewChanTUN("host")
	hostNAT := netip.MustParseAddr("10.250.0.10")
	destination := netip.MustParseAddr("10.20.1.2")
	source := netip.MustParseAddr("100.65.0.10")
	routeTable := func(profileID string) packetmap.Table {
		routes := new(bart.Table[packetmap.SubnetRoute])
		routes.Insert(netip.MustParsePrefix("10.20.0.0/16"), packetmap.SubnetRoute{ProfileID: profileID, Active: true})
		return packetmap.Table{
			Destinations: new(bart.Table[packetmap.Destination]),
			ExactRoutes:  routes,
			Sources: map[packetmap.SourceKey]packetmap.Source{
				{ProfileID: profileID}: {HostIP: hostNAT, CanonicalIP: source},
			},
		}
	}
	mux := NewMux(host, nil, packetmap.New(routeTable("work")), nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- mux.Run(ctx) }()

	work := NewChanTUN("work")
	if err := mux.AddProfile("work", work); err != nil {
		t.Fatal(err)
	}
	injectTestOutbound(t, host, testUDP(hostNAT, destination))
	select {
	case owned := <-work.outbound:
		owned.Release()
	case <-time.After(time.Second):
		t.Fatal("dynamically added profile did not receive a packet")
	}
	mux.RemoveProfile("work")
	select {
	case err := <-done:
		t.Fatalf("mux stopped after profile removal: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	home := NewChanTUN("home")
	mux.SetMapper(packetmap.New(routeTable("home")))
	if err := mux.AddProfile("home", home); err != nil {
		t.Fatal(err)
	}
	injectTestOutbound(t, host, testUDP(hostNAT, destination))
	select {
	case owned := <-home.outbound:
		owned.Release()
	case <-time.After(time.Second):
		t.Fatal("replacement profile did not receive a packet")
	}
}

func TestMuxBatchesHostPacketsAcrossProfiles(t *testing.T) {
	hostNAT := netip.MustParseAddr("10.250.0.10")
	workEffectivePeer := netip.MustParseAddr("100.127.0.1")
	homeEffectivePeer := netip.MustParseAddr("100.127.0.2")
	canonicalSelf := netip.MustParseAddr("100.65.0.10")
	workCanonicalPeer := netip.MustParseAddr("100.64.0.1")
	homeCanonicalPeer := netip.MustParseAddr("100.64.0.2")
	host := newBatchTestTUN(4)
	host.reads <- [][]byte{
		testUDP(hostNAT, workEffectivePeer),
		testUDP(hostNAT, homeEffectivePeer),
		testUDP(hostNAT, workEffectivePeer),
	}
	close(host.reads)
	work := NewChanTUN("work")
	home := NewChanTUN("home")
	table := packetmap.Table{
		Destinations: new(bart.Table[packetmap.Destination]),
		Sources: map[packetmap.SourceKey]packetmap.Source{
			{ProfileID: "work"}: {HostIP: hostNAT, CanonicalIP: canonicalSelf},
			{ProfileID: "home"}: {HostIP: hostNAT, CanonicalIP: canonicalSelf},
		},
	}
	table.Destinations.Insert(netip.PrefixFrom(workEffectivePeer, 32), packetmap.Destination{ProfileID: "work", CanonicalIP: workCanonicalPeer})
	table.Destinations.Insert(netip.PrefixFrom(homeEffectivePeer, 32), packetmap.Destination{ProfileID: "home", CanonicalIP: homeCanonicalPeer})
	mux := NewMux(host, map[string]*ChanTUN{"work": work, "home": home}, packetmap.New(table), nil)
	if err := mux.runHostToProfiles(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := len(work.outbound); got != 2 {
		t.Fatalf("work outbound queue length = %d, want 2", got)
	}
	if got := len(home.outbound); got != 1 {
		t.Fatalf("home outbound queue length = %d, want 1", got)
	}
	for i := range 2 {
		owned := <-work.outbound
		var parsed packet.Parsed
		parsed.Decode(owned.Bytes())
		owned.Release()
		if parsed.Dst.Addr() != workCanonicalPeer {
			t.Fatalf("work packet %d destination = %v, want %v", i, parsed.Dst.Addr(), workCanonicalPeer)
		}
	}
	owned := <-home.outbound
	var parsed packet.Parsed
	parsed.Decode(owned.Bytes())
	owned.Release()
	if parsed.Dst.Addr() != homeCanonicalPeer {
		t.Fatalf("home packet destination = %v, want %v", parsed.Dst.Addr(), homeCanonicalPeer)
	}
}

func TestMuxProcessesHostPacketsReturnedWithReadError(t *testing.T) {
	hostNAT := netip.MustParseAddr("10.250.0.10")
	effectivePeer := netip.MustParseAddr("100.127.0.1")
	canonicalSelf := netip.MustParseAddr("100.65.0.10")
	canonicalPeer := netip.MustParseAddr("100.64.0.1")
	host := newBatchTestTUN(2)
	host.reads <- [][]byte{testUDP(hostNAT, effectivePeer), testUDP(hostNAT, effectivePeer)}
	host.readErr = errBatchTestStop
	work := NewChanTUN("work")
	table := packetmap.Table{
		Destinations: new(bart.Table[packetmap.Destination]),
		Sources: map[packetmap.SourceKey]packetmap.Source{
			{ProfileID: "work"}: {HostIP: hostNAT, CanonicalIP: canonicalSelf},
		},
	}
	table.Destinations.Insert(netip.PrefixFrom(effectivePeer, 32), packetmap.Destination{ProfileID: "work", CanonicalIP: canonicalPeer})
	mux := NewMux(host, map[string]*ChanTUN{"work": work}, packetmap.New(table), nil)
	if err := mux.runHostToProfiles(context.Background()); !errors.Is(err, errBatchTestStop) {
		t.Fatalf("runHostToProfiles error = %v, want %v", err, errBatchTestStop)
	}
	if got := len(work.outbound); got != 2 {
		t.Fatalf("profile outbound queue length = %d, want 2", got)
	}
	for range 2 {
		owned := <-work.outbound
		owned.Release()
	}
}

func TestMuxBatchesAndCompactsProfilePacketsToHost(t *testing.T) {
	hostNAT := netip.MustParseAddr("10.250.0.10")
	effectivePeer := netip.MustParseAddr("100.127.0.1")
	canonicalSelf := netip.MustParseAddr("100.65.0.10")
	canonicalPeer := netip.MustParseAddr("100.64.0.1")
	inbound := new(bart.Table[netip.Addr])
	inbound.Insert(netip.PrefixFrom(canonicalPeer, 32), effectivePeer)
	host := newBatchTestTUN(4)
	host.writeErr = errBatchTestStop
	work := NewChanTUN("work")
	mux := NewMux(host, map[string]*ChanTUN{"work": work}, packetmap.New(packetmap.Table{
		InboundPeers: map[string]*bart.Table[netip.Addr]{"work": inbound},
		Sources: map[packetmap.SourceKey]packetmap.Source{
			{ProfileID: "work"}: {HostIP: hostNAT, CanonicalIP: canonicalSelf},
		},
	}), nil)

	inputs := [][]byte{
		testUDP(canonicalPeer, canonicalSelf),
		testUDP(netip.MustParseAddr("100.64.0.99"), canonicalSelf),
		testUDP(canonicalPeer, canonicalSelf),
	}
	stale := make([]Packet, len(inputs))
	for i, pkt := range inputs {
		owned := work.pool.copy(pkt)
		stale[i] = owned
		ok, err := work.tryInjectInboundPacket(owned)
		if err != nil || !ok {
			owned.Release()
			t.Fatalf("inject packet %d = (%v, %v)", i, ok, err)
		}
	}
	if err := mux.runProfileToHost(context.Background(), "work", work); !errors.Is(err, errBatchTestStop) {
		t.Fatalf("runProfileToHost error = %v, want %v", err, errBatchTestStop)
	}
	written := <-host.writes
	if len(written) != 2 {
		t.Fatalf("host write batch length = %d, want 2", len(written))
	}
	for i, pkt := range written {
		var parsed packet.Parsed
		parsed.Decode(pkt)
		if parsed.Src.Addr() != effectivePeer || parsed.Dst.Addr() != hostNAT {
			t.Fatalf("written packet %d = %v > %v, want %v > %v", i, parsed.Src.Addr(), parsed.Dst.Addr(), effectivePeer, hostNAT)
		}
	}
	for i := range stale {
		owned := stale[i]
		assertPanics(t, func() { owned.Bytes() })
	}
}

func TestMuxBatchesLocalServicePacketsToHost(t *testing.T) {
	host := newBatchTestTUN(4)
	handler := &testLocalHandler{
		outbound: make(chan []byte, 3),
		handled:  make(chan []byte, 1),
	}
	for _, pkt := range [][]byte{[]byte("first"), []byte("second"), []byte("third")} {
		handler.outbound <- pkt
	}
	close(handler.outbound)
	mux := NewMux(host, nil, nil, nil)
	mux.SetLocalPacketHandler(handler)
	if err := mux.runLocalToHost(context.Background()); err == nil || err.Error() != "local packet handler stopped" {
		t.Fatalf("runLocalToHost error = %v, want stopped error", err)
	}
	written := <-host.writes
	if len(written) != 3 {
		t.Fatalf("host write batch length = %d, want 3", len(written))
	}
	for i, want := range [][]byte{[]byte("first"), []byte("second"), []byte("third")} {
		if !bytes.Equal(written[i], want) {
			t.Fatalf("written packet %d = %q, want %q", i, written[i], want)
		}
	}
}

func TestMuxClampsZeroHostBatchSize(t *testing.T) {
	host := newBatchTestTUN(0)
	handler := &testLocalHandler{
		outbound: make(chan []byte, 1),
		handled:  make(chan []byte, 1),
	}
	handler.outbound <- []byte("packet")
	close(handler.outbound)
	mux := NewMux(host, nil, nil, nil)
	mux.SetLocalPacketHandler(handler)
	if err := mux.runLocalToHost(context.Background()); err == nil || err.Error() != "local packet handler stopped" {
		t.Fatalf("runLocalToHost error = %v, want stopped error", err)
	}
	written := <-host.writes
	if len(written) != 1 || !bytes.Equal(written[0], []byte("packet")) {
		t.Fatalf("host write batch = %q, want one packet", written)
	}
}

var errBatchTestStop = errors.New("stop after recorded batch")

type batchTestTUN struct {
	batchSize int
	reads     chan [][]byte
	writes    chan [][]byte
	events    chan tun.Event
	readErr   error
	writeErr  error
}

func newBatchTestTUN(batchSize int) *batchTestTUN {
	return &batchTestTUN{
		batchSize: batchSize,
		reads:     make(chan [][]byte, 1),
		writes:    make(chan [][]byte, 1),
		events:    make(chan tun.Event),
	}
}

func (*batchTestTUN) File() *os.File { return nil }
func (*batchTestTUN) Close() error   { return nil }
func (*batchTestTUN) MTU() (int, error) {
	return chanTUNMTU, nil
}
func (*batchTestTUN) Name() (string, error) { return "batch-test", nil }
func (t *batchTestTUN) Events() <-chan tun.Event {
	return t.events
}
func (t *batchTestTUN) BatchSize() int { return t.batchSize }
func (t *batchTestTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	batch, ok := <-t.reads
	if !ok {
		return 0, io.EOF
	}
	for i, pkt := range batch {
		sizes[i] = copy(bufs[i][offset:], pkt)
	}
	return len(batch), t.readErr
}
func (t *batchTestTUN) Write(bufs [][]byte, offset int) (int, error) {
	batch := make([][]byte, len(bufs))
	for i, buf := range bufs {
		batch[i] = append([]byte(nil), buf[offset:]...)
	}
	t.writes <- batch
	if t.writeErr != nil {
		return min(1, len(bufs)), t.writeErr
	}
	return len(bufs), nil
}
