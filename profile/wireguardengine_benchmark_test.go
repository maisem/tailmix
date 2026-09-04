package profile

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gaissmai/bart"
	"github.com/maisem/tailmix/packetmap"
	"github.com/maisem/tailmix/tunmux"
	"github.com/maisem/tailmix/wireguardcfg"
	"tailscale.com/net/packet"
)

var wireGuardBenchmarkPacketSizes = [...]int{64, 512, 1280}

const (
	wireGuardBenchmarkWindow       = 256
	wireGuardBenchmarkReceiveLimit = 5 * time.Second
	wireGuardBenchmarkDrainQuiet   = 20 * time.Millisecond
	wireGuardBenchmarkDrainLimit   = 2 * time.Second
)

func TestWireGuardBenchmarkRejectsDuplicateDropSubstitution(t *testing.T) {
	source := netip.MustParseAddr("10.0.0.1")
	destination := netip.MustParseAddr("10.0.0.2")
	packets := wireGuardBenchmarkPackets(source, destination, 64)[:2]
	validator, err := newWireGuardBenchmarkDeliveryValidator(packets)
	if err != nil {
		t.Fatal(err)
	}
	if err := validator.observe(packets[0]); err != nil {
		t.Fatal(err)
	}
	if err := validator.observe(packets[0]); err == nil {
		t.Fatal("duplicate delivery replaced a missing sequence")
	}
}

func TestWireGuardBenchmarkRejectsExcessDelivery(t *testing.T) {
	source := netip.MustParseAddr("10.0.0.1")
	destination := netip.MustParseAddr("10.0.0.2")
	packets := wireGuardBenchmarkPackets(source, destination, 64)
	validator, err := newWireGuardBenchmarkDeliveryValidator(packets[:1])
	if err != nil {
		t.Fatal(err)
	}
	if err := validator.observe(packets[0]); err != nil {
		t.Fatal(err)
	}
	if !validator.complete() {
		t.Fatal("validator did not complete after the expected delivery")
	}
	if err := validator.observe(packets[1]); err == nil {
		t.Fatal("excess delivery was accepted")
	}
}

func BenchmarkWireGuardEngine(b *testing.B) {
	benchmarkWireGuardPath(b, newWireGuardEngineBenchmarkFixture)
}

func BenchmarkWireGuardTailmixPath(b *testing.B) {
	benchmarkWireGuardPath(b, newWireGuardTailmixBenchmarkFixture)
}

type wireGuardBenchmarkFixture struct {
	source              *tunmux.ChanTUN
	destination         *tunmux.ChanTUN
	sourceIP            netip.Addr
	destinationIP       netip.Addr
	expectedSourceIP    netip.Addr
	expectedDestination netip.Addr
	muxDone             []<-chan error
}

func benchmarkWireGuardPath(b *testing.B, newFixture func(testing.TB) *wireGuardBenchmarkFixture) {
	b.Helper()
	for _, packetSize := range wireGuardBenchmarkPacketSizes {
		b.Run(fmt.Sprintf("SteadyState/%d", packetSize), func(b *testing.B) {
			fixture := newFixture(b)
			fixture.establishSession(b, packetSize)
			fixture.verifyWindow(b, packetSize)
			benchmarkWireGuardSteadyState(b, fixture, packetSize)
		})
		b.Run(fmt.Sprintf("OfferedLoad/%d", packetSize), func(b *testing.B) {
			fixture := newFixture(b)
			fixture.establishSession(b, packetSize)
			fixture.verifyWindow(b, packetSize)
			benchmarkWireGuardOfferedLoad(b, fixture, packetSize)
		})
	}
}

func benchmarkWireGuardSteadyState(b *testing.B, fixture *wireGuardBenchmarkFixture, packetSize int) {
	b.Helper()
	packets := wireGuardBenchmarkPackets(fixture.sourceIP, fixture.destinationIP, packetSize)
	timer := time.NewTimer(wireGuardBenchmarkReceiveLimit)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()

	b.SetBytes(int64(packetSize))
	b.ReportAllocs()
	b.ResetTimer()
	for completed := 0; completed < b.N; {
		batchSize := min(wireGuardBenchmarkWindow, b.N-completed)
		for i := range batchSize {
			fixture.source.Outbound <- packets[i]
		}
		resetWireGuardBenchmarkTimer(timer, wireGuardBenchmarkReceiveLimit)
		for range batchSize {
			select {
			case <-fixture.destination.Inbound:
			case err := <-fixture.muxError():
				b.Fatalf("WireGuard benchmark mux stopped: %v", err)
			case <-timer.C:
				b.Fatalf("timed out after %v waiting for steady-state packet %d of %d", wireGuardBenchmarkReceiveLimit, completed+1, b.N)
			}
			completed++
		}
	}
	b.StopTimer()

	elapsed := b.Elapsed().Seconds()
	if elapsed > 0 {
		b.ReportMetric(float64(b.N)/elapsed, "packets/s")
	}
	fixture.checkMuxes(b)
}

func benchmarkWireGuardOfferedLoad(b *testing.B, fixture *wireGuardBenchmarkFixture, packetSize int) {
	b.Helper()
	packets := wireGuardBenchmarkPackets(fixture.sourceIP, fixture.destinationIP, packetSize)
	var delivered atomic.Int64
	stopDrain := make(chan struct{})
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		for {
			select {
			case <-stopDrain:
				return
			case <-fixture.destination.Inbound:
				delivered.Add(1)
			}
		}
	}()

	var accepted, backpressure int64
	b.SetBytes(int64(packetSize))
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		select {
		case fixture.source.Outbound <- packets[i%len(packets)]:
			accepted++
		default:
			backpressure++
		}
	}
	b.StopTimer()

	waitForWireGuardBenchmarkDrain(&delivered)
	close(stopDrain)
	<-drainDone
	fixture.checkMuxes(b)

	deliveredPackets := delivered.Load()
	if deliveredPackets > accepted {
		b.Fatalf("WireGuard benchmark delivered %d packets after accepting %d", deliveredPackets, accepted)
	}
	lost := accepted - deliveredPackets
	attempts := float64(max(1, b.N))
	elapsed := b.Elapsed().Seconds()
	b.ReportMetric(float64(accepted)/attempts, "accepted/op")
	b.ReportMetric(float64(deliveredPackets)/attempts, "delivered/op")
	b.ReportMetric(float64(backpressure)/attempts, "backpressure/op")
	b.ReportMetric(float64(lost)/attempts, "loss/op")
	if elapsed > 0 {
		b.ReportMetric(float64(accepted)/elapsed, "accepted-packets/s")
	}
}

func newWireGuardEngineBenchmarkFixture(tb testing.TB) *wireGuardBenchmarkFixture {
	tb.Helper()
	fabric := newWGTestFabric()
	nodes := newWireGuardBenchmarkNodes(tb, fabric)
	startWireGuardBenchmarkEngines(tb, nodes[:])
	fixture := &wireGuardBenchmarkFixture{
		source:              nodes[0].profileTUN,
		destination:         nodes[1].profileTUN,
		sourceIP:            nodes[0].canonicalIP,
		destinationIP:       nodes[1].canonicalIP,
		expectedSourceIP:    nodes[0].canonicalIP,
		expectedDestination: nodes[1].canonicalIP,
	}
	return fixture
}

func newWireGuardTailmixBenchmarkFixture(tb testing.TB) *wireGuardBenchmarkFixture {
	tb.Helper()
	fabric := newWGTestFabric()
	nodes := newWireGuardBenchmarkNodes(tb, fabric)
	startWireGuardBenchmarkEngines(tb, nodes[:])

	ctx, cancel := context.WithCancel(context.Background())
	hostTUNs := make([]*tunmux.ChanTUN, len(nodes))
	muxDone := make([]<-chan error, len(nodes))
	for i := range nodes {
		hostTUNs[i] = tunmux.NewChanTUN("wireguard-benchmark-host")
		mapper := wireGuardBenchmarkMapper(nodes[i], nodes[1-i])
		mux := tunmux.NewMux(hostTUNs[i], map[string]*tunmux.ChanTUN{
			nodes[i].profileID: nodes[i].profileTUN,
		}, mapper, nil)
		done := make(chan error, 1)
		muxDone[i] = done
		go func() { done <- mux.Run(ctx) }()
	}

	fixture := &wireGuardBenchmarkFixture{
		source:              hostTUNs[0],
		destination:         hostTUNs[1],
		sourceIP:            nodes[0].hostIP,
		destinationIP:       nodes[0].effectivePeerIP,
		expectedSourceIP:    nodes[1].effectivePeerIP,
		expectedDestination: nodes[1].hostIP,
		muxDone:             muxDone,
	}
	fixture.registerCleanup(tb, hostTUNs, cancel)
	return fixture
}

type wireGuardBenchmarkNode struct {
	profileID       string
	canonicalIP     netip.Addr
	hostIP          netip.Addr
	effectivePeerIP netip.Addr
	port            uint16
	privateKey      wireguardcfg.Key
	publicKey       wireguardcfg.Key
	profileTUN      *tunmux.ChanTUN
	engine          *WireGuardEngine
	config          wireguardcfg.Config
}

func newWireGuardBenchmarkNodes(tb testing.TB, fabric *wgTestFabric) [2]wireGuardBenchmarkNode {
	tb.Helper()
	nodes := [2]wireGuardBenchmarkNode{
		{
			profileID:       "wireguard-benchmark-a",
			canonicalIP:     netip.MustParseAddr("100.64.0.1"),
			hostIP:          netip.MustParseAddr("10.250.0.1"),
			effectivePeerIP: netip.MustParseAddr("100.127.0.2"),
			port:            13001,
		},
		{
			profileID:       "wireguard-benchmark-b",
			canonicalIP:     netip.MustParseAddr("100.64.0.2"),
			hostIP:          netip.MustParseAddr("10.250.0.2"),
			effectivePeerIP: netip.MustParseAddr("100.127.0.1"),
			port:            13002,
		},
	}
	for i := range nodes {
		privateKey, err := wireguardcfg.GeneratePrivateKey()
		if err != nil {
			tb.Fatal(err)
		}
		publicKey, err := privateKey.Public()
		if err != nil {
			tb.Fatal(err)
		}
		nodes[i].privateKey = privateKey
		nodes[i].publicKey = publicKey
		nodes[i].profileTUN = tunmux.NewChanTUN(nodes[i].profileID)
	}
	for i := range nodes {
		peer := nodes[1-i]
		nodes[i].config = wireGuardBenchmarkConfig(nodes[i], peer)
		nodes[i].engine = NewWireGuardEngine(WireGuardEngineConfig{
			ProfileID: nodes[i].profileID,
			Config:    nodes[i].config,
			Secrets:   wireguardcfg.Secrets{PrivateKey: &nodes[i].privateKey},
			Tun:       nodes[i].profileTUN,
			Bind:      fabric.newBind(),
		})
		engine := nodes[i].engine
		nodeNumber := i + 1
		tb.Cleanup(func() {
			if err := engine.Close(); err != nil {
				tb.Errorf("close WireGuard benchmark node %d: %v", nodeNumber, err)
			}
		})
	}
	tb.Cleanup(fabric.close)
	return nodes
}

func wireGuardBenchmarkConfig(self, peer wireGuardBenchmarkNode) wireguardcfg.Config {
	return wireguardcfg.Config{
		Version:    wireguardcfg.Version,
		Name:       self.profileID,
		DNSSuffix:  "benchmark.invalid",
		ListenPort: self.port,
		Addresses:  []netip.Addr{self.canonicalIP},
		PacketFilter: wireguardcfg.PacketFilter{Grants: []wireguardcfg.Grant{{
			Src: []string{"peer:*"}, Dst: []string{"self"}, IP: []string{"udp:*"},
		}}},
		Peers: []wireguardcfg.Peer{{
			Name:      peer.profileID,
			PublicKey: peer.publicKey,
			Endpoint:  netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), peer.port).String(),
			Addresses: []netip.Addr{peer.canonicalIP},
		}},
	}
}

func startWireGuardBenchmarkEngines(tb testing.TB, nodes []wireGuardBenchmarkNode) {
	tb.Helper()
	for i := range nodes {
		if err := nodes[i].engine.Start(context.Background()); err != nil {
			tb.Fatalf("start WireGuard benchmark node %d: %v", i+1, err)
		}
	}
}

func wireGuardBenchmarkMapper(self, peer wireGuardBenchmarkNode) *packetmap.Mapper {
	destinations := new(bart.Table[packetmap.Destination])
	destinations.Insert(netip.PrefixFrom(self.effectivePeerIP, 32), packetmap.Destination{
		ProfileID:   self.profileID,
		CanonicalIP: peer.canonicalIP,
	})
	inbound := new(bart.Table[netip.Addr])
	inbound.Insert(netip.PrefixFrom(peer.canonicalIP, 32), self.effectivePeerIP)
	return packetmap.New(packetmap.Table{
		Destinations: destinations,
		Sources: map[packetmap.SourceKey]packetmap.Source{
			{ProfileID: self.profileID}: {
				HostIP:      self.hostIP,
				CanonicalIP: self.canonicalIP,
			},
		},
		InboundPeers: map[string]*bart.Table[netip.Addr]{self.profileID: inbound},
	})
}

func (f *wireGuardBenchmarkFixture) registerCleanup(tb testing.TB, hostTUNs []*tunmux.ChanTUN, cancel context.CancelFunc) {
	tb.Helper()
	tb.Cleanup(func() {
		if cancel != nil {
			cancel()
		}
		for _, hostTUN := range hostTUNs {
			if err := hostTUN.Close(); err != nil {
				tb.Errorf("close benchmark host TUN: %v", err)
			}
		}
		f.checkMuxes(tb)
	})
}

func (f *wireGuardBenchmarkFixture) establishSession(tb testing.TB, packetSize int) {
	tb.Helper()
	packet := wireGuardBenchmarkPacket(f.sourceIP, f.destinationIP, packetSize, 0)
	select {
	case f.source.Outbound <- packet:
	case err := <-f.muxError():
		tb.Fatalf("WireGuard benchmark mux stopped during warmup: %v", err)
	case <-time.After(wireGuardBenchmarkReceiveLimit):
		tb.Fatalf("timed out after %v injecting WireGuard warmup packet", wireGuardBenchmarkReceiveLimit)
	}
	select {
	case got := <-f.destination.Inbound:
		want := wireGuardBenchmarkPacket(f.expectedSourceIP, f.expectedDestination, packetSize, 0)
		if !bytes.Equal(got, want) {
			tb.Fatalf("WireGuard benchmark warmup packet changed in transit\n got: %x\nwant: %x", got, want)
		}
	case err := <-f.muxError():
		tb.Fatalf("WireGuard benchmark mux stopped during warmup: %v", err)
	case <-time.After(wireGuardBenchmarkReceiveLimit):
		tb.Fatalf("timed out after %v waiting for WireGuard warmup packet", wireGuardBenchmarkReceiveLimit)
	}
}

func (f *wireGuardBenchmarkFixture) verifyWindow(tb testing.TB, packetSize int) {
	tb.Helper()
	packets := wireGuardBenchmarkPackets(f.sourceIP, f.destinationIP, packetSize)
	expected := wireGuardBenchmarkPackets(f.expectedSourceIP, f.expectedDestination, packetSize)
	validator, err := newWireGuardBenchmarkDeliveryValidator(expected)
	if err != nil {
		tb.Fatal(err)
	}
	deadline := time.NewTimer(wireGuardBenchmarkReceiveLimit)
	defer deadline.Stop()
	for _, packet := range packets {
		select {
		case f.source.Outbound <- packet:
		case err := <-f.muxError():
			tb.Fatalf("WireGuard benchmark mux stopped during correctness preflight: %v", err)
		case <-deadline.C:
			tb.Fatalf("timed out after %v injecting correctness packet", wireGuardBenchmarkReceiveLimit)
		}
	}
	for !validator.complete() {
		select {
		case packet := <-f.destination.Inbound:
			if err := validator.observe(packet); err != nil {
				tb.Fatal(err)
			}
		case err := <-f.muxError():
			tb.Fatalf("WireGuard benchmark mux stopped during correctness preflight: %v", err)
		case <-deadline.C:
			tb.Fatalf("timed out after %v waiting for correctness packet %d of %d", wireGuardBenchmarkReceiveLimit, validator.delivered()+1, len(expected))
		}
	}

	quiet := time.NewTimer(wireGuardBenchmarkDrainQuiet)
	defer quiet.Stop()
	select {
	case packet := <-f.destination.Inbound:
		err := validator.observe(packet)
		if err == nil {
			tb.Fatal("WireGuard benchmark accepted an excess correctness delivery")
		}
		tb.Fatal(err)
	case err := <-f.muxError():
		tb.Fatalf("WireGuard benchmark mux stopped after correctness preflight: %v", err)
	case <-quiet.C:
	}
}

func (f *wireGuardBenchmarkFixture) muxError() <-chan error {
	if len(f.muxDone) == 0 {
		return nil
	}
	return f.muxDone[0]
}

func (f *wireGuardBenchmarkFixture) checkMuxes(tb testing.TB) {
	tb.Helper()
	for i, done := range f.muxDone {
		select {
		case err := <-done:
			if err != nil {
				tb.Errorf("WireGuard benchmark mux %d stopped: %v", i+1, err)
			}
		default:
		}
	}
}

type wireGuardBenchmarkDeliveryValidator struct {
	expected  map[uint64][]byte
	seen      map[uint64]struct{}
	remaining int
}

func newWireGuardBenchmarkDeliveryValidator(expectedPackets [][]byte) (*wireGuardBenchmarkDeliveryValidator, error) {
	validator := &wireGuardBenchmarkDeliveryValidator{
		expected:  make(map[uint64][]byte, len(expectedPackets)),
		seen:      make(map[uint64]struct{}, len(expectedPackets)),
		remaining: len(expectedPackets),
	}
	for _, packet := range expectedPackets {
		sequence, err := wireGuardBenchmarkSequence(packet)
		if err != nil {
			return nil, err
		}
		if _, exists := validator.expected[sequence]; exists {
			return nil, fmt.Errorf("duplicate expected WireGuard benchmark sequence %d", sequence)
		}
		validator.expected[sequence] = packet
	}
	return validator, nil
}

func (v *wireGuardBenchmarkDeliveryValidator) observe(packet []byte) error {
	sequence, err := wireGuardBenchmarkSequence(packet)
	if err != nil {
		return err
	}
	want, exists := v.expected[sequence]
	if !exists {
		return fmt.Errorf("unexpected WireGuard benchmark sequence %d", sequence)
	}
	if _, duplicate := v.seen[sequence]; duplicate {
		return fmt.Errorf("duplicate WireGuard benchmark sequence %d", sequence)
	}
	if !bytes.Equal(packet, want) {
		return fmt.Errorf("WireGuard benchmark sequence %d changed in transit", sequence)
	}
	v.seen[sequence] = struct{}{}
	v.remaining--
	return nil
}

func (v *wireGuardBenchmarkDeliveryValidator) complete() bool { return v.remaining == 0 }
func (v *wireGuardBenchmarkDeliveryValidator) delivered() int { return len(v.seen) }

func wireGuardBenchmarkPackets(source, destination netip.Addr, packetSize int) [][]byte {
	packets := make([][]byte, wireGuardBenchmarkWindow)
	for i := range packets {
		packets[i] = wireGuardBenchmarkPacket(source, destination, packetSize, uint64(i+1))
	}
	return packets
}

func wireGuardBenchmarkPacket(source, destination netip.Addr, packetSize int, sequence uint64) []byte {
	const headerSize = 20 + 8
	payload := make([]byte, packetSize-headerSize)
	binary.BigEndian.PutUint64(payload, sequence)
	for i := 8; i < len(payload); i++ {
		payload[i] = byte(i)
	}
	return packet.Generate(packet.UDP4Header{
		IP4Header: packet.IP4Header{Src: source, Dst: destination},
		SrcPort:   10000,
		DstPort:   20000,
	}, payload)
}

func wireGuardBenchmarkSequence(packet []byte) (uint64, error) {
	const sequenceOffset = 20 + 8
	if len(packet) < sequenceOffset+8 {
		return 0, fmt.Errorf("WireGuard benchmark packet is too short: %d bytes", len(packet))
	}
	return binary.BigEndian.Uint64(packet[sequenceOffset : sequenceOffset+8]), nil
}

func waitForWireGuardBenchmarkDrain(delivered *atomic.Int64) {
	deadline := time.Now().Add(wireGuardBenchmarkDrainLimit)
	lastDelivered := int64(-1)
	lastProgress := time.Now()
	for time.Now().Before(deadline) {
		current := delivered.Load()
		if current != lastDelivered {
			lastDelivered = current
			lastProgress = time.Now()
		}
		if time.Since(lastProgress) >= wireGuardBenchmarkDrainQuiet {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

func resetWireGuardBenchmarkTimer(timer *time.Timer, timeout time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(timeout)
}
