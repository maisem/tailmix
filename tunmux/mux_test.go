package tunmux

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/gaissmai/bart"
	"github.com/maisem/tailmix/packetmap"
	"tailscale.com/net/packet"
)

func testUDP(src, dst netip.Addr) []byte {
	return packet.Generate(packet.UDP4Header{
		IP4Header: packet.IP4Header{Src: src, Dst: dst},
		SrcPort:   1000,
		DstPort:   2000,
	}, []byte("mux"))
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
	host.Outbound <- testUDP(hostNAT, effectivePeer)
	select {
	case got := <-work.Outbound:
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
	work.Inbound <- testUDP(canonicalPeer, canonicalSelf)
	select {
	case got := <-host.Inbound:
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
	host.Outbound <- query
	select {
	case got := <-handler.handled:
		if string(got) != string(query) {
			t.Fatalf("local handler packet differs from query")
		}
	case got := <-work.Outbound:
		t.Fatalf("local service packet unexpectedly reached profile: %x", got)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for local handler")
	}

	response := testUDP(serviceIP, clientIP)
	handler.outbound <- response
	select {
	case got := <-host.Inbound:
		var parsed packet.Parsed
		parsed.Decode(got)
		if parsed.Src.Addr() != serviceIP || parsed.Dst.Addr() != clientIP {
			t.Fatalf("local response = %v > %v, want %v > %v", parsed.Src.Addr(), parsed.Dst.Addr(), serviceIP, clientIP)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for local response")
	}
}
