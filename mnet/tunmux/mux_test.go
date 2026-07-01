package tunmux

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/mnet/packetmap"
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
	effectiveSelf := netip.MustParseAddr("100.127.0.10")
	effectivePeer := netip.MustParseAddr("100.127.0.1")
	canonicalSelf := netip.MustParseAddr("100.65.0.10")
	canonicalPeer := netip.MustParseAddr("100.64.0.1")
	mux := NewMux(host, map[string]*ChanTUN{"work": work}, packetmap.New(packetmap.Table{
		Destinations: map[netip.Addr]packetmap.Destination{
			effectivePeer: {ProfileID: "work", CanonicalIP: canonicalPeer},
		},
		Sources: map[string]packetmap.Source{
			"work": {EffectiveIP: effectiveSelf, CanonicalIP: canonicalSelf},
		},
	}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go mux.Run(ctx)
	host.Outbound <- testUDP(effectiveSelf, effectivePeer)
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
