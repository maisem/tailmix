package packetmap

import (
	"net/netip"
	"testing"

	"tailscale.com/net/packet"
)

func udp4(src, dst netip.Addr, sport, dport uint16) []byte {
	return packet.Generate(packet.UDP4Header{
		IP4Header: packet.IP4Header{Src: src, Dst: dst},
		SrcPort:   sport,
		DstPort:   dport,
	}, []byte("hello"))
}

func udp6(src, dst netip.Addr, sport, dport uint16) []byte {
	return packet.Generate(packet.UDP6Header{
		IP6Header: packet.IP6Header{Src: src, Dst: dst},
		SrcPort:   sport,
		DstPort:   dport,
	}, []byte("hello"))
}

func TestOutboundMapsEffectiveDestinationToCanonicalProfile(t *testing.T) {
	effectiveDst := netip.MustParseAddr("100.127.0.1")
	canonicalDst := netip.MustParseAddr("100.64.0.1")
	effectiveSrc := netip.MustParseAddr("100.127.0.10")
	canonicalSrc := netip.MustParseAddr("100.65.0.10")
	mapper := New(Table{
		Destinations: map[netip.Addr]Destination{
			effectiveDst: {ProfileID: "work", CanonicalIP: canonicalDst},
		},
		Sources: map[SourceKey]Source{
			{ProfileID: "work"}: {EffectiveIP: effectiveSrc, CanonicalIP: canonicalSrc},
		},
	})
	translated, route, err := mapper.Outbound(udp4(effectiveSrc, effectiveDst, 1111, 2222))
	if err != nil {
		t.Fatal(err)
	}
	if route.ProfileID != "work" {
		t.Fatalf("route profile = %q, want work", route.ProfileID)
	}
	var p packet.Parsed
	p.Decode(translated)
	if p.Src.Addr() != canonicalSrc || p.Dst.Addr() != canonicalDst {
		t.Fatalf("translated packet = %v > %v, want %v > %v", p.Src.Addr(), p.Dst.Addr(), canonicalSrc, canonicalDst)
	}
}

func TestInboundMapsCanonicalAddressesToEffective(t *testing.T) {
	effectivePeer := netip.MustParseAddr("100.127.0.1")
	canonicalPeer := netip.MustParseAddr("100.64.0.1")
	effectiveSelf := netip.MustParseAddr("100.127.0.10")
	canonicalSelf := netip.MustParseAddr("100.65.0.10")
	mapper := New(Table{
		InboundPeers: map[InboundKey]netip.Addr{{ProfileID: "work", CanonicalIP: canonicalPeer}: effectivePeer},
		Sources:      map[SourceKey]Source{{ProfileID: "work"}: {EffectiveIP: effectiveSelf, CanonicalIP: canonicalSelf}},
	})
	translated, err := mapper.Inbound("work", udp4(canonicalPeer, canonicalSelf, 2222, 1111))
	if err != nil {
		t.Fatal(err)
	}
	var p packet.Parsed
	p.Decode(translated)
	if p.Src.Addr() != effectivePeer || p.Dst.Addr() != effectiveSelf {
		t.Fatalf("translated packet = %v > %v, want %v > %v", p.Src.Addr(), p.Dst.Addr(), effectivePeer, effectiveSelf)
	}
}

func TestOutboundUnknownEffectiveDestinationIsRejected(t *testing.T) {
	mapper := New(Table{})
	_, _, err := mapper.Outbound(udp4(netip.MustParseAddr("100.127.0.10"), netip.MustParseAddr("100.127.0.99"), 1, 2))
	if err == nil {
		t.Fatal("expected unknown destination error")
	}
}

func TestIPv6UsesIPv6ProfileSource(t *testing.T) {
	effectiveDst := netip.MustParseAddr("fd6d:6e65:7400::20")
	canonicalDst := netip.MustParseAddr("fd7a:115c:a1e0::20")
	effectiveSrc := netip.MustParseAddr("fd6d:6e65:7400::10")
	canonicalSrc := netip.MustParseAddr("fd7a:115c:a1e0::10")
	mapper := New(Table{
		Destinations: map[netip.Addr]Destination{
			effectiveDst: {ProfileID: "work", CanonicalIP: canonicalDst},
		},
		Sources: map[SourceKey]Source{
			{ProfileID: "work", IPv6: true}: {EffectiveIP: effectiveSrc, CanonicalIP: canonicalSrc},
		},
	})
	translated, _, err := mapper.Outbound(udp6(effectiveSrc, effectiveDst, 1111, 2222))
	if err != nil {
		t.Fatal(err)
	}
	var p packet.Parsed
	p.Decode(translated)
	if p.Src.Addr() != canonicalSrc || p.Dst.Addr() != canonicalDst {
		t.Fatalf("translated IPv6 packet = %v > %v, want %v > %v", p.Src.Addr(), p.Dst.Addr(), canonicalSrc, canonicalDst)
	}
}
