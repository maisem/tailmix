package packetmap

import (
	"net/netip"
	"testing"

	"github.com/gaissmai/bart"
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
	hostNAT := netip.MustParseAddr("10.250.0.10")
	canonicalSrc := netip.MustParseAddr("100.65.0.10")
	table := Table{
		Destinations: new(bart.Table[Destination]),
		Sources: map[SourceKey]Source{
			{ProfileID: "work"}: {HostIP: hostNAT, CanonicalIP: canonicalSrc},
		},
	}
	table.Destinations.Insert(netip.PrefixFrom(effectiveDst, 32), Destination{ProfileID: "work", CanonicalIP: canonicalDst})
	mapper := New(table)
	translated, route, err := mapper.Outbound(udp4(hostNAT, effectiveDst, 1111, 2222))
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
	hostNAT := netip.MustParseAddr("10.250.0.10")
	canonicalSelf := netip.MustParseAddr("100.65.0.10")
	inbound := new(bart.Table[netip.Addr])
	inbound.Insert(netip.PrefixFrom(canonicalPeer, 32), effectivePeer)
	mapper := New(Table{
		InboundPeers: map[string]*bart.Table[netip.Addr]{"work": inbound},
		Sources:      map[SourceKey]Source{{ProfileID: "work"}: {HostIP: hostNAT, CanonicalIP: canonicalSelf}},
	})
	translated, err := mapper.Inbound("work", udp4(canonicalPeer, canonicalSelf, 2222, 1111))
	if err != nil {
		t.Fatal(err)
	}
	var p packet.Parsed
	p.Decode(translated)
	if p.Src.Addr() != effectivePeer || p.Dst.Addr() != hostNAT {
		t.Fatalf("translated packet = %v > %v, want %v > %v", p.Src.Addr(), p.Dst.Addr(), effectivePeer, hostNAT)
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
	hostNAT := netip.MustParseAddr("fd6d:6e65:7400::10")
	canonicalSrc := netip.MustParseAddr("fd7a:115c:a1e0::10")
	table := Table{
		Destinations: new(bart.Table[Destination]),
		Sources: map[SourceKey]Source{
			{ProfileID: "work", IPv6: true}: {HostIP: hostNAT, CanonicalIP: canonicalSrc},
		},
	}
	table.Destinations.Insert(netip.PrefixFrom(effectiveDst, 128), Destination{ProfileID: "work", CanonicalIP: canonicalDst})
	mapper := New(table)
	translated, _, err := mapper.Outbound(udp6(hostNAT, effectiveDst, 1111, 2222))
	if err != nil {
		t.Fatal(err)
	}
	var p packet.Parsed
	p.Decode(translated)
	if p.Src.Addr() != canonicalSrc || p.Dst.Addr() != canonicalDst {
		t.Fatalf("translated IPv6 packet = %v > %v, want %v > %v", p.Src.Addr(), p.Dst.Addr(), canonicalSrc, canonicalDst)
	}
}

func TestExplicitSubnetRouteOverridesMoreSpecificImport(t *testing.T) {
	hostNAT := netip.MustParseAddr("10.250.0.10")
	labSelf := netip.MustParseAddr("100.65.0.10")
	exact := new(bart.Table[SubnetRoute])
	exact.Insert(netip.MustParsePrefix("10.0.0.0/8"), SubnetRoute{ProfileID: "lab", Active: true})
	imported := new(bart.Table[SubnetRoute])
	imported.Insert(netip.MustParsePrefix("10.20.0.0/16"), SubnetRoute{ProfileID: "work", Active: true})
	mapper := New(Table{
		Destinations:   new(bart.Table[Destination]),
		ExactRoutes:    exact,
		ImportedRoutes: imported,
		Sources: map[SourceKey]Source{
			{ProfileID: "lab"}: {HostIP: hostNAT, CanonicalIP: labSelf},
		},
	})
	destination := netip.MustParseAddr("10.20.1.2")
	translated, route, err := mapper.Outbound(udp4(hostNAT, destination, 1111, 2222))
	if err != nil {
		t.Fatal(err)
	}
	if route.ProfileID != "lab" || !route.PreserveDestination {
		t.Fatalf("route = %+v, want preserved lab route", route)
	}
	var parsed packet.Parsed
	parsed.Decode(translated)
	if parsed.Src.Addr() != labSelf || parsed.Dst.Addr() != destination {
		t.Fatalf("translated subnet packet = %v > %v", parsed.Src.Addr(), parsed.Dst.Addr())
	}
}

func TestWaitingExplicitSubnetRouteDoesNotFallBack(t *testing.T) {
	exact := new(bart.Table[SubnetRoute])
	exact.Insert(netip.MustParsePrefix("10.20.0.0/16"), SubnetRoute{ProfileID: "lab"})
	imported := new(bart.Table[SubnetRoute])
	imported.Insert(netip.MustParsePrefix("10.0.0.0/8"), SubnetRoute{ProfileID: "work", Active: true})
	mapper := New(Table{
		Destinations:   new(bart.Table[Destination]),
		ExactRoutes:    exact,
		ImportedRoutes: imported,
	})
	_, _, err := mapper.Outbound(udp4(
		netip.MustParseAddr("10.250.0.10"),
		netip.MustParseAddr("10.20.1.2"),
		1111, 2222))
	if err == nil {
		t.Fatal("waiting explicit route unexpectedly fell back to imported route")
	}
}
