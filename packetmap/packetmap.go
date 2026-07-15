package packetmap

import (
	"fmt"
	"net/netip"
	"slices"

	"github.com/gaissmai/bart"
	"tailscale.com/net/packet"
	"tailscale.com/net/packet/checksum"
)

type Destination struct {
	ProfileID   string
	CanonicalIP netip.Addr
}

type Source struct {
	HostIP      netip.Addr
	CanonicalIP netip.Addr
}

type SourceKey struct {
	ProfileID string
	IPv6      bool
}

type Table struct {
	Destinations *bart.Table[Destination]
	Sources      map[SourceKey]Source
	InboundPeers map[string]*bart.Table[netip.Addr]
}

type Route struct {
	ProfileID   string
	CanonicalIP netip.Addr
}

type Mapper struct {
	table Table
}

func New(table Table) *Mapper {
	return &Mapper{table: table}
}

func (m *Mapper) Outbound(pkt []byte) ([]byte, Route, error) {
	var p packet.Parsed
	out := slices.Clone(pkt)
	p.Decode(out)
	if p.IPVersion == 0 {
		return nil, Route{}, fmt.Errorf("unsupported packet")
	}
	if m.table.Destinations == nil {
		return nil, Route{}, fmt.Errorf("no destination routes")
	}
	dst, ok := m.table.Destinations.Lookup(p.Dst.Addr())
	if !ok {
		return nil, Route{}, fmt.Errorf("no profile route for effective destination %v", p.Dst.Addr())
	}
	src, ok := m.table.Sources[sourceKey(dst.ProfileID, p.Src.Addr())]
	if !ok {
		return nil, Route{}, fmt.Errorf("no %s source mapping for profile %q", addressFamily(p.Src.Addr()), dst.ProfileID)
	}
	if src.HostIP.Is6() != p.Src.Addr().Is6() || src.CanonicalIP.Is6() != p.Src.Addr().Is6() || dst.CanonicalIP.Is6() != p.Dst.Addr().Is6() {
		return nil, Route{}, fmt.Errorf("address family mismatch for profile %q", dst.ProfileID)
	}
	// SNAT the shared host address to the selected profile's canonical self
	// address before the packet enters that profile's tsnet engine.
	checksum.UpdateSrcAddr(&p, src.CanonicalIP)
	checksum.UpdateDstAddr(&p, dst.CanonicalIP)
	return out, Route{ProfileID: dst.ProfileID, CanonicalIP: dst.CanonicalIP}, nil
}

func (m *Mapper) Inbound(profileID string, pkt []byte) ([]byte, error) {
	var p packet.Parsed
	out := slices.Clone(pkt)
	p.Decode(out)
	if p.IPVersion == 0 {
		return nil, fmt.Errorf("unsupported packet")
	}
	inbound := m.table.InboundPeers[profileID]
	if inbound == nil {
		return nil, fmt.Errorf("no inbound routes for profile=%q", profileID)
	}
	effectivePeer, ok := inbound.Lookup(p.Src.Addr())
	if !ok {
		return nil, fmt.Errorf("no inbound peer mapping for profile=%q canonical=%v", profileID, p.Src.Addr())
	}
	src, ok := m.table.Sources[sourceKey(profileID, p.Dst.Addr())]
	if !ok {
		return nil, fmt.Errorf("no %s source mapping for profile %q", addressFamily(p.Dst.Addr()), profileID)
	}
	if effectivePeer.Is6() != p.Src.Addr().Is6() || src.HostIP.Is6() != p.Dst.Addr().Is6() {
		return nil, fmt.Errorf("address family mismatch for profile %q", profileID)
	}
	checksum.UpdateSrcAddr(&p, effectivePeer)
	// DNAT the profile's canonical self address back to the one address the
	// host owns on the shared TUN.
	checksum.UpdateDstAddr(&p, src.HostIP)
	return out, nil
}

func sourceKey(profileID string, ip netip.Addr) SourceKey {
	return SourceKey{ProfileID: profileID, IPv6: ip.Is6()}
}

func addressFamily(ip netip.Addr) string {
	if ip.Is6() {
		return "IPv6"
	}
	return "IPv4"
}
