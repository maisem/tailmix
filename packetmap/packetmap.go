package packetmap

import (
	"fmt"
	"net/netip"

	"github.com/gaissmai/bart"
	"tailscale.com/net/packet"
	"tailscale.com/net/packet/checksum"
)

type Destination struct {
	ProfileID   string
	CanonicalIP netip.Addr
}

type SubnetRoute struct {
	ProfileID string
	Active    bool
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
	Destinations   *bart.Table[Destination]
	ExactRoutes    *bart.Table[SubnetRoute]
	ImportedRoutes *bart.Table[SubnetRoute]
	Sources        map[SourceKey]Source
	InboundPeers   map[string]*bart.Table[netip.Addr]
}

type Route struct {
	ProfileID           string
	CanonicalIP         netip.Addr
	PreserveDestination bool
}

type Mapper struct {
	table Table
}

func New(table Table) *Mapper {
	return &Mapper{table: table}
}

func (m *Mapper) Outbound(pkt []byte) ([]byte, Route, error) {
	var p packet.Parsed
	p.Decode(pkt)
	if p.IPVersion == 0 {
		return nil, Route{}, fmt.Errorf("unsupported packet")
	}
	if m.table.Destinations == nil {
		return nil, Route{}, fmt.Errorf("no destination routes")
	}
	dst, preserve, err := m.outboundDestination(p.Dst.Addr())
	if err != nil {
		return nil, Route{}, err
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
	if !preserve {
		checksum.UpdateDstAddr(&p, dst.CanonicalIP)
	}
	return pkt, Route{
		ProfileID:           dst.ProfileID,
		CanonicalIP:         dst.CanonicalIP,
		PreserveDestination: preserve,
	}, nil
}

func (m *Mapper) Inbound(profileID string, pkt []byte) ([]byte, error) {
	var p packet.Parsed
	p.Decode(pkt)
	if p.IPVersion == 0 {
		return nil, fmt.Errorf("unsupported packet")
	}
	src, ok := m.table.Sources[sourceKey(profileID, p.Dst.Addr())]
	if !ok {
		return nil, fmt.Errorf("no %s source mapping for profile %q", addressFamily(p.Dst.Addr()), profileID)
	}
	inbound := m.table.InboundPeers[profileID]
	if inbound != nil {
		if effectivePeer, ok := inbound.Lookup(p.Src.Addr()); ok {
			if effectivePeer.Is6() != p.Src.Addr().Is6() || src.HostIP.Is6() != p.Dst.Addr().Is6() {
				return nil, fmt.Errorf("address family mismatch for profile %q", profileID)
			}
			checksum.UpdateSrcAddr(&p, effectivePeer)
			checksum.UpdateDstAddr(&p, src.HostIP)
			return pkt, nil
		}
	}
	route, err := m.inboundSubnetRoute(p.Src.Addr())
	if err != nil {
		return nil, err
	}
	if route.ProfileID != profileID {
		return nil, fmt.Errorf("subnet source %v is pinned to profile %q, not %q", p.Src.Addr(), route.ProfileID, profileID)
	}
	// DNAT the profile's canonical self address back to the one address the
	// host owns on the shared TUN.
	checksum.UpdateDstAddr(&p, src.HostIP)
	return pkt, nil
}

func (m *Mapper) outboundDestination(ip netip.Addr) (Destination, bool, error) {
	if m.table.Destinations != nil {
		if destination, ok := m.table.Destinations.Lookup(ip); ok {
			return destination, false, nil
		}
	}
	if route, ok := lookupSubnet(m.table.ExactRoutes, ip); ok {
		if !route.Active || route.ProfileID == "" {
			return Destination{}, false, fmt.Errorf("exact route for destination %v is unavailable", ip)
		}
		return Destination{ProfileID: route.ProfileID, CanonicalIP: ip}, true, nil
	}
	if route, ok := lookupSubnet(m.table.ImportedRoutes, ip); ok {
		if !route.Active || route.ProfileID == "" {
			return Destination{}, false, fmt.Errorf("imported route for destination %v is ambiguous or unavailable", ip)
		}
		return Destination{ProfileID: route.ProfileID, CanonicalIP: ip}, true, nil
	}
	return Destination{}, false, fmt.Errorf("no profile route for destination %v", ip)
}

func (m *Mapper) inboundSubnetRoute(ip netip.Addr) (SubnetRoute, error) {
	if route, ok := lookupSubnet(m.table.ExactRoutes, ip); ok {
		if !route.Active || route.ProfileID == "" {
			return SubnetRoute{}, fmt.Errorf("exact route for subnet source %v is unavailable", ip)
		}
		return route, nil
	}
	if route, ok := lookupSubnet(m.table.ImportedRoutes, ip); ok {
		if !route.Active || route.ProfileID == "" {
			return SubnetRoute{}, fmt.Errorf("imported route for subnet source %v is ambiguous or unavailable", ip)
		}
		return route, nil
	}
	return SubnetRoute{}, fmt.Errorf("no inbound mapping for profile=%q source=%v", "", ip)
}

func lookupSubnet(table *bart.Table[SubnetRoute], ip netip.Addr) (SubnetRoute, bool) {
	if table == nil {
		return SubnetRoute{}, false
	}
	return table.Lookup(ip)
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
