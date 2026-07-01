package packetmap

import (
	"fmt"
	"net/netip"
	"slices"

	"tailscale.com/net/packet"
	"tailscale.com/net/packet/checksum"
)

type Destination struct {
	ProfileID   string
	CanonicalIP netip.Addr
}

type Source struct {
	EffectiveIP netip.Addr
	CanonicalIP netip.Addr
}

type InboundKey struct {
	ProfileID   string
	CanonicalIP netip.Addr
}

type Table struct {
	Destinations map[netip.Addr]Destination
	Sources      map[string]Source
	InboundPeers map[InboundKey]netip.Addr
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
	dst, ok := m.table.Destinations[p.Dst.Addr()]
	if !ok {
		return nil, Route{}, fmt.Errorf("no profile route for effective destination %v", p.Dst.Addr())
	}
	src, ok := m.table.Sources[dst.ProfileID]
	if !ok {
		return nil, Route{}, fmt.Errorf("no source mapping for profile %q", dst.ProfileID)
	}
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
	effectivePeer, ok := m.table.InboundPeers[InboundKey{ProfileID: profileID, CanonicalIP: p.Src.Addr()}]
	if !ok {
		return nil, fmt.Errorf("no inbound peer mapping for profile=%q canonical=%v", profileID, p.Src.Addr())
	}
	src, ok := m.table.Sources[profileID]
	if !ok {
		return nil, fmt.Errorf("no source mapping for profile %q", profileID)
	}
	checksum.UpdateSrcAddr(&p, effectivePeer)
	checksum.UpdateDstAddr(&p, src.EffectiveIP)
	return out, nil
}
