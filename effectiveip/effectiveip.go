package effectiveip

import (
	"fmt"
	"net/netip"
	"sort"
)

type Node struct {
	ProfileID   string
	NodeID      string
	CanonicalIP netip.Addr
}

type NodeKey struct {
	ProfileID   string
	NodeID      string
	CanonicalIP netip.Addr
}

type Lease struct {
	NodeKey     NodeKey
	EffectiveIP netip.Addr
}

type Allocator struct {
	pool     netip.Prefix
	leases   map[NodeKey]netip.Addr
	used     map[netip.Addr]NodeKey
	reserved map[netip.Addr]bool
}

type Plan struct {
	Leases []Lease
	byKey  map[NodeKey]netip.Addr
}

func NewAllocator(pool netip.Prefix, existing []Lease, reserved ...netip.Addr) *Allocator {
	pool = pool.Masked()
	a := &Allocator{
		pool:     pool,
		leases:   map[NodeKey]netip.Addr{},
		used:     map[netip.Addr]NodeKey{},
		reserved: map[netip.Addr]bool{},
	}
	for _, ip := range reserved {
		if ip.IsValid() && ip.Is6() == pool.Addr().Is6() && pool.Contains(ip) {
			a.reserved[ip] = true
		}
	}
	for _, l := range existing {
		if !l.NodeKey.CanonicalIP.IsValid() || !l.EffectiveIP.IsValid() {
			continue
		}
		if l.NodeKey.CanonicalIP.Is6() != l.EffectiveIP.Is6() {
			continue
		}
		if !pool.Contains(l.EffectiveIP) {
			continue
		}
		if a.reserved[l.EffectiveIP] {
			continue
		}
		a.leases[l.NodeKey] = l.EffectiveIP
		a.used[l.EffectiveIP] = l.NodeKey
	}
	return a
}

func (a *Allocator) Assign(nodes []Node) (*Plan, error) {
	for _, n := range nodes {
		if !n.CanonicalIP.IsValid() {
			return nil, fmt.Errorf("invalid canonical IP for profile=%q node=%q", n.ProfileID, n.NodeID)
		}
		if !a.pool.IsValid() || a.pool.Addr().Is6() != n.CanonicalIP.Is6() {
			return nil, fmt.Errorf("effective IP pool %v cannot allocate for canonical address %v", a.pool, n.CanonicalIP)
		}
	}
	out := &Plan{byKey: map[NodeKey]netip.Addr{}}
	for _, n := range nodes {
		key := NodeKey{ProfileID: n.ProfileID, NodeID: n.NodeID, CanonicalIP: n.CanonicalIP}
		if existing, ok := a.leases[key]; ok {
			out.add(key, existing)
			continue
		}
		effective, err := a.nextSynthetic(key)
		if err != nil {
			return nil, err
		}
		a.leases[key] = effective
		a.used[effective] = key
		out.add(key, effective)
	}
	sort.Slice(out.Leases, func(i, j int) bool {
		a, b := out.Leases[i], out.Leases[j]
		if a.NodeKey.ProfileID != b.NodeKey.ProfileID {
			return a.NodeKey.ProfileID < b.NodeKey.ProfileID
		}
		return a.NodeKey.NodeID < b.NodeKey.NodeID
	})
	return out, nil
}

func (a *Allocator) nextSynthetic(key NodeKey) (netip.Addr, error) {
	for ip := a.pool.Addr(); a.pool.Contains(ip); ip = ip.Next() {
		if !ip.IsValid() {
			break
		}
		if a.reserved[ip] {
			continue
		}
		if owner, used := a.used[ip]; !used || owner == key {
			return ip, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("effective IP pool %v exhausted for profile=%q node=%q canonical=%v", a.pool, key.ProfileID, key.NodeID, key.CanonicalIP)
}

func (p *Plan) add(key NodeKey, effective netip.Addr) {
	p.byKey[key] = effective
	p.Leases = append(p.Leases, Lease{NodeKey: key, EffectiveIP: effective})
}

func (p *Plan) MustEffective(key NodeKey) netip.Addr {
	ip, ok := p.byKey[key]
	if !ok {
		panic(fmt.Sprintf("missing effective IP for %+v", key))
	}
	return ip
}
