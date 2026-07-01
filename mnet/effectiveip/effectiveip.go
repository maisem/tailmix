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
	pool   netip.Prefix
	leases map[NodeKey]netip.Addr
	used   map[netip.Addr]NodeKey
}

type Plan struct {
	Leases []Lease
	byKey  map[NodeKey]netip.Addr
}

func NewAllocator(pool netip.Prefix, existing []Lease) *Allocator {
	a := &Allocator{
		pool:   pool,
		leases: map[NodeKey]netip.Addr{},
		used:   map[netip.Addr]NodeKey{},
	}
	for _, l := range existing {
		if !l.NodeKey.CanonicalIP.IsValid() || !l.EffectiveIP.IsValid() {
			continue
		}
		a.leases[l.NodeKey] = l.EffectiveIP
		a.used[l.EffectiveIP] = l.NodeKey
	}
	return a
}

func (a *Allocator) Assign(nodes []Node) (*Plan, error) {
	canonicalCount := map[netip.Addr]int{}
	for _, n := range nodes {
		canonicalCount[n.CanonicalIP]++
	}
	out := &Plan{byKey: map[NodeKey]netip.Addr{}}
	for _, n := range nodes {
		key := NodeKey{ProfileID: n.ProfileID, NodeID: n.NodeID, CanonicalIP: n.CanonicalIP}
		if existing, ok := a.leases[key]; ok {
			out.add(key, existing)
			continue
		}
		effective := n.CanonicalIP
		if canonicalCount[n.CanonicalIP] > 1 || a.claimedByOther(key, effective) {
			var err error
			effective, err = a.nextSynthetic(key)
			if err != nil {
				return nil, err
			}
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

func (a *Allocator) claimedByOther(key NodeKey, ip netip.Addr) bool {
	owner, ok := a.used[ip]
	return ok && owner != key
}

func (a *Allocator) nextSynthetic(key NodeKey) (netip.Addr, error) {
	for ip := a.pool.Addr(); a.pool.Contains(ip); ip = ip.Next() {
		if !ip.IsValid() {
			break
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
