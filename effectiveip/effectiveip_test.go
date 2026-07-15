package effectiveip

import (
	"net/netip"
	"testing"
)

func TestAllocatorAssignsEveryNodeFromEffectivePool(t *testing.T) {
	pool := netip.MustParsePrefix("100.127.0.0/29")
	a := NewAllocator(pool, nil)
	nodes := []Node{
		{ProfileID: "work", NodeID: "node-a", CanonicalIP: netip.MustParseAddr("100.64.0.1")},
		{ProfileID: "home", NodeID: "node-b", CanonicalIP: netip.MustParseAddr("100.64.0.1")},
		{ProfileID: "lab", NodeID: "node-c", CanonicalIP: netip.MustParseAddr("100.64.0.2")},
	}
	plan, err := a.Assign(nodes)
	if err != nil {
		t.Fatal(err)
	}
	gotA := plan.MustEffective(NodeKey{ProfileID: "work", NodeID: "node-a", CanonicalIP: nodes[0].CanonicalIP})
	gotB := plan.MustEffective(NodeKey{ProfileID: "home", NodeID: "node-b", CanonicalIP: nodes[1].CanonicalIP})
	gotC := plan.MustEffective(NodeKey{ProfileID: "lab", NodeID: "node-c", CanonicalIP: nodes[2].CanonicalIP})
	if gotA == gotB {
		t.Fatalf("conflicting canonical IPs received same effective IP: %v", gotA)
	}
	for _, got := range []netip.Addr{gotA, gotB, gotC} {
		if !pool.Contains(got) {
			t.Fatalf("effective IP %v is outside pool %v", got, pool)
		}
	}
	if gotA == gotC || gotB == gotC {
		t.Fatalf("effective IPs are not unique: %v %v %v", gotA, gotB, gotC)
	}
}

func TestAllocatorPreservesExistingLeases(t *testing.T) {
	canonical := netip.MustParseAddr("100.64.0.1")
	effective := netip.MustParseAddr("100.127.0.1")
	key := NodeKey{ProfileID: "work", NodeID: "node-a", CanonicalIP: canonical}
	a := NewAllocator(netip.MustParsePrefix("100.127.0.0/30"), []Lease{{NodeKey: key, EffectiveIP: effective}})
	plan, err := a.Assign([]Node{{ProfileID: key.ProfileID, NodeID: key.NodeID, CanonicalIP: canonical}})
	if err != nil {
		t.Fatal(err)
	}
	if got := plan.MustEffective(key); got != effective {
		t.Fatalf("effective IP changed across restart: got %v want %v", got, effective)
	}
}

func TestAllocatorDoesNotReuseSyntheticLeaseOutsidePool(t *testing.T) {
	canonical := netip.MustParseAddr("100.64.0.1")
	key := NodeKey{ProfileID: "work", NodeID: "node-a", CanonicalIP: canonical}
	allocator := NewAllocator(netip.MustParsePrefix("10.250.0.0/24"), []Lease{{
		NodeKey:     key,
		EffectiveIP: netip.MustParseAddr("100.127.0.1"),
	}})
	plan, err := allocator.Assign([]Node{{
		ProfileID: "work", NodeID: "node-a", CanonicalIP: canonical,
	}, {
		ProfileID: "home", NodeID: "node-b", CanonicalIP: canonical,
	}})
	if err != nil {
		t.Fatal(err)
	}
	pool := netip.MustParsePrefix("10.250.0.0/24")
	for _, lease := range plan.Leases {
		if !pool.Contains(lease.EffectiveIP) {
			t.Fatalf("effective IP %v is outside configured pool %v", lease.EffectiveIP, pool)
		}
	}
}

func TestAllocatorReportsPoolExhaustion(t *testing.T) {
	a := NewAllocator(netip.MustParsePrefix("100.127.0.0/32"), nil)
	_, err := a.Assign([]Node{
		{ProfileID: "a", NodeID: "n1", CanonicalIP: netip.MustParseAddr("100.64.0.1")},
		{ProfileID: "b", NodeID: "n2", CanonicalIP: netip.MustParseAddr("100.64.0.1")},
		{ProfileID: "c", NodeID: "n3", CanonicalIP: netip.MustParseAddr("100.64.0.1")},
	})
	if err == nil {
		t.Fatal("expected pool exhaustion error")
	}
}

func TestAllocatorDoesNotAssignReservedNATAddress(t *testing.T) {
	pool := netip.MustParsePrefix("10.250.0.0/30")
	natIP := netip.MustParseAddr("10.250.0.0")
	a := NewAllocator(pool, nil, natIP)
	plan, err := a.Assign([]Node{{ProfileID: "work", NodeID: "peer", CanonicalIP: netip.MustParseAddr("100.64.0.42")}})
	if err != nil {
		t.Fatal(err)
	}
	if got := plan.Leases[0].EffectiveIP; got == natIP || !pool.Contains(got) {
		t.Fatalf("peer effective IP = %v, want non-NAT address in %v", got, pool)
	}
}

func TestAllocatorRejectsSyntheticAddressFamilyMismatch(t *testing.T) {
	canonical := netip.MustParseAddr("fd7a:115c:a1e0::1")
	a := NewAllocator(netip.MustParsePrefix("100.127.0.0/24"), nil)
	_, err := a.Assign([]Node{
		{ProfileID: "a", NodeID: "n1", CanonicalIP: canonical},
		{ProfileID: "b", NodeID: "n2", CanonicalIP: canonical},
	})
	if err == nil {
		t.Fatal("expected address family mismatch error")
	}
}
