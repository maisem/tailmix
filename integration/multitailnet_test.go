package integration

import (
	"net/netip"
	"testing"

	"github.com/maisem/tailmix/effectiveip"
)

func TestTwoTailnetsWithCollidingCanonicalIPsReceiveStableEffectiveIPs(t *testing.T) {
	canonical := netip.MustParseAddr("100.64.0.1")
	selfA := effectiveip.Node{ProfileID: "tailnet-a", NodeID: "self-a", CanonicalIP: canonical}
	selfB := effectiveip.Node{ProfileID: "tailnet-b", NodeID: "self-b", CanonicalIP: canonical}
	alloc := effectiveip.NewAllocator(netip.MustParsePrefix("100.127.0.0/24"), nil)
	first, err := alloc.Assign([]effectiveip.Node{selfA, selfB})
	if err != nil {
		t.Fatal(err)
	}
	second, err := effectiveip.NewAllocator(netip.MustParsePrefix("100.127.0.0/24"), first.Leases).Assign([]effectiveip.Node{selfA, selfB})
	if err != nil {
		t.Fatal(err)
	}
	keyA := effectiveip.NodeKey{ProfileID: selfA.ProfileID, NodeID: selfA.NodeID, CanonicalIP: canonical}
	keyB := effectiveip.NodeKey{ProfileID: selfB.ProfileID, NodeID: selfB.NodeID, CanonicalIP: canonical}
	if first.MustEffective(keyA) == first.MustEffective(keyB) {
		t.Fatal("colliding tailnets received same effective self IP")
	}
	if first.MustEffective(keyA) != second.MustEffective(keyA) || first.MustEffective(keyB) != second.MustEffective(keyB) {
		t.Fatal("effective IPs changed after restart")
	}
}
