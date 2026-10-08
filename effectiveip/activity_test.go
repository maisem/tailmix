package effectiveip

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

func activityLease(node, canonical, effective string) Lease {
	return Lease{
		NodeKey:     NodeKey{ProfileID: "work", NodeID: node, CanonicalIP: netip.MustParseAddr(canonical)},
		EffectiveIP: netip.MustParseAddr(effective),
	}
}

func activityKeys(leases []Lease) []NodeKey {
	keys := make([]NodeKey, 0, len(leases))
	for _, lease := range leases {
		keys = append(keys, lease.NodeKey)
	}
	return keys
}

func TestActivityTrackerRetainsForExactlyOneHour(t *testing.T) {
	lease := activityLease("gone", "100.64.0.2", "100.127.0.3")
	v6 := activityLease("gone", "fd7a:115c:a1e0::2", "fd6d:6e65:7400::3")
	observable := map[string]bool{"work": true}
	now := time.Now()

	var a ActivityTracker
	a.SetLeases([]Lease{lease, v6})
	if got := a.Retain([]Lease{lease, v6}, nil, observable, now); len(got) != 2 {
		t.Fatalf("first absence dropped leases: %v", activityKeys(got))
	}
	if got := a.Retain([]Lease{lease, v6}, nil, observable, now.Add(LeaseRetention-time.Nanosecond)); len(got) != 2 {
		t.Fatalf("dropped before retention elapsed: %v", activityKeys(got))
	}
	if got := a.Retain([]Lease{lease, v6}, nil, observable, now.Add(LeaseRetention)); len(got) != 0 {
		t.Fatalf("retained after retention elapsed: %v", activityKeys(got))
	}
	if len(a.entries) != 0 {
		t.Fatalf("dropped leases still tracked: %d", len(a.entries))
	}
}

func TestActivityTrackerOutboundExtendsDormantGrace(t *testing.T) {
	lease := activityLease("gone", "100.64.0.2", "100.127.0.3")
	observable := map[string]bool{"work": true}
	var a ActivityTracker
	a.SetLeases([]Lease{lease})
	start := time.Now()
	a.Retain([]Lease{lease}, nil, observable, start)

	a.ObserveOutbound(netip.MustParseAddr("::ffff:100.127.0.3"))
	touched := a.entries[lease.EffectiveIP].lastSeen
	if !touched.After(start) {
		t.Fatal("mapped outbound packet did not extend the dormant lease")
	}
	if got := a.Retain([]Lease{lease}, nil, observable, start.Add(LeaseRetention)); len(got) != 1 {
		t.Fatal("recently addressed dormant lease was dropped")
	}
	if got := a.Retain([]Lease{lease}, nil, observable, touched.Add(LeaseRetention)); len(got) != 0 {
		t.Fatal("dormant lease survived a full quiet hour")
	}

	// Unknown addresses never allocate state, and present leases are not
	// touched because they never expire.
	a.SetLeases([]Lease{lease})
	a.ObserveOutbound(netip.MustParseAddr("100.127.0.4"))
	before := a.entries[lease.EffectiveIP]
	a.ObserveOutbound(lease.EffectiveIP)
	if len(a.entries) != 1 || a.entries[lease.EffectiveIP] != before {
		t.Fatalf("tracker state changed unexpectedly: %+v", a.entries)
	}
}

func TestActivityTrackerPresenceAndUnobservableProfiles(t *testing.T) {
	lease := activityLease("peer", "100.64.0.2", "100.127.0.3")
	other := Lease{
		NodeKey:     NodeKey{ProfileID: "home", NodeID: "peer", CanonicalIP: netip.MustParseAddr("100.64.0.2")},
		EffectiveIP: netip.MustParseAddr("100.127.0.4"),
	}
	leases := []Lease{lease, other}
	observable := map[string]bool{"work": true}
	var a ActivityTracker
	a.SetLeases(leases)
	now := time.Now()

	// "home" is not observable, so its lease counts as present. "work" sees
	// its peer in the netmap.
	present := map[NodeKey]bool{lease.NodeKey: true}
	for i := 0; i < 3; i++ {
		now = now.Add(LeaseRetention)
		if got := a.Retain(leases, present, observable, now); len(got) != 2 {
			t.Fatalf("present or unobservable lease dropped: %v", activityKeys(got))
		}
	}
	// A target that was present at the previous observation gets a full
	// window from the observation that first misses it.
	if got := a.Retain(leases, nil, observable, now.Add(LeaseRetention)); len(got) != 2 {
		t.Fatalf("absence did not start a full window: %v", activityKeys(got))
	}
	if got := a.Retain(leases, nil, observable, now.Add(2*LeaseRetention)); len(got) != 1 || got[0].NodeKey != other.NodeKey {
		t.Fatalf("expected only the unobservable profile's lease, got %v", activityKeys(got))
	}
}

func TestActivityTrackerRecycledAddressAndReindex(t *testing.T) {
	old := activityLease("old", "100.64.0.2", "100.127.0.3")
	recycled := activityLease("new", "100.64.0.5", "100.127.0.3")
	observable := map[string]bool{"work": true}
	var a ActivityTracker
	a.SetLeases([]Lease{old})
	start := time.Now()
	a.Retain([]Lease{old}, nil, observable, start)

	// SetLeases keeps the dormant record for the same target and address.
	a.SetLeases([]Lease{old, activityLease("other", "100.64.0.9", "100.127.0.9")})
	if got := a.Retain([]Lease{old}, nil, observable, start.Add(LeaseRetention)); len(got) != 0 {
		t.Fatal("reindex restarted the dormant window")
	}
	// A different target at the same effective IP never inherits the old
	// target's absence.
	a.SetLeases([]Lease{old})
	a.Retain([]Lease{old}, nil, observable, start)
	a.SetLeases([]Lease{recycled})
	if entry := a.entries[recycled.EffectiveIP]; !entry.present || entry.key != recycled.NodeKey {
		t.Fatalf("recycled address inherited the old record: %+v", entry)
	}
	a.SetLeases([]Lease{old})
	a.Retain([]Lease{old}, nil, observable, start)
	if got := a.Retain([]Lease{recycled}, nil, observable, start.Add(LeaseRetention)); len(got) != 1 {
		t.Fatal("recycled address inherited the old target's absence")
	}
	// Invalid and duplicate addresses are ignored; state stays bounded.
	invalid := Lease{NodeKey: NodeKey{ProfileID: "work", NodeID: "x"}, EffectiveIP: netip.MustParseAddr("100.127.0.7")}
	a.SetLeases([]Lease{recycled, recycled, invalid})
	if len(a.entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(a.entries))
	}
}

func TestActivityTrackerConcurrentUse(t *testing.T) {
	lease := activityLease("gone", "100.64.0.2", "100.127.0.3")
	observable := map[string]bool{"work": true}
	var a ActivityTracker
	a.SetLeases([]Lease{lease})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				a.ObserveOutbound(lease.EffectiveIP)
				a.Retain([]Lease{lease}, nil, observable, time.Now())
				a.SetLeases([]Lease{lease})
			}
		}()
	}
	wg.Wait()
	if got := a.Retain([]Lease{lease}, nil, observable, time.Now()); len(got) != 1 {
		t.Fatal("recently used lease dropped")
	}
}
