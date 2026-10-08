package effectiveip

import (
	"net/netip"
	"sync"
	"time"
)

// LeaseRetention is how long a lease survives after its target was last
// present in a netmap or last received an outbound packet from this host.
const LeaseRetention = time.Hour

// ActivityTracker decides when dormant leases may be reclaimed. It only keeps
// process-local monotonic timestamps: wall-clock changes are ignored, every
// lease starts a fresh retention window after a restart, and time spent in
// system sleep counts only as far as the platform monotonic clock advances.
// Its zero value is usable and all methods are safe to call concurrently.
type ActivityTracker struct {
	mu      sync.Mutex
	entries map[netip.Addr]activityEntry
}

type activityEntry struct {
	key      NodeKey
	lastSeen time.Time
	present  bool
}

// SetLeases replaces the known leases, keyed by effective IP. A lease whose
// effective IP already tracks the same target keeps its record; any other
// lease starts present with a full retention window.
func (a *ActivityTracker) SetLeases(leases []Lease) {
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	entries := make(map[netip.Addr]activityEntry, len(leases))
	for _, lease := range leases {
		effective, ok := leaseAddr(lease)
		if !ok {
			continue
		}
		if _, dup := entries[effective]; dup {
			continue
		}
		entry, ok := a.entries[effective]
		if !ok || entry.key != lease.NodeKey {
			entry = activityEntry{key: lease.NodeKey, lastSeen: now, present: true}
		}
		entries[effective] = entry
	}
	a.entries = entries
}

// ObserveOutbound records a host packet or dial aimed at an effective IP.
// Only dormant leases are updated: present targets never expire anyway, and
// unknown addresses never allocate tracker state.
func (a *ActivityTracker) ObserveOutbound(effective netip.Addr) {
	effective = effective.Unmap()
	a.mu.Lock()
	defer a.mu.Unlock()
	entry, ok := a.entries[effective]
	if !ok || entry.present {
		return
	}
	if now := time.Now(); now.After(entry.lastSeen) {
		entry.lastSeen = now
		a.entries[effective] = entry
	}
}

// Retain returns the leases that survive this observation, in input order.
// present lists targets in a current netmap and observable lists profiles
// whose netmap was actually observed; a lease of an unobservable profile is
// treated as present. A lease is dropped once its target has been absent and
// its effective IP unused for LeaseRetention. Absence is measured from the
// observation that first missed the target, so a lease that was present at the
// previous observation, or is new to the tracker, always gets a full window.
func (a *ActivityTracker) Retain(leases []Lease, present map[NodeKey]bool, observable map[string]bool, now time.Time) []Lease {
	a.mu.Lock()
	defer a.mu.Unlock()
	entries := make(map[netip.Addr]activityEntry, len(leases))
	out := make([]Lease, 0, len(leases))
	for _, lease := range leases {
		effective, ok := leaseAddr(lease)
		if !ok {
			continue
		}
		if _, dup := entries[effective]; dup {
			continue
		}
		entry, known := a.entries[effective]
		known = known && entry.key == lease.NodeKey
		switch {
		case present[lease.NodeKey] || !observable[lease.NodeKey.ProfileID]:
			entry = activityEntry{key: lease.NodeKey, lastSeen: now, present: true}
		case !known || entry.present:
			entry = activityEntry{key: lease.NodeKey, lastSeen: now}
		case now.Sub(entry.lastSeen) >= LeaseRetention:
			continue
		}
		entries[effective] = entry
		out = append(out, lease)
	}
	a.entries = entries
	return out
}

func leaseAddr(lease Lease) (netip.Addr, bool) {
	if !lease.NodeKey.CanonicalIP.IsValid() || !lease.EffectiveIP.IsValid() {
		return netip.Addr{}, false
	}
	return lease.EffectiveIP.Unmap(), true
}
