package main

import (
	"slices"
	"time"

	"github.com/maisem/tailmix/effectiveip"
	tailmixprofile "github.com/maisem/tailmix/profile"
)

// Reclamation happens only during an existing reconciliation. The tracker keeps
// process-local monotonic timestamps, so restarting grants a fresh grace period.
func (s *supervisor) refreshLeasesLocked(statuses []tailmixprofile.Status, now time.Time) error {
	present := make(map[effectiveip.NodeKey]bool)
	observable := make(map[string]bool)
	for _, status := range statuses {
		managed := s.runtimes[status.ProfileID]
		if managed == nil || !managed.statusFresh || len(status.SelfIPs) == 0 {
			continue
		}
		observable[status.ProfileID] = true
		for _, node := range leaseTargets([]tailmixprofile.Status{status}) {
			present[effectiveip.NodeKey(node)] = true
		}
	}
	retained := s.leaseActivity.Retain(leasesFromState(s.st.Leases), present, observable, now)
	next := leasesToState(retained)
	if slices.Equal(next, s.st.Leases) {
		return nil
	}
	st := cloneState(s.st)
	st.Leases = next
	if err := s.store.Save(st); err != nil {
		return err
	}
	s.st = st
	return nil
}
