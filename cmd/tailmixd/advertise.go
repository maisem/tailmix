package main

import (
	"context"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"sort"

	"github.com/maisem/tailmix/controlapi"
	tailmixprofile "github.com/maisem/tailmix/profile"
	"github.com/maisem/tailmix/state"
)

// tailscaledSocketPath and tailscaleInterfaceSysPath locate the signals used
// to detect a running tailscaled before advertising subnet routes. They are
// variables so tests can point them at scratch directories.
var (
	tailscaledSocketPath       = "/var/run/tailscale/tailscaled.sock"
	tailscaleInterfaceSysPath  = "/sys/class/net/tailscale0"
	tailscaledConflictDetected = detectTailscaledConflict
)

func (s *supervisor) requireAdvertiseSupportedLocked() error {
	if runtime.GOOS != "linux" || s.cfg.Mode != "tun" {
		return controlapi.NewError("unsupported", "route advertisement requires tun mode on Linux")
	}
	return nil
}

// detectTailscaledConflict reports whether a standalone tailscaled appears to
// own this host's routes or DNS. Advertising tailmix subnet routes while
// tailscaled is running would leave two daemons fighting over forwarding
// rules, so the advertise API refuses with a typed error until tailscaled is
// stopped (see docs/linux-install.md).
func detectTailscaledConflict() *controlapi.Error {
	if _, err := os.Stat(tailscaledSocketPath); err == nil {
		return controlapi.NewError("tailscaled_running",
			"tailscaled socket is present; stop tailscaled before advertising routes")
	}
	if _, err := os.Stat(tailscaleInterfaceSysPath); err == nil {
		return controlapi.NewError("tailscaled_running",
			"tailscale0 interface is present; stop tailscaled before advertising routes")
	}
	return nil
}

func (s *supervisor) AdvertiseRoutes(_ context.Context) (controlapi.AdvertisedRoutes, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireAdvertiseSupportedLocked(); err != nil {
		return controlapi.AdvertisedRoutes{}, err
	}
	return s.advertisedRoutesLocked(s.statusesLocked()), nil
}

func (s *supervisor) SetAdvertiseRoutes(_ context.Context, request controlapi.PatchAdvertiseRoutesRequest) (controlapi.AdvertisedRoutes, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireAdvertiseSupportedLocked(); err != nil {
		return controlapi.AdvertisedRoutes{}, err
	}
	next := cloneState(s.st)
	configured, err := profileByName(&next, request.ProfileName)
	if err != nil {
		return controlapi.AdvertisedRoutes{}, err
	}
	if configured.Removed {
		return controlapi.AdvertisedRoutes{}, controlapi.NewError("profile_not_found", "profile %q is removed", request.ProfileName)
	}
	desired := append([]netip.Prefix(nil), configured.AdvertiseRoutes...)
	if request.Replace {
		desired = nil
	}
	for _, prefix := range request.Remove {
		prefix, err := validateAdvertisePrefix(next, prefix)
		if err != nil {
			return controlapi.AdvertisedRoutes{}, err
		}
		desired = slices.DeleteFunc(desired, func(existing netip.Prefix) bool { return existing == prefix })
	}
	for _, prefix := range request.Add {
		prefix, err := validateAdvertisePrefix(next, prefix)
		if err != nil {
			return controlapi.AdvertisedRoutes{}, err
		}
		if !slices.Contains(desired, prefix) {
			desired = append(desired, prefix)
		}
	}
	if len(desired) != 0 {
		if conflict := tailscaledConflictDetected(); conflict != nil {
			return controlapi.AdvertisedRoutes{}, conflict
		}
	}
	configured.AdvertiseRoutes = desired
	if err := s.commitPolicyLocked(next); err != nil {
		return controlapi.AdvertisedRoutes{}, err
	}
	return s.advertisedRoutesLocked(s.statusesLocked()), nil
}

func (s *supervisor) ClearAdvertiseRoutes(_ context.Context, name string) (controlapi.AdvertisedRoutes, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireAdvertiseSupportedLocked(); err != nil {
		return controlapi.AdvertisedRoutes{}, err
	}
	next := cloneState(s.st)
	configured, err := profileByName(&next, name)
	if err != nil {
		return controlapi.AdvertisedRoutes{}, err
	}
	if configured.Removed {
		return controlapi.AdvertisedRoutes{}, controlapi.NewError("profile_not_found", "profile %q is removed", name)
	}
	if len(configured.AdvertiseRoutes) == 0 {
		return s.advertisedRoutesLocked(s.statusesLocked()), nil
	}
	configured.AdvertiseRoutes = nil
	if err := s.commitPolicyLocked(next); err != nil {
		return controlapi.AdvertisedRoutes{}, err
	}
	return s.advertisedRoutesLocked(s.statusesLocked()), nil
}

// validateAdvertisePrefix canonicalizes an advertise-side prefix. Unlike the
// accept-side policy validator, default routes are valid here: advertising
// 0.0.0.0/0 and ::/0 offers exit-node service. Reserved-range overlap is
// rejected for subnet advertisements; a default route trivially contains
// every range, so the reserved check cannot apply to it.
func validateAdvertisePrefix(st state.State, prefix netip.Prefix) (netip.Prefix, error) {
	if !prefix.IsValid() {
		return netip.Prefix{}, controlapi.NewError("invalid_prefix", "invalid IP prefix")
	}
	prefix = prefix.Masked()
	if prefix.Bits() != 0 && routeOverlapsReserved(st, prefix) {
		return netip.Prefix{}, controlapi.NewError("invalid_prefix", "route %v overlaps a tailmix reserved range", prefix)
	}
	return prefix, nil
}

func (s *supervisor) advertisedRoutesLocked(statuses []tailmixprofile.Status) controlapi.AdvertisedRoutes {
	result := controlapi.AdvertisedRoutes{ReconcileError: s.reconcileErr}
	byStatus := make(map[string]tailmixprofile.Status, len(statuses))
	for _, status := range statuses {
		byStatus[status.ProfileID] = status
	}
	for _, configured := range s.st.Profiles {
		if configured.Removed {
			continue
		}
		entry := controlapi.ProfileAdvertisedRoutes{
			ProfileID:   configured.ID,
			ProfileName: profileName(configured),
			Routes:      append([]netip.Prefix(nil), configured.AdvertiseRoutes...),
		}
		status, ok := byStatus[configured.ID]
		if ok {
			entry.Applied = append([]netip.Prefix(nil), status.AdvertisedRoutes...)
		}
		switch {
		case configured.Disabled:
			entry.State = "disabled"
			entry.Reason = "profile_disabled"
		case len(entry.Routes) == 0 && len(entry.Applied) == 0:
			entry.State = "off"
		case !ok || (status.BackendState != "" && status.BackendState != "Running"):
			entry.State = "waiting"
			entry.Reason = "profile_unavailable"
		case len(entry.Routes) != 0 && !engineSupportsAdvertise(s.runtimes[configured.ID]):
			entry.State = "unsupported"
			entry.Reason = "advertise_unsupported"
		case !slices.Equal(entry.Routes, entry.Applied):
			entry.State = "waiting"
			entry.Reason = "advertise_not_applied"
		default:
			entry.State = "installed"
		}
		result.Profiles = append(result.Profiles, entry)
	}
	sort.Slice(result.Profiles, func(i, j int) bool {
		return result.Profiles[i].ProfileName < result.Profiles[j].ProfileName
	})
	return result
}

func engineSupportsAdvertise(managed *managedProfile) bool {
	if managed == nil {
		return false
	}
	_, ok := managed.runtime.Engine.(tailmixprofile.AdvertiseRoutesController)
	return ok
}

// setAdvertisePreferencesLocked converges each running engine's advertised
// routes to the persisted desired set. Engines that are not Running are
// skipped; their desired state applies on the next successful reconcile.
func (s *supervisor) setAdvertisePreferencesLocked(statuses []tailmixprofile.Status) error {
	desiredByProfile := make(map[string][]netip.Prefix, len(s.st.Profiles))
	for _, configured := range s.st.Profiles {
		if configured.Disabled || configured.Removed || len(configured.AdvertiseRoutes) == 0 {
			continue
		}
		desiredByProfile[configured.ID] = configured.AdvertiseRoutes
	}
	if len(desiredByProfile) != 0 {
		if conflict := tailscaledConflictDetected(); conflict != nil {
			return conflict
		}
	}
	appliedByProfile := make(map[string][]netip.Prefix, len(statuses))
	for _, status := range statuses {
		appliedByProfile[status.ProfileID] = status.AdvertisedRoutes
	}
	for id, managed := range s.runtimes {
		desired := desiredByProfile[id]
		if slices.Equal(appliedByProfile[id], desired) {
			continue
		}
		if managed.status.BackendState != "Running" {
			continue
		}
		controller, ok := managed.runtime.Engine.(tailmixprofile.AdvertiseRoutesController)
		if !ok {
			if len(desired) == 0 {
				continue
			}
			return controlapi.NewError("advertise_unsupported",
				"profile %q does not support route advertisement", s.nameForIDLocked(id))
		}
		if err := controller.SetAdvertiseRoutes(s.ctx, desired); err != nil {
			s.lastErrors[id] = "set advertised routes: " + err.Error()
			return controlapi.NewError("reconcile_failed",
				"advertise routes for profile %q: %v", s.nameForIDLocked(id), err)
		}
		managed.status.AdvertisedRoutes = append([]netip.Prefix(nil), desired...)
	}
	return nil
}

// withdrawAdvertisedRoutesLocked clears a profile's tailnet advertisements
// before its engine closes so stale ads cannot survive a later re-add that
// reuses the same state directory. Removal continues when withdrawal fails;
// the persisted desired set is already cleared, so the next reconcile cannot
// reapply it.
func (s *supervisor) withdrawAdvertisedRoutesLocked(profileID string) {
	managed, ok := s.runtimes[profileID]
	if !ok || managed.status.BackendState != "Running" {
		return
	}
	controller, ok := managed.runtime.Engine.(tailmixprofile.AdvertiseRoutesController)
	if !ok {
		return
	}
	if len(managed.status.AdvertisedRoutes) == 0 {
		return
	}
	if err := controller.SetAdvertiseRoutes(s.ctx, nil); err != nil {
		s.lastErrors[profileID] = "withdraw advertised routes: " + err.Error()
	}
}
