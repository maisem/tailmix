package main

import (
	"context"
	"net/netip"
	"strings"

	"github.com/maisem/tailmix/controlapi"
	"github.com/maisem/tailmix/routingpolicy"
	"github.com/maisem/tailmix/state"
	"tailscale.com/util/dnsname"
)

func (s *supervisor) IPRoutes(_ context.Context, available bool) (controlapi.IPRoutes, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ipPolicy = routingpolicy.BuildIP(s.st, s.statusesLocked())
	result := s.ipPolicy.Resource
	result.ReconcileError = s.reconcileErr
	if available {
		result.AcceptAllProfiles = nil
		result.Bindings = nil
		result.Imported = nil
	} else {
		result.Available = nil
	}
	return result, nil
}

func (s *supervisor) PatchIPRoutes(_ context.Context, request controlapi.PatchIPRoutesRequest) (controlapi.IPRoutes, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneState(s.st)
	if err := s.applyIPPatchLocked(&next, request); err != nil {
		return controlapi.IPRoutes{}, err
	}
	if err := s.commitPolicyLocked(next); err != nil {
		return controlapi.IPRoutes{}, err
	}
	return s.ipPolicy.Resource, nil
}

func (s *supervisor) ReplaceIPRoutes(_ context.Context, request controlapi.ReplaceIPRoutesRequest) (controlapi.IPRoutes, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneState(s.st)
	next.IPRouteBindings = nil
	for i := range next.Profiles {
		next.Profiles[i].AcceptAllRoutes = false
	}
	patch := controlapi.PatchIPRoutesRequest{Replace: true, Bind: request.Bindings, AcceptAll: map[string]bool{}}
	for _, name := range request.AcceptAll {
		patch.AcceptAll[name] = true
	}
	if err := s.applyIPPatchLocked(&next, patch); err != nil {
		return controlapi.IPRoutes{}, err
	}
	if err := s.commitPolicyLocked(next); err != nil {
		return controlapi.IPRoutes{}, err
	}
	return s.ipPolicy.Resource, nil
}

func (s *supervisor) ClearIPRoutes(_ context.Context) (controlapi.IPRoutes, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneState(s.st)
	next.IPRouteBindings = nil
	for i := range next.Profiles {
		next.Profiles[i].AcceptAllRoutes = false
	}
	if err := s.commitPolicyLocked(next); err != nil {
		return controlapi.IPRoutes{}, err
	}
	return s.ipPolicy.Resource, nil
}

func (s *supervisor) applyIPPatchLocked(next *state.State, request controlapi.PatchIPRoutesRequest) error {
	for name, accept := range request.AcceptAll {
		configured, err := profileByName(next, name)
		if err != nil {
			return err
		}
		if configured.Removed {
			return controlapi.NewError("profile_not_found", "profile %q is removed", name)
		}
		configured.AcceptAllRoutes = accept
	}
	for _, mutation := range request.Unbind {
		prefix, err := validatePolicyPrefix(*next, mutation.Prefix)
		if err != nil {
			return err
		}
		index := ipBindingIndex(next.IPRouteBindings, prefix)
		if index < 0 {
			continue
		}
		if mutation.ProfileName != "" {
			configured, err := profileByName(next, mutation.ProfileName)
			if err != nil {
				return err
			}
			if next.IPRouteBindings[index].ProfileID != configured.ID {
				return controlapi.NewError("binding_profile_mismatch",
					"route %v is bound to profile %q, not %q",
					prefix, profileNameByID(*next, next.IPRouteBindings[index].ProfileID), mutation.ProfileName)
			}
		}
		next.IPRouteBindings = append(next.IPRouteBindings[:index], next.IPRouteBindings[index+1:]...)
	}
	for _, mutation := range request.Bind {
		prefix, err := validatePolicyPrefix(*next, mutation.Prefix)
		if err != nil {
			return err
		}
		configured, err := profileByName(next, mutation.ProfileName)
		if err != nil {
			return err
		}
		if configured.Removed {
			return controlapi.NewError("profile_not_found", "profile %q is removed", mutation.ProfileName)
		}
		index := ipBindingIndex(next.IPRouteBindings, prefix)
		if index >= 0 {
			existing := next.IPRouteBindings[index]
			if existing.ProfileID == configured.ID {
				continue
			}
			if !request.Replace {
				return controlapi.NewError("route_binding_conflict",
					"route %v is already bound to profile %q; pass --replace to override it",
					prefix, profileNameByID(*next, existing.ProfileID))
			}
			next.IPRouteBindings[index].ProfileID = configured.ID
			continue
		}
		next.IPRouteBindings = append(next.IPRouteBindings, state.IPRouteBinding{
			Prefix: prefix, ProfileID: configured.ID,
		})
	}
	state.Normalize(next)
	return nil
}

func validatePolicyPrefix(st state.State, prefix netip.Prefix) (netip.Prefix, error) {
	if !prefix.IsValid() {
		return netip.Prefix{}, controlapi.NewError("invalid_prefix", "invalid IP prefix")
	}
	prefix = prefix.Masked()
	if prefix.Bits() == 0 {
		return netip.Prefix{}, controlapi.NewError("invalid_prefix", "default route %v must use exit-node policy", prefix)
	}
	if routeOverlapsReserved(st, prefix) {
		return netip.Prefix{}, controlapi.NewError("invalid_prefix", "route %v overlaps a tailmix reserved range", prefix)
	}
	return prefix, nil
}

func ipBindingIndex(bindings []state.IPRouteBinding, prefix netip.Prefix) int {
	for i, binding := range bindings {
		if binding.Prefix.Masked() == prefix {
			return i
		}
	}
	return -1
}

func (s *supervisor) DNSRoutes(_ context.Context, available bool) (controlapi.DNSRoutes, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dnsPolicy = routingpolicy.BuildDNS(s.st, s.statusesLocked())
	result := s.dnsPolicy.Resource
	result.ReconcileError = s.reconcileErr
	if available {
		result.AcceptAllProfiles = nil
		result.Bindings = nil
		result.Imported = nil
		result.Automatic = nil
	} else {
		result.Available = nil
	}
	return result, nil
}

func (s *supervisor) PatchDNSRoutes(_ context.Context, request controlapi.PatchDNSRoutesRequest) (controlapi.DNSRoutes, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneState(s.st)
	if err := s.applyDNSPatchLocked(&next, request); err != nil {
		return controlapi.DNSRoutes{}, err
	}
	if err := s.commitPolicyLocked(next); err != nil {
		return controlapi.DNSRoutes{}, err
	}
	return s.dnsPolicy.Resource, nil
}

func (s *supervisor) ReplaceDNSRoutes(_ context.Context, request controlapi.ReplaceDNSRoutesRequest) (controlapi.DNSRoutes, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneState(s.st)
	next.DNSRouteBindings = nil
	for i := range next.Profiles {
		next.Profiles[i].AcceptAllDNSRoutes = false
	}
	patch := controlapi.PatchDNSRoutesRequest{Replace: true, Bind: request.Bindings, AcceptAll: map[string]bool{}}
	for _, name := range request.AcceptAll {
		patch.AcceptAll[name] = true
	}
	if err := s.applyDNSPatchLocked(&next, patch); err != nil {
		return controlapi.DNSRoutes{}, err
	}
	if err := s.commitPolicyLocked(next); err != nil {
		return controlapi.DNSRoutes{}, err
	}
	return s.dnsPolicy.Resource, nil
}

func (s *supervisor) ClearDNSRoutes(_ context.Context) (controlapi.DNSRoutes, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneState(s.st)
	next.DNSRouteBindings = nil
	for i := range next.Profiles {
		next.Profiles[i].AcceptAllDNSRoutes = false
	}
	if err := s.commitPolicyLocked(next); err != nil {
		return controlapi.DNSRoutes{}, err
	}
	return s.dnsPolicy.Resource, nil
}

func (s *supervisor) applyDNSPatchLocked(next *state.State, request controlapi.PatchDNSRoutesRequest) error {
	for name, accept := range request.AcceptAll {
		configured, err := profileByName(next, name)
		if err != nil {
			return err
		}
		if configured.Removed {
			return controlapi.NewError("profile_not_found", "profile %q is removed", name)
		}
		configured.AcceptAllDNSRoutes = accept
	}
	for _, mutation := range request.Unbind {
		domain, err := canonicalDNSDomain(mutation.Domain, true)
		if err != nil {
			return err
		}
		index := dnsBindingIndex(next.DNSRouteBindings, domain)
		if index < 0 {
			continue
		}
		if mutation.ProfileName != "" {
			configured, err := profileByName(next, mutation.ProfileName)
			if err != nil {
				return err
			}
			if next.DNSRouteBindings[index].ProfileID != configured.ID {
				return controlapi.NewError("binding_profile_mismatch",
					"DNS route %q is bound to profile %q, not %q",
					domain, profileNameByID(*next, next.DNSRouteBindings[index].ProfileID), mutation.ProfileName)
			}
		}
		next.DNSRouteBindings = append(next.DNSRouteBindings[:index], next.DNSRouteBindings[index+1:]...)
	}
	for _, mutation := range request.Bind {
		domain, err := canonicalDNSDomain(mutation.Domain, true)
		if err != nil {
			return err
		}
		configured, err := profileByName(next, mutation.ProfileName)
		if err != nil {
			return err
		}
		if configured.Removed {
			return controlapi.NewError("profile_not_found", "profile %q is removed", mutation.ProfileName)
		}
		index := dnsBindingIndex(next.DNSRouteBindings, domain)
		if index >= 0 {
			existing := next.DNSRouteBindings[index]
			if existing.ProfileID == configured.ID {
				continue
			}
			if !request.Replace {
				return controlapi.NewError("dns_route_binding_conflict",
					"DNS route %q is already bound to profile %q; pass --replace to override it",
					domain, profileNameByID(*next, existing.ProfileID))
			}
			next.DNSRouteBindings[index].ProfileID = configured.ID
			continue
		}
		next.DNSRouteBindings = append(next.DNSRouteBindings, state.DNSRouteBinding{
			Domain: domain, ProfileID: configured.ID,
		})
	}
	state.Normalize(next)
	return nil
}

func canonicalDNSDomain(raw string, allowRoot bool) (string, error) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return "", controlapi.NewError("invalid_dns_name", "DNS domain is empty")
	}
	domain, err := dnsname.ToFQDN(raw)
	if err != nil || domain == dnsname.FQDN(".") && !allowRoot {
		return "", controlapi.NewError("invalid_dns_name", "invalid DNS domain %q", raw)
	}
	if domain == dnsname.FQDN(".") {
		return ".", nil
	}
	return domain.WithoutTrailingDot(), nil
}

func dnsBindingIndex(bindings []state.DNSRouteBinding, domain string) int {
	for i, binding := range bindings {
		if routingpolicy.NormalizeDomain(binding.Domain) == domain {
			return i
		}
	}
	return -1
}

func (s *supervisor) SearchDomains(_ context.Context) (controlapi.SearchDomains, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dnsPolicy = routingpolicy.BuildDNS(s.st, s.statusesLocked())
	result := s.dnsPolicy.Search
	result.ReconcileError = s.reconcileErr
	return result, nil
}

func (s *supervisor) PatchSearchDomains(_ context.Context, request controlapi.PatchSearchDomainsRequest) (controlapi.SearchDomains, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneState(s.st)
	remove := map[string]bool{}
	for _, raw := range request.Remove {
		domain, err := canonicalDNSDomain(raw, false)
		if err != nil {
			return controlapi.SearchDomains{}, err
		}
		remove[domain] = true
	}
	desired := next.SearchDomains[:0]
	seen := map[string]bool{}
	for _, domain := range next.SearchDomains {
		if !remove[domain] {
			desired = append(desired, domain)
			seen[domain] = true
		}
	}
	for _, raw := range request.Add {
		domain, err := canonicalDNSDomain(raw, false)
		if err != nil {
			return controlapi.SearchDomains{}, err
		}
		if !seen[domain] {
			desired = append(desired, domain)
			seen[domain] = true
		}
	}
	next.SearchDomains = desired
	if err := s.commitPolicyLocked(next); err != nil {
		return controlapi.SearchDomains{}, err
	}
	return s.dnsPolicy.Search, nil
}

func (s *supervisor) ReplaceSearchDomains(_ context.Context, request controlapi.ReplaceSearchDomainsRequest) (controlapi.SearchDomains, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneState(s.st)
	next.SearchDomains = nil
	seen := map[string]bool{}
	for _, raw := range request.Desired {
		domain, err := canonicalDNSDomain(raw, false)
		if err != nil {
			return controlapi.SearchDomains{}, err
		}
		if !seen[domain] {
			next.SearchDomains = append(next.SearchDomains, domain)
			seen[domain] = true
		}
	}
	if err := s.commitPolicyLocked(next); err != nil {
		return controlapi.SearchDomains{}, err
	}
	return s.dnsPolicy.Search, nil
}

func (s *supervisor) ClearSearchDomains(_ context.Context) (controlapi.SearchDomains, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneState(s.st)
	next.SearchDomains = nil
	if err := s.commitPolicyLocked(next); err != nil {
		return controlapi.SearchDomains{}, err
	}
	return s.dnsPolicy.Search, nil
}

func (s *supervisor) commitPolicyLocked(next state.State) error {
	state.Normalize(&next)
	if err := s.store.Save(next); err != nil {
		return err
	}
	s.st = next
	if err := s.reconcileLocked(); err != nil {
		return controlapi.NewError("reconcile_failed", "%v", err)
	}
	return nil
}

func profileByName(st *state.State, name string) (*state.Profile, error) {
	name = strings.TrimSpace(name)
	for i := range st.Profiles {
		if profileName(st.Profiles[i]) == name {
			return &st.Profiles[i], nil
		}
	}
	return nil, controlapi.NewError("profile_not_found", "profile %q not found", name)
}

func profileNameByID(st state.State, profileID string) string {
	for _, configured := range st.Profiles {
		if configured.ID == profileID {
			return profileName(configured)
		}
	}
	return profileID
}
