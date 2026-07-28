package routingpolicy

import (
	"net/netip"
	"sort"
	"strings"

	"github.com/maisem/tailmix/controlapi"
	"github.com/maisem/tailmix/profile"
	"github.com/maisem/tailmix/state"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/dnstype"
	"tailscale.com/util/dnsname"
)

type IPEntry struct {
	Prefix        netip.Prefix
	ProfileID     string
	Policy        string
	Active        bool
	Reason        string
	CoveringRoute netip.Prefix
	PrimaryRouter string
	OverriddenBy  netip.Prefix
}

type IPPlan struct {
	Exact    []IPEntry
	Imported []IPEntry
	Resource controlapi.IPRoutes
}

type DNSEntry struct {
	Domain        string
	ProfileID     string
	Policy        string
	Source        string
	ProfileDNS    bool
	Active        bool
	Reason        string
	CoveringRoute string
	Resolvers     []*dnstype.Resolver
	OverriddenBy  string
}

type DNSPlan struct {
	Exact     []DNSEntry
	Imported  []DNSEntry
	Automatic []DNSEntry
	Resource  controlapi.DNSRoutes
	Search    controlapi.SearchDomains
}

func BuildIP(st state.State, statuses []profile.Status) IPPlan {
	profilesByID := make(map[string]state.Profile, len(st.Profiles))
	names := make(map[string]string, len(st.Profiles))
	for _, configured := range st.Profiles {
		profilesByID[configured.ID] = configured
		names[configured.ID] = profileName(configured)
	}
	statusByID := make(map[string]profile.Status, len(statuses))
	for _, status := range statuses {
		statusByID[status.ProfileID] = status
	}

	var plan IPPlan
	for _, status := range statuses {
		for _, available := range status.AvailableRoutes {
			if !available.Prefix.IsValid() || available.Prefix.Bits() == 0 {
				continue
			}
			plan.Resource.Available = append(plan.Resource.Available, controlapi.AvailableIPRoute{
				Prefix:        available.Prefix.Masked(),
				ProfileID:     status.ProfileID,
				ProfileName:   names[status.ProfileID],
				PrimaryRouter: available.PrimaryRouter,
			})
		}
	}

	for _, binding := range st.IPRouteBindings {
		entry := IPEntry{
			Prefix:    binding.Prefix.Masked(),
			ProfileID: binding.ProfileID,
			Policy:    "bound",
		}
		configured, exists := profilesByID[binding.ProfileID]
		status, active := statusByID[binding.ProfileID]
		active = active && profileAvailable(status)
		switch {
		case !exists || configured.Removed || configured.Disabled || !active:
			entry.Reason = "profile_unavailable"
		default:
			cover, ok := coveringIPRoute(entry.Prefix, status.AvailableRoutes)
			if !ok {
				entry.Reason = "route_not_advertised"
			} else {
				entry.Active = true
				entry.CoveringRoute = cover.Prefix
				entry.PrimaryRouter = cover.PrimaryRouter
			}
		}
		if routeOverlapsReserved(st, entry.Prefix) {
			entry.Active = false
			entry.Reason = "host_route_conflict"
		}
		plan.Exact = append(plan.Exact, entry)
		plan.Resource.Bindings = append(plan.Resource.Bindings, ipResource(entry, names))
	}

	importCandidates := map[netip.Prefix][]IPEntry{}
	for _, configured := range st.Profiles {
		if !configured.AcceptAllRoutes {
			continue
		}
		accept := controlapi.AcceptAllProfile{
			ProfileID:   configured.ID,
			ProfileName: profileName(configured),
			State:       "installed",
		}
		status, active := statusByID[configured.ID]
		active = active && profileAvailable(status)
		if configured.Removed || configured.Disabled || !active {
			accept.State = "waiting"
			accept.Reason = "profile_unavailable"
		} else {
			for _, available := range status.AvailableRoutes {
				if !available.Prefix.IsValid() || available.Prefix.Bits() == 0 {
					continue
				}
				prefix := available.Prefix.Masked()
				entry := IPEntry{
					Prefix:        prefix,
					ProfileID:     configured.ID,
					Policy:        "accept-all",
					Active:        true,
					CoveringRoute: prefix,
					PrimaryRouter: available.PrimaryRouter,
				}
				if routeOverlapsReserved(st, prefix) {
					entry.Active = false
					entry.Reason = "host_route_conflict"
				}
				importCandidates[prefix] = addIPCandidate(importCandidates[prefix], entry)
			}
		}
		plan.Resource.AcceptAllProfiles = append(plan.Resource.AcceptAllProfiles, accept)
	}
	for prefix, candidates := range importCandidates {
		if len(candidates) == 1 {
			plan.Imported = append(plan.Imported, candidates[0])
			plan.Resource.Imported = append(plan.Resource.Imported, ipResource(candidates[0], names))
			continue
		}
		ambiguous := IPEntry{Prefix: prefix, Policy: "accept-all", Reason: "ambiguous_route"}
		plan.Imported = append(plan.Imported, ambiguous)
		plan.Resource.Imported = append(plan.Resource.Imported, ipResource(ambiguous, names))
	}
	plan.Resource.Imported = nil
	for i := range plan.Imported {
		full, partial := ipOverride(plan.Imported[i].Prefix, plan.Exact)
		switch {
		case full.IsValid():
			plan.Imported[i].Active = false
			plan.Imported[i].Reason = "explicit_override"
			plan.Imported[i].OverriddenBy = full
		case partial.IsValid() && plan.Imported[i].Reason == "":
			plan.Imported[i].Reason = "partially_overridden"
			plan.Imported[i].OverriddenBy = partial
		}
		resource := ipResource(plan.Imported[i], names)
		resource.OverrideProfileID = ipOverrideOwner(plan.Imported[i].OverriddenBy, plan.Exact)
		resource.OverrideProfileName = names[resource.OverrideProfileID]
		plan.Resource.Imported = append(plan.Resource.Imported, resource)
	}
	sortIPPlan(&plan)
	return plan
}

func BuildDNS(st state.State, statuses []profile.Status) DNSPlan {
	profilesByID := make(map[string]state.Profile, len(st.Profiles))
	names := make(map[string]string, len(st.Profiles))
	for _, configured := range st.Profiles {
		profilesByID[configured.ID] = configured
		names[configured.ID] = profileName(configured)
	}
	statusByID := make(map[string]profile.Status, len(statuses))
	availableSearch := map[string]bool{}
	var plan DNSPlan
	for _, status := range statuses {
		statusByID[status.ProfileID] = status
		for _, available := range dnsRoutesForStatus(status) {
			domain := NormalizeDomain(available.Domain)
			if domain == "" {
				continue
			}
			plan.Resource.Available = append(plan.Resource.Available, controlapi.AvailableDNSRoute{
				Domain:      domain,
				ProfileID:   status.ProfileID,
				ProfileName: names[status.ProfileID],
				Source:      available.Source,
				Resolvers:   resolverResources(available.Resolvers),
			})
		}
		for _, raw := range status.SearchDomains {
			domain := NormalizeDomain(raw)
			if domain == "" || domain == "." {
				continue
			}
			key := status.ProfileID + "\x00" + domain
			if availableSearch[key] {
				continue
			}
			availableSearch[key] = true
			plan.Search.Available = append(plan.Search.Available, controlapi.AvailableSearchDomain{
				Domain:      domain,
				ProfileID:   status.ProfileID,
				ProfileName: names[status.ProfileID],
			})
		}
	}

	for _, binding := range st.DNSRouteBindings {
		entry := DNSEntry{
			Domain:    NormalizeDomain(binding.Domain),
			ProfileID: binding.ProfileID,
			Policy:    "bound",
		}
		configured, exists := profilesByID[binding.ProfileID]
		status, active := statusByID[binding.ProfileID]
		active = active && profileAvailable(status)
		switch {
		case !exists || configured.Removed || configured.Disabled || !active:
			entry.Reason = "profile_unavailable"
		default:
			cover, ok := coveringDNSRoute(entry.Domain, dnsRoutesForStatus(status))
			if !ok {
				entry.Reason = "dns_route_not_advertised"
			} else {
				entry.Active = true
				entry.Source = cover.Source
				entry.CoveringRoute = NormalizeDomain(cover.Domain)
				entry.Resolvers = cloneResolvers(cover.Resolvers)
			}
		}
		plan.Exact = append(plan.Exact, entry)
		plan.Resource.Bindings = append(plan.Resource.Bindings, dnsResource(entry, names))
	}

	importCandidates := map[string][]DNSEntry{}
	for _, configured := range st.Profiles {
		if !configured.AcceptAllDNSRoutes {
			continue
		}
		accept := controlapi.AcceptAllProfile{
			ProfileID:   configured.ID,
			ProfileName: profileName(configured),
			State:       "installed",
		}
		status, active := statusByID[configured.ID]
		active = active && profileAvailable(status)
		if configured.Removed || configured.Disabled || !active {
			accept.State = "waiting"
			accept.Reason = "profile_unavailable"
		} else {
			for _, available := range dnsRoutesForStatus(status) {
				domain := NormalizeDomain(available.Domain)
				if domain == "" {
					continue
				}
				importCandidates[domain] = addDNSCandidate(importCandidates[domain], DNSEntry{
					Domain:        domain,
					ProfileID:     configured.ID,
					Policy:        "accept-all",
					Source:        available.Source,
					Active:        true,
					CoveringRoute: domain,
					Resolvers:     cloneResolvers(available.Resolvers),
				})
			}
		}
		plan.Resource.AcceptAllProfiles = append(plan.Resource.AcceptAllProfiles, accept)
	}
	for domain, candidates := range importCandidates {
		if len(candidates) == 1 {
			plan.Imported = append(plan.Imported, candidates[0])
			plan.Resource.Imported = append(plan.Resource.Imported, dnsResource(candidates[0], names))
			continue
		}
		ambiguous := DNSEntry{Domain: domain, Policy: "accept-all", Reason: "ambiguous_route"}
		plan.Imported = append(plan.Imported, ambiguous)
		plan.Resource.Imported = append(plan.Resource.Imported, dnsResource(ambiguous, names))
	}

	automaticCandidates := map[string][]DNSEntry{}
	for _, status := range statuses {
		configured, ok := profilesByID[status.ProfileID]
		if !ok || configured.Removed || configured.Disabled || !profileAvailable(status) {
			continue
		}
		for _, available := range dnsRoutesForStatus(status) {
			if available.Source != "magicdns" {
				continue
			}
			domain := NormalizeDomain(available.Domain)
			if domain == "" {
				continue
			}
			automaticCandidates[domain] = addDNSCandidate(automaticCandidates[domain], DNSEntry{
				Domain:        domain,
				ProfileID:     status.ProfileID,
				Policy:        "automatic",
				Source:        "magicdns",
				Active:        true,
				CoveringRoute: domain,
			})
		}
	}
	if exitProfileID := activeDNSExitProfile(st, statuses); exitProfileID != "" {
		automaticCandidates["."] = []DNSEntry{{
			Domain:        ".",
			ProfileID:     exitProfileID,
			Policy:        "automatic",
			Source:        "exit-node",
			ProfileDNS:    true,
			Active:        true,
			CoveringRoute: ".",
		}}
	}
	for domain, candidates := range automaticCandidates {
		if len(candidates) == 1 {
			plan.Automatic = append(plan.Automatic, candidates[0])
			plan.Resource.Automatic = append(plan.Resource.Automatic, dnsResource(candidates[0], names))
			continue
		}
		ambiguous := DNSEntry{Domain: domain, Policy: "automatic", Source: "magicdns", Reason: "ambiguous_route"}
		plan.Automatic = append(plan.Automatic, ambiguous)
		plan.Resource.Automatic = append(plan.Resource.Automatic, dnsResource(ambiguous, names))
	}
	plan.Resource.Imported = nil
	for i := range plan.Imported {
		full, partial := dnsOverride(plan.Imported[i].Domain, plan.Exact)
		switch {
		case full != "":
			plan.Imported[i].Active = false
			plan.Imported[i].Reason = "explicit_override"
			plan.Imported[i].OverriddenBy = full
		case partial != "" && plan.Imported[i].Reason == "":
			plan.Imported[i].Reason = "partially_overridden"
			plan.Imported[i].OverriddenBy = partial
		}
		resource := dnsResource(plan.Imported[i], names)
		resource.OverrideProfileID = dnsOverrideOwner(plan.Imported[i].OverriddenBy, plan.Exact)
		resource.OverrideProfileName = names[resource.OverrideProfileID]
		plan.Resource.Imported = append(plan.Resource.Imported, resource)
	}
	plan.Resource.Automatic = nil
	for i := range plan.Automatic {
		full, partial := dnsOverride(plan.Automatic[i].Domain, append(append([]DNSEntry(nil), plan.Exact...), plan.Imported...))
		switch {
		case full != "":
			plan.Automatic[i].Active = false
			plan.Automatic[i].Reason = "policy_override"
			plan.Automatic[i].OverriddenBy = full
		case partial != "" && plan.Automatic[i].Reason == "":
			plan.Automatic[i].Reason = "partially_overridden"
			plan.Automatic[i].OverriddenBy = partial
		}
		resource := dnsResource(plan.Automatic[i], names)
		resource.OverrideProfileID = dnsOverrideOwner(plan.Automatic[i].OverriddenBy, append(append([]DNSEntry(nil), plan.Exact...), plan.Imported...))
		resource.OverrideProfileName = names[resource.OverrideProfileID]
		plan.Resource.Automatic = append(plan.Resource.Automatic, resource)
	}

	plan.Search.Desired = append([]string(nil), st.SearchDomains...)
	for _, domain := range st.SearchDomains {
		entry, matched := plan.Resolve(domain)
		if !matched || !entry.Active {
			reason := "no_active_route"
			if matched && entry.Reason != "" {
				reason = entry.Reason
			}
			plan.Search.Waiting = append(plan.Search.Waiting, controlapi.WaitingSearchDomain{Domain: domain, Reason: reason})
			continue
		}
		plan.Search.Installed = append(plan.Search.Installed, controlapi.InstalledSearchDomain{
			Domain:      domain,
			ProfileID:   entry.ProfileID,
			ProfileName: names[entry.ProfileID],
		})
	}
	sortDNSPlan(&plan)
	return plan
}

func activeDNSExitProfile(st state.State, statuses []profile.Status) string {
	if st.ExitNode == nil {
		return ""
	}
	for _, status := range statuses {
		if status.ProfileID == st.ExitNode.ProfileID &&
			profileAvailable(status) &&
			status.ExitNodeID == st.ExitNode.NodeID {
			return status.ProfileID
		}
	}
	return ""
}

func dnsRoutesForStatus(status profile.Status) []profile.DNSRouteStatus {
	routes := append([]profile.DNSRouteStatus(nil), status.DNSRoutes...)
	suffix := NormalizeDomain(status.MagicDNSSuffix)
	if suffix == "" {
		return routes
	}
	for _, route := range routes {
		if route.Source == "magicdns" && NormalizeDomain(route.Domain) == suffix {
			return routes
		}
	}
	return append(routes, profile.DNSRouteStatus{Domain: suffix, Source: "magicdns"})
}

func (p DNSPlan) Resolve(domain string) (DNSEntry, bool) {
	domain = NormalizeDomain(domain)
	var best DNSEntry
	bestLength := -1
	for _, entries := range [][]DNSEntry{p.Exact, p.Imported, p.Automatic} {
		entry, ok := longestDNSMatch(domain, entries)
		if !ok || len(entry.Domain) <= bestLength {
			continue
		}
		best = entry
		bestLength = len(entry.Domain)
	}
	return best, bestLength >= 0
}

func coveringIPRoute(prefix netip.Prefix, routes []profile.RouteStatus) (profile.RouteStatus, bool) {
	var best profile.RouteStatus
	found := false
	for _, route := range routes {
		candidate := route.Prefix.Masked()
		if !candidate.IsValid() || candidate.Bits() == 0 ||
			candidate.Addr().BitLen() != prefix.Addr().BitLen() ||
			!candidate.Contains(prefix.Addr()) || candidate.Bits() > prefix.Bits() {
			continue
		}
		if !found || candidate.Bits() > best.Prefix.Bits() {
			best = route
			best.Prefix = candidate
			found = true
		}
	}
	return best, found
}

func routeOverlapsReserved(st state.State, prefix netip.Prefix) bool {
	for _, reserved := range []netip.Prefix{tsaddr.CGNATRange(), tsaddr.TailscaleULARange()} {
		if prefixesOverlap(prefix, reserved) {
			return true
		}
	}
	for _, raw := range []string{st.SyntheticPool, st.SyntheticPoolV6} {
		if reserved, err := netip.ParsePrefix(raw); err == nil && prefixesOverlap(prefix, reserved) {
			return true
		}
	}
	for _, address := range []netip.Addr{st.NATIP, st.NATIPv6} {
		if address.IsValid() && address.Is6() == prefix.Addr().Is6() && prefix.Contains(address) {
			return true
		}
	}
	return false
}

func prefixesOverlap(a, b netip.Prefix) bool {
	if !a.IsValid() || !b.IsValid() || a.Addr().BitLen() != b.Addr().BitLen() {
		return false
	}
	a, b = a.Masked(), b.Masked()
	return a.Contains(b.Addr()) || b.Contains(a.Addr())
}

func coveringDNSRoute(domain string, routes []profile.DNSRouteStatus) (profile.DNSRouteStatus, bool) {
	var best profile.DNSRouteStatus
	bestLength := -1
	for _, route := range routes {
		candidate := NormalizeDomain(route.Domain)
		if !DNSContains(candidate, domain) || len(candidate) <= bestLength {
			continue
		}
		best = route
		best.Domain = candidate
		bestLength = len(candidate)
	}
	return best, bestLength >= 0
}

func longestDNSMatch(domain string, entries []DNSEntry) (DNSEntry, bool) {
	var best DNSEntry
	bestLength := -1
	for _, entry := range entries {
		if !DNSContains(entry.Domain, domain) || len(entry.Domain) <= bestLength {
			continue
		}
		best = entry
		bestLength = len(entry.Domain)
	}
	return best, bestLength >= 0
}

func ipOverride(imported netip.Prefix, exact []IPEntry) (full, partial netip.Prefix) {
	for _, candidate := range exact {
		if candidate.Prefix.Addr().BitLen() != imported.Addr().BitLen() {
			continue
		}
		if candidate.Prefix.Contains(imported.Addr()) && candidate.Prefix.Bits() <= imported.Bits() {
			if !full.IsValid() || candidate.Prefix.Bits() > full.Bits() {
				full = candidate.Prefix
			}
			continue
		}
		if imported.Contains(candidate.Prefix.Addr()) && candidate.Prefix.Bits() > imported.Bits() {
			if !partial.IsValid() || candidate.Prefix.Bits() < partial.Bits() {
				partial = candidate.Prefix
			}
		}
	}
	return full, partial
}

func addIPCandidate(candidates []IPEntry, entry IPEntry) []IPEntry {
	for i := range candidates {
		if candidates[i].ProfileID != entry.ProfileID {
			continue
		}
		if candidates[i].PrimaryRouter == "" ||
			entry.PrimaryRouter != "" && entry.PrimaryRouter < candidates[i].PrimaryRouter {
			candidates[i] = entry
		}
		return candidates
	}
	return append(candidates, entry)
}

func addDNSCandidate(candidates []DNSEntry, entry DNSEntry) []DNSEntry {
	for i := range candidates {
		if candidates[i].ProfileID != entry.ProfileID {
			continue
		}
		if dnsSourcePriority(entry.Source) < dnsSourcePriority(candidates[i].Source) {
			candidates[i] = entry
		}
		return candidates
	}
	return append(candidates, entry)
}

func dnsSourcePriority(source string) int {
	switch source {
	case "magicdns":
		return 0
	case "split-dns":
		return 1
	case "default":
		return 2
	default:
		return 3
	}
}

func dnsOverride(imported string, overrides []DNSEntry) (full, partial string) {
	for _, candidate := range overrides {
		switch {
		case candidate.Domain == imported:
			full = candidate.Domain
		case DNSContains(imported, candidate.Domain):
			if partial == "" || len(candidate.Domain) < len(partial) {
				partial = candidate.Domain
			}
		}
	}
	return full, partial
}

func ipOverrideOwner(prefix netip.Prefix, overrides []IPEntry) string {
	if !prefix.IsValid() {
		return ""
	}
	for _, entry := range overrides {
		if entry.Prefix == prefix {
			return entry.ProfileID
		}
	}
	return ""
}

func dnsOverrideOwner(domain string, overrides []DNSEntry) string {
	if domain == "" {
		return ""
	}
	for _, entry := range overrides {
		if entry.Domain == domain {
			return entry.ProfileID
		}
	}
	return ""
}

func NormalizeDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return ""
	}
	parsed, err := dnsname.ToFQDN(domain)
	if err != nil {
		return ""
	}
	if parsed == dnsname.FQDN(".") {
		return "."
	}
	return parsed.WithoutTrailingDot()
}

func DNSContains(suffix, name string) bool {
	suffix, name = NormalizeDomain(suffix), NormalizeDomain(name)
	if suffix == "" || name == "" {
		return false
	}
	suffixFQDN, suffixErr := dnsname.ToFQDN(suffix)
	nameFQDN, nameErr := dnsname.ToFQDN(name)
	return suffixErr == nil && nameErr == nil && suffixFQDN.Contains(nameFQDN)
}

func profileName(configured state.Profile) string {
	if configured.Name != "" {
		return configured.Name
	}
	return configured.ID
}

func profileAvailable(status profile.Status) bool {
	return status.BackendState == "" || status.BackendState == "Running"
}

func ipResource(entry IPEntry, names map[string]string) controlapi.IPRouteBinding {
	stateValue := "waiting"
	if entry.Active {
		stateValue = "installed"
	} else if entry.Reason == "explicit_override" || entry.Reason == "policy_override" {
		stateValue = "overridden"
	}
	return controlapi.IPRouteBinding{
		Prefix:        entry.Prefix,
		ProfileID:     entry.ProfileID,
		ProfileName:   names[entry.ProfileID],
		Policy:        entry.Policy,
		State:         stateValue,
		Reason:        entry.Reason,
		CoveringRoute: entry.CoveringRoute,
		PrimaryRouter: entry.PrimaryRouter,
		OverriddenBy:  entry.OverriddenBy,
	}
}

func dnsResource(entry DNSEntry, names map[string]string) controlapi.DNSRouteBinding {
	stateValue := "waiting"
	if entry.Active {
		stateValue = "installed"
	} else if entry.Reason == "explicit_override" || entry.Reason == "policy_override" {
		stateValue = "overridden"
	}
	return controlapi.DNSRouteBinding{
		Domain:        entry.Domain,
		ProfileID:     entry.ProfileID,
		ProfileName:   names[entry.ProfileID],
		Policy:        entry.Policy,
		Source:        entry.Source,
		State:         stateValue,
		Reason:        entry.Reason,
		CoveringRoute: entry.CoveringRoute,
		Resolvers:     resolverResources(entry.Resolvers),
		OverriddenBy:  entry.OverriddenBy,
	}
}

func resolverResources(in []*dnstype.Resolver) []controlapi.DNSResolver {
	out := make([]controlapi.DNSResolver, 0, len(in))
	for _, resolver := range in {
		if resolver == nil {
			continue
		}
		out = append(out, controlapi.DNSResolver{
			Addr:                resolver.Addr,
			BootstrapResolution: append([]netip.Addr(nil), resolver.BootstrapResolution...),
			UseWithExitNode:     resolver.UseWithExitNode,
		})
	}
	return out
}

func cloneResolvers(in []*dnstype.Resolver) []*dnstype.Resolver {
	out := make([]*dnstype.Resolver, 0, len(in))
	for _, resolver := range in {
		if resolver != nil {
			out = append(out, resolver.Clone())
		}
	}
	return out
}

func sortIPPlan(plan *IPPlan) {
	sort.Slice(plan.Exact, func(i, j int) bool { return plan.Exact[i].Prefix.String() < plan.Exact[j].Prefix.String() })
	sort.Slice(plan.Imported, func(i, j int) bool { return plan.Imported[i].Prefix.String() < plan.Imported[j].Prefix.String() })
	sort.Slice(plan.Resource.Bindings, func(i, j int) bool {
		return plan.Resource.Bindings[i].Prefix.String() < plan.Resource.Bindings[j].Prefix.String()
	})
	sort.Slice(plan.Resource.Imported, func(i, j int) bool {
		return plan.Resource.Imported[i].Prefix.String() < plan.Resource.Imported[j].Prefix.String()
	})
	sort.Slice(plan.Resource.Available, func(i, j int) bool {
		if plan.Resource.Available[i].Prefix != plan.Resource.Available[j].Prefix {
			return plan.Resource.Available[i].Prefix.String() < plan.Resource.Available[j].Prefix.String()
		}
		return plan.Resource.Available[i].ProfileName < plan.Resource.Available[j].ProfileName
	})
	sort.Slice(plan.Resource.AcceptAllProfiles, func(i, j int) bool {
		return plan.Resource.AcceptAllProfiles[i].ProfileName < plan.Resource.AcceptAllProfiles[j].ProfileName
	})
}

func sortDNSPlan(plan *DNSPlan) {
	sort.Slice(plan.Exact, func(i, j int) bool { return plan.Exact[i].Domain < plan.Exact[j].Domain })
	sort.Slice(plan.Imported, func(i, j int) bool { return plan.Imported[i].Domain < plan.Imported[j].Domain })
	sort.Slice(plan.Automatic, func(i, j int) bool { return plan.Automatic[i].Domain < plan.Automatic[j].Domain })
	sort.Slice(plan.Resource.Bindings, func(i, j int) bool { return plan.Resource.Bindings[i].Domain < plan.Resource.Bindings[j].Domain })
	sort.Slice(plan.Resource.Imported, func(i, j int) bool { return plan.Resource.Imported[i].Domain < plan.Resource.Imported[j].Domain })
	sort.Slice(plan.Resource.Automatic, func(i, j int) bool { return plan.Resource.Automatic[i].Domain < plan.Resource.Automatic[j].Domain })
	sort.Slice(plan.Resource.Available, func(i, j int) bool {
		if plan.Resource.Available[i].Domain != plan.Resource.Available[j].Domain {
			return plan.Resource.Available[i].Domain < plan.Resource.Available[j].Domain
		}
		return plan.Resource.Available[i].ProfileName < plan.Resource.Available[j].ProfileName
	})
	sort.Slice(plan.Resource.AcceptAllProfiles, func(i, j int) bool {
		return plan.Resource.AcceptAllProfiles[i].ProfileName < plan.Resource.AcceptAllProfiles[j].ProfileName
	})
	sort.Slice(plan.Search.Available, func(i, j int) bool {
		if plan.Search.Available[i].Domain != plan.Search.Available[j].Domain {
			return plan.Search.Available[i].Domain < plan.Search.Available[j].Domain
		}
		return plan.Search.Available[i].ProfileName < plan.Search.Available[j].ProfileName
	})
}
