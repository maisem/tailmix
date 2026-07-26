package state

import (
	"net/netip"
	"slices"
	"sort"
	"strings"

	"tailscale.com/util/dnsname"
)

// Normalize applies backwards-compatible defaults and canonical ordering to
// persisted daemon state. It does not validate policy against live profiles.
func Normalize(st *State) {
	if st == nil {
		return
	}
	for i := range st.Profiles {
		if st.Profiles[i].Name == "" {
			st.Profiles[i].Name = st.Profiles[i].ID
		}
	}
	sort.SliceStable(st.Profiles, func(i, j int) bool {
		return st.Profiles[i].ID < st.Profiles[j].ID
	})

	ipByPrefix := make(map[netip.Prefix]IPRouteBinding, len(st.IPRouteBindings))
	for _, binding := range st.IPRouteBindings {
		if !binding.Prefix.IsValid() || binding.ProfileID == "" {
			continue
		}
		binding.Prefix = binding.Prefix.Masked()
		ipByPrefix[binding.Prefix] = binding
	}
	st.IPRouteBindings = st.IPRouteBindings[:0]
	for _, binding := range ipByPrefix {
		st.IPRouteBindings = append(st.IPRouteBindings, binding)
	}
	sort.Slice(st.IPRouteBindings, func(i, j int) bool {
		return st.IPRouteBindings[i].Prefix.String() < st.IPRouteBindings[j].Prefix.String()
	})

	dnsByDomain := make(map[string]DNSRouteBinding, len(st.DNSRouteBindings))
	for _, binding := range st.DNSRouteBindings {
		domain := normalizeDomain(binding.Domain)
		if domain == "" || binding.ProfileID == "" {
			continue
		}
		binding.Domain = domain
		dnsByDomain[domain] = binding
	}
	st.DNSRouteBindings = st.DNSRouteBindings[:0]
	for _, binding := range dnsByDomain {
		st.DNSRouteBindings = append(st.DNSRouteBindings, binding)
	}
	sort.Slice(st.DNSRouteBindings, func(i, j int) bool {
		return st.DNSRouteBindings[i].Domain < st.DNSRouteBindings[j].Domain
	})

	search := st.SearchDomains[:0]
	seen := map[string]bool{}
	for _, raw := range st.SearchDomains {
		domain := normalizeDomain(raw)
		if domain == "" || domain == "." || seen[domain] {
			continue
		}
		seen[domain] = true
		search = append(search, domain)
	}
	st.SearchDomains = slices.Clip(search)

	if st.ExitNode != nil &&
		(st.ExitNode.ProfileID == "" || st.ExitNode.NodeID == "" || !st.ExitNode.PeerIP.IsValid()) {
		st.ExitNode = nil
	}
}

func normalizeDomain(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return ""
	}
	domain, err := dnsname.ToFQDN(raw)
	if err != nil {
		return ""
	}
	if domain == dnsname.FQDN(".") {
		return "."
	}
	return domain.WithoutTrailingDot()
}
