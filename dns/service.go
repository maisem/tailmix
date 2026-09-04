package dns

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	tailscaledns "tailscale.com/net/dns"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/logger"
	"tailscale.com/util/dnsname"
)

type Domain struct {
	ProfileID         string
	Suffix            string
	AuthoritativeOnly bool
}

type Route struct {
	Suffix     string
	ProfileID  string
	ProfileDNS bool
	Resolvers  []*dnstype.Resolver
}

type LiveConfig struct {
	Domains       []Domain
	Records       []Record
	Routes        []Route
	SearchDomains []string
}

type ServiceConfig struct {
	TunName       string
	ResolverIP    netip.Addr
	Domains       []Domain
	Records       []Record
	Routes        []Route
	SearchDomains []string
	Logf          logger.Logf
}

type Service interface {
	Addr() netip.AddrPort
	Configure([]Domain, []Record) error
	ConfigureFull(LiveConfig) error
	HandlePacket([]byte) bool
	Outbound() <-chan []byte
	Err() error
	Close() error
}

func ServiceIP() netip.Addr {
	return tsaddr.TailscaleServiceIP()
}

func configForService(cfg ServiceConfig) (tailscaledns.Config, error) {
	domainByProfile := map[string]dnsname.FQDN{}
	ownerByDomain := map[dnsname.FQDN]string{}
	for _, domain := range cfg.Domains {
		if domain.ProfileID == "" {
			return tailscaledns.Config{}, fmt.Errorf("MagicDNS profile ID is required")
		}
		suffix, err := dnsname.ToFQDN(strings.ToLower(strings.TrimSpace(domain.Suffix)))
		if err != nil {
			return tailscaledns.Config{}, fmt.Errorf("profile %q MagicDNS suffix %q: %w", domain.ProfileID, domain.Suffix, err)
		}
		if existing, ok := domainByProfile[domain.ProfileID]; ok && existing != suffix {
			return tailscaledns.Config{}, fmt.Errorf("profile %q has conflicting MagicDNS suffixes %q and %q", domain.ProfileID, existing, suffix)
		}
		if owner, ok := ownerByDomain[suffix]; ok && owner != domain.ProfileID {
			return tailscaledns.Config{}, fmt.Errorf("MagicDNS suffix %q belongs to both profiles %q and %q", suffix, owner, domain.ProfileID)
		}
		domainByProfile[domain.ProfileID] = suffix
		ownerByDomain[suffix] = domain.ProfileID
	}
	hosts := map[dnsname.FQDN][]netip.Addr{}
	exactRoutes := map[dnsname.FQDN]bool{}
	for _, record := range cfg.Records {
		if !record.EffectiveIP.IsValid() {
			return tailscaledns.Config{}, fmt.Errorf("MagicDNS record %q has invalid effective IP", record.Name)
		}
		domain, ok := domainByProfile[record.ProfileID]
		if !ok {
			return tailscaledns.Config{}, fmt.Errorf("MagicDNS record %q refers to unknown profile %q", record.Name, record.ProfileID)
		}
		name, err := dnsname.ToFQDN(strings.ToLower(strings.TrimSpace(record.Name)))
		if err != nil {
			return tailscaledns.Config{}, fmt.Errorf("profile %q MagicDNS name %q: %w", record.ProfileID, record.Name, err)
		}
		if !domain.Contains(name) {
			// Shared-in peers retain their source tailnet's FQDN. Route only
			// that exact name to tailmix instead of claiming its entire suffix.
			exactRoutes[name] = true
		}
		if !containsAddr(hosts[name], record.EffectiveIP) {
			hosts[name] = append(hosts[name], record.EffectiveIP)
		}
	}
	for name := range hosts {
		sort.Slice(hosts[name], func(i, j int) bool { return hosts[name][i].Compare(hosts[name][j]) < 0 })
	}

	routes := make(map[dnsname.FQDN][]*dnstype.Resolver, len(ownerByDomain))
	for _, domain := range cfg.Domains {
		if domain.AuthoritativeOnly {
			continue
		}
		suffix, _ := dnsname.ToFQDN(strings.ToLower(strings.TrimSpace(domain.Suffix)))
		routes[suffix] = nil
	}
	for name := range exactRoutes {
		covered := false
		for domain := range ownerByDomain {
			if domain.Contains(name) {
				covered = true
				break
			}
		}
		if !covered {
			routes[name] = nil
		}
	}
	var defaultResolvers []*dnstype.Resolver
	for _, route := range cfg.Routes {
		suffix, err := dnsname.ToFQDN(strings.ToLower(strings.TrimSpace(route.Suffix)))
		if err != nil {
			return tailscaledns.Config{}, fmt.Errorf("DNS route suffix %q: %w", route.Suffix, err)
		}
		if suffix == dnsname.FQDN(".") {
			if defaultResolvers != nil && !sameResolvers(defaultResolvers, route.Resolvers) {
				return tailscaledns.Config{}, fmt.Errorf("default DNS route is configured more than once")
			}
			defaultResolvers = cloneDNSResolvers(route.Resolvers)
			continue
		}
		if existing, ok := routes[suffix]; ok && !sameResolvers(existing, route.Resolvers) {
			return tailscaledns.Config{}, fmt.Errorf("DNS route %q has conflicting resolvers", suffix)
		}
		routes[suffix] = cloneDNSResolvers(route.Resolvers)
	}
	searchDomains := make([]dnsname.FQDN, 0, len(cfg.SearchDomains))
	seenSearch := map[dnsname.FQDN]bool{}
	for _, raw := range cfg.SearchDomains {
		domain, err := dnsname.ToFQDN(strings.ToLower(strings.TrimSpace(raw)))
		if err != nil {
			return tailscaledns.Config{}, fmt.Errorf("search domain %q: %w", raw, err)
		}
		if domain == dnsname.FQDN(".") || seenSearch[domain] {
			continue
		}
		seenSearch[domain] = true
		searchDomains = append(searchDomains, domain)
	}
	return tailscaledns.Config{
		AcceptDNS:        true,
		DefaultResolvers: defaultResolvers,
		Hosts:            hosts,
		Routes:           routes,
		SearchDomains:    searchDomains,
	}, nil
}

func containsAddr(addrs []netip.Addr, want netip.Addr) bool {
	for _, addr := range addrs {
		if addr == want {
			return true
		}
	}
	return false
}

func sameResolvers(a, b []*dnstype.Resolver) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] == nil || b[i] == nil {
			if a[i] != b[i] {
				return false
			}
			continue
		}
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}

func cloneDNSResolvers(in []*dnstype.Resolver) []*dnstype.Resolver {
	out := make([]*dnstype.Resolver, 0, len(in))
	for _, resolver := range in {
		if resolver != nil {
			out = append(out, resolver.Clone())
		}
	}
	return out
}
