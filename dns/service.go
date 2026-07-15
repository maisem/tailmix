package dns

import (
	"fmt"
	"net/netip"
	"sort"

	tailscaledns "tailscale.com/net/dns"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/logger"
	"tailscale.com/util/dnsname"
)

type Domain struct {
	ProfileID string
	Suffix    string
}

type ServiceConfig struct {
	TunName string
	Domains []Domain
	Records []Record
	Logf    logger.Logf
}

type Service interface {
	Addr() netip.AddrPort
	Configure([]Domain, []Record) error
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
		suffix, err := dnsname.ToFQDN(domain.Suffix)
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
	if len(domainByProfile) == 0 {
		return tailscaledns.Config{}, fmt.Errorf("no MagicDNS suffixes are available")
	}

	hosts := map[dnsname.FQDN][]netip.Addr{}
	exactRoutes := map[dnsname.FQDN]bool{}
	for _, record := range cfg.Records {
		if !record.EffectiveIP.IsValid() {
			return tailscaledns.Config{}, fmt.Errorf("MagicDNS record %q has invalid effective IP", record.Name)
		}
		domain, ok := domainByProfile[record.ProfileAlias]
		if !ok {
			return tailscaledns.Config{}, fmt.Errorf("MagicDNS record %q refers to unknown profile %q", record.Name, record.ProfileAlias)
		}
		name, err := dnsname.ToFQDN(record.Name)
		if err != nil {
			return tailscaledns.Config{}, fmt.Errorf("profile %q MagicDNS name %q: %w", record.ProfileAlias, record.Name, err)
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
	for domain := range ownerByDomain {
		routes[domain] = nil
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
	return tailscaledns.Config{
		AcceptDNS: true,
		Hosts:     hosts,
		Routes:    routes,
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
