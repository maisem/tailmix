package socksproxy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"

	"github.com/gaissmai/bart"
	"github.com/maisem/tailmix/effectiveip"
	"tailscale.com/util/dnsname"
)

type Dialer interface {
	Dial(context.Context, string, string) (net.Conn, error)
}

type Profile struct {
	ID             string
	MagicDNSSuffix string
	Dialer         Dialer
}

type Decision struct {
	ProfileID string
	DialAddr  string
}

type Router struct {
	profilesByID   map[string]Profile
	suffixes       map[string]string
	effectiveIPs   map[netip.Addr]effectiveRoute
	exactRoutes    *bart.Table[SubnetRoute]
	importedRoutes *bart.Table[SubnetRoute]
	exitRoutes     *bart.Table[SubnetRoute]
	exactDNS       []DomainRoute
	importedDNS    []DomainRoute
	automaticDNS   []DomainRoute
}

type effectiveRoute struct {
	profileID string
	canonical netip.Addr
}

type SubnetRoute struct {
	Prefix    netip.Prefix
	ProfileID string
	Active    bool
	Exact     bool
}

type DomainRoute struct {
	Suffix    string
	ProfileID string
	Active    bool
	Exact     bool
	Automatic bool
}

type DynamicRouter struct {
	current atomic.Pointer[Router]
}

func NewDynamicRouter(router *Router) *DynamicRouter {
	d := new(DynamicRouter)
	d.Set(router)
	return d
}

func (d *DynamicRouter) Set(router *Router) {
	if router == nil {
		panic("nil SOCKS router")
	}
	d.current.Store(router)
}

func (d *DynamicRouter) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	router := d.current.Load()
	if router == nil {
		return nil, fmt.Errorf("SOCKS router is not configured")
	}
	return router.Dial(ctx, network, addr)
}

func NewRouter(profiles []Profile, leases []effectiveip.Lease) (*Router, error) {
	return NewRouterWithRoutes(profiles, leases, nil)
}

func NewRouterWithRoutes(profiles []Profile, leases []effectiveip.Lease, subnetRoutes []SubnetRoute) (*Router, error) {
	return NewRouterWithPolicies(profiles, leases, subnetRoutes, nil)
}

func NewRouterWithPolicies(profiles []Profile, leases []effectiveip.Lease, subnetRoutes []SubnetRoute, domainRoutes []DomainRoute) (*Router, error) {
	r := &Router{
		profilesByID:   map[string]Profile{},
		suffixes:       map[string]string{},
		effectiveIPs:   map[netip.Addr]effectiveRoute{},
		exactRoutes:    new(bart.Table[SubnetRoute]),
		importedRoutes: new(bart.Table[SubnetRoute]),
		exitRoutes:     new(bart.Table[SubnetRoute]),
	}
	for _, p := range profiles {
		if p.ID == "" {
			return nil, fmt.Errorf("profile id is required")
		}
		if p.Dialer == nil {
			return nil, fmt.Errorf("profile %q has no dialer", p.ID)
		}
		r.profilesByID[p.ID] = p
		if p.MagicDNSSuffix != "" {
			suffix := normalizeDNSName(p.MagicDNSSuffix)
			if suffix == "" {
				return nil, fmt.Errorf("profile %q has invalid MagicDNS suffix %q", p.ID, p.MagicDNSSuffix)
			}
			if existing, ok := r.suffixes[suffix]; ok && existing != p.ID {
				// An identical automatic suffix is ambiguous until a policy
				// route explicitly selects one profile.
				r.suffixes[suffix] = ""
			} else if !ok {
				r.suffixes[suffix] = p.ID
			}
		}
	}
	for _, lease := range leases {
		if lease.EffectiveIP == lease.NodeKey.CanonicalIP {
			continue
		}
		if _, ok := r.profilesByID[lease.NodeKey.ProfileID]; !ok {
			continue
		}
		if existing, ok := r.effectiveIPs[lease.EffectiveIP]; ok && (existing.profileID != lease.NodeKey.ProfileID || existing.canonical != lease.NodeKey.CanonicalIP) {
			return nil, fmt.Errorf("effective IP %v is leased to multiple nodes", lease.EffectiveIP)
		}
		r.effectiveIPs[lease.EffectiveIP] = effectiveRoute{
			profileID: lease.NodeKey.ProfileID,
			canonical: lease.NodeKey.CanonicalIP,
		}
	}
	for _, route := range subnetRoutes {
		if !route.Prefix.IsValid() {
			continue
		}
		route.Prefix = route.Prefix.Masked()
		if route.ProfileID != "" {
			if _, ok := r.profilesByID[route.ProfileID]; !ok {
				route.Active = false
			}
		}
		if route.Prefix.Bits() == 0 {
			r.exitRoutes.Insert(route.Prefix, route)
		} else if route.Exact {
			r.exactRoutes.Insert(route.Prefix, route)
		} else {
			r.importedRoutes.Insert(route.Prefix, route)
		}
	}
	for _, route := range domainRoutes {
		rawSuffix := strings.TrimSpace(route.Suffix)
		route.Suffix = normalizeDNSName(rawSuffix)
		if rawSuffix == "." {
			route.Suffix = "."
		}
		if route.Suffix == "" {
			continue
		}
		if route.ProfileID != "" {
			if _, ok := r.profilesByID[route.ProfileID]; !ok {
				route.Active = false
			}
		}
		switch {
		case route.Exact:
			r.exactDNS = append(r.exactDNS, route)
		case route.Automatic:
			r.automaticDNS = append(r.automaticDNS, route)
		default:
			r.importedDNS = append(r.importedDNS, route)
		}
	}
	return r, nil
}

func (r *Router) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	decision, err := r.Resolve(network, addr)
	if err != nil {
		return nil, err
	}
	profile := r.profilesByID[decision.ProfileID]
	return profile.Dialer.Dial(ctx, network, decision.DialAddr)
}

func (r *Router) Resolve(network, addr string) (Decision, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return Decision{}, fmt.Errorf("SOCKS %s is not supported in userspace multi-tailnet mode", network)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return Decision{}, fmt.Errorf("SOCKS target must be host:port: %w", err)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if route, ok := r.effectiveIPs[ip]; ok {
			return Decision{ProfileID: route.profileID, DialAddr: net.JoinHostPort(route.canonical.String(), port)}, nil
		}
		if route, ok := r.exactRoutes.Lookup(ip); ok {
			if !route.Active || route.ProfileID == "" {
				return Decision{}, fmt.Errorf("exact route for SOCKS destination %v is unavailable", ip)
			}
			return Decision{ProfileID: route.ProfileID, DialAddr: net.JoinHostPort(ip.String(), port)}, nil
		}
		if route, ok := r.importedRoutes.Lookup(ip); ok {
			if !route.Active || route.ProfileID == "" {
				return Decision{}, fmt.Errorf("imported route for SOCKS destination %v is ambiguous or unavailable", ip)
			}
			return Decision{ProfileID: route.ProfileID, DialAddr: net.JoinHostPort(ip.String(), port)}, nil
		}
		if route, ok := r.exitRoutes.Lookup(ip); ok {
			if !route.Active || route.ProfileID == "" {
				return Decision{}, fmt.Errorf("exit-node route for SOCKS destination %v is unavailable", ip)
			}
			return Decision{ProfileID: route.ProfileID, DialAddr: net.JoinHostPort(ip.String(), port)}, nil
		}
		return Decision{}, fmt.Errorf("canonical Tailscale and unbound IP literals are disabled in SOCKS mode: %v", ip)
	}
	name := normalizeDNSName(host)
	if !strings.Contains(name, ".") {
		return Decision{}, fmt.Errorf("unqualified MagicDNS names are disabled in multi-tailnet mode: %q", host)
	}
	for _, tier := range [][]DomainRoute{r.exactDNS, r.importedDNS, r.automaticDNS} {
		if route, ok := longestDomainRoute(name, tier); ok {
			if !route.Active || route.ProfileID == "" {
				return Decision{}, fmt.Errorf("DNS route for SOCKS destination %q is ambiguous or unavailable", host)
			}
			return Decision{ProfileID: route.ProfileID, DialAddr: net.JoinHostPort(name, port)}, nil
		}
	}
	bestSuffix := ""
	bestProfileID := ""
	nameFQDN, _ := dnsname.ToFQDN(name)
	for suffix, profileID := range r.suffixes {
		suffixFQDN, err := dnsname.ToFQDN(suffix)
		if err == nil && nameFQDN != suffixFQDN && suffixFQDN.Contains(nameFQDN) {
			if len(suffix) > len(bestSuffix) {
				bestSuffix = suffix
				bestProfileID = profileID
			}
		}
	}
	if bestProfileID != "" {
		return Decision{ProfileID: bestProfileID, DialAddr: net.JoinHostPort(name, port)}, nil
	}
	return Decision{}, fmt.Errorf("MagicDNS FQDN %q does not match any active profile", host)
}

func longestDomainRoute(name string, routes []DomainRoute) (DomainRoute, bool) {
	nameFQDN, err := dnsname.ToFQDN(name)
	if err != nil {
		return DomainRoute{}, false
	}
	var best DomainRoute
	bestLabels := -1
	for _, route := range routes {
		suffix, err := dnsname.ToFQDN(route.Suffix)
		if err != nil || !suffix.Contains(nameFQDN) || suffix.NumLabels() <= bestLabels {
			continue
		}
		best = route
		bestLabels = suffix.NumLabels()
	}
	return best, bestLabels >= 0
}

func normalizeDNSName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return ""
	}
	parsed, err := dnsname.ToFQDN(name)
	if err != nil || parsed == dnsname.FQDN(".") {
		return ""
	}
	return parsed.WithoutTrailingDot()
}
