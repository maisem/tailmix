package socksproxy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"tailscale.com/mnet/effectiveip"
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
	profilesByID map[string]Profile
	suffixes     map[string]string
	effectiveIPs map[netip.Addr]effectiveRoute
}

type effectiveRoute struct {
	profileID string
	canonical netip.Addr
}

func NewRouter(profiles []Profile, leases []effectiveip.Lease) (*Router, error) {
	r := &Router{
		profilesByID: map[string]Profile{},
		suffixes:     map[string]string{},
		effectiveIPs: map[netip.Addr]effectiveRoute{},
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
			if existing, ok := r.suffixes[suffix]; ok && existing != p.ID {
				return nil, fmt.Errorf("MagicDNS suffix %q is configured for both %q and %q", suffix, existing, p.ID)
			}
			r.suffixes[suffix] = p.ID
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
		route, ok := r.effectiveIPs[ip]
		if !ok {
			return Decision{}, fmt.Errorf("canonical Tailscale IP literals are disabled in SOCKS mode: %v", ip)
		}
		return Decision{ProfileID: route.profileID, DialAddr: net.JoinHostPort(route.canonical.String(), port)}, nil
	}
	name := normalizeDNSName(host)
	if !strings.Contains(name, ".") {
		return Decision{}, fmt.Errorf("unqualified MagicDNS names are disabled in multi-tailnet mode: %q", host)
	}
	bestSuffix := ""
	bestProfileID := ""
	for suffix, profileID := range r.suffixes {
		if name != suffix && strings.HasSuffix(name, "."+suffix) {
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

func normalizeDNSName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}
