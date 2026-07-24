package dns

import (
	"fmt"
	"net/netip"
	"strings"

	"tailscale.com/util/dnsname"
)

type Record struct {
	ProfileID   string
	Name        string
	EffectiveIP netip.Addr
}

type Resolver struct {
	records map[dnsname.FQDN]netip.Addr
}

func NewResolver(records []Record) *Resolver {
	r := &Resolver{records: map[dnsname.FQDN]netip.Addr{}}
	for _, rec := range records {
		name, err := dnsname.ToFQDN(strings.ToLower(strings.TrimSpace(rec.Name)))
		if err == nil && name != dnsname.FQDN(".") {
			r.records[name] = rec.EffectiveIP
		}
	}
	return r
}

func (r *Resolver) Resolve(name string) (netip.Addr, error) {
	key, err := dnsname.ToFQDN(strings.ToLower(strings.TrimSpace(name)))
	if err != nil || key == dnsname.FQDN(".") {
		return netip.Addr{}, fmt.Errorf("invalid MagicDNS name %q", name)
	}
	if key.NumLabels() < 2 {
		return netip.Addr{}, fmt.Errorf("unqualified MagicDNS names are disabled in multi-tailnet mode: %q", name)
	}
	ip, ok := r.records[key]
	if !ok {
		return netip.Addr{}, fmt.Errorf("no explicit tailmix DNS record for %q", name)
	}
	return ip, nil
}
