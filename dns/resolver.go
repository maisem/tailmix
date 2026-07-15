package dns

import (
	"fmt"
	"net/netip"
	"strings"
)

type Record struct {
	ProfileAlias string
	Name         string
	EffectiveIP  netip.Addr
}

type Resolver struct {
	records map[string]netip.Addr
}

func NewResolver(records []Record) *Resolver {
	r := &Resolver{records: map[string]netip.Addr{}}
	for _, rec := range records {
		r.records[strings.TrimSuffix(strings.ToLower(rec.Name), ".")] = rec.EffectiveIP
	}
	return r
}

func (r *Resolver) Resolve(name string) (netip.Addr, error) {
	key := strings.TrimSuffix(strings.ToLower(name), ".")
	if !strings.Contains(key, ".") {
		return netip.Addr{}, fmt.Errorf("unqualified MagicDNS names are disabled in multi-tailnet mode: %q", name)
	}
	ip, ok := r.records[key]
	if !ok {
		return netip.Addr{}, fmt.Errorf("no explicit tailmix DNS record for %q", name)
	}
	return ip, nil
}
