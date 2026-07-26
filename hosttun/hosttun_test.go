package hosttun

import (
	"net/netip"
	"strings"
	"testing"
)

func TestNormalizeConfigRequiresLocalRouteSource(t *testing.T) {
	local := netip.MustParseAddr("10.250.0.1")
	destination := netip.MustParsePrefix("0.0.0.0/1")
	for name, source := range map[string]netip.Addr{
		"missing":      {},
		"wrong family": netip.MustParseAddr("fd6d:6e65:7400::1"),
		"not local":    netip.MustParseAddr("10.250.0.2"),
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := normalizeConfig(Config{
				LocalAddrs: []netip.Prefix{netip.PrefixFrom(local, 32)},
				Routes:     []Route{{Destination: destination, Source: source}},
			})
			if err == nil {
				t.Fatal("route with invalid source unexpectedly accepted")
			}
		})
	}

	_, routes, err := normalizeConfig(Config{
		LocalAddrs: []netip.Prefix{netip.PrefixFrom(local, 32)},
		Routes:     []Route{{Destination: destination, Source: local}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 || routes[0].Source != local {
		t.Fatalf("normalized routes = %+v", routes)
	}
}

func TestNormalizeConfigReportsRouteSourceConflict(t *testing.T) {
	local := netip.MustParseAddr("10.250.0.1")
	other := netip.MustParseAddr("10.250.0.2")
	_, _, err := normalizeConfig(Config{
		LocalAddrs: []netip.Prefix{
			netip.PrefixFrom(local, 32),
			netip.PrefixFrom(other, 32),
		},
		Routes: []Route{
			{Destination: netip.MustParsePrefix("0.0.0.0/1"), Source: local},
			{Destination: netip.MustParsePrefix("0.0.0.0/1"), Source: other},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "conflicting sources") {
		t.Fatalf("conflicting source error = %v", err)
	}
}
