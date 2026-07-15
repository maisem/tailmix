//go:build darwin

package hosttun

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestDarwinConfigureUsesProfileSourceForRoute(t *testing.T) {
	var commands []string
	h := &darwinHost{
		name: "utun42",
		run: func(name string, args ...string) ([]byte, error) {
			commands = append(commands, strings.Join(append([]string{name}, args...), " "))
			return nil, nil
		},
	}
	source := netip.MustParseAddr("100.127.0.10")
	destination := netip.MustParsePrefix("100.127.0.20/32")
	if err := h.Configure(Config{
		LocalAddrs: []netip.Prefix{netip.PrefixFrom(source, 32)},
		Routes:     []Route{{Destination: destination, Source: source}},
	}); err != nil {
		t.Fatal(err)
	}
	want := "/sbin/route -q -n add -inet 100.127.0.20/32 -iface utun42 -ifa 100.127.0.10"
	if !slices.Contains(commands, want) {
		t.Fatalf("commands = %q, missing %q", commands, want)
	}
}

func TestDarwinConfigureRejectsRouteSourceNotOnTun(t *testing.T) {
	h := &darwinHost{name: "utun42", run: func(string, ...string) ([]byte, error) { return nil, nil }}
	err := h.Configure(Config{
		LocalAddrs: []netip.Prefix{netip.MustParsePrefix("100.127.0.10/32")},
		Routes: []Route{{
			Destination: netip.MustParsePrefix("100.127.0.20/32"),
			Source:      netip.MustParseAddr("100.127.0.11"),
		}},
	})
	if err == nil {
		t.Fatal("expected invalid route source to fail")
	}
}
