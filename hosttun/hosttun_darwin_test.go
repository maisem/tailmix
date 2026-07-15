//go:build darwin

package hosttun

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestDarwinConfigureDoesNotSetRoutePreferredSource(t *testing.T) {
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
		Routes:     []Route{{Destination: destination}},
	}); err != nil {
		t.Fatal(err)
	}
	want := "/sbin/route -q -n add -inet 100.127.0.20/32 -iface utun42"
	if !slices.Contains(commands, want) {
		t.Fatalf("commands = %q, missing %q", commands, want)
	}
	for _, command := range commands {
		if strings.Contains(command, " -ifa ") {
			t.Fatalf("route command still selects a source: %q", command)
		}
	}
}

func TestDarwinConfigureReconcilesAddressesAndRoutes(t *testing.T) {
	var commands []string
	h := &darwinHost{
		name: "utun42",
		run: func(name string, args ...string) ([]byte, error) {
			commands = append(commands, strings.Join(append([]string{name}, args...), " "))
			return nil, nil
		},
	}
	oldSource := netip.MustParseAddr("100.127.0.10")
	newSource := netip.MustParseAddr("10.250.0.10")
	keptDestination := netip.MustParsePrefix("10.250.0.20/32")
	removedDestination := netip.MustParsePrefix("10.250.0.30/32")
	addedDestination := netip.MustParsePrefix("10.250.0.40/32")
	if err := h.Configure(Config{
		LocalAddrs: []netip.Prefix{netip.PrefixFrom(oldSource, 32)},
		Routes: []Route{
			{Destination: keptDestination},
			{Destination: removedDestination},
		},
	}); err != nil {
		t.Fatal(err)
	}
	commands = nil
	want := Config{
		LocalAddrs: []netip.Prefix{netip.PrefixFrom(newSource, 32)},
		Routes: []Route{
			{Destination: keptDestination},
			{Destination: addedDestination},
		},
	}
	if err := h.Configure(want); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{
		"/sbin/ifconfig utun42 inet 10.250.0.10/32 10.250.0.10 alias",
		"/sbin/route -q -n delete -inet 10.250.0.30/32 -iface utun42",
		"/sbin/route -q -n add -inet 10.250.0.40/32 -iface utun42",
		"/sbin/ifconfig utun42 inet 100.127.0.10/32 -alias",
	} {
		if !slices.Contains(commands, command) {
			t.Fatalf("commands = %q, missing %q", commands, command)
		}
	}
	commands = nil
	if err := h.Configure(want); err != nil {
		t.Fatal(err)
	}
	if len(commands) != 0 {
		t.Fatalf("no-op reconciliation ran commands: %q", commands)
	}
}
