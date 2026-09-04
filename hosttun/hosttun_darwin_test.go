//go:build darwin

package hosttun

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"tailscale.com/net/routetable"
)

func TestDarwinConfigureSetsSharedRouteSource(t *testing.T) {
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
	for _, want := range []string{
		"/sbin/ifconfig utun42 inet 100.127.0.10/32 100.127.0.10",
		"/sbin/route -q -n add -inet 100.127.0.20/32 -iface utun42 -ifa 100.127.0.10",
	} {
		if !slices.Contains(commands, want) {
			t.Fatalf("commands = %q, missing %q", commands, want)
		}
	}
}

func TestDarwinConfigureAddsScopedUnderlayDefaultBeforeExitRoutes(t *testing.T) {
	var commands []string
	gateway := netip.MustParseAddr("10.20.0.1")
	h := &darwinHost{
		name: "utun42",
		run: func(name string, args ...string) ([]byte, error) {
			commands = append(commands, strings.Join(append([]string{name}, args...), " "))
			return nil, nil
		},
		underlayDefault: func(ipv6 bool) (darwinUnderlayDefault, error) {
			if ipv6 {
				return darwinUnderlayDefault{}, errors.New("no IPv6 underlay")
			}
			return darwinUnderlayDefault{
				Interface: "en0",
				Gateway:   gateway,
			}, nil
		},
	}
	source := netip.MustParseAddr("10.250.0.1")
	localAddrs := []netip.Prefix{netip.PrefixFrom(source, 32)}
	exitRoutes := []Route{
		{
			Destination: netip.MustParsePrefix("0.0.0.0/1"),
			Source:      source,
			Exit:        true,
		},
		{
			Destination: netip.MustParsePrefix("128.0.0.0/1"),
			Source:      source,
			Exit:        true,
		},
	}
	if err := h.Configure(Config{LocalAddrs: localAddrs, Routes: exitRoutes}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"/sbin/route -q -n add -inet -proto2 -ifscope en0 0.0.0.0/0 10.20.0.1",
		"/sbin/route -q -n add -inet 0.0.0.0/1 -iface utun42 -ifa 10.250.0.1",
		"/sbin/route -q -n add -inet 128.0.0.0/1 -iface utun42 -ifa 10.250.0.1",
	} {
		if !slices.Contains(commands, want) {
			t.Fatalf("commands = %q, missing %q", commands, want)
		}
	}
	if scoped, aggregate := slices.Index(commands, "/sbin/route -q -n add -inet -proto2 -ifscope en0 0.0.0.0/0 10.20.0.1"), slices.Index(commands, "/sbin/route -q -n add -inet 0.0.0.0/1 -iface utun42 -ifa 10.250.0.1"); scoped >= aggregate {
		t.Fatalf("scoped underlay default must be installed before aggregate exit route: %q", commands)
	}

	commands = nil
	gateway = netip.MustParseAddr("10.21.0.1")
	if err := h.Configure(Config{LocalAddrs: localAddrs, Routes: exitRoutes}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"/sbin/route -q -n delete -inet 0.0.0.0/1 -iface utun42",
		"/sbin/route -q -n delete -inet -ifscope en0 0.0.0.0/0 10.20.0.1",
		"/sbin/route -q -n add -inet -proto2 -ifscope en0 0.0.0.0/0 10.21.0.1",
		"/sbin/route -q -n add -inet 0.0.0.0/1 -iface utun42 -ifa 10.250.0.1",
	} {
		if !slices.Contains(commands, want) {
			t.Fatalf("gateway-change commands = %q, missing %q", commands, want)
		}
	}
	if removeExit, removeOldScoped := slices.Index(commands, "/sbin/route -q -n delete -inet 0.0.0.0/1 -iface utun42"), slices.Index(commands, "/sbin/route -q -n delete -inet -ifscope en0 0.0.0.0/0 10.20.0.1"); removeExit >= removeOldScoped {
		t.Fatalf("aggregate exit route must be removed before changing underlay default: %q", commands)
	}
	if addNewScoped, addExit := slices.Index(commands, "/sbin/route -q -n add -inet -proto2 -ifscope en0 0.0.0.0/0 10.21.0.1"), slices.Index(commands, "/sbin/route -q -n add -inet 0.0.0.0/1 -iface utun42 -ifa 10.250.0.1"); addNewScoped >= addExit {
		t.Fatalf("new underlay default must be installed before restoring aggregate exit route: %q", commands)
	}

	commands = nil
	if err := h.Configure(Config{LocalAddrs: localAddrs}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"/sbin/route -q -n delete -inet 0.0.0.0/1 -iface utun42",
		"/sbin/route -q -n delete -inet 128.0.0.0/1 -iface utun42",
		"/sbin/route -q -n delete -inet -ifscope en0 0.0.0.0/0 10.21.0.1",
	} {
		if !slices.Contains(commands, want) {
			t.Fatalf("commands = %q, missing %q", commands, want)
		}
	}
	if aggregate, scoped := slices.Index(commands, "/sbin/route -q -n delete -inet 0.0.0.0/1 -iface utun42"), slices.Index(commands, "/sbin/route -q -n delete -inet -ifscope en0 0.0.0.0/0 10.21.0.1"); aggregate >= scoped {
		t.Fatalf("aggregate exit route must be removed before scoped underlay default: %q", commands)
	}
}

func TestDarwinConfigureRejectsExitRouteWithoutUnderlay(t *testing.T) {
	var commands []string
	h := &darwinHost{
		name: "utun42",
		run: func(name string, args ...string) ([]byte, error) {
			commands = append(commands, strings.Join(append([]string{name}, args...), " "))
			return nil, nil
		},
		underlayDefault: func(bool) (darwinUnderlayDefault, error) {
			return darwinUnderlayDefault{}, errors.New("no physical default")
		},
	}
	source := netip.MustParseAddr("10.250.0.1")
	err := h.Configure(Config{
		LocalAddrs: []netip.Prefix{netip.PrefixFrom(source, 32)},
		Routes: []Route{{
			Destination: netip.MustParsePrefix("0.0.0.0/1"),
			Source:      source,
			Exit:        true,
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "discover physical default route") {
		t.Fatalf("Configure error = %v, want missing underlay error", err)
	}
	if len(commands) != 0 {
		t.Fatalf("Configure changed host before finding underlay: %q", commands)
	}
}

func TestUnderlayDefaultFromRoutesIgnoresScopedDefault(t *testing.T) {
	scopedGateway := netip.MustParseAddr("10.19.0.1")
	physicalGateway := netip.MustParseAddr("10.20.0.1")
	defaultDestination := routetable.RouteDestination{
		Prefix: netip.MustParsePrefix("0.0.0.0/0"),
	}
	routes := []routetable.RouteEntry{
		{
			Family:    4,
			Dst:       defaultDestination,
			Gateway:   scopedGateway,
			Interface: "en0",
			Sys: routetable.RouteEntryBSD{
				RawFlags: unix.RTF_IFSCOPE,
			},
		},
		{
			Family:    4,
			Dst:       defaultDestination,
			Gateway:   physicalGateway,
			Interface: "en0",
			Sys:       routetable.RouteEntryBSD{},
		},
	}

	got, err := underlayDefaultFromRoutes("en0", routes, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.Interface != "en0" || got.Gateway != physicalGateway {
		t.Fatalf("underlay default = %+v, want en0 via %v", got, physicalGateway)
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
			{Destination: keptDestination, Source: oldSource},
			{Destination: removedDestination, Source: oldSource},
		},
	}); err != nil {
		t.Fatal(err)
	}
	commands = nil
	want := Config{
		LocalAddrs: []netip.Prefix{netip.PrefixFrom(newSource, 32)},
		Routes: []Route{
			{Destination: keptDestination, Source: newSource},
			{Destination: addedDestination, Source: newSource},
		},
	}
	if err := h.Configure(want); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{
		"/sbin/route -q -n delete -inet 10.250.0.20/32 -iface utun42",
		"/sbin/route -q -n delete -inet 10.250.0.30/32 -iface utun42",
		"/sbin/ifconfig utun42 inet 100.127.0.10/32 -alias",
		"/sbin/ifconfig utun42 inet 10.250.0.10/32 10.250.0.10",
		"/sbin/route -q -n add -inet 10.250.0.20/32 -iface utun42 -ifa 10.250.0.10",
		"/sbin/route -q -n add -inet 10.250.0.40/32 -iface utun42 -ifa 10.250.0.10",
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

func TestDarwinConfigureRejectsRouteCommandFalseSuccess(t *testing.T) {
	source := netip.MustParseAddr("10.250.0.1")
	local := netip.PrefixFrom(source, 32)
	route := Route{Destination: netip.MustParsePrefix("10.250.0.53/32"), Source: source}
	states := []darwinInstalledState{
		{},
		{localAddrs: []netip.Prefix{local}},
	}
	stateIndex := 0
	h := &darwinHost{
		name: "utun42",
		run: func(string, ...string) ([]byte, error) {
			return []byte("route: writing to routing socket: Network is unreachable\n"), nil
		},
		readState: func([]Route) (darwinInstalledState, error) {
			state := states[stateIndex]
			stateIndex++
			return state, nil
		},
	}
	err := h.Configure(Config{LocalAddrs: []netip.Prefix{local}, Routes: []Route{route}})
	if err == nil || !strings.Contains(err.Error(), "missing TUN route") {
		t.Fatalf("Configure error = %v, want missing route verification error", err)
	}
}

func TestDarwinConfigureAllowsMissingOptionalRoute(t *testing.T) {
	source := netip.MustParseAddr("10.250.0.1")
	local := netip.PrefixFrom(source, 32)
	route := Route{
		Destination: netip.MustParsePrefix("100.100.100.100/32"),
		Source:      source,
		Optional:    true,
	}
	states := []darwinInstalledState{
		{localAddrs: []netip.Prefix{local}},
		{localAddrs: []netip.Prefix{local}},
	}
	stateIndex := 0
	var logs []string
	h := &darwinHost{
		name: "utun42",
		logf: func(format string, args ...any) {
			logs = append(logs, fmt.Sprintf(format, args...))
		},
		run: func(string, ...string) ([]byte, error) { return nil, nil },
		readState: func([]Route) (darwinInstalledState, error) {
			state := states[stateIndex]
			stateIndex++
			return state, nil
		},
	}
	if err := h.Configure(Config{LocalAddrs: []netip.Prefix{local}, Routes: []Route{route}}); err != nil {
		t.Fatal(err)
	}
	if len(logs) == 0 || !strings.Contains(logs[len(logs)-1], "optional TUN route") {
		t.Fatalf("logs = %q, want optional route warning", logs)
	}
}
