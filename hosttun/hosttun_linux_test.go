//go:build linux

package hosttun

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/tailscale/netlink"
	"go4.org/netipx"
	"golang.org/x/sys/unix"
)

func noOpLinuxOps() linuxNetlinkOps {
	return linuxNetlinkOps{
		addrReplace:  func(netlink.Link, *netlink.Addr) error { return nil },
		addrDel:      func(netlink.Link, *netlink.Addr) error { return nil },
		routeReplace: func(*netlink.Route) error { return nil },
		routeDel:     func(*netlink.Route) error { return nil },
		ruleAdd:      func(*netlink.Rule) error { return nil },
		ruleDel:      func(*netlink.Rule) error { return nil },
	}
}

func testLinuxHost(states ...linuxInstalledState) *linuxHost {
	stateIndex := 0
	h := &linuxHost{
		name: "tailmix0",
		link: &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
			Name:  "tailmix0",
			Index: 42,
		}},
		logf: func(string, ...any) {},
		ops:  noOpLinuxOps(),
	}
	h.readState = func([]Route) (linuxInstalledState, error) {
		if stateIndex >= len(states) {
			return linuxInstalledState{}, fmt.Errorf("unexpected state read %d", stateIndex+1)
		}
		state := states[stateIndex]
		stateIndex++
		return state, nil
	}
	return h
}

func TestLinuxConfigureRejectsRouteCommandFalseSuccess(t *testing.T) {
	source := netip.MustParseAddr("10.250.0.1")
	local := netip.PrefixFrom(source, 32)
	route := Route{Destination: netip.MustParsePrefix("10.250.0.53/32"), Source: source}
	h := testLinuxHost(
		linuxInstalledState{},
		linuxInstalledState{localAddrs: []netip.Prefix{local}},
	)
	err := h.Configure(Config{LocalAddrs: []netip.Prefix{local}, Routes: []Route{route}})
	if err == nil || !strings.Contains(err.Error(), "missing Linux main table route") {
		t.Fatalf("Configure error = %v, want missing route verification error", err)
	}
}

func TestLinuxConfigureRejectsAddressCommandFalseSuccess(t *testing.T) {
	source := netip.MustParseAddr("10.250.0.1")
	local := netip.PrefixFrom(source, 32)
	h := testLinuxHost(linuxInstalledState{}, linuxInstalledState{})
	err := h.Configure(Config{LocalAddrs: []netip.Prefix{local}})
	if err == nil || !strings.Contains(err.Error(), "missing TUN address") {
		t.Fatalf("Configure error = %v, want missing address verification error", err)
	}
}

func TestLinuxConfigureRejectsRuleCommandFalseSuccess(t *testing.T) {
	source := netip.MustParseAddr("10.250.0.1")
	local := netip.PrefixFrom(source, 32)
	route := Route{Destination: netip.MustParsePrefix("0.0.0.0/1"), Source: source, Exit: true}
	h := testLinuxHost(
		linuxInstalledState{localAddrs: []netip.Prefix{local}},
		linuxInstalledState{
			localAddrs: []netip.Prefix{local},
			tableRoutes: []linuxInstalledRoute{{
				Route:      route,
				controlled: true,
			}},
		},
	)
	err := h.Configure(Config{LocalAddrs: []netip.Prefix{local}, Routes: []Route{route}})
	if err == nil || !strings.Contains(err.Error(), "missing Linux policy rule") {
		t.Fatalf("Configure error = %v, want missing policy rule verification error", err)
	}
}

func TestLinuxConfigureAllowsMissingOptionalRoute(t *testing.T) {
	source := netip.MustParseAddr("10.250.0.1")
	local := netip.PrefixFrom(source, 32)
	route := Route{
		Destination: netip.MustParsePrefix("100.100.100.100/32"),
		Source:      source,
		Optional:    true,
	}
	h := testLinuxHost(
		linuxInstalledState{localAddrs: []netip.Prefix{local}},
		linuxInstalledState{localAddrs: []netip.Prefix{local}},
	)
	var logs []string
	h.logf = func(format string, args ...any) {
		logs = append(logs, fmt.Sprintf(format, args...))
	}
	if err := h.Configure(Config{LocalAddrs: []netip.Prefix{local}, Routes: []Route{route}}); err != nil {
		t.Fatal(err)
	}
	if len(logs) == 0 || !strings.Contains(logs[len(logs)-1], "optional TUN route") {
		t.Fatalf("logs = %q, want optional route warning", logs)
	}
}

func TestLinuxConfigureRemovesObservedStaleRoute(t *testing.T) {
	source := netip.MustParseAddr("10.250.0.1")
	local := netip.PrefixFrom(source, 32)
	stale := Route{Destination: netip.MustParsePrefix("10.250.0.99/32"), Source: source}
	h := testLinuxHost(
		linuxInstalledState{
			localAddrs: []netip.Prefix{local},
			mainRoutes: []linuxInstalledRoute{{Route: stale, controlled: true}},
		},
		linuxInstalledState{localAddrs: []netip.Prefix{local}},
	)
	var deleted []*netlink.Route
	h.ops.routeDel = func(route *netlink.Route) error {
		copy := *route
		deleted = append(deleted, &copy)
		return nil
	}
	if err := h.Configure(Config{LocalAddrs: []netip.Prefix{local}}); err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 1 || deleted[0].Dst.String() != stale.Destination.String() {
		t.Fatalf("deleted routes = %v, want %v", deleted, stale.Destination)
	}
}

// TestLinuxConfigureAcceptsKernelInstalledState builds the state that the Linux
// kernel reports for a device that tailmix already configured: IPv6 routes carry
// the kernel's default IPv6 metric, and the kernel adds a route of its own for
// each address on the device. Configure must accept that state and leave the
// kernel's own route alone.
func TestLinuxConfigureAcceptsKernelInstalledState(t *testing.T) {
	source := netip.MustParseAddr("fd6d:6e65:7400::1")
	local := netip.PrefixFrom(source, 128)
	route := Route{Destination: netip.MustParsePrefix("fd6d:6e65:7400::2/128"), Source: source}
	wantByDestination := map[netip.Prefix]Route{route.Destination: route}
	localAddrs := map[netip.Addr]bool{source: true}
	mainRoutes := appendLinuxRoutes(nil, []netlink.Route{
		{
			LinkIndex: 42,
			Dst:       netipx.PrefixIPNet(local),
			Protocol:  unix.RTPROT_KERNEL,
			Type:      unix.RTN_UNICAST,
			Scope:     netlink.SCOPE_UNIVERSE,
			Priority:  256,
		},
		{
			LinkIndex: 42,
			Dst:       netipx.PrefixIPNet(route.Destination),
			Src:       net.IP(source.AsSlice()),
			Protocol:  unix.RTPROT_BOOT,
			Type:      unix.RTN_UNICAST,
			Scope:     netlink.SCOPE_UNIVERSE,
			Priority:  linuxIPv6RouteMetric,
		},
	}, netlink.FAMILY_V6, wantByDestination, localAddrs)
	installed := linuxInstalledState{localAddrs: []netip.Prefix{local}, mainRoutes: mainRoutes}
	h := testLinuxHost(installed, installed)
	var deleted []string
	h.ops.routeDel = func(route *netlink.Route) error {
		deleted = append(deleted, route.Dst.String())
		return nil
	}
	cfg := Config{LocalAddrs: []netip.Prefix{local}, Routes: []Route{route}}
	if err := h.Configure(cfg); err != nil {
		t.Fatalf("Configure error = %v, want nil", err)
	}
	for _, deletedRoute := range deleted {
		if deletedRoute == local.String() {
			t.Fatalf("Configure deleted the kernel's own route for %v", local)
		}
	}
}
