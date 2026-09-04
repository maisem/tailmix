//go:build linux

package hosttun

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"

	"github.com/tailscale/netlink"
	"github.com/tailscale/wireguard-go/tun"
	"go4.org/netipx"
	"golang.org/x/sys/unix"
	"tailscale.com/net/tstun"
	"tailscale.com/tsconst"
	"tailscale.com/types/logger"
)

const (
	tailmixExitRouteTable = 527
	tailmixExitRulePref   = 5300
)

type linuxNetlinkOps struct {
	addrReplace  func(netlink.Link, *netlink.Addr) error
	addrDel      func(netlink.Link, *netlink.Addr) error
	routeReplace func(*netlink.Route) error
	routeDel     func(*netlink.Route) error
	ruleAdd      func(*netlink.Rule) error
	ruleDel      func(*netlink.Rule) error
}

type linuxInstalledRoute struct {
	Route
	controlled bool
}

type linuxInstalledState struct {
	localAddrs  []netip.Prefix
	mainRoutes  []linuxInstalledRoute
	tableRoutes []linuxInstalledRoute
	rules       []netlink.Rule
}

type linuxHost struct {
	dev        tun.Device
	name       string
	link       netlink.Link
	logf       logger.Logf
	ops        linuxNetlinkOps
	readState  func([]Route) (linuxInstalledState, error)
	mu         sync.Mutex
	localAddrs []netip.Prefix
	routes     []Route
	closed     bool
	closeOnce  sync.Once
	closeErr   error
}

func Open(cfg OpenConfig) (Host, error) {
	if cfg.Name == "" {
		cfg.Name = "tailmix0"
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	dev, name, err := tstun.New(cfg.Logf, cfg.Name)
	if err != nil {
		tstun.Diagnose(cfg.Logf, cfg.Name, err)
		return nil, fmt.Errorf("create Linux TUN %q (requires root or CAP_NET_ADMIN): %w", cfg.Name, err)
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("find Linux TUN %q: %w", name, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("bring Linux TUN %q up: %w", name, err)
	}
	h := &linuxHost{
		dev:  dev,
		name: name,
		link: link,
		logf: cfg.Logf,
		ops: linuxNetlinkOps{
			addrReplace:  netlink.AddrReplace,
			addrDel:      netlink.AddrDel,
			routeReplace: netlink.RouteReplace,
			routeDel:     netlink.RouteDel,
			ruleAdd:      netlink.RuleAdd,
			ruleDel:      netlink.RuleDel,
		},
	}
	h.readState = h.readInstalledState
	return h, nil
}

func (h *linuxHost) Device() tun.Device { return h.dev }
func (h *linuxHost) Name() string       { return h.name }

func (h *linuxHost) Configure(cfg Config) error {
	localAddrs, routes, err := normalizeConfig(cfg)
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return errors.New("linux host TUN is closed")
	}

	installed, err := h.installedState(routes)
	if err != nil {
		return err
	}
	h.localAddrs = installed.localAddrs
	h.routes = logicalLinuxRoutes(installed, routes)
	if err := h.removeUnexpectedRules(installed.rules, routes); err != nil {
		return err
	}

	currentAddrs := make(map[netip.Addr]netip.Prefix, len(installed.localAddrs))
	for _, addr := range installed.localAddrs {
		currentAddrs[addr.Addr()] = addr
	}
	for _, addr := range localAddrs {
		if current, ok := currentAddrs[addr.Addr()]; ok && current == addr {
			continue
		}
		if err := h.ops.addrReplace(h.link, &netlink.Addr{IPNet: netipx.PrefixIPNet(addr)}); err != nil {
			return fmt.Errorf("add %v to Linux TUN %s: %w", addr, h.name, err)
		}
	}

	mainRoutes, tableRoutes := desiredLinuxRoutes(routes)
	if err := h.reconcileRouteTable("main", 0, installed.mainRoutes, mainRoutes); err != nil {
		return err
	}
	if err := h.reconcileRouteTable(fmt.Sprintf("table %d", tailmixExitRouteTable), tailmixExitRouteTable, installed.tableRoutes, tableRoutes); err != nil {
		return err
	}
	if err := h.addMissingRules(installed.rules, routes); err != nil {
		return err
	}

	wantAddrByIP := make(map[netip.Addr]bool, len(localAddrs))
	for _, addr := range localAddrs {
		wantAddrByIP[addr.Addr()] = true
	}
	for _, addr := range installed.localAddrs {
		if wantAddrByIP[addr.Addr()] {
			continue
		}
		if err := h.ops.addrDel(h.link, &netlink.Addr{IPNet: netipx.PrefixIPNet(addr)}); err != nil {
			return fmt.Errorf("remove %v from Linux TUN %s: %w", addr, h.name, err)
		}
	}

	actual, err := h.installedState(routes)
	if err != nil {
		return err
	}
	h.localAddrs = actual.localAddrs
	h.routes = logicalLinuxRoutes(actual, routes)
	if err := verifyLinuxState(localAddrs, routes, actual); err != nil {
		return fmt.Errorf("verify Linux TUN %s configuration: %w", h.name, err)
	}
	h.logOptionalRouteWarnings(routes, actual)
	return nil
}

func (h *linuxHost) installedState(wantRoutes []Route) (linuxInstalledState, error) {
	if h.readState != nil {
		return h.readState(wantRoutes)
	}
	return h.readInstalledState(wantRoutes)
}

func (h *linuxHost) readInstalledState(wantRoutes []Route) (linuxInstalledState, error) {
	addrs, err := netlink.AddrList(h.link, netlink.FAMILY_ALL)
	if err != nil {
		return linuxInstalledState{}, fmt.Errorf("list Linux TUN %s addresses: %w", h.name, err)
	}
	var state linuxInstalledState
	for _, addr := range addrs {
		prefix, ok := netipx.FromStdIPNet(addr.IPNet)
		if ok && prefix.Addr().IsGlobalUnicast() {
			state.localAddrs = append(state.localAddrs, prefix)
		}
	}
	wantByDestination := make(map[netip.Prefix]Route, len(wantRoutes))
	for _, route := range wantRoutes {
		wantByDestination[route.Destination] = route
	}
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		mainRoutes, err := netlink.RouteList(h.link, family)
		if err != nil {
			return linuxInstalledState{}, fmt.Errorf("list Linux TUN %s routes: %w", h.name, err)
		}
		state.mainRoutes = appendLinuxRoutes(state.mainRoutes, mainRoutes, family, wantByDestination)

		tableRoutes, err := netlink.RouteListFiltered(family, &netlink.Route{
			LinkIndex: h.link.Attrs().Index,
			Table:     tailmixExitRouteTable,
		}, netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE)
		if err != nil {
			return linuxInstalledState{}, fmt.Errorf("list Linux TUN %s routes in table %d: %w", h.name, tailmixExitRouteTable, err)
		}
		state.tableRoutes = appendLinuxRoutes(state.tableRoutes, tableRoutes, family, wantByDestination)

		rules, err := netlink.RuleList(family)
		if err != nil {
			return linuxInstalledState{}, fmt.Errorf("list Linux policy rules for family %d: %w", family, err)
		}
		for _, rule := range rules {
			if rule.Priority == tailmixExitRulePref {
				if rule.Family == 0 {
					rule.Family = family
				}
				state.rules = append(state.rules, rule)
			}
		}
	}
	return state, nil
}

func appendLinuxRoutes(dst []linuxInstalledRoute, routes []netlink.Route, family int, want map[netip.Prefix]Route) []linuxInstalledRoute {
	for _, route := range routes {
		if installed, ok := linuxRouteFromNetlink(route, family, want); ok {
			dst = append(dst, installed)
		}
	}
	return dst
}

func linuxRouteFromNetlink(route netlink.Route, family int, want map[netip.Prefix]Route) (linuxInstalledRoute, bool) {
	var destination netip.Prefix
	if route.Dst == nil {
		if family == netlink.FAMILY_V6 {
			destination = netip.PrefixFrom(netip.IPv6Unspecified(), 0)
		} else {
			destination = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
		}
	} else {
		var ok bool
		destination, ok = netipx.FromStdIPNet(route.Dst)
		if !ok {
			return linuxInstalledRoute{}, false
		}
	}
	source, _ := netip.AddrFromSlice(route.Src)
	source = source.Unmap()
	installed := linuxInstalledRoute{
		Route: Route{Destination: destination.Masked(), Source: source},
		controlled: len(route.Gw) == 0 && len(route.MultiPath) == 0 && route.Via == nil && route.Encap == nil &&
			(route.Type == 0 || route.Type == unix.RTN_UNICAST) && route.Scope == netlink.SCOPE_UNIVERSE &&
			route.Priority == 0 && route.Tos == 0,
	}
	if desired, ok := want[installed.Destination]; ok {
		installed.Exit = desired.Exit
		installed.Optional = desired.Optional
	}
	return installed, true
}

func desiredLinuxRoutes(routes []Route) (mainRoutes, tableRoutes []Route) {
	wantsExit := hasExitRoutes(routes)
	for _, route := range routes {
		if !route.Exit {
			mainRoutes = append(mainRoutes, route)
		}
		if wantsExit {
			tableRoutes = append(tableRoutes, route)
		}
	}
	return mainRoutes, tableRoutes
}

func logicalLinuxRoutes(state linuxInstalledState, want []Route) []Route {
	wantByDestination := make(map[netip.Prefix]Route, len(want))
	for _, route := range want {
		wantByDestination[route.Destination] = route
	}
	var routes []Route
	for _, installed := range state.mainRoutes {
		if desired, ok := wantByDestination[installed.Destination]; ok && !desired.Exit {
			routes = append(routes, installed.Route)
		}
	}
	for _, installed := range state.tableRoutes {
		if desired, ok := wantByDestination[installed.Destination]; ok && desired.Exit {
			routes = append(routes, installed.Route)
		}
	}
	return routes
}

func (h *linuxHost) reconcileRouteTable(name string, table int, installed []linuxInstalledRoute, want []Route) error {
	wantByDestination := make(map[netip.Prefix]Route, len(want))
	for _, route := range want {
		wantByDestination[route.Destination] = route
	}
	installedByDestination := make(map[netip.Prefix]linuxInstalledRoute, len(installed))
	for _, route := range installed {
		installedByDestination[route.Destination] = route
		if _, ok := wantByDestination[route.Destination]; ok {
			continue
		}
		if err := h.deleteRouteFromTable(route.Route, table); err != nil {
			return fmt.Errorf("remove stale route %v from Linux TUN %s %s: %w", route.Destination, h.name, name, err)
		}
	}
	for _, route := range want {
		current, ok := installedByDestination[route.Destination]
		if ok && current.controlled && current.Source == route.Source {
			continue
		}
		if err := h.replaceRouteInTable(route, table); err != nil {
			if route.Optional {
				h.logf("optional TUN route %v could not be installed in Linux %s: %v", route.Destination, name, err)
				continue
			}
			return err
		}
	}
	return nil
}

func (h *linuxHost) removeUnexpectedRules(installed []netlink.Rule, routes []Route) error {
	want := desiredLinuxRules(routes)
	for i := range installed {
		if containsLinuxRule(want, installed[i]) {
			continue
		}
		if err := h.ops.ruleDel(&installed[i]); err != nil && !isNotExist(err) {
			return fmt.Errorf("remove stale Linux exit-node policy rule for family %d: %w", installed[i].Family, err)
		}
	}
	return nil
}

func (h *linuxHost) addMissingRules(installed []netlink.Rule, routes []Route) error {
	want := desiredLinuxRules(routes)
	var added []netlink.Rule
	for i := range want {
		if containsLinuxRule(installed, want[i]) {
			continue
		}
		err := h.ops.ruleAdd(&want[i])
		if errors.Is(err, os.ErrExist) || errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			for j := range added {
				_ = h.ops.ruleDel(&added[j])
			}
			return fmt.Errorf("add Linux exit-node policy rule for family %d: %w", want[i].Family, err)
		}
		added = append(added, want[i])
	}
	return nil
}

func desiredLinuxRules(routes []Route) []netlink.Rule {
	if !hasExitRoutes(routes) {
		return nil
	}
	return []netlink.Rule{tailmixExitRule(unix.AF_INET), tailmixExitRule(unix.AF_INET6)}
}

func containsLinuxRule(rules []netlink.Rule, want netlink.Rule) bool {
	for _, rule := range rules {
		if sameLinuxRule(rule, want) {
			return true
		}
	}
	return false
}

func sameLinuxRule(a, b netlink.Rule) bool {
	return a.Family == b.Family && a.Priority == b.Priority && a.Table == b.Table &&
		a.Mark == b.Mark && a.Mask == b.Mask && a.Invert == b.Invert &&
		a.Src == nil && b.Src == nil && a.Dst == nil && b.Dst == nil &&
		a.IifName == "" && b.IifName == "" && a.OifName == "" && b.OifName == ""
}

func verifyLinuxState(wantAddrs []netip.Prefix, wantRoutes []Route, got linuxInstalledState) error {
	mainRoutes, tableRoutes := desiredLinuxRoutes(wantRoutes)
	var errs []error
	if err := verifyHostConfig(wantAddrs, nil, got.localAddrs, nil); err != nil {
		errs = append(errs, err)
	}
	if err := verifyLinuxRouteTable("main table", mainRoutes, got.mainRoutes); err != nil {
		errs = append(errs, err)
	}
	if err := verifyLinuxRouteTable(fmt.Sprintf("table %d", tailmixExitRouteTable), tableRoutes, got.tableRoutes); err != nil {
		errs = append(errs, err)
	}
	wantRules := desiredLinuxRules(wantRoutes)
	for _, rule := range got.rules {
		if !containsLinuxRule(wantRules, rule) {
			errs = append(errs, fmt.Errorf("unexpected Linux policy rule at priority %d for family %d", rule.Priority, rule.Family))
		}
	}
	for _, rule := range wantRules {
		count := 0
		for _, actual := range got.rules {
			if sameLinuxRule(actual, rule) {
				count++
			}
		}
		if count == 0 {
			errs = append(errs, fmt.Errorf("missing Linux policy rule at priority %d for family %d", rule.Priority, rule.Family))
		} else if count > 1 {
			errs = append(errs, fmt.Errorf("duplicate Linux policy rule at priority %d for family %d", rule.Priority, rule.Family))
		}
	}
	return errors.Join(errs...)
}

func verifyLinuxRouteTable(name string, want []Route, got []linuxInstalledRoute) error {
	wantByDestination := make(map[netip.Prefix]Route, len(want))
	for _, route := range want {
		wantByDestination[route.Destination] = route
	}
	gotByDestination := make(map[netip.Prefix]linuxInstalledRoute, len(got))
	var errs []error
	for _, route := range got {
		gotByDestination[route.Destination] = route
		desired, ok := wantByDestination[route.Destination]
		if !ok {
			errs = append(errs, fmt.Errorf("unexpected Linux %s route %v", name, route.Destination))
			continue
		}
		if desired.Optional {
			continue
		}
		if !route.controlled || route.Source != desired.Source {
			errs = append(errs, fmt.Errorf("Linux %s route %v has source %v or unexpected attributes; want source %v", name, route.Destination, route.Source, desired.Source))
		}
	}
	for _, route := range want {
		if route.Optional {
			continue
		}
		if _, ok := gotByDestination[route.Destination]; !ok {
			errs = append(errs, fmt.Errorf("missing Linux %s route %v", name, route.Destination))
		}
	}
	return errors.Join(errs...)
}

func (h *linuxHost) logOptionalRouteWarnings(routes []Route, state linuxInstalledState) {
	mainRoutes, tableRoutes := desiredLinuxRoutes(routes)
	h.logOptionalRouteTableWarnings("main table", mainRoutes, state.mainRoutes)
	h.logOptionalRouteTableWarnings(fmt.Sprintf("table %d", tailmixExitRouteTable), tableRoutes, state.tableRoutes)
}

func (h *linuxHost) logOptionalRouteTableWarnings(name string, want []Route, got []linuxInstalledRoute) {
	gotByDestination := make(map[netip.Prefix]linuxInstalledRoute, len(got))
	for _, route := range got {
		gotByDestination[route.Destination] = route
	}
	for _, route := range want {
		if !route.Optional {
			continue
		}
		actual, ok := gotByDestination[route.Destination]
		if !ok || !actual.controlled || actual.Source != route.Source {
			h.logf("optional TUN route %v is not installed correctly in Linux %s", route.Destination, name)
		}
	}
}

func (h *linuxHost) replaceRouteInTable(route Route, table int) error {
	if err := h.ops.routeReplace(&netlink.Route{
		LinkIndex: h.link.Attrs().Index,
		Dst:       netipx.PrefixIPNet(route.Destination),
		Src:       net.IP(route.Source.AsSlice()),
		Table:     table,
	}); err != nil {
		return fmt.Errorf("route %v through Linux TUN %s: %w", route.Destination, h.name, err)
	}
	return nil
}

func (h *linuxHost) deleteRouteFromTable(route Route, table int) error {
	err := h.ops.routeDel(&netlink.Route{
		LinkIndex: h.link.Attrs().Index,
		Dst:       netipx.PrefixIPNet(route.Destination),
		Table:     table,
	})
	if err != nil && !isNotExist(err) {
		return fmt.Errorf("remove route %v from Linux TUN %s: %w", route.Destination, h.name, err)
	}
	return nil
}

func (h *linuxHost) Close() error {
	h.closeOnce.Do(func() {
		h.mu.Lock()
		var errs []error
		state, err := h.installedState(h.routes)
		if err != nil {
			errs = append(errs, fmt.Errorf("read Linux TUN %s before close: %w", h.name, err))
			mainRoutes, tableRoutes := desiredLinuxRoutes(h.routes)
			state.localAddrs = slices.Clone(h.localAddrs)
			for _, route := range mainRoutes {
				state.mainRoutes = append(state.mainRoutes, linuxInstalledRoute{Route: route, controlled: true})
			}
			for _, route := range tableRoutes {
				state.tableRoutes = append(state.tableRoutes, linuxInstalledRoute{Route: route, controlled: true})
			}
			state.rules = desiredLinuxRules(h.routes)
		}
		for i := range state.rules {
			if err := h.ops.ruleDel(&state.rules[i]); err != nil && !isNotExist(err) {
				errs = append(errs, fmt.Errorf("remove Linux exit-node policy rule for family %d: %w", state.rules[i].Family, err))
			}
		}
		for _, route := range slices.Backward(state.tableRoutes) {
			if err := h.deleteRouteFromTable(route.Route, tailmixExitRouteTable); err != nil {
				errs = append(errs, err)
			}
		}
		for _, route := range slices.Backward(state.mainRoutes) {
			if err := h.deleteRouteFromTable(route.Route, 0); err != nil {
				errs = append(errs, err)
			}
		}
		for _, addr := range slices.Backward(state.localAddrs) {
			if err := h.ops.addrDel(h.link, &netlink.Addr{IPNet: netipx.PrefixIPNet(addr)}); err != nil && !isNotExist(err) {
				errs = append(errs, fmt.Errorf("remove %v from Linux TUN %s: %w", addr, h.name, err))
			}
		}
		h.localAddrs = nil
		h.routes = nil
		h.closed = true
		h.mu.Unlock()
		if h.dev != nil {
			h.closeErr = errors.Join(errors.Join(errs...), h.dev.Close())
		} else {
			h.closeErr = errors.Join(errs...)
		}
	})
	return h.closeErr
}

func hasExitRoutes(routes []Route) bool {
	for _, route := range routes {
		if route.Exit {
			return true
		}
	}
	return false
}

func tailmixExitRule(family int) netlink.Rule {
	rule := *netlink.NewRule()
	rule.Family = family
	rule.Priority = tailmixExitRulePref
	rule.Table = tailmixExitRouteTable
	rule.Mark = tsconst.LinuxBypassMarkNum
	rule.Mask = tsconst.LinuxFwmarkMaskNum
	rule.Invert = true
	return rule
}

func isNotExist(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH)
}
