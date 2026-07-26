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

type linuxHost struct {
	dev        tun.Device
	name       string
	link       netlink.Link
	logf       logger.Logf
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
	return &linuxHost{dev: dev, name: name, link: link, logf: cfg.Logf}, nil
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

	wantAddrs := make(map[netip.Addr]netip.Prefix, len(localAddrs))
	for _, addr := range localAddrs {
		wantAddrs[addr.Addr()] = addr
	}
	currentAddrs := make(map[netip.Addr]bool, len(h.localAddrs))
	for _, addr := range h.localAddrs {
		currentAddrs[addr.Addr()] = true
	}
	for _, addr := range localAddrs {
		if currentAddrs[addr.Addr()] {
			continue
		}
		if err := netlink.AddrReplace(h.link, &netlink.Addr{IPNet: netipx.PrefixIPNet(addr)}); err != nil {
			return fmt.Errorf("add %v to Linux TUN %s: %w", addr, h.name, err)
		}
		h.localAddrs = append(h.localAddrs, addr)
	}

	wantRoutes := make(map[netip.Prefix]Route, len(routes))
	for _, route := range routes {
		wantRoutes[route.Destination] = route
	}
	hadExitRoutes := hasExitRoutes(h.routes)
	wantsExitRoutes := hasExitRoutes(routes)
	if hadExitRoutes && !wantsExitRoutes {
		if err := h.deleteExitRules(); err != nil {
			return err
		}
		for _, route := range h.routes {
			if !route.Exit {
				if err := h.deleteRouteFromTable(route, tailmixExitRouteTable); err != nil {
					return err
				}
			}
		}
	}
	for _, route := range slices.Clone(h.routes) {
		want, ok := wantRoutes[route.Destination]
		if ok && want == route {
			continue
		}
		if err := h.deleteRoute(route); err != nil {
			return err
		}
		if hadExitRoutes && wantsExitRoutes && !route.Exit {
			if err := h.deleteRouteFromTable(route, tailmixExitRouteTable); err != nil {
				return err
			}
		}
		h.routes = slices.DeleteFunc(h.routes, func(candidate Route) bool {
			return candidate.Destination == route.Destination
		})
	}
	currentRoutes := make(map[netip.Prefix]Route, len(h.routes))
	for _, route := range h.routes {
		currentRoutes[route.Destination] = route
	}
	for _, route := range routes {
		if current, ok := currentRoutes[route.Destination]; ok && current == route {
			continue
		}
		if err := h.replaceRoute(route); err != nil {
			return err
		}
		if hadExitRoutes && wantsExitRoutes && !route.Exit {
			if err := h.replaceRouteInTable(route, tailmixExitRouteTable); err != nil {
				return err
			}
		}
		h.routes = append(h.routes, route)
	}
	if !hadExitRoutes && wantsExitRoutes {
		for _, route := range routes {
			if route.Exit {
				continue
			}
			if err := h.replaceRouteInTable(route, tailmixExitRouteTable); err != nil {
				return err
			}
		}
	}
	if !hadExitRoutes && wantsExitRoutes {
		if err := h.addExitRules(); err != nil {
			for _, route := range slices.Clone(h.routes) {
				if route.Exit {
					_ = h.deleteRoute(route)
					h.routes = slices.DeleteFunc(h.routes, func(candidate Route) bool {
						return candidate == route
					})
				} else {
					_ = h.deleteRouteFromTable(route, tailmixExitRouteTable)
				}
			}
			return err
		}
	}
	for _, addr := range slices.Clone(h.localAddrs) {
		if _, ok := wantAddrs[addr.Addr()]; ok {
			continue
		}
		if err := netlink.AddrDel(h.link, &netlink.Addr{IPNet: netipx.PrefixIPNet(addr)}); err != nil {
			return fmt.Errorf("remove %v from Linux TUN %s: %w", addr, h.name, err)
		}
		h.localAddrs = slices.DeleteFunc(h.localAddrs, func(candidate netip.Prefix) bool {
			return candidate.Addr() == addr.Addr()
		})
	}
	h.localAddrs = localAddrs
	h.routes = routes
	return nil
}

func (h *linuxHost) replaceRoute(route Route) error {
	table := 0
	if route.Exit {
		table = tailmixExitRouteTable
	}
	return h.replaceRouteInTable(route, table)
}

func (h *linuxHost) replaceRouteInTable(route Route, table int) error {
	err := netlink.RouteReplace(&netlink.Route{
		LinkIndex: h.link.Attrs().Index,
		Dst:       netipx.PrefixIPNet(route.Destination),
		Src:       net.IP(route.Source.AsSlice()),
		Table:     table,
	})
	if err != nil {
		return fmt.Errorf("route %v through Linux TUN %s: %w", route.Destination, h.name, err)
	}
	return nil
}

func (h *linuxHost) deleteRoute(route Route) error {
	table := 0
	if route.Exit {
		table = tailmixExitRouteTable
	}
	return h.deleteRouteFromTable(route, table)
}

func (h *linuxHost) deleteRouteFromTable(route Route, table int) error {
	err := netlink.RouteDel(&netlink.Route{
		LinkIndex: h.link.Attrs().Index,
		Dst:       netipx.PrefixIPNet(route.Destination),
		Table:     table,
	})
	if err != nil {
		return fmt.Errorf("remove route %v from Linux TUN %s: %w", route.Destination, h.name, err)
	}
	return nil
}

func (h *linuxHost) Close() error {
	h.closeOnce.Do(func() {
		h.mu.Lock()
		var errs []error
		if hasExitRoutes(h.routes) {
			if err := h.deleteExitRules(); err != nil {
				errs = append(errs, err)
			}
		}
		for _, route := range slices.Backward(h.routes) {
			if err := h.deleteRoute(route); err != nil {
				errs = append(errs, err)
			}
			if !route.Exit && hasExitRoutes(h.routes) {
				if err := h.deleteRouteFromTable(route, tailmixExitRouteTable); err != nil {
					errs = append(errs, err)
				}
			}
		}
		h.routes = nil
		for _, addr := range slices.Backward(h.localAddrs) {
			if err := netlink.AddrDel(h.link, &netlink.Addr{IPNet: netipx.PrefixIPNet(addr)}); err != nil {
				errs = append(errs, fmt.Errorf("remove %v from Linux TUN %s: %w", addr, h.name, err))
			}
		}
		h.localAddrs = nil
		h.closed = true
		h.mu.Unlock()
		h.closeErr = errors.Join(errors.Join(errs...), h.dev.Close())
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

func (h *linuxHost) addExitRules() error {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rule := tailmixExitRule(family)
		if err := netlink.RuleAdd(&rule); err != nil && !errors.Is(err, os.ErrExist) && !errors.Is(err, unix.EEXIST) {
			_ = h.deleteExitRules()
			return fmt.Errorf("add Linux exit-node policy rule for family %d: %w", family, err)
		}
	}
	return nil
}

func (h *linuxHost) deleteExitRules() error {
	var errs []error
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rule := tailmixExitRule(family)
		if err := netlink.RuleDel(&rule); err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ESRCH) {
			errs = append(errs, fmt.Errorf("remove Linux exit-node policy rule for family %d: %w", family, err))
		}
	}
	return errors.Join(errs...)
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
