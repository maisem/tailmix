//go:build darwin

package hosttun

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"

	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/unix"

	"tailscale.com/net/netmon"
	"tailscale.com/net/routetable"
	"tailscale.com/net/tstun"
	"tailscale.com/types/logger"
)

type commandRunner func(string, ...string) ([]byte, error)

type darwinUnderlayDefault struct {
	Interface string
	Gateway   netip.Addr
}

type darwinScopedDefault struct {
	Destination netip.Prefix
	Interface   string
	Gateway     netip.Addr
}

type darwinHost struct {
	dev             tun.Device
	name            string
	logf            logger.Logf
	run             commandRunner
	readState       func([]Route) (darwinInstalledState, error)
	underlayDefault func(bool) (darwinUnderlayDefault, error)
	mu              sync.Mutex
	localAddrs      []netip.Prefix
	routes          []Route
	scopedDefaults  []darwinScopedDefault
	configured      bool
	closed          bool
	closeOnce       sync.Once
	closeErr        error
}

func Open(cfg OpenConfig) (Host, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("darwin TUN mode requires root; run tailmixd with sudo")
	}
	if cfg.Name == "" {
		cfg.Name = "utun"
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	dev, name, err := tstun.New(cfg.Logf, cfg.Name)
	if err != nil {
		tstun.Diagnose(cfg.Logf, cfg.Name, err)
		return nil, fmt.Errorf("create Darwin TUN %q: %w", cfg.Name, err)
	}
	h := &darwinHost{
		dev:  dev,
		name: name,
		logf: cfg.Logf,
		run: func(name string, args ...string) ([]byte, error) {
			return exec.Command(name, args...).CombinedOutput()
		},
	}
	h.readState = h.readInstalledState
	h.underlayDefault = systemUnderlayDefault
	if err := h.command("/sbin/ifconfig", name, "up"); err != nil {
		_ = dev.Close()
		return nil, err
	}
	return h, nil
}

func (h *darwinHost) Device() tun.Device { return h.dev }
func (h *darwinHost) Name() string       { return h.name }

func (h *darwinHost) Configure(cfg Config) error {
	localAddrs, routes, err := normalizeConfig(cfg)
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return errors.New("darwin host TUN is closed")
	}
	installed, err := h.installedState(routes)
	if err != nil {
		return err
	}
	h.localAddrs = installed.localAddrs
	h.routes = installed.routes
	h.scopedDefaults = installed.scopedDefaults
	scopedDefaults, err := h.desiredScopedDefaults(routes)
	if err != nil {
		return err
	}

	wantAddrs := make(map[netip.Addr]netip.Prefix, len(localAddrs))
	for _, addr := range localAddrs {
		wantAddrs[addr.Addr()] = addr
	}
	currentAddrs := make(map[netip.Addr]bool, len(h.localAddrs))
	for _, addr := range h.localAddrs {
		currentAddrs[addr.Addr()] = true
	}

	wantScopedDefaults := make(map[darwinScopedDefault]bool, len(scopedDefaults))
	for _, route := range scopedDefaults {
		wantScopedDefaults[route] = true
	}
	scopedDefaultsChanged := len(wantScopedDefaults) != len(h.scopedDefaults)
	if !scopedDefaultsChanged {
		for _, route := range h.scopedDefaults {
			if !wantScopedDefaults[route] {
				scopedDefaultsChanged = true
				break
			}
		}
	}

	wantRoutes := make(map[netip.Prefix]Route, len(routes))
	for _, route := range routes {
		wantRoutes[route.Destination] = route
	}
	for _, route := range slices.Clone(h.routes) {
		want, ok := wantRoutes[route.Destination]
		if ok && want == route && !(route.Exit && scopedDefaultsChanged) {
			continue
		}
		if err := h.command(routeDeleteCommand(h.name, route)...); err != nil {
			if route.Optional {
				h.logf("optional TUN route %v could not be removed: %v", route.Destination, err)
				continue
			}
			return err
		}
		h.routes = slices.DeleteFunc(h.routes, func(candidate Route) bool {
			return candidate.Destination == route.Destination
		})
	}
	for _, route := range slices.Clone(h.scopedDefaults) {
		if wantScopedDefaults[route] {
			continue
		}
		if h.logf != nil {
			h.logf("remove scoped underlay default %v via %v on %s", route.Destination, route.Gateway, route.Interface)
		}
		if err := h.command(scopedDefaultDeleteCommand(route)...); err != nil {
			return err
		}
		h.scopedDefaults = slices.DeleteFunc(h.scopedDefaults, func(candidate darwinScopedDefault) bool {
			return candidate == route
		})
	}
	for _, addr := range slices.Clone(h.localAddrs) {
		if _, ok := wantAddrs[addr.Addr()]; ok {
			continue
		}
		if err := h.command(addressDeleteCommand(h.name, addr)...); err != nil {
			return err
		}
		h.localAddrs = slices.DeleteFunc(h.localAddrs, func(candidate netip.Prefix) bool {
			return candidate.Addr() == addr.Addr()
		})
	}
	for _, addr := range localAddrs {
		if currentAddrs[addr.Addr()] {
			continue
		}
		if err := h.command(addressAddCommand(h.name, addr)...); err != nil {
			return err
		}
		h.localAddrs = append(h.localAddrs, addr)
	}
	currentScopedDefaults := make(map[darwinScopedDefault]bool, len(h.scopedDefaults))
	for _, route := range h.scopedDefaults {
		currentScopedDefaults[route] = true
	}
	for _, route := range scopedDefaults {
		if currentScopedDefaults[route] {
			continue
		}
		if h.logf != nil {
			h.logf("add scoped underlay default %v via %v on %s", route.Destination, route.Gateway, route.Interface)
		}
		if err := h.command(scopedDefaultAddCommand(route)...); err != nil {
			return err
		}
		h.scopedDefaults = append(h.scopedDefaults, route)
	}
	currentRoutes := make(map[netip.Prefix]Route, len(h.routes))
	for _, route := range h.routes {
		currentRoutes[route.Destination] = route
	}
	for _, route := range routes {
		if current, ok := currentRoutes[route.Destination]; ok && current == route {
			continue
		}
		if route.Exit && h.logf != nil {
			h.logf("add aggregate exit route %v on %s", route.Destination, h.name)
		}
		if err := h.command(routeAddCommand(h.name, route)...); err != nil {
			if route.Optional {
				h.logf("optional TUN route %v could not be installed: %v", route.Destination, err)
				continue
			}
			return err
		}
		h.routes = append(h.routes, route)
	}
	actual, err := h.installedState(routes)
	if err != nil {
		return err
	}
	h.localAddrs = actual.localAddrs
	h.routes = actual.routes
	h.scopedDefaults = actual.scopedDefaults
	if err := errors.Join(
		verifyHostConfig(localAddrs, routes, actual.localAddrs, actual.routes),
		verifyDarwinScopedDefaults(scopedDefaults, actual.scopedDefaults),
	); err != nil {
		return fmt.Errorf("verify Darwin TUN %s configuration: %w", h.name, err)
	}
	for _, route := range optionalRouteWarnings(routes, actual.routes) {
		h.logf("optional TUN route %v is not installed", route.Destination)
	}
	h.configured = true
	return nil
}

func (h *darwinHost) desiredScopedDefaults(routes []Route) ([]darwinScopedDefault, error) {
	var haveExitRoute bool
	for _, route := range routes {
		if route.Exit {
			haveExitRoute = true
			break
		}
	}
	if !haveExitRoute {
		return nil, nil
	}
	if h.underlayDefault == nil {
		return nil, errors.New("darwin underlay default route lookup is unavailable")
	}

	var (
		defaults   []darwinScopedDefault
		lookupErrs []error
	)
	for _, ipv6 := range []bool{false, true} {
		underlay, err := h.underlayDefault(ipv6)
		if err != nil {
			family := "IPv4"
			if ipv6 {
				family = "IPv6"
			}
			lookupErrs = append(lookupErrs, fmt.Errorf("%s underlay: %w", family, err))
			continue
		}
		addr := netip.IPv4Unspecified()
		if ipv6 {
			addr = netip.IPv6Unspecified()
		}
		defaults = append(defaults, darwinScopedDefault{
			Destination: netip.PrefixFrom(addr, 0),
			Interface:   underlay.Interface,
			Gateway:     underlay.Gateway,
		})
	}
	if len(defaults) == 0 {
		return nil, fmt.Errorf("discover physical default route for exit-node underlay: %w", errors.Join(lookupErrs...))
	}
	return defaults, nil
}

func systemUnderlayDefault(ipv6 bool) (darwinUnderlayDefault, error) {
	details, err := netmon.DefaultRoute()
	if err != nil {
		return darwinUnderlayDefault{}, err
	}
	routes, err := routetable.Get(65536)
	if err != nil {
		return darwinUnderlayDefault{}, err
	}
	return underlayDefaultFromRoutes(details.InterfaceName, routes, ipv6)
}

func underlayDefaultFromRoutes(interfaceName string, routes []routetable.RouteEntry, ipv6 bool) (darwinUnderlayDefault, error) {
	for _, route := range routes {
		sys, ok := route.Sys.(routetable.RouteEntryBSD)
		if !ok || sys.RawFlags&unix.RTF_IFSCOPE != 0 ||
			!route.Dst.IsValid() || route.Dst.Bits() != 0 ||
			route.Dst.Addr().Is6() != ipv6 || route.Interface != interfaceName {
			continue
		}
		return darwinUnderlayDefault{
			Interface: route.Interface,
			Gateway:   route.Gateway,
		}, nil
	}
	family := "IPv4"
	if ipv6 {
		family = "IPv6"
	}
	return darwinUnderlayDefault{}, fmt.Errorf("no unscoped %s default route on %s", family, interfaceName)
}

func (h *darwinHost) Close() error {
	h.closeOnce.Do(func() {
		h.mu.Lock()
		clearErr := h.clearLocked()
		h.closed = true
		h.mu.Unlock()
		h.closeErr = errors.Join(clearErr, h.dev.Close())
	})
	return h.closeErr
}

func (h *darwinHost) clearLocked() error {
	var errs []error
	for _, route := range slices.Backward(h.routes) {
		if err := h.command(routeDeleteCommand(h.name, route)...); err != nil {
			errs = append(errs, err)
		}
	}
	h.routes = nil
	for _, route := range slices.Backward(h.scopedDefaults) {
		if err := h.command(scopedDefaultDeleteCommand(route)...); err != nil {
			errs = append(errs, err)
		}
	}
	h.scopedDefaults = nil
	for _, addr := range slices.Backward(h.localAddrs) {
		if err := h.command(addressDeleteCommand(h.name, addr)...); err != nil {
			errs = append(errs, err)
		}
	}
	h.localAddrs = nil
	h.configured = false
	return errors.Join(errs...)
}

func (h *darwinHost) command(argv ...string) error {
	out, err := h.run(argv[0], argv[1:]...)
	if err == nil {
		return nil
	}
	msg := strings.TrimSpace(string(out))
	if msg == "" {
		return fmt.Errorf("%s: %w", strings.Join(argv, " "), err)
	}
	return fmt.Errorf("%s: %w: %s", strings.Join(argv, " "), err, msg)
}

func addressAddCommand(name string, prefix netip.Prefix) []string {
	return []string{"/sbin/ifconfig", name, inet(prefix.Addr()), prefix.String(), prefix.Addr().String()}
}

func addressDeleteCommand(name string, prefix netip.Prefix) []string {
	return []string{"/sbin/ifconfig", name, inet(prefix.Addr()), prefix.String(), "-alias"}
}

func routeAddCommand(name string, route Route) []string {
	return []string{"/sbin/route", "-q", "-n", "add", "-" + inet(route.Destination.Addr()), route.Destination.String(), "-iface", name, "-ifa", route.Source.String()}
}

func routeDeleteCommand(name string, route Route) []string {
	return []string{"/sbin/route", "-q", "-n", "delete", "-" + inet(route.Destination.Addr()), route.Destination.String(), "-iface", name}
}

func scopedDefaultAddCommand(route darwinScopedDefault) []string {
	command := []string{
		"/sbin/route", "-q", "-n", "add", "-" + inet(route.Destination.Addr()),
		"-proto2", "-ifscope", route.Interface, route.Destination.String(),
	}
	if route.Gateway.IsValid() {
		return append(command, route.Gateway.String())
	}
	return append(command, "-iface", route.Interface)
}

func scopedDefaultDeleteCommand(route darwinScopedDefault) []string {
	command := []string{
		"/sbin/route", "-q", "-n", "delete", "-" + inet(route.Destination.Addr()),
		"-ifscope", route.Interface, route.Destination.String(),
	}
	if route.Gateway.IsValid() {
		return append(command, route.Gateway.String())
	}
	return append(command, "-iface", route.Interface)
}

func inet(ip netip.Addr) string {
	if ip.Is6() {
		return "inet6"
	}
	return "inet"
}
