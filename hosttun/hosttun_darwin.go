//go:build darwin

package hosttun

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/tailscale/wireguard-go/tun"

	"tailscale.com/net/tstun"
	"tailscale.com/types/logger"
)

type commandRunner func(string, ...string) ([]byte, error)

type darwinHost struct {
	dev        tun.Device
	name       string
	logf       logger.Logf
	run        commandRunner
	localAddrs []netip.Prefix
	routes     []Route
	configured bool
	closeOnce  sync.Once
	closeErr   error
}

func Open(cfg OpenConfig) (Host, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("Darwin TUN mode requires root; run tailmixd with sudo")
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
	if err := h.command("/sbin/ifconfig", name, "up"); err != nil {
		_ = dev.Close()
		return nil, err
	}
	return h, nil
}

func (h *darwinHost) Device() tun.Device { return h.dev }
func (h *darwinHost) Name() string       { return h.name }

func (h *darwinHost) Configure(cfg Config) error {
	if h.configured {
		return errors.New("Darwin host TUN is already configured")
	}
	localAddrs, routes, err := normalizeConfig(cfg)
	if err != nil {
		return err
	}
	for _, addr := range localAddrs {
		if err := h.command(addressAddCommand(h.name, addr)...); err != nil {
			_ = h.clear()
			return err
		}
		h.localAddrs = append(h.localAddrs, addr)
	}
	for _, route := range routes {
		if err := h.command(routeAddCommand(h.name, route)...); err != nil {
			_ = h.clear()
			return err
		}
		h.routes = append(h.routes, route)
	}
	h.configured = true
	return nil
}

func normalizeConfig(cfg Config) ([]netip.Prefix, []Route, error) {
	localSet := map[netip.Addr]netip.Prefix{}
	for _, prefix := range cfg.LocalAddrs {
		if !prefix.IsValid() || prefix.Bits() != prefix.Addr().BitLen() {
			return nil, nil, fmt.Errorf("local TUN address must be a host prefix: %v", prefix)
		}
		localSet[prefix.Addr()] = prefix
	}
	localAddrs := make([]netip.Prefix, 0, len(localSet))
	for _, prefix := range localSet {
		localAddrs = append(localAddrs, prefix)
	}
	sort.Slice(localAddrs, func(i, j int) bool { return localAddrs[i].Addr().Compare(localAddrs[j].Addr()) < 0 })

	routeSet := map[netip.Prefix]Route{}
	for _, route := range cfg.Routes {
		if !route.Destination.IsValid() || route.Destination.Bits() != route.Destination.Addr().BitLen() {
			return nil, nil, fmt.Errorf("TUN route must be a host prefix: %v", route.Destination)
		}
		if !route.Source.IsValid() || route.Source.Is6() != route.Destination.Addr().Is6() {
			return nil, nil, fmt.Errorf("route %v has invalid source %v", route.Destination, route.Source)
		}
		if _, ok := localSet[route.Source]; !ok {
			return nil, nil, fmt.Errorf("route %v source %v is not a local TUN address", route.Destination, route.Source)
		}
		if existing, ok := routeSet[route.Destination]; ok && existing.Source != route.Source {
			return nil, nil, fmt.Errorf("route %v has conflicting sources %v and %v", route.Destination, existing.Source, route.Source)
		}
		routeSet[route.Destination] = route
	}
	routes := make([]Route, 0, len(routeSet))
	for _, route := range routeSet {
		routes = append(routes, route)
	}
	sort.Slice(routes, func(i, j int) bool {
		return routes[i].Destination.Addr().Compare(routes[j].Destination.Addr()) < 0
	})
	return localAddrs, routes, nil
}

func (h *darwinHost) Close() error {
	h.closeOnce.Do(func() {
		h.closeErr = errors.Join(h.clear(), h.dev.Close())
	})
	return h.closeErr
}

func (h *darwinHost) clear() error {
	var errs []error
	for _, route := range slices.Backward(h.routes) {
		if err := h.command(routeDeleteCommand(h.name, route)...); err != nil {
			errs = append(errs, err)
		}
	}
	h.routes = nil
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
	return []string{"/sbin/ifconfig", name, inet(prefix.Addr()), prefix.String(), prefix.Addr().String(), "alias"}
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

func inet(ip netip.Addr) string {
	if ip.Is6() {
		return "inet6"
	}
	return "inet"
}
