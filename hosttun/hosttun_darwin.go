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

	"tailscale.com/net/tstun"
	"tailscale.com/types/logger"
)

type commandRunner func(string, ...string) ([]byte, error)

type darwinHost struct {
	dev        tun.Device
	name       string
	logf       logger.Logf
	run        commandRunner
	mu         sync.Mutex
	localAddrs []netip.Prefix
	routes     []Route
	configured bool
	closed     bool
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
	localAddrs, routes, err := normalizeConfig(cfg)
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return errors.New("Darwin host TUN is closed")
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
		if err := h.command(addressAddCommand(h.name, addr)...); err != nil {
			return err
		}
		h.localAddrs = append(h.localAddrs, addr)
	}

	wantRoutes := make(map[netip.Prefix]Route, len(routes))
	for _, route := range routes {
		wantRoutes[route.Destination] = route
	}
	for _, route := range slices.Clone(h.routes) {
		want, ok := wantRoutes[route.Destination]
		if ok && want == route {
			continue
		}
		if err := h.command(routeDeleteCommand(h.name, route)...); err != nil {
			return err
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
		if err := h.command(routeAddCommand(h.name, route)...); err != nil {
			return err
		}
		h.routes = append(h.routes, route)
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
	h.localAddrs = localAddrs
	h.routes = routes
	h.configured = true
	return nil
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
	return []string{"/sbin/route", "-q", "-n", "add", "-" + inet(route.Destination.Addr()), route.Destination.String(), "-iface", name}
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
