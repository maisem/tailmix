package hosttun

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/types/logger"
)

type Route struct {
	Destination netip.Prefix
	Source      netip.Addr
	Exit        bool
}

type Config struct {
	LocalAddrs []netip.Prefix
	Routes     []Route
}

type Host interface {
	Device() tun.Device
	Name() string
	Configure(Config) error
	Close() error
}

type OpenConfig struct {
	Name string
	Logf logger.Logf
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
		if !route.Destination.IsValid() {
			return nil, nil, fmt.Errorf("TUN route must be a valid prefix: %v", route.Destination)
		}
		route.Destination = route.Destination.Masked()
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
		if comparison := routes[i].Destination.Addr().Compare(routes[j].Destination.Addr()); comparison != 0 {
			return comparison < 0
		}
		return routes[i].Destination.Bits() < routes[j].Destination.Bits()
	})
	return localAddrs, routes, nil
}
