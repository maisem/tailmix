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
		if !route.Destination.IsValid() || route.Destination.Bits() != route.Destination.Addr().BitLen() {
			return nil, nil, fmt.Errorf("TUN route must be a host prefix: %v", route.Destination)
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
