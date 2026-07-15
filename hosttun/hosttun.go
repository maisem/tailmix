package hosttun

import (
	"net/netip"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/types/logger"
)

type Route struct {
	Destination netip.Prefix
	Source      netip.Addr
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
