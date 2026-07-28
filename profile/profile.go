package profile

import (
	"context"
	"net"
	"net/netip"

	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/types/dnstype"
)

type Engine interface {
	Start(context.Context) error
	Close() error
	Dial(context.Context, string, string) (net.Conn, error)
	Status(context.Context) (Status, error)
	WatchUpdates(context.Context, func()) error
}

type LocalBackendProvider interface {
	LocalBackend() (*ipnlocal.LocalBackend, error)
}

type Update struct {
	ProfileID string
	Err       error
}

type Status struct {
	ProfileID       string
	Alias           string
	MagicDNSSuffix  string
	BackendState    string
	AuthURL         string
	SelfNodeID      string
	SelfDNSName     string
	SelfIPs         []netip.Addr
	Peers           []PeerStatus
	PeerCount       int
	ShieldsUp       bool
	AvailableRoutes []RouteStatus
	DNSRoutes       []DNSRouteStatus
	SearchDomains   []string
	RouteAll        bool
	ExitNodeID      string
}

type PeerStatus struct {
	NodeID         string
	DNSName        string
	TailscaleIPs   []netip.Addr
	Online         bool
	ExitNode       bool
	ExitNodeOption bool
	Location       *PeerLocation
}

type PeerLocation struct {
	Country     string
	CountryCode string
	City        string
	CityCode    string
	Priority    int
}

type RouteStatus struct {
	Prefix        netip.Prefix
	PrimaryRouter string
}

type DNSRouteStatus struct {
	Domain    string
	Source    string
	Resolvers []*dnstype.Resolver
}

type RoutePreferenceController interface {
	SetRouteAll(context.Context, bool) error
}

type ExitNodePreferenceController interface {
	SetExitNodeIP(context.Context, netip.Addr) error
}
