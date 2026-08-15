package profile

import (
	"context"
	"net"
	"net/netip"
	"time"

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
	Kind            string
	MagicDNSSuffix  string
	BackendState    string
	AuthURL         string
	SelfNodeID      string
	SelfDNSName     string
	SelfIPs         []netip.Addr
	Peers           []PeerStatus
	Services        []ServiceStatus
	PeerCount       int
	ShieldsUp       bool
	AvailableRoutes []RouteStatus
	DNSRoutes       []DNSRouteStatus
	SearchDomains   []string
	RouteAll        bool
	ExitNodeID      string
	PublicKey       string
	ListenPort      uint16
}

type PeerStatus struct {
	NodeID         string
	DNSName        string
	PublicKey      string
	Endpoint       string
	TailscaleIPs   []netip.Addr
	Online         bool
	LastHandshake  time.Time
	RxBytes        uint64
	TxBytes        uint64
	ExitNode       bool
	ExitNodeOption bool
	Location       *PeerLocation
}

// ServiceStatus describes a Tailscale Service that is visible to this profile.
// Name is the stable, tailnet-scoped service name, including its "svc:" prefix.
type ServiceStatus struct {
	Name         string
	DNSName      string
	TailscaleIPs []netip.Addr
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
