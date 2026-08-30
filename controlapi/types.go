package controlapi

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/maisem/tailmix/wireguardcfg"
)

// DaemonState describes whether tailmix is running profile data planes.
type DaemonState struct {
	State string `json:"state"`
}

// UpdateStatus describes the daemon's automatic-update policy and most recent
// update activity.
type UpdateStatus struct {
	Enabled          bool   `json:"enabled"`
	CurrentVersion   string `json:"currentVersion"`
	AvailableVersion string `json:"availableVersion,omitempty"`
	State            string `json:"state"`
	LastChecked      string `json:"lastChecked,omitempty"`
	LastError        string `json:"lastError,omitempty"`
}

type Error struct {
	Code        string `json:"code"`
	Message     string `json:"message"`
	ProfileID   string `json:"profileId,omitempty"`
	ProfileName string `json:"profileName,omitempty"`
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

type Profile struct {
	ID                     string                  `json:"id"`
	Name                   string                  `json:"name"`
	Kind                   string                  `json:"kind,omitempty"`
	StateDir               string                  `json:"stateDir"`
	Hostname               string                  `json:"hostname,omitempty"`
	Enabled                bool                    `json:"enabled"`
	Removed                bool                    `json:"removed"`
	AcceptAllRoutes        bool                    `json:"acceptAllRoutes"`
	AcceptAllDNSRoutes     bool                    `json:"acceptAllDnsRoutes"`
	RuntimeState           string                  `json:"runtimeState"`
	BackendState           string                  `json:"backendState,omitempty"`
	MagicDNSSuffix         string                  `json:"magicDnsSuffix,omitempty"`
	SelfDNSName            string                  `json:"selfDnsName,omitempty"`
	SelfIPs                []netip.Addr            `json:"selfIps,omitempty"`
	PeerCount              int                     `json:"peerCount"`
	ShieldsUp              bool                    `json:"shieldsUp"`
	AuthURL                string                  `json:"authUrl,omitempty"`
	LocalAPISocket         string                  `json:"localApiSocket,omitempty"`
	AvailableRoutes        []AvailableIPRoute      `json:"availableRoutes,omitempty"`
	AvailableDNSRoutes     []AvailableDNSRoute     `json:"availableDnsRoutes,omitempty"`
	AvailableSearchDomains []AvailableSearchDomain `json:"availableSearchDomains,omitempty"`
	LastError              string                  `json:"lastError,omitempty"`
}

// ApplyWireGuardRequest is the transient local-control request used to apply a
// declarative WireGuard profile. Secrets are never included in profile
// responses or persisted as part of this request object by the control API.
type ApplyWireGuardRequest struct {
	Config  wireguardcfg.Config  `json:"config"`
	Secrets wireguardcfg.Secrets `json:"secrets"`
}

// WireGuardProfile is the public runtime view of a WireGuard profile.
type WireGuardProfile struct {
	Name       string          `json:"name"`
	Kind       string          `json:"kind"`
	PublicKey  string          `json:"publicKey"`
	ListenPort uint16          `json:"listenPort,omitempty"`
	Addresses  []netip.Addr    `json:"addresses,omitempty"`
	DNSSuffix  string          `json:"dnsSuffix"`
	Peers      []WireGuardPeer `json:"peers,omitempty"`
}

// WireGuardPeer is the public configured and effective view of one peer.
// It intentionally contains no private or preshared key material.
type WireGuardPeer struct {
	Name               string         `json:"name"`
	PublicKey          string         `json:"publicKey"`
	Endpoint           string         `json:"endpoint,omitempty"`
	Online             bool           `json:"online"`
	LastHandshake      time.Time      `json:"lastHandshake,omitzero"`
	ReceiveBytes       int64          `json:"receiveBytes,omitempty"`
	TransmitBytes      int64          `json:"transmitBytes,omitempty"`
	Addresses          []netip.Addr   `json:"canonicalAddresses,omitempty"`
	EffectiveAddresses []netip.Addr   `json:"effectiveAddresses,omitempty"`
	Routes             []netip.Prefix `json:"routes,omitempty"`
	ExitNode           bool           `json:"exitNode"`
	ExitNodeSelected   bool           `json:"exitNodeSelected"`
}

type Profiles struct {
	Profiles []Profile `json:"profiles"`
}

// Status is a daemon-wide snapshot of active profiles and the policy selected
// from them. Available-but-unselected routes and exit nodes remain available
// through their dedicated list endpoints.
type Status struct {
	State         string        `json:"state"`
	Profiles      []Profile     `json:"profiles"`
	IPRoutes      IPRoutes      `json:"ipRoutes"`
	ExitNodes     ExitNodes     `json:"exitNodes"`
	DNSRoutes     DNSRoutes     `json:"dnsRoutes"`
	SearchDomains SearchDomains `json:"searchDomains"`
}

type AddProfileRequest struct {
	Name     string `json:"name"`
	StateDir string `json:"stateDir,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	AuthKey  string `json:"authKey,omitempty"`
	Disabled bool   `json:"disabled,omitempty"`
}

type PatchProfileRequest struct {
	Name     *string `json:"name,omitempty"`
	Hostname *string `json:"hostname,omitempty"`
}

type AvailableIPRoute struct {
	Prefix        netip.Prefix `json:"prefix"`
	ProfileID     string       `json:"profileId"`
	ProfileName   string       `json:"profileName"`
	PrimaryRouter string       `json:"primaryRouter,omitempty"`
}

type IPRouteBinding struct {
	Prefix              netip.Prefix `json:"prefix"`
	ProfileID           string       `json:"profileId"`
	ProfileName         string       `json:"profileName"`
	Policy              string       `json:"policy"`
	State               string       `json:"state"`
	Reason              string       `json:"reason,omitempty"`
	CoveringRoute       netip.Prefix `json:"coveringRoute,omitempty"`
	PrimaryRouter       string       `json:"primaryRouter,omitempty"`
	OverriddenBy        netip.Prefix `json:"overriddenBy,omitempty"`
	OverrideProfileID   string       `json:"overrideProfileId,omitempty"`
	OverrideProfileName string       `json:"overrideProfileName,omitempty"`
}

type AcceptAllProfile struct {
	ProfileID   string `json:"profileId"`
	ProfileName string `json:"profileName"`
	State       string `json:"state"`
	Reason      string `json:"reason,omitempty"`
}

type IPRoutes struct {
	AcceptAllProfiles []AcceptAllProfile `json:"acceptAllProfiles,omitempty"`
	Bindings          []IPRouteBinding   `json:"bindings,omitempty"`
	Imported          []IPRouteBinding   `json:"imported,omitempty"`
	Available         []AvailableIPRoute `json:"available,omitempty"`
	ReconcileError    string             `json:"reconcileError,omitempty"`
}

type IPRouteMutation struct {
	Prefix      netip.Prefix `json:"prefix"`
	ProfileName string       `json:"profileName"`
}

type IPRouteUnbind struct {
	Prefix      netip.Prefix `json:"prefix"`
	ProfileName string       `json:"profileName,omitempty"`
}

type PatchIPRoutesRequest struct {
	Bind      []IPRouteMutation `json:"bind,omitempty"`
	Unbind    []IPRouteUnbind   `json:"unbind,omitempty"`
	Replace   bool              `json:"replace,omitempty"`
	AcceptAll map[string]bool   `json:"acceptAll,omitempty"`
}

type ReplaceIPRoutesRequest struct {
	Bindings  []IPRouteMutation `json:"bindings,omitempty"`
	AcceptAll []string          `json:"acceptAll,omitempty"`
}

type AvailableExitNode struct {
	ProfileID   string            `json:"profileId"`
	ProfileName string            `json:"profileName"`
	NodeID      string            `json:"nodeId"`
	DNSName     string            `json:"dnsName,omitempty"`
	IPs         []netip.Addr      `json:"ips,omitempty"`
	Online      bool              `json:"online"`
	Location    *ExitNodeLocation `json:"location,omitempty"`
}

type ExitNodeLocation struct {
	Country     string `json:"country,omitempty"`
	CountryCode string `json:"countryCode,omitempty"`
	City        string `json:"city,omitempty"`
	CityCode    string `json:"cityCode,omitempty"`
	Priority    int    `json:"priority,omitempty"`
}

type SelectedExitNode struct {
	ProfileID   string            `json:"profileId"`
	ProfileName string            `json:"profileName"`
	NodeID      string            `json:"nodeId"`
	DNSName     string            `json:"dnsName,omitempty"`
	PeerIP      netip.Addr        `json:"peerIp"`
	Online      bool              `json:"online"`
	Location    *ExitNodeLocation `json:"location,omitempty"`
	State       string            `json:"state"`
	Reason      string            `json:"reason,omitempty"`
}

type ExitNodes struct {
	Selected       *SelectedExitNode   `json:"selected,omitempty"`
	Available      []AvailableExitNode `json:"available,omitempty"`
	ReconcileError string              `json:"reconcileError,omitempty"`
}

type SetExitNodeRequest struct {
	ProfileName string `json:"profileName"`
	Peer        string `json:"peer"`
}

type DNSResolver struct {
	Addr                string       `json:"addr"`
	BootstrapResolution []netip.Addr `json:"bootstrapResolution,omitempty"`
	UseWithExitNode     bool         `json:"useWithExitNode,omitempty"`
}

type AvailableDNSRoute struct {
	Domain      string        `json:"domain"`
	ProfileID   string        `json:"profileId"`
	ProfileName string        `json:"profileName"`
	Source      string        `json:"source"`
	Resolvers   []DNSResolver `json:"resolvers,omitempty"`
}

type DNSRouteBinding struct {
	Domain              string        `json:"domain"`
	ProfileID           string        `json:"profileId"`
	ProfileName         string        `json:"profileName"`
	Policy              string        `json:"policy"`
	Source              string        `json:"source,omitempty"`
	State               string        `json:"state"`
	Reason              string        `json:"reason,omitempty"`
	CoveringRoute       string        `json:"coveringRoute,omitempty"`
	Resolvers           []DNSResolver `json:"resolvers,omitempty"`
	OverriddenBy        string        `json:"overriddenBy,omitempty"`
	OverrideProfileID   string        `json:"overrideProfileId,omitempty"`
	OverrideProfileName string        `json:"overrideProfileName,omitempty"`
}

type DNSRoutes struct {
	AcceptAllProfiles []AcceptAllProfile  `json:"acceptAllProfiles,omitempty"`
	Bindings          []DNSRouteBinding   `json:"bindings,omitempty"`
	Imported          []DNSRouteBinding   `json:"imported,omitempty"`
	Automatic         []DNSRouteBinding   `json:"automatic,omitempty"`
	Available         []AvailableDNSRoute `json:"available,omitempty"`
	ReconcileError    string              `json:"reconcileError,omitempty"`
}

type DNSRouteMutation struct {
	Domain      string `json:"domain"`
	ProfileName string `json:"profileName"`
}

type DNSRouteUnbind struct {
	Domain      string `json:"domain"`
	ProfileName string `json:"profileName,omitempty"`
}

type PatchDNSRoutesRequest struct {
	Bind      []DNSRouteMutation `json:"bind,omitempty"`
	Unbind    []DNSRouteUnbind   `json:"unbind,omitempty"`
	Replace   bool               `json:"replace,omitempty"`
	AcceptAll map[string]bool    `json:"acceptAll,omitempty"`
}

type ReplaceDNSRoutesRequest struct {
	Bindings  []DNSRouteMutation `json:"bindings,omitempty"`
	AcceptAll []string           `json:"acceptAll,omitempty"`
}

type InstalledSearchDomain struct {
	Domain      string `json:"domain"`
	ProfileID   string `json:"profileId"`
	ProfileName string `json:"profileName"`
}

type WaitingSearchDomain struct {
	Domain string `json:"domain"`
	Reason string `json:"reason"`
}

type AvailableSearchDomain struct {
	Domain      string `json:"domain"`
	ProfileID   string `json:"profileId"`
	ProfileName string `json:"profileName"`
}

type SearchDomains struct {
	Desired        []string                `json:"desired"`
	Installed      []InstalledSearchDomain `json:"installed,omitempty"`
	Waiting        []WaitingSearchDomain   `json:"waiting,omitempty"`
	Available      []AvailableSearchDomain `json:"available,omitempty"`
	ReconcileError string                  `json:"reconcileError,omitempty"`
}

type PatchSearchDomainsRequest struct {
	Add    []string `json:"add,omitempty"`
	Remove []string `json:"remove,omitempty"`
}

type ReplaceSearchDomainsRequest struct {
	Desired []string `json:"desired"`
}

func NewError(code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}
