package state

import "net/netip"

type UpdateState struct {
	// Disabled is stored instead of Enabled so existing state files default to
	// automatic updates being enabled.
	Disabled         bool   `json:"disabled,omitempty"`
	AvailableVersion string `json:"availableVersion,omitempty"`
	State            string `json:"state,omitempty"`
	LastChecked      string `json:"lastChecked,omitempty"`
	LastError        string `json:"lastError,omitempty"`
}

type State struct {
	SyntheticPool    string            `json:"syntheticPool"`
	SyntheticPoolV6  string            `json:"syntheticPoolV6,omitempty"`
	NATIP            netip.Addr        `json:"natIp,omitempty"`
	NATIPv6          netip.Addr        `json:"natIpV6,omitempty"`
	Profiles         []Profile         `json:"profiles"`
	Leases           []EffectiveLease  `json:"leases"`
	IPRouteBindings  []IPRouteBinding  `json:"ipRouteBindings,omitempty"`
	DNSRouteBindings []DNSRouteBinding `json:"dnsRouteBindings,omitempty"`
	SearchDomains    []string          `json:"searchDomains,omitempty"`
	ExitNode         *ExitNode         `json:"exitNode,omitempty"`
	Updates          UpdateState       `json:"updates,omitempty"`
}

type Profile struct {
	ID                 string `json:"id"`
	Name               string `json:"name,omitempty"`
	Alias              string `json:"alias,omitempty"`
	StateDir           string `json:"stateDir"`
	Hostname           string `json:"hostname,omitempty"`
	MagicDNSSuffix     string `json:"magicDnsSuffix,omitempty"`
	Disabled           bool   `json:"disabled,omitempty"`
	Removed            bool   `json:"removed,omitempty"`
	AcceptAllRoutes    bool   `json:"acceptAllRoutes,omitempty"`
	AcceptAllDNSRoutes bool   `json:"acceptAllDnsRoutes,omitempty"`
}

type IPRouteBinding struct {
	Prefix    netip.Prefix `json:"prefix"`
	ProfileID string       `json:"profileId"`
}

type DNSRouteBinding struct {
	Domain    string `json:"domain"`
	ProfileID string `json:"profileId"`
}

type EffectiveLease struct {
	ProfileID   string     `json:"profileId"`
	NodeID      string     `json:"nodeId"`
	CanonicalIP netip.Addr `json:"canonicalIp"`
	EffectiveIP netip.Addr `json:"effectiveIp"`
}

type ExitNode struct {
	ProfileID string     `json:"profileId"`
	NodeID    string     `json:"nodeId"`
	PeerIP    netip.Addr `json:"peerIp"`
}
