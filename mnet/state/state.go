package state

import "net/netip"

type State struct {
	SyntheticPool string           `json:"syntheticPool"`
	Profiles      []Profile        `json:"profiles"`
	Leases        []EffectiveLease `json:"leases"`
	ExitNode      *ExitNode        `json:"exitNode,omitempty"`
}

type Profile struct {
	ID             string `json:"id"`
	Alias          string `json:"alias"`
	StateDir       string `json:"stateDir"`
	Hostname       string `json:"hostname,omitempty"`
	ControlURL     string `json:"controlUrl,omitempty"`
	MagicDNSSuffix string `json:"magicDnsSuffix,omitempty"`
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
