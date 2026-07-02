package status

import (
	"net/netip"

	"tailscale.com/mnet/effectiveip"
	"tailscale.com/mnet/profile"
)

type Status struct {
	Profiles []Profile `json:"profiles"`
}

type Profile struct {
	ID             string   `json:"id"`
	Alias          string   `json:"alias"`
	MagicDNSSuffix string   `json:"magicDnsSuffix,omitempty"`
	BackendState   string   `json:"backendState,omitempty"`
	SelfNode       string   `json:"selfNode"`
	SelfIPs        []IPPair `json:"selfIps"`
	PeerCount      int      `json:"peerCount"`
	ShieldsUp      bool     `json:"shieldsUp"`
}

type IPPair struct {
	Canonical string `json:"canonical"`
	Effective string `json:"effective"`
}

func Project(profiles []profile.Status, leases []effectiveip.Lease) Status {
	byKey := map[effectiveip.NodeKey]netip.Addr{}
	for _, lease := range leases {
		byKey[lease.NodeKey] = lease.EffectiveIP
	}
	out := Status{}
	for _, p := range profiles {
		proj := Profile{
			ID:             p.ProfileID,
			Alias:          p.Alias,
			MagicDNSSuffix: p.MagicDNSSuffix,
			BackendState:   p.BackendState,
			SelfNode:       p.SelfNodeID,
			PeerCount:      p.PeerCount,
			ShieldsUp:      p.ShieldsUp,
		}
		for _, canonical := range p.SelfIPs {
			effective := canonical
			key := effectiveip.NodeKey{ProfileID: p.ProfileID, NodeID: p.SelfNodeID, CanonicalIP: canonical}
			if leased, ok := byKey[key]; ok {
				effective = leased
			}
			proj.SelfIPs = append(proj.SelfIPs, IPPair{Canonical: canonical.String(), Effective: effective.String()})
		}
		out.Profiles = append(out.Profiles, proj)
	}
	return out
}
