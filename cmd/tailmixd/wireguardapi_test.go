package main

import (
	"net/netip"
	"testing"

	"github.com/maisem/tailmix/state"
	"github.com/maisem/tailmix/wireguardcfg"
)

func TestWireGuardProfileProjectsStableEffectiveAddresses(t *testing.T) {
	canonical := netip.MustParseAddr("10.80.0.2")
	effective := netip.MustParseAddr("100.127.0.7")
	config := wireguardcfg.Config{
		Version: wireguardcfg.Version,
		Name:    "lab", DNSSuffix: "lab.example",
		Addresses: []netip.Addr{netip.MustParseAddr("10.80.0.1")},
		Peers: []wireguardcfg.Peer{{
			Name:      "gateway",
			PublicKey: wireguardcfg.Key{1}, Addresses: []netip.Addr{canonical},
			Routes: []netip.Prefix{netip.MustParsePrefix("10.90.0.0/16")}, ExitNode: true,
		}},
	}
	configured := state.Profile{
		ID: "p_lab", Name: "lab", Kind: state.ProfileKindWireGuard,
		StateDir: t.TempDir(), WireGuard: &config,
		WireGuardSecretFile: "wireguard-secrets-unavailable.json",
	}
	s := &supervisor{
		st: state.State{
			Profiles: []state.Profile{configured},
			Leases: []state.EffectiveLease{{
				ProfileID: configured.ID, NodeID: "gateway",
				CanonicalIP: canonical, EffectiveIP: effective,
			}},
		},
		runtimes: map[string]*managedProfile{},
	}

	got, err := s.wireGuardProfileLocked(configured)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Peers) != 1 || len(got.Peers[0].EffectiveAddresses) != 1 || got.Peers[0].EffectiveAddresses[0] != effective {
		t.Fatalf("profile effective addresses = %+v, want %v", got.Peers, effective)
	}
	if got.Peers[0].Name != "gateway" || got.Peers[0].Addresses[0] != canonical || got.Peers[0].Routes[0] != netip.MustParsePrefix("10.90.0.0/16") || !got.Peers[0].ExitNode {
		t.Fatalf("profile peer projection lost declarative state: %+v", got.Peers[0])
	}
}

func TestValidateWireGuardEndpointNamesRejectsProfileDNSRecursion(t *testing.T) {
	config := wireguardcfg.Config{Peers: []wireguardcfg.Peer{{
		Name: "gateway", Endpoint: "gateway.lab.example:51820",
	}}}
	config.DNSSuffix = "lab.example"
	if err := validateWireGuardEndpointNames(config); err == nil {
		t.Fatal("accepted an endpoint served by the same WireGuard profile")
	}
	config.Peers[0].Endpoint = "gateway.example.net:51820"
	if err := validateWireGuardEndpointNames(config); err != nil {
		t.Fatalf("rejected independent endpoint: %v", err)
	}
}
