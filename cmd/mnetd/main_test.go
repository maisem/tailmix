package main

import (
	"net/netip"
	"path/filepath"
	"testing"

	"tailscale.com/mnet/effectiveip"
	mnetprofile "tailscale.com/mnet/profile"
	"tailscale.com/mnet/state"
)

func TestParseProfileSpecUsesMagicDNSSuffixAndAuthKeyEnv(t *testing.T) {
	got, err := parseProfileSpec("id=work,dir=/tmp/work,hostname=mnet-work,suffix=example.ts.net,auth-key-env=WORK_AUTHKEY")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "work" || got.Alias != "work" {
		t.Fatalf("profile identity = id %q alias %q, want work/work", got.ID, got.Alias)
	}
	if got.Dir != "/tmp/work" || got.Hostname != "mnet-work" {
		t.Fatalf("profile storage = dir %q hostname %q", got.Dir, got.Hostname)
	}
	if got.MagicDNSSuffix != "example.ts.net" || got.AuthKeyEnv != "WORK_AUTHKEY" {
		t.Fatalf("profile routing/login config = suffix %q auth env %q", got.MagicDNSSuffix, got.AuthKeyEnv)
	}
}

func TestResolveProfilesMergesFlagsWithPersistentState(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	got, err := resolveProfiles(state.State{
		Profiles: []state.Profile{{
			ID:             "work",
			Alias:          "old",
			StateDir:       "/var/lib/mnet/work",
			Hostname:       "mnet-old",
			MagicDNSSuffix: "old.ts.net",
		}},
	}, []profileSpec{{
		ID:             "work",
		Alias:          "work",
		MagicDNSSuffix: "new.ts.net",
		AuthKeyEnv:     "WORK_AUTHKEY",
	}, {
		ID: "home",
	}}, statePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("profile count = %d, want 2", len(got))
	}
	work := got[1]
	if got[0].State.ID == "work" {
		work = got[0]
	}
	if work.State.Alias != "work" || work.State.StateDir != "/var/lib/mnet/work" || work.State.Hostname != "mnet-old" {
		t.Fatalf("merged work profile = %+v", work.State)
	}
	if work.State.MagicDNSSuffix != "new.ts.net" || work.AuthKeyEnv != "WORK_AUTHKEY" {
		t.Fatalf("work routing/login config = %+v auth=%q", work.State, work.AuthKeyEnv)
	}
	home := got[0]
	if home.State.ID != "home" {
		home = got[1]
	}
	if home.State.Alias != "home" || home.State.StateDir == "" || home.State.Hostname != "mnet-home" {
		t.Fatalf("defaulted home profile = %+v", home.State)
	}
}

func TestLeaseNodesIncludesSelfAndPeersInStableOrder(t *testing.T) {
	statuses := []mnetprofile.Status{{
		ProfileID:  "work",
		SelfNodeID: "self",
		SelfIPs:    []netip.Addr{netip.MustParseAddr("100.64.0.10")},
		Peers: []mnetprofile.PeerStatus{{
			NodeID:       "peer-b",
			TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.2")},
		}, {
			NodeID:       "peer-a",
			TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
		}},
	}}
	got := leaseNodes(statuses)
	want := []effectiveip.Node{
		{ProfileID: "work", NodeID: "peer-a", CanonicalIP: netip.MustParseAddr("100.64.0.1")},
		{ProfileID: "work", NodeID: "peer-b", CanonicalIP: netip.MustParseAddr("100.64.0.2")},
		{ProfileID: "work", NodeID: "self", CanonicalIP: netip.MustParseAddr("100.64.0.10")},
	}
	if len(got) != len(want) {
		t.Fatalf("node count = %d, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("node[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestLeasesRoundTripThroughStateShape(t *testing.T) {
	lease := effectiveip.Lease{
		NodeKey: effectiveip.NodeKey{
			ProfileID:   "work",
			NodeID:      "node",
			CanonicalIP: netip.MustParseAddr("100.64.0.1"),
		},
		EffectiveIP: netip.MustParseAddr("100.127.0.1"),
	}
	got := leasesFromState(leasesToState([]effectiveip.Lease{lease}))
	if len(got) != 1 || got[0] != lease {
		t.Fatalf("lease round trip = %+v, want %+v", got, lease)
	}
}
