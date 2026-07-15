package main

import (
	"net/netip"
	"path/filepath"
	"testing"

	tailmixdns "github.com/maisem/tailmix/dns"
	"github.com/maisem/tailmix/effectiveip"
	"github.com/maisem/tailmix/packetmap"
	tailmixprofile "github.com/maisem/tailmix/profile"
	"github.com/maisem/tailmix/state"
)

func TestParseProfileSpecUsesMagicDNSSuffixAndAuthKeyEnv(t *testing.T) {
	got, err := parseProfileSpec("id=work,dir=/tmp/work,hostname=tailmix-work,suffix=example.ts.net,auth-key-env=WORK_AUTHKEY")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "work" || got.Alias != "work" {
		t.Fatalf("profile identity = id %q alias %q, want work/work", got.ID, got.Alias)
	}
	if got.Dir != "/tmp/work" || got.Hostname != "tailmix-work" {
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
			StateDir:       "/var/lib/tailmix/work",
			Hostname:       "tailmix-old",
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
	if work.State.Alias != "work" || work.State.StateDir != "/var/lib/tailmix/work" || work.State.Hostname != "tailmix-old" {
		t.Fatalf("merged work profile = %+v", work.State)
	}
	if work.State.MagicDNSSuffix != "new.ts.net" || work.AuthKeyEnv != "WORK_AUTHKEY" {
		t.Fatalf("work routing/login config = %+v auth=%q", work.State, work.AuthKeyEnv)
	}
	home := got[0]
	if home.State.ID != "home" {
		home = got[1]
	}
	if home.State.Alias != "home" || home.State.StateDir == "" || home.State.Hostname != "tailmix-home" {
		t.Fatalf("defaulted home profile = %+v", home.State)
	}
}

func TestConfigureSyntheticPoolsUsesPersistedValuesAndDefaults(t *testing.T) {
	st := state.State{SyntheticPool: "10.42.1.7/16"}
	if err := configureSyntheticPools(&st, "", ""); err != nil {
		t.Fatal(err)
	}
	if st.SyntheticPool != "10.42.0.0/16" {
		t.Fatalf("IPv4 pool = %q, want normalized persisted pool", st.SyntheticPool)
	}
	if st.SyntheticPoolV6 != defaultSyntheticPoolV6 {
		t.Fatalf("IPv6 pool = %q, want default %q", st.SyntheticPoolV6, defaultSyntheticPoolV6)
	}
}

func TestConfigureSyntheticPoolsOverrideDiscardsOnlyChangedFamilySyntheticLeases(t *testing.T) {
	canonicalV4 := state.EffectiveLease{
		ProfileID:   "work",
		NodeID:      "unique-v4",
		CanonicalIP: netip.MustParseAddr("100.64.0.1"),
		EffectiveIP: netip.MustParseAddr("100.64.0.1"),
	}
	syntheticV4 := state.EffectiveLease{
		ProfileID:   "home",
		NodeID:      "colliding-v4",
		CanonicalIP: netip.MustParseAddr("100.64.0.1"),
		EffectiveIP: netip.MustParseAddr("100.127.0.1"),
	}
	syntheticV6 := state.EffectiveLease{
		ProfileID:   "home",
		NodeID:      "colliding-v6",
		CanonicalIP: netip.MustParseAddr("fd7a:115c:a1e0::1"),
		EffectiveIP: netip.MustParseAddr("fd6d:6e65:7400::1"),
	}
	st := state.State{
		SyntheticPool:   defaultSyntheticPool,
		SyntheticPoolV6: defaultSyntheticPoolV6,
		Leases:          []state.EffectiveLease{canonicalV4, syntheticV4, syntheticV6},
	}
	if err := configureSyntheticPools(&st, "10.250.1.9/16", ""); err != nil {
		t.Fatal(err)
	}
	if st.SyntheticPool != "10.250.0.0/16" {
		t.Fatalf("IPv4 pool = %q, want 10.250.0.0/16", st.SyntheticPool)
	}
	if len(st.Leases) != 2 || st.Leases[0] != canonicalV4 || st.Leases[1] != syntheticV6 {
		t.Fatalf("leases after IPv4 pool change = %+v, want canonical IPv4 and synthetic IPv6", st.Leases)
	}
}

func TestConfigureSyntheticPoolsRejectsInvalidOverrides(t *testing.T) {
	for _, test := range []struct {
		name string
		ipv4 string
		ipv6 string
	}{
		{name: "invalid", ipv4: "not-a-prefix"},
		{name: "wrong-family-v4", ipv4: "fd00::/64"},
		{name: "wrong-family-v6", ipv6: "10.0.0.0/8"},
		{name: "non-unicast", ipv4: "224.0.0.0/24"},
		{name: "magic-dns-overlap", ipv4: "100.64.0.0/10"},
	} {
		t.Run(test.name, func(t *testing.T) {
			st := state.State{}
			if err := configureSyntheticPools(&st, test.ipv4, test.ipv6); err == nil {
				t.Fatalf("configureSyntheticPools(%q, %q) succeeded", test.ipv4, test.ipv6)
			}
		})
	}
}

func TestLeaseNodesIncludesSelfAndPeersInStableOrder(t *testing.T) {
	statuses := []tailmixprofile.Status{{
		ProfileID:  "work",
		SelfNodeID: "self",
		SelfIPs:    []netip.Addr{netip.MustParseAddr("100.64.0.10")},
		Peers: []tailmixprofile.PeerStatus{{
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

func TestAssignEffectiveIPsPreservesDormantLeases(t *testing.T) {
	dormant := state.EffectiveLease{
		ProfileID:   "work",
		NodeID:      "offline-peer",
		CanonicalIP: netip.MustParseAddr("100.64.0.20"),
		EffectiveIP: netip.MustParseAddr("100.127.0.20"),
	}
	st := state.State{
		SyntheticPool:   "100.127.0.0/24",
		SyntheticPoolV6: "fd6d:6e65:7400::/120",
		Leases:          []state.EffectiveLease{dormant},
	}
	statuses := []tailmixprofile.Status{{
		ProfileID:  "work",
		SelfNodeID: "self",
		SelfIPs:    []netip.Addr{netip.MustParseAddr("100.64.0.10")},
	}}
	active, all, err := assignEffectiveIPs(st, statuses)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 {
		t.Fatalf("active leases = %d, want 1", len(active))
	}
	wantDormant := leasesFromState([]state.EffectiveLease{dormant})[0]
	found := false
	for _, lease := range all {
		if lease == wantDormant {
			found = true
		}
	}
	if !found {
		t.Fatalf("dormant lease was discarded: %+v", all)
	}
}

func TestAssignEffectiveIPsSynthesizesIPv6CollisionsFromIPv6Pool(t *testing.T) {
	canonical := netip.MustParseAddr("fd7a:115c:a1e0::10")
	statuses := []tailmixprofile.Status{{
		ProfileID:  "home",
		SelfNodeID: "home-self",
		SelfIPs:    []netip.Addr{canonical},
	}, {
		ProfileID:  "work",
		SelfNodeID: "work-self",
		SelfIPs:    []netip.Addr{canonical},
	}}
	active, _, err := assignEffectiveIPs(state.State{
		SyntheticPool:   "100.127.0.0/24",
		SyntheticPoolV6: "fd6d:6e65:7400::/120",
	}, statuses)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 2 || !active[0].EffectiveIP.Is6() || !active[1].EffectiveIP.Is6() || active[0].EffectiveIP == active[1].EffectiveIP {
		t.Fatalf("IPv6 collision leases = %+v", active)
	}
}

func TestTunConfigBuildsPerProfileSourceSelectedRoutes(t *testing.T) {
	canonicalSelf := netip.MustParseAddr("100.64.0.10")
	canonicalPeer := netip.MustParseAddr("100.64.0.20")
	statuses := []tailmixprofile.Status{{
		ProfileID:  "home",
		SelfNodeID: "home-self",
		SelfIPs:    []netip.Addr{canonicalSelf},
		Peers: []tailmixprofile.PeerStatus{{
			NodeID:       "home-peer",
			TailscaleIPs: []netip.Addr{canonicalPeer},
		}},
	}, {
		ProfileID:  "work",
		SelfNodeID: "work-self",
		SelfIPs:    []netip.Addr{canonicalSelf},
		Peers: []tailmixprofile.PeerStatus{{
			NodeID:       "work-peer",
			TailscaleIPs: []netip.Addr{canonicalPeer},
		}},
	}}
	leases, _, err := assignEffectiveIPs(state.State{
		SyntheticPool:   "100.127.0.0/24",
		SyntheticPoolV6: "fd6d:6e65:7400::/120",
	}, statuses)
	if err != nil {
		t.Fatal(err)
	}
	table, hostCfg, err := tunConfig(statuses, leases)
	if err != nil {
		t.Fatal(err)
	}
	if len(table.Sources) != 2 || len(table.Destinations) != 2 || len(hostCfg.LocalAddrs) != 3 || len(hostCfg.Routes) != 2 {
		t.Fatalf("TUN config sizes: sources=%d destinations=%d local=%d routes=%d", len(table.Sources), len(table.Destinations), len(hostCfg.LocalAddrs), len(hostCfg.Routes))
	}
	foundDNSServiceIP := false
	for _, prefix := range hostCfg.LocalAddrs {
		if prefix.Addr() == tailmixdns.ServiceIP() {
			foundDNSServiceIP = true
		}
	}
	if !foundDNSServiceIP {
		t.Fatalf("local TUN addresses %v do not include MagicDNS service IP %v", hostCfg.LocalAddrs, tailmixdns.ServiceIP())
	}
	for _, route := range hostCfg.Routes {
		if route.Source == route.Destination.Addr() {
			t.Fatalf("peer route unexpectedly uses peer address as source: %+v", route)
		}
		if source := table.Sources[packetmap.SourceKey{ProfileID: table.Destinations[route.Destination.Addr()].ProfileID}]; source.EffectiveIP != route.Source {
			t.Fatalf("route %+v does not use profile source %+v", route, source)
		}
	}
}

func TestTunDNSConfigUsesEffectiveAddresses(t *testing.T) {
	canonicalSelf := netip.MustParseAddr("100.64.0.10")
	canonicalPeer := netip.MustParseAddr("100.64.0.20")
	statuses := []tailmixprofile.Status{{
		ProfileID:      "home",
		MagicDNSSuffix: "home.ts.net",
		SelfNodeID:     "home-self",
		SelfDNSName:    "tailmix.home.ts.net",
		SelfIPs:        []netip.Addr{canonicalSelf},
		Peers: []tailmixprofile.PeerStatus{{
			NodeID:       "home-peer",
			DNSName:      "db.home.ts.net",
			TailscaleIPs: []netip.Addr{canonicalPeer},
		}},
	}, {
		ProfileID:      "work",
		MagicDNSSuffix: "work.ts.net",
		SelfNodeID:     "work-self",
		SelfDNSName:    "tailmix.work.ts.net",
		SelfIPs:        []netip.Addr{canonicalSelf},
		Peers: []tailmixprofile.PeerStatus{{
			NodeID:       "work-peer",
			DNSName:      "db.work.ts.net",
			TailscaleIPs: []netip.Addr{canonicalPeer},
		}},
	}}
	leases, _, err := assignEffectiveIPs(state.State{
		SyntheticPool:   "100.127.0.0/24",
		SyntheticPoolV6: "fd6d:6e65:7400::/120",
	}, statuses)
	if err != nil {
		t.Fatal(err)
	}
	domains, records, err := tunDNSConfig(statuses, leases)
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 2 || len(records) != 4 {
		t.Fatalf("MagicDNS config has domains=%v records=%v", domains, records)
	}
	wantByName := map[string]netip.Addr{}
	for _, lease := range leases {
		switch lease.NodeKey.NodeID {
		case "home-peer":
			wantByName["db.home.ts.net"] = lease.EffectiveIP
		case "work-peer":
			wantByName["db.work.ts.net"] = lease.EffectiveIP
		}
	}
	for _, record := range records {
		want, ok := wantByName[record.Name]
		if !ok {
			continue
		}
		if record.EffectiveIP != want {
			t.Fatalf("record %q = %v, want effective IP %v", record.Name, record.EffectiveIP, want)
		}
		if record.EffectiveIP == canonicalPeer {
			t.Fatalf("record %q unexpectedly uses colliding canonical IP %v", record.Name, canonicalPeer)
		}
		delete(wantByName, record.Name)
	}
	if len(wantByName) != 0 {
		t.Fatalf("missing peer MagicDNS records: %v", wantByName)
	}
}
