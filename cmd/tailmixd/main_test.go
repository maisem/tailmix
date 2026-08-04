package main

import (
	"bytes"
	"context"
	"flag"
	"net/netip"
	"path/filepath"
	"testing"

	tailmixdns "github.com/maisem/tailmix/dns"
	"github.com/maisem/tailmix/effectiveip"
	tailmixprofile "github.com/maisem/tailmix/profile"
	"github.com/maisem/tailmix/state"
	tailmixversion "github.com/maisem/tailmix/version"
	"tailscale.com/types/dnstype"
)

func TestVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"--version"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	want := tailmixversion.GetMeta().Format("tailmixd") + "\n"
	if got := stdout.String(); got != want {
		t.Fatalf("version output = %q, want %q", got, want)
	}
	if got := stderr.String(); got != "" {
		t.Fatalf("version stderr = %q, want empty", got)
	}
}

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

func TestParseProfileSpecRejectsLegacyControlURL(t *testing.T) {
	if _, err := parseProfileSpec("id=work,control-url=https://headscale.example.com"); err == nil {
		t.Fatal("legacy control-url field unexpectedly accepted")
	}
}

func TestRegisterProfileFlagsAcceptsLongAndShortOptions(t *testing.T) {
	var profiles profileFlag
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	registerProfileFlags(fs, &profiles)
	if err := fs.Parse([]string{"--profile", "id=work", "-p", "id=home"}); err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 2 || profiles[0].ID != "work" || profiles[1].ID != "home" {
		t.Fatalf("profiles = %+v", profiles)
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

func TestConfigureSyntheticPoolsOverrideDiscardsChangedFamilyLeasesAndNAT(t *testing.T) {
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
		NATIP:           netip.MustParseAddr("100.127.0.2"),
		NATIPv6:         netip.MustParseAddr("fd6d:6e65:7400::2"),
		Leases:          []state.EffectiveLease{canonicalV4, syntheticV4, syntheticV6},
	}
	if err := configureSyntheticPools(&st, "10.250.1.9/16", ""); err != nil {
		t.Fatal(err)
	}
	if st.SyntheticPool != "10.250.0.0/16" {
		t.Fatalf("IPv4 pool = %q, want 10.250.0.0/16", st.SyntheticPool)
	}
	if len(st.Leases) != 1 || st.Leases[0] != syntheticV6 {
		t.Fatalf("leases after IPv4 pool change = %+v, want only IPv6 lease", st.Leases)
	}
	if st.NATIP.IsValid() || st.NATIPv6 != netip.MustParseAddr("fd6d:6e65:7400::2") {
		t.Fatalf("NAT addresses after IPv4 pool change = %v, %v", st.NATIP, st.NATIPv6)
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

func TestEnsureNATIPsSkipsAndMigratesPrefixBase(t *testing.T) {
	st := state.State{
		SyntheticPool:   "10.250.0.0/29",
		SyntheticPoolV6: "fd6d:6e65:7400::/125",
		NATIP:           netip.MustParseAddr("10.250.0.0"),
		NATIPv6:         netip.MustParseAddr("fd6d:6e65:7400::"),
		Leases: []state.EffectiveLease{{
			ProfileID:   "work",
			NodeID:      "peer-v4",
			CanonicalIP: netip.MustParseAddr("100.64.0.2"),
			EffectiveIP: netip.MustParseAddr("10.250.0.1"),
		}, {
			ProfileID:   "work",
			NodeID:      "peer-v6",
			CanonicalIP: netip.MustParseAddr("fd7a:115c:a1e0::2"),
			EffectiveIP: netip.MustParseAddr("fd6d:6e65:7400::1"),
		}},
	}

	if err := ensureNATIPs(&st); err != nil {
		t.Fatal(err)
	}
	if want := netip.MustParseAddr("10.250.0.2"); st.NATIP != want {
		t.Fatalf("migrated IPv4 NAT address = %v, want %v", st.NATIP, want)
	}
	if want := netip.MustParseAddr("fd6d:6e65:7400::2"); st.NATIPv6 != want {
		t.Fatalf("migrated IPv6 NAT address = %v, want %v", st.NATIPv6, want)
	}
}

func TestLeaseTargetsIncludesPeersAndServicesInStableOrder(t *testing.T) {
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
		Services: []tailmixprofile.ServiceStatus{{
			Name:         "svc:api",
			TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.100.0.1")},
		}},
	}}
	got := leaseTargets(statuses)
	want := []effectiveip.Node{
		{ProfileID: "work", NodeID: "peer-a", CanonicalIP: netip.MustParseAddr("100.64.0.1")},
		{ProfileID: "work", NodeID: "peer-b", CanonicalIP: netip.MustParseAddr("100.64.0.2")},
		{ProfileID: "work", NodeID: "svc:api", CanonicalIP: netip.MustParseAddr("100.100.0.1")},
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
	if len(active) != 0 {
		t.Fatalf("active leases = %d, want none without peers", len(active))
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
		SelfIPs:    []netip.Addr{netip.MustParseAddr("fd7a:115c:a1e0::1")},
		Peers: []tailmixprofile.PeerStatus{{
			NodeID: "home-peer", TailscaleIPs: []netip.Addr{canonical},
		}},
	}, {
		ProfileID:  "work",
		SelfNodeID: "work-self",
		SelfIPs:    []netip.Addr{netip.MustParseAddr("fd7a:115c:a1e0::2")},
		Peers: []tailmixprofile.PeerStatus{{
			NodeID: "work-peer", TailscaleIPs: []netip.Addr{canonical},
		}},
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

func TestTunConfigUsesSharedNATRouteSource(t *testing.T) {
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
	st := state.State{
		SyntheticPool:   "100.127.0.0/24",
		SyntheticPoolV6: "fd6d:6e65:7400::/120",
	}
	if err := ensureNATIPs(&st); err != nil {
		t.Fatal(err)
	}
	leases, _, err := assignEffectiveIPs(st, statuses)
	if err != nil {
		t.Fatal(err)
	}
	table, hostCfg, err := tunConfig(st, statuses, leases)
	if err != nil {
		t.Fatal(err)
	}
	if len(table.Sources) != 2 || table.Destinations.Size() != 2 || len(hostCfg.LocalAddrs) != 1 || len(hostCfg.Routes) != 3 {
		t.Fatalf("TUN config sizes: sources=%d destinations=%d local=%d routes=%d", len(table.Sources), table.Destinations.Size(), len(hostCfg.LocalAddrs), len(hostCfg.Routes))
	}
	if hostCfg.LocalAddrs[0].Addr() != st.NATIP {
		t.Fatalf("local TUN addresses = %v, want only NAT IP %v", hostCfg.LocalAddrs, st.NATIP)
	}
	foundDNSRoute := false
	for _, route := range hostCfg.Routes {
		if route.Destination.Addr() == tailmixdns.ServiceIP() {
			foundDNSRoute = true
		}
	}
	if !foundDNSRoute {
		t.Fatalf("host routes %v do not route MagicDNS through the TUN", hostCfg.Routes)
	}
	for _, route := range hostCfg.Routes {
		if route.Source != st.NATIP {
			t.Fatalf("host route %+v does not select shared NAT source %v", route, st.NATIP)
		}
	}
	for key, source := range table.Sources {
		if source.HostIP != st.NATIP || source.CanonicalIP != canonicalSelf {
			t.Fatalf("profile source %v = %+v, want host NAT %v and canonical %v", key, source, st.NATIP, canonicalSelf)
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
	st := state.State{
		SyntheticPool:   "100.127.0.0/24",
		SyntheticPoolV6: "fd6d:6e65:7400::/120",
	}
	if err := ensureNATIPs(&st); err != nil {
		t.Fatal(err)
	}
	leases, _, err := assignEffectiveIPs(st, statuses)
	if err != nil {
		t.Fatal(err)
	}
	domains, records, err := tunDNSConfig(st, statuses, leases)
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
	if !hasDNSRecord(records, "tailmix.home.ts.net", st.NATIP) || !hasDNSRecord(records, "tailmix.work.ts.net", st.NATIP) {
		t.Fatalf("self MagicDNS records do not point at shared NAT IP %v: %v", st.NATIP, records)
	}
}

func TestTUNPlanTreatsServicesLikeNodesAcrossProfiles(t *testing.T) {
	canonicalV4 := netip.MustParseAddr("100.100.1.10")
	canonicalV6 := netip.MustParseAddr("fd7a:115c:a1e0::110")
	statuses := []tailmixprofile.Status{
		{
			ProfileID:      "home",
			MagicDNSSuffix: "home.ts.net",
			SelfNodeID:     "home-self",
			SelfIPs: []netip.Addr{
				netip.MustParseAddr("100.64.0.1"),
				netip.MustParseAddr("fd7a:115c:a1e0::1"),
			},
			Services: []tailmixprofile.ServiceStatus{{
				Name:         "svc:api",
				DNSName:      "api.home.ts.net",
				TailscaleIPs: []netip.Addr{canonicalV4, canonicalV6},
			}},
		},
		{
			ProfileID:      "work",
			MagicDNSSuffix: "work.ts.net",
			SelfNodeID:     "work-self",
			SelfIPs: []netip.Addr{
				netip.MustParseAddr("100.64.0.2"),
				netip.MustParseAddr("fd7a:115c:a1e0::2"),
			},
			Services: []tailmixprofile.ServiceStatus{{
				Name:         "svc:api",
				DNSName:      "api.work.ts.net",
				TailscaleIPs: []netip.Addr{canonicalV4, canonicalV6},
			}},
		},
	}
	plan, err := buildTUNPlan(state.State{
		SyntheticPool:   "10.250.0.0/24",
		SyntheticPoolV6: "fd6d:6e65:7400::/120",
	}, statuses)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.ActiveLeases) != 4 || plan.Table.Destinations.Size() != 4 {
		t.Fatalf("service plan = leases %v destinations %v", plan.ActiveLeases, plan.Table.Destinations)
	}

	effective := map[string]map[netip.Addr]netip.Addr{}
	for _, lease := range plan.ActiveLeases {
		if lease.NodeKey.NodeID != "svc:api" {
			t.Fatalf("service lease has identity %q, want svc:api", lease.NodeKey.NodeID)
		}
		if effective[lease.NodeKey.ProfileID] == nil {
			effective[lease.NodeKey.ProfileID] = map[netip.Addr]netip.Addr{}
		}
		effective[lease.NodeKey.ProfileID][lease.NodeKey.CanonicalIP] = lease.EffectiveIP
	}
	for _, canonical := range []netip.Addr{canonicalV4, canonicalV6} {
		homeIP := effective["home"][canonical]
		workIP := effective["work"][canonical]
		if !homeIP.IsValid() || !workIP.IsValid() || homeIP == workIP {
			t.Fatalf("colliding service IP %v mapped to home=%v work=%v", canonical, homeIP, workIP)
		}
		if !hasDNSRecord(plan.Records, "api.home.ts.net", homeIP) ||
			!hasDNSRecord(plan.Records, "api.work.ts.net", workIP) {
			t.Fatalf("service DNS records = %v, want profile-specific effective addresses", plan.Records)
		}
		for profileID, want := range map[string]netip.Addr{"home": homeIP, "work": workIP} {
			inbound := plan.Table.InboundPeers[profileID]
			got, ok := inbound.Get(netip.PrefixFrom(canonical, canonical.BitLen()))
			if !ok || got != want {
				t.Fatalf("%s inbound service mapping for %v = %v, %v; want %v", profileID, canonical, got, ok, want)
			}
		}
	}

	withoutServices := append([]tailmixprofile.Status(nil), statuses...)
	for i := range withoutServices {
		withoutServices[i].Services = nil
	}
	removed, err := buildTUNPlan(plan.State, withoutServices)
	if err != nil {
		t.Fatal(err)
	}
	if removed.Table.Destinations.Size() != 0 ||
		hasDNSRecord(removed.Records, "api.home.ts.net", effective["home"][canonicalV4]) ||
		hasDNSRecord(removed.Records, "api.work.ts.net", effective["work"][canonicalV4]) {
		t.Fatalf("service remained active after removal: destinations=%v records=%v", removed.Table.Destinations, removed.Records)
	}
	if len(removed.State.Leases) != 4 {
		t.Fatalf("removed service leases were not retained: %v", removed.State.Leases)
	}
	restored, err := buildTUNPlan(removed.State, statuses)
	if err != nil {
		t.Fatal(err)
	}
	for _, lease := range restored.ActiveLeases {
		want := effective[lease.NodeKey.ProfileID][lease.NodeKey.CanonicalIP]
		if lease.EffectiveIP != want {
			t.Fatalf("restored service lease %+v changed from %v", lease, want)
		}
	}
}

func TestTUNPlanKeepsMagicDNSMoreSpecificThanExplicitDefault(t *testing.T) {
	st := state.State{
		SyntheticPool:   "10.250.0.0/16",
		SyntheticPoolV6: "fd6d:6e65:7400::/120",
		Profiles: []state.Profile{
			{ID: "home", Name: "home"},
			{ID: "work", Name: "work"},
		},
		DNSRouteBindings: []state.DNSRouteBinding{{
			Domain: ".", ProfileID: "work",
		}},
	}
	statuses := []tailmixprofile.Status{
		{
			ProfileID:      "home",
			BackendState:   "Running",
			MagicDNSSuffix: "home.example",
			SelfNodeID:     "home-self",
			SelfDNSName:    "tailmix-home.home.example",
			SelfIPs:        []netip.Addr{netip.MustParseAddr("100.64.0.1")},
		},
		{
			ProfileID:    "work",
			BackendState: "Running",
			DNSRoutes: []tailmixprofile.DNSRouteStatus{{
				Domain: ".", Source: "default", Resolvers: []*dnstype.Resolver{{Addr: "9.9.9.9"}},
			}},
		},
	}

	plan, err := buildTUNPlan(st, statuses)
	if err != nil {
		t.Fatal(err)
	}
	if !hasDNSRecord(plan.Records, "tailmix-home.home.example", plan.State.NATIP) {
		t.Fatalf("MagicDNS record was dropped by the default route: %v", plan.Records)
	}
	if len(plan.DNSConfig.Routes) != 2 ||
		plan.DNSConfig.Routes[0].Suffix != "." ||
		plan.DNSConfig.Routes[1].Suffix != "home.example" {
		t.Fatalf("DNS routes = %+v, want default plus MagicDNS", plan.DNSConfig.Routes)
	}
}

func TestTUNPlanTracksPeerAddAndRemoveAcrossNetmapUpdates(t *testing.T) {
	baseState := state.State{
		SyntheticPool:   "10.250.0.0/16",
		SyntheticPoolV6: "fd6d:6e65:7400::/120",
		Profiles:        []state.Profile{{ID: "home", Alias: "home"}},
		Leases: []state.EffectiveLease{{
			ProfileID:   "home",
			NodeID:      "peer-node",
			CanonicalIP: netip.MustParseAddr("100.64.0.2"),
			EffectiveIP: netip.MustParseAddr("100.64.0.2"),
		}, {
			ProfileID:   "home",
			NodeID:      "peer-node",
			CanonicalIP: netip.MustParseAddr("fd7a:115c:a1e0::2"),
			EffectiveIP: netip.MustParseAddr("fd7a:115c:a1e0::2"),
		}},
	}
	baseStatus := tailmixprofile.Status{
		ProfileID:      "home",
		MagicDNSSuffix: "home.example",
		SelfNodeID:     "home-self",
		SelfDNSName:    "tailmix-home.home.example",
		SelfIPs: []netip.Addr{
			netip.MustParseAddr("100.64.0.1"),
			netip.MustParseAddr("fd7a:115c:a1e0::1"),
		},
	}

	initial, err := buildTUNPlan(baseState, []tailmixprofile.Status{baseStatus})
	if err != nil {
		t.Fatal(err)
	}
	if initial.Table.Destinations.Size() != 0 || len(initial.HostConfig.Routes) != 1 {
		t.Fatalf("initial config = destinations %v routes %v, want only MagicDNS route", initial.Table.Destinations, initial.HostConfig.Routes)
	}

	withPeer := baseStatus
	withPeer.Peers = []tailmixprofile.PeerStatus{{
		NodeID:  "peer-node",
		DNSName: "peer.home.example",
		TailscaleIPs: []netip.Addr{
			netip.MustParseAddr("100.64.0.2"),
			netip.MustParseAddr("fd7a:115c:a1e0::2"),
		},
	}}
	added, err := buildTUNPlan(initial.State, []tailmixprofile.Status{withPeer})
	if err != nil {
		t.Fatal(err)
	}
	if added.Table.Destinations.Size() != 2 || len(added.HostConfig.Routes) != 3 {
		t.Fatalf("config after add = destinations %v routes %v, want peer plus MagicDNS", added.Table.Destinations, added.HostConfig.Routes)
	}
	effectiveByCanonical := map[netip.Addr]netip.Addr{}
	for prefix, destination := range added.Table.Destinations.All() {
		if destination.ProfileID == "home" {
			effectiveByCanonical[destination.CanonicalIP] = prefix.Addr()
		}
	}
	canonicalV4 := netip.MustParseAddr("100.64.0.2")
	canonicalV6 := netip.MustParseAddr("fd7a:115c:a1e0::2")
	peerV4 := effectiveByCanonical[canonicalV4]
	peerV6 := effectiveByCanonical[canonicalV6]
	if !netip.MustParsePrefix("10.250.0.0/16").Contains(peerV4) || peerV4 == canonicalV4 {
		t.Fatalf("peer IPv4 effective IP = %v, want address from configured pool", peerV4)
	}
	if !netip.MustParsePrefix("fd6d:6e65:7400::/120").Contains(peerV6) || peerV6 == canonicalV6 {
		t.Fatalf("peer IPv6 effective IP = %v, want address from configured pool", peerV6)
	}
	if !hasDNSRecord(added.Records, "peer.home.example", peerV4) || !hasDNSRecord(added.Records, "peer.home.example", peerV6) {
		t.Fatalf("MagicDNS records after add = %v, want peer -> [%v, %v]", added.Records, peerV4, peerV6)
	}

	removed, err := buildTUNPlan(added.State, []tailmixprofile.Status{baseStatus})
	if err != nil {
		t.Fatal(err)
	}
	if removed.Table.Destinations.Size() != 0 || len(removed.HostConfig.Routes) != 1 || hasDNSRecord(removed.Records, "peer.home.example", peerV4) || hasDNSRecord(removed.Records, "peer.home.example", peerV6) {
		t.Fatalf("peer remained active after removal: routes=%v records=%v", removed.HostConfig.Routes, removed.Records)
	}
	foundDormantLeases := 0
	for _, lease := range removed.State.Leases {
		if lease.ProfileID == "home" && lease.NodeID == "peer-node" && (lease.EffectiveIP == peerV4 || lease.EffectiveIP == peerV6) {
			foundDormantLeases++
		}
	}
	if foundDormantLeases != 2 {
		t.Fatalf("peer lease was not preserved for stable reuse: %v", removed.State.Leases)
	}
}

func TestTUNPlanInstallsSelectedExitNodeDefaults(t *testing.T) {
	st := state.State{
		SyntheticPool:   "10.250.0.0/16",
		SyntheticPoolV6: "fd6d:6e65:7400::/120",
		Profiles:        []state.Profile{{ID: "work", Name: "work"}},
		ExitNode: &state.ExitNode{
			ProfileID: "work",
			NodeID:    "exit-node",
			PeerIP:    netip.MustParseAddr("100.64.0.20"),
		},
	}
	status := tailmixprofile.Status{
		ProfileID:    "work",
		BackendState: "Running",
		ExitNodeID:   "exit-node",
		SelfNodeID:   "self",
		SelfIPs: []netip.Addr{
			netip.MustParseAddr("100.64.0.10"),
			netip.MustParseAddr("fd7a:115c:a1e0::10"),
		},
	}
	plan, err := buildTUNPlan(st, []tailmixprofile.Status{status})
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/1"),
		netip.MustParsePrefix("128.0.0.0/1"),
		netip.MustParsePrefix("::/1"),
		netip.MustParsePrefix("8000::/1"),
	} {
		found := false
		for _, route := range plan.HostConfig.Routes {
			if route.Destination != prefix {
				continue
			}
			found = true
			if want := natIPFor(plan.State, prefix.Addr()); route.Source != want {
				t.Fatalf("exit route %v source = %v, want shared NAT %v", prefix, route.Source, want)
			}
		}
		if !found {
			t.Fatalf("host routes %v do not contain exit route %v", plan.HostConfig.Routes, prefix)
		}
	}
	for _, ip := range []netip.Addr{
		netip.MustParseAddr("203.0.113.10"),
		netip.MustParseAddr("2001:db8::10"),
	} {
		route, ok := plan.Table.ExitRoutes.Lookup(ip)
		if !ok || !route.Active || route.ProfileID != "work" {
			t.Fatalf("exit route for %v = %+v, %v", ip, route, ok)
		}
	}
	if len(plan.DNSConfig.Routes) != 1 ||
		plan.DNSConfig.Routes[0].Suffix != "." ||
		plan.DNSConfig.Routes[0].ProfileID != "work" ||
		!plan.DNSConfig.Routes[0].ProfileDNS {
		t.Fatalf("exit-node DNS routes = %+v", plan.DNSConfig.Routes)
	}

	pending := status
	pending.ExitNodeID = ""
	plan, err = buildTUNPlan(st, []tailmixprofile.Status{pending})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Table.ExitRoutes.Size() != 0 {
		t.Fatalf("exit routes installed before profile preference applied: %+v", plan.Table.ExitRoutes)
	}
	for _, route := range plan.HostConfig.Routes {
		if route.Exit {
			t.Fatalf("host exit route installed before profile preference applied: %+v", route)
		}
	}
	if len(plan.DNSConfig.Routes) != 0 {
		t.Fatalf("exit-node DNS route installed before profile preference applied: %+v", plan.DNSConfig.Routes)
	}
}

func hasDNSRecord(records []tailmixdns.Record, name string, ip netip.Addr) bool {
	for _, record := range records {
		if record.Name == name && record.EffectiveIP == ip {
			return true
		}
	}
	return false
}
