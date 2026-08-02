package state

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStoreRoundTripPreservesEffectiveLeases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store := NewJSONStore(path)
	want := State{
		SyntheticPool: "100.127.0.0/24",
		NATIP:         netip.MustParseAddr("100.127.0.2"),
		Profiles:      []Profile{{ID: "work", Alias: "work", StateDir: "profiles/work"}},
		Leases: []EffectiveLease{{
			ProfileID:   "work",
			NodeID:      "node-a",
			CanonicalIP: netip.MustParseAddr("100.64.0.1"),
			EffectiveIP: netip.MustParseAddr("100.127.0.1"),
		}},
		ExitNode: &ExitNode{
			ProfileID: "work",
			NodeID:    "exit-node",
			PeerIP:    netip.MustParseAddr("100.64.0.20"),
		},
		Updates: UpdateState{AvailableVersion: "1.2.4", State: "available", LastChecked: "2026-08-02T00:00:00Z"},
	}
	if err := store.Save(want); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.Leases[0].EffectiveIP != want.Leases[0].EffectiveIP {
		t.Fatalf("effective IP did not round trip: got %v want %v", got.Leases[0].EffectiveIP, want.Leases[0].EffectiveIP)
	}
	if got.NATIP != want.NATIP {
		t.Fatalf("host NAT IP did not round trip: got %v want %v", got.NATIP, want.NATIP)
	}
	if got.ExitNode == nil || *got.ExitNode != *want.ExitNode {
		t.Fatalf("exit node did not round trip: got %+v want %+v", got.ExitNode, want.ExitNode)
	}
	if got.Updates != want.Updates {
		t.Fatalf("updates did not round trip: got %+v want %+v", got.Updates, want.Updates)
	}
}

func TestStoreMissingFileReturnsEmptyState(t *testing.T) {
	got, err := NewJSONStore(filepath.Join(t.TempDir(), "missing.json")).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Profiles) != 0 || len(got.Leases) != 0 {
		t.Fatalf("missing file returned non-empty state: %+v", got)
	}
}

func TestStoreCorruptFileFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewJSONStore(path).Load(); err == nil {
		t.Fatal("expected corrupt state to fail")
	}
}

func TestStoreDropsLegacyProfileControlURL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{
		"profiles":[{
			"id":"work",
			"stateDir":"profiles/work",
			"controlUrl":"https://headscale.example.com"
		}]
	}`), 0600); err != nil {
		t.Fatal(err)
	}
	store := NewJSONStore(path)
	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "controlUrl") {
		t.Fatalf("legacy controlUrl remained in state:\n%s", got)
	}
}

func TestNormalizeMigratesProfileNameAndDNSPolicy(t *testing.T) {
	st := State{
		Profiles: []Profile{{ID: "stable-id", Alias: "old-display-name"}},
		DNSRouteBindings: []DNSRouteBinding{
			{Domain: "_Service._TCP.Example.COM.", ProfileID: "stable-id"},
			{Domain: "bad..example.com", ProfileID: "stable-id"},
		},
		SearchDomains: []string{"Work.Example.COM.", "work.example.com", "."},
	}
	Normalize(&st)
	if got := st.Profiles[0].Name; got != "stable-id" {
		t.Fatalf("migrated name = %q, want stable ID", got)
	}
	if len(st.DNSRouteBindings) != 1 || st.DNSRouteBindings[0].Domain != "_service._tcp.example.com" {
		t.Fatalf("DNS bindings = %+v", st.DNSRouteBindings)
	}
	if len(st.SearchDomains) != 1 || st.SearchDomains[0] != "work.example.com" {
		t.Fatalf("search domains = %q", st.SearchDomains)
	}
}
