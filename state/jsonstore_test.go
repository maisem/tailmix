package state

import (
	"net/netip"
	"os"
	"path/filepath"
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
