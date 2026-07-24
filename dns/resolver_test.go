package dns

import (
	"net/netip"
	"testing"
)

func TestResolverRejectsUnqualifiedNames(t *testing.T) {
	r := NewResolver([]Record{{ProfileID: "work", Name: "db.work.ts.net", EffectiveIP: netip.MustParseAddr("100.127.0.1")}})
	if _, err := r.Resolve("db"); err == nil {
		t.Fatal("expected unqualified name to fail")
	}
}

func TestResolverReturnsEffectiveIPForQualifiedName(t *testing.T) {
	want := netip.MustParseAddr("100.127.0.1")
	r := NewResolver([]Record{{ProfileID: "work", Name: "db.work.ts.net", EffectiveIP: want}})
	got, err := r.Resolve("db.work.ts.net")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("Resolve returned %v, want %v", got, want)
	}
}
