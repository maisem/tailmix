package socksproxy

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/maisem/tailmix/effectiveip"
)

type recordingDialer struct {
	network string
	addr    string
}

func (d *recordingDialer) Dial(_ context.Context, network, addr string) (net.Conn, error) {
	d.network = network
	d.addr = addr
	return nil, net.ErrClosed
}

func TestResolveRoutesMagicDNSFQDNBySuffix(t *testing.T) {
	d := &recordingDialer{}
	r, err := NewRouter([]Profile{{ID: "work", MagicDNSSuffix: "tail-scale.ts.net", Dialer: d}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Resolve("tcp", "db.tail-scale.ts.net:443")
	if err != nil {
		t.Fatal(err)
	}
	if got.ProfileID != "work" || got.DialAddr != "db.tail-scale.ts.net:443" {
		t.Fatalf("Resolve = %+v", got)
	}
}

func TestResolveUsesMostSpecificMagicDNSSuffix(t *testing.T) {
	r, err := NewRouter([]Profile{
		{ID: "broad", MagicDNSSuffix: "ts.net", Dialer: &recordingDialer{}},
		{ID: "specific", MagicDNSSuffix: "tail-scale.ts.net", Dialer: &recordingDialer{}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Resolve("tcp", "db.tail-scale.ts.net:443")
	if err != nil {
		t.Fatal(err)
	}
	if got.ProfileID != "specific" {
		t.Fatalf("Resolve profile = %q, want specific", got.ProfileID)
	}
}

func TestResolveRejectsShortNames(t *testing.T) {
	d := &recordingDialer{}
	r, err := NewRouter([]Profile{{ID: "work", MagicDNSSuffix: "tail-scale.ts.net", Dialer: d}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve("tcp", "db:443"); err == nil {
		t.Fatal("expected short name to fail")
	}
}

func TestResolveRejectsCanonicalIPLiteral(t *testing.T) {
	d := &recordingDialer{}
	r, err := NewRouter([]Profile{{ID: "work", MagicDNSSuffix: "tail-scale.ts.net", Dialer: d}}, []effectiveip.Lease{{
		NodeKey:     effectiveip.NodeKey{ProfileID: "work", NodeID: "node", CanonicalIP: netip.MustParseAddr("100.64.0.1")},
		EffectiveIP: netip.MustParseAddr("100.64.0.1"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve("tcp", "100.64.0.1:443"); err == nil {
		t.Fatal("expected canonical IP literal to fail")
	}
}

func TestResolveRoutesSyntheticEffectiveIPToCanonicalIP(t *testing.T) {
	d := &recordingDialer{}
	r, err := NewRouter([]Profile{{ID: "work", MagicDNSSuffix: "tail-scale.ts.net", Dialer: d}}, []effectiveip.Lease{{
		NodeKey:     effectiveip.NodeKey{ProfileID: "work", NodeID: "node", CanonicalIP: netip.MustParseAddr("100.64.0.1")},
		EffectiveIP: netip.MustParseAddr("100.127.0.1"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Resolve("tcp", "100.127.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	if got.ProfileID != "work" || got.DialAddr != "100.64.0.1:443" {
		t.Fatalf("Resolve = %+v", got)
	}
}

func TestNewRouterRejectsDuplicateSyntheticEffectiveIPLeases(t *testing.T) {
	d := &recordingDialer{}
	_, err := NewRouter([]Profile{
		{ID: "work", MagicDNSSuffix: "work.ts.net", Dialer: d},
		{ID: "home", MagicDNSSuffix: "home.ts.net", Dialer: d},
	}, []effectiveip.Lease{{
		NodeKey:     effectiveip.NodeKey{ProfileID: "work", NodeID: "node-a", CanonicalIP: netip.MustParseAddr("100.64.0.1")},
		EffectiveIP: netip.MustParseAddr("100.127.0.1"),
	}, {
		NodeKey:     effectiveip.NodeKey{ProfileID: "home", NodeID: "node-b", CanonicalIP: netip.MustParseAddr("100.64.0.2")},
		EffectiveIP: netip.MustParseAddr("100.127.0.1"),
	}})
	if err == nil {
		t.Fatal("expected duplicate effective IP lease to fail")
	}
}

func TestResolveRejectsUDP(t *testing.T) {
	d := &recordingDialer{}
	r, err := NewRouter([]Profile{{ID: "work", MagicDNSSuffix: "tail-scale.ts.net", Dialer: d}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve("udp", "db.tail-scale.ts.net:443"); err == nil {
		t.Fatal("expected UDP to fail")
	}
}

func TestExplicitDomainRouteOverridesImportedRoute(t *testing.T) {
	r, err := NewRouterWithPolicies([]Profile{
		{ID: "work", Dialer: &recordingDialer{}},
		{ID: "lab", Dialer: &recordingDialer{}},
	}, nil, nil, []DomainRoute{
		{Suffix: "corp.example", ProfileID: "work", Active: true},
		{Suffix: "dev.corp.example", ProfileID: "lab", Active: true, Exact: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Resolve("tcp", "db.dev.corp.example:443")
	if err != nil {
		t.Fatal(err)
	}
	if got.ProfileID != "lab" {
		t.Fatalf("Resolve profile = %q, want lab", got.ProfileID)
	}
	got, err = r.Resolve("tcp", "db.corp.example:443")
	if err != nil {
		t.Fatal(err)
	}
	if got.ProfileID != "work" {
		t.Fatalf("Resolve profile = %q, want work", got.ProfileID)
	}
}

func TestWaitingExplicitDomainRouteFailsClosed(t *testing.T) {
	r, err := NewRouterWithPolicies([]Profile{
		{ID: "work", Dialer: &recordingDialer{}},
		{ID: "lab", Dialer: &recordingDialer{}},
	}, nil, nil, []DomainRoute{
		{Suffix: "corp.example", ProfileID: "work", Active: true},
		{Suffix: "dev.corp.example", ProfileID: "lab", Exact: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve("tcp", "db.dev.corp.example:443"); err == nil {
		t.Fatal("waiting explicit route unexpectedly fell back to imported route")
	}
}

func TestExitNodeRoutesUnboundDestinationsAsFallback(t *testing.T) {
	r, err := NewRouterWithPolicies([]Profile{
		{ID: "exit", Dialer: &recordingDialer{}},
	}, nil, []SubnetRoute{{
		Prefix: netip.MustParsePrefix("0.0.0.0/0"), ProfileID: "exit", Active: true,
	}}, []DomainRoute{{
		Suffix: ".", ProfileID: "exit", Active: true, Automatic: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"203.0.113.10:443", "example.com:443"} {
		got, err := r.Resolve("tcp", target)
		if err != nil {
			t.Fatalf("Resolve(%q): %v", target, err)
		}
		if got.ProfileID != "exit" || got.DialAddr != target {
			t.Fatalf("Resolve(%q) = %+v", target, got)
		}
	}
}

func TestExplicitRoutesOverrideExitNodeFallback(t *testing.T) {
	r, err := NewRouterWithPolicies([]Profile{
		{ID: "work", Dialer: &recordingDialer{}},
		{ID: "exit", Dialer: &recordingDialer{}},
	}, nil, []SubnetRoute{
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), ProfileID: "work", Active: true},
		{Prefix: netip.MustParsePrefix("0.0.0.0/0"), ProfileID: "exit", Active: true},
	}, []DomainRoute{
		{Suffix: "corp.example", ProfileID: "work", Active: true, Exact: true},
		{Suffix: ".", ProfileID: "exit", Active: true, Automatic: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"10.20.1.2:443", "db.corp.example:443"} {
		got, err := r.Resolve("tcp", target)
		if err != nil {
			t.Fatalf("Resolve(%q): %v", target, err)
		}
		if got.ProfileID != "work" {
			t.Fatalf("Resolve(%q) profile = %q, want work", target, got.ProfileID)
		}
	}
}
