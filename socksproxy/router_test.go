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
