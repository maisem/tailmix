package main

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestOtherTailscaleInterfaces(t *testing.T) {
	p := netip.MustParsePrefix
	ifaces := []interfaceAddrs{
		{Name: "lo", Addrs: []netip.Prefix{p("127.0.0.1/8")}},
		{Name: "eth0", Addrs: []netip.Prefix{p("192.0.2.10/24")}},
		// A carrier CGNAT uplink is not a Tailscale node address.
		{Name: "wwan0", Addrs: []netip.Prefix{p("100.70.1.2/10")}},
		{Name: "tailmix0", Addrs: []netip.Prefix{p("100.127.0.1/32"), p("fd7a:115c:a1e0::1/128")}},
		{Name: "tailscale0", Addrs: []netip.Prefix{p("100.101.102.103/32")}},
		{Name: "utun4", Addrs: []netip.Prefix{p("fe80::1/64"), p("fd7a:115c:a1e0::53/128")}},
	}
	got := otherTailscaleInterfaces("tailmix0", ifaces)
	if want := []string{"tailscale0", "utun4"}; !slices.Equal(got, want) {
		t.Fatalf("interfaces = %q, want %q", got, want)
	}
}

func TestStatusWarnsWhileAnotherTailscaleClientIsConnected(t *testing.T) {
	p := netip.MustParsePrefix
	for _, tc := range []struct {
		name   string
		ifaces []interfaceAddrs
		err    error
		warn   bool
	}{
		{name: "tailscaled connected", ifaces: []interfaceAddrs{{Name: "tailscale0", Addrs: []netip.Prefix{p("100.101.102.103/32")}}}, warn: true},
		{name: "tailscaled disconnected", ifaces: []interfaceAddrs{{Name: "tailscale0"}}},
		{name: "carrier CGNAT uplink", ifaces: []interfaceAddrs{{Name: "wwan0", Addrs: []netip.Prefix{p("100.70.1.2/10")}}}},
		{name: "interfaces unreadable", err: errors.New("boom")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &supervisor{ctx: context.Background(), lastErrors: map[string]string{}}
			s.cfg.Interfaces = func() ([]interfaceAddrs, error) { return tc.ifaces, tc.err }
			got, err := s.Status(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if warned := len(got.Warnings) > 0; warned != tc.warn {
				t.Fatalf("warned = %v, want %v (warnings %q)", warned, tc.warn, got.Warnings)
			}
			// Logs and status must not reveal tailnet addresses.
			for _, warning := range got.Warnings {
				if strings.Contains(warning, "100.101.102.103") {
					t.Fatalf("warning reveals the node address: %q", warning)
				}
			}
		})
	}
}
