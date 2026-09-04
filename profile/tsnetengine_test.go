package profile

import (
	"net/netip"
	"testing"

	"github.com/maisem/tailmix/tunmux"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
)

func TestTSNetEngineAcceptsProvidedTunBeforeStart(t *testing.T) {
	tun := tunmux.NewChanTUN("profile-work")
	engine := NewTSNetEngine(TSNetConfig{
		ProfileID: "work",
		Alias:     "work",
		Dir:       t.TempDir(),
		Hostname:  "tailmix-work",
		Tun:       tun,
	})
	if engine == nil {
		t.Fatal("engine is nil")
	}
	if got := tun.BatchSize(); got != 128 {
		t.Fatalf("provided TUN batch size = %d, want 128", got)
	}
	if got := engine.cfg.Tun.BatchSize(); got != tun.BatchSize() {
		t.Fatalf("engine TUN batch size = %d, want %d", got, tun.BatchSize())
	}
}

func TestExitNodePrefsUsesBackendResolutionPath(t *testing.T) {
	for _, test := range []struct {
		name   string
		peerIP netip.Addr
	}{
		{name: "select", peerIP: netip.MustParseAddr("100.64.0.20")},
		{name: "clear"},
	} {
		t.Run(test.name, func(t *testing.T) {
			mp := exitNodePrefs(test.peerIP)
			if mp.ExitNodeIP != test.peerIP {
				t.Fatalf("exit node IP = %v, want %v", mp.ExitNodeIP, test.peerIP)
			}
			if mp.ExitNodeID != "" {
				t.Fatalf("exit node ID = %q, want backend resolution", mp.ExitNodeID)
			}
			if !mp.ExitNodeIDSet || !mp.ExitNodeIPSet {
				t.Fatalf("exit node masks are not both set: %+v", mp)
			}
			if mp.AutoExitNodeSet || mp.RouteAllSet {
				t.Fatalf("exit selection changes unrelated preferences: %+v", mp)
			}
			prefs := ipn.Prefs{
				RouteAll:   true,
				ExitNodeID: "previous-node",
				ExitNodeIP: netip.MustParseAddr("100.64.0.99"),
			}
			prefs.ApplyEdits(mp)
			if prefs.ExitNodeID != "" || prefs.ExitNodeIP != test.peerIP {
				t.Fatalf("applied exit preferences = ID %q, IP %v", prefs.ExitNodeID, prefs.ExitNodeIP)
			}
			if !prefs.RouteAll {
				t.Fatal("exit selection disabled RouteAll")
			}
		})
	}
}

func TestRouteAdvertiserNamePrefersReadableNodeIdentity(t *testing.T) {
	tests := []struct {
		name     string
		hostName string
		dnsName  string
		nodeID   string
		want     string
	}{
		{
			name:     "hostname",
			hostName: "subnet-router",
			dnsName:  "other-name.example.ts.net.",
			nodeID:   "nEsFwM1CNTRL",
			want:     "subnet-router",
		},
		{
			name:    "DNS name fallback",
			dnsName: "router-a.example.ts.net.",
			nodeID:  "nEsFwM1CNTRL",
			want:    "router-a",
		},
		{
			name:   "node ID fallback",
			nodeID: "nEsFwM1CNTRL",
			want:   "nEsFwM1CNTRL",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := routeAdvertiserName(test.hostName, test.dnsName, test.nodeID); got != test.want {
				t.Fatalf("advertiser = %q, want %q", got, test.want)
			}
		})
	}
}

func TestPeerLocationCopiesExitNodeDisplayMetadata(t *testing.T) {
	upstream := &tailcfg.Location{
		Country: "Canada", CountryCode: "CA", City: "Squamish", CityCode: "YSE", Priority: 10,
	}
	got := peerLocation(upstream)
	if got == nil ||
		got.Country != "Canada" ||
		got.CountryCode != "CA" ||
		got.City != "Squamish" ||
		got.CityCode != "YSE" ||
		got.Priority != 10 {
		t.Fatalf("location = %+v", got)
	}
	if peerLocation(nil) != nil {
		t.Fatal("nil upstream location did not remain nil")
	}
}

func TestServiceStatusesBuildStableMagicDNSTargets(t *testing.T) {
	zetaIPs := []netip.Addr{
		netip.MustParseAddr("100.100.1.2"),
		netip.MustParseAddr("fd7a:115c:a1e0::102"),
	}
	got := serviceStatuses(map[tailcfg.ServiceName]tailcfg.ServiceDetails{
		"svc:zeta": {
			Name:  "svc:zeta",
			Addrs: zetaIPs,
		},
		"svc:alpha": {
			// Exercise the map-key fallback used for older or partial data.
			Addrs: []netip.Addr{netip.MustParseAddr("100.100.1.1")},
		},
		"not-a-service": {
			Addrs: []netip.Addr{netip.MustParseAddr("100.100.1.3")},
		},
	}, "example.ts.net")
	if len(got) != 2 {
		t.Fatalf("service statuses = %+v, want two valid services", got)
	}
	if got[0].Name != "svc:alpha" || got[0].DNSName != "alpha.example.ts.net" {
		t.Fatalf("first service = %+v, want alpha MagicDNS target", got[0])
	}
	if got[1].Name != "svc:zeta" || got[1].DNSName != "zeta.example.ts.net" || len(got[1].TailscaleIPs) != 2 {
		t.Fatalf("second service = %+v, want zeta dual-stack target", got[1])
	}
	zetaIPs[0] = netip.MustParseAddr("100.100.1.99")
	if got[1].TailscaleIPs[0] == zetaIPs[0] {
		t.Fatal("service status aliases upstream address storage")
	}

	withoutDNS := serviceStatuses(map[tailcfg.ServiceName]tailcfg.ServiceDetails{
		"svc:alpha": {Name: "svc:alpha"},
	}, "")
	if len(withoutDNS) != 1 || withoutDNS[0].DNSName != "" {
		t.Fatalf("service without MagicDNS suffix = %+v", withoutDNS)
	}
}
