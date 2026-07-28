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
