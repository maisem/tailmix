package profile

import (
	"testing"

	"github.com/maisem/tailmix/tunmux"
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
