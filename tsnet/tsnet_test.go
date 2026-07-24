package tsnet

import (
	"testing"

	"tailscale.com/ipn"
)

func TestStartupPrefsPreserveNativeTailscaleSettings(t *testing.T) {
	saved := ipn.NewPrefs()
	saved.ControlURL = "https://headscale.example.com"
	saved.ShieldsUp = true
	saved.RunWebClient = true
	saved.AdvertiseTags = []string{"tag:native"}
	saved.Hostname = "old-hostname"
	saved.WantRunning = false

	server := &Server{hostname: "tailmix-work"}
	got := server.startupPrefs(saved.View())

	if got.ControlURL != saved.ControlURL {
		t.Fatalf("ControlURL = %q, want saved value %q", got.ControlURL, saved.ControlURL)
	}
	if !got.ShieldsUp {
		t.Fatal("ShieldsUp was not preserved")
	}
	if !got.RunWebClient {
		t.Fatal("RunWebClient was not preserved")
	}
	if len(got.AdvertiseTags) != 1 || got.AdvertiseTags[0] != "tag:native" {
		t.Fatalf("AdvertiseTags = %q, want saved value", got.AdvertiseTags)
	}
	if got.Hostname != "tailmix-work" {
		t.Fatalf("Hostname = %q, want Tailmix-owned hostname", got.Hostname)
	}
	if !got.WantRunning {
		t.Fatal("WantRunning = false, want true")
	}
}

func TestStartupPrefsExplicitControlURLWins(t *testing.T) {
	saved := ipn.NewPrefs()
	saved.ControlURL = "https://saved.example.com"

	server := &Server{
		hostname:   "tailmix-work",
		ControlURL: "https://configured.example.com",
	}
	got := server.startupPrefs(saved.View())

	if got.ControlURL != server.ControlURL {
		t.Fatalf("ControlURL = %q, want explicit value %q", got.ControlURL, server.ControlURL)
	}
}
