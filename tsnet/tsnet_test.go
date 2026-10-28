package tsnet

import (
	"net"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

func TestListenSSHAuthCallbackForwarded(t *testing.T) {
	for _, name := range []string{"nil", "allow", "deny"} {
		t.Run(name, func(t *testing.T) {
			s := &Server{lb: new(ipnlocal.LocalBackend)}
			// Exercise listener registration without starting a real node.
			s.initOnce.Do(func() {})
			wantPeer := (&tailcfg.Node{ID: 123}).View()
			wantUser := tailcfg.UserProfile{ID: 456}
			called := false
			if name != "nil" {
				s.SSHAuthCallback = func(peer tailcfg.NodeView, user tailcfg.UserProfile) bool {
					called = true
					if peer.ID() != wantPeer.ID() || user.ID != wantUser.ID {
						t.Error("callback received a different peer identity")
					}
					return name == "allow"
				}
			}
			hookCalled := false
			t.Cleanup(ipnlocal.HookListenSSH.SetForTest(func(ln net.Listener, lb *ipnlocal.LocalBackend, auth ipnlocal.SSHAuthCallback, logf logger.Logf) (net.Listener, error) {
				hookCalled = true
				if lb != s.lb {
					t.Error("listener received a different backend")
				}
				if name == "nil" {
					if auth != nil {
						t.Error("nil callback was not preserved")
					}
				} else if auth == nil {
					t.Error("configured callback was not forwarded")
				} else if got, want := auth(wantPeer, wantUser), name == "allow"; got != want {
					t.Error("callback authorization decision was not preserved")
				}
				return ln, nil
			}))
			ln, err := s.ListenSSH(":2222")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			if !hookCalled {
				t.Error("SSH listener hook was not called")
			}
			if got, want := called, name != "nil"; got != want {
				t.Error("configured authorization callback was not called")
			}
		})
	}
}

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

func TestGetAuthKeyCanIgnoreEnvironment(t *testing.T) {
	t.Setenv("TS_AUTHKEY", "global-key")
	t.Setenv("TS_AUTH_KEY", "global-key-alias")

	server := &Server{DisableAuthKeyEnv: true}
	if got := server.getAuthKey(); got != "" {
		t.Fatalf("getAuthKey() = %q, want global environment ignored", got)
	}

	server.AuthKey = "profile-key"
	if got := server.getAuthKey(); got != "profile-key" {
		t.Fatalf("getAuthKey() = %q, want explicit profile key", got)
	}
}

func TestGetAuthKeyUsesEnvironmentByDefault(t *testing.T) {
	t.Setenv("TS_AUTHKEY", "global-key")

	if got := new(Server).getAuthKey(); got != "global-key" {
		t.Fatalf("getAuthKey() = %q, want default environment fallback", got)
	}
}
