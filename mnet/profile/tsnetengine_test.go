package profile

import (
	"testing"

	"tailscale.com/mnet/tunmux"
)

func TestTSNetEngineAcceptsProvidedTunBeforeStart(t *testing.T) {
	tun := tunmux.NewChanTUN("profile-work")
	engine := NewTSNetEngine(TSNetConfig{
		ProfileID: "work",
		Alias:     "work",
		Dir:       t.TempDir(),
		Hostname:  "mnet-work",
		Tun:       tun,
	})
	if engine == nil {
		t.Fatal("engine is nil")
	}
}
