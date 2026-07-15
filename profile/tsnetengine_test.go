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
