package main

import (
	"io"
	"testing"

	"github.com/maisem/tailmix/state"
	"github.com/maisem/tailmix/tunmux"
	"github.com/tailscale/wireguard-go/tun"
)

func TestTSNetConfigTUNSelection(t *testing.T) {
	rp := runtimeProfile{State: state.Profile{ID: "test"}}
	t.Run("userspace", func(t *testing.T) {
		cfg, err := tsnetConfig(rp, io.Discard, false, false, "")
		if err != nil {
			t.Fatal("could not construct userspace configuration")
		}
		// A typed-nil *ChanTUN in this interface makes tsnet select its
		// custom-TUN path and panic when it reads device events.
		if cfg.Tun != nil {
			t.Fatal("userspace configuration must have a nil TUN interface")
		}
	})
	for _, name := range []string{"custom_TUN", "wrapped_TUN"} {
		t.Run(name, func(t *testing.T) {
			device := tunmux.NewChanTUN("test")
			t.Cleanup(func() { _ = device.Close() })
			rp.Tun = device
			if name == "wrapped_TUN" {
				rp.Tun = struct{ tun.Device }{device}
			}
			cfg, err := tsnetConfig(rp, io.Discard, false, false, "")
			if err != nil || cfg.Tun != rp.Tun {
				t.Fatal("custom TUN interface was not preserved")
			}
		})
	}
}
