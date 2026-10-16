package main

import (
	"io"
	"testing"

	"github.com/maisem/tailmix/state"
	"github.com/maisem/tailmix/tunmux"
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
	t.Run("custom_TUN", func(t *testing.T) {
		device := tunmux.NewChanTUN("test")
		t.Cleanup(func() { _ = device.Close() })
		rp.Tun = device
		cfg, err := tsnetConfig(rp, io.Discard, false, false, "")
		if err != nil || cfg.Tun != device {
			t.Fatal("custom TUN was not preserved")
		}
	})
}
