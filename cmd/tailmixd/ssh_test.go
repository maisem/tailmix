//go:build (linux || darwin || freebsd || openbsd || plan9) && !ts_omit_ssh

package main

import (
	"testing"

	"tailscale.com/cmd/tailscaled/childproc"
	"tailscale.com/ipn/ipnlocal"
)

func TestTailscaleSSHIsLinked(t *testing.T) {
	if _, ok := ipnlocal.HookListenSSH.GetOk(); !ok {
		t.Fatal("Tailscale SSH hook is not registered")
	}
	for _, mode := range []string{"ssh", "sftp"} {
		if _, ok := childproc.Code[mode]; !ok {
			t.Errorf("Tailscale %s child process is not registered", mode)
		}
	}
}
