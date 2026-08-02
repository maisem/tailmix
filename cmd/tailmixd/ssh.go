//go:build (linux || darwin || freebsd || openbsd || plan9) && !ts_omit_ssh

package main

// Register Tailscale's SSH server and related LocalBackend hooks.
import _ "tailscale.com/feature/ssh"
