package main

import (
	"errors"
	"fmt"

	"tailscale.com/cmd/tailscaled/childproc"
)

// runChildProcess dispatches subprocesses registered by linked Tailscale
// features. Tailscale SSH re-execs the daemon this way for login shells and
// SFTP sessions.
func runChildProcess(args []string) (handled bool, err error) {
	if len(args) == 0 || args[0] != "be-child" {
		return false, nil
	}
	if len(args) < 2 {
		return true, errors.New("missing be-child mode argument")
	}
	mode := args[1]
	f, ok := childproc.Code[mode]
	if !ok {
		return true, fmt.Errorf("unknown be-child mode %q", mode)
	}
	return true, f(args[2:])
}
