package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/maisem/tailmix/hosttun"
	"github.com/tailscale/wireguard-go/tun"
)

type closeErrorHost struct {
	err error
}

func (h closeErrorHost) Device() tun.Device             { return nil }
func (h closeErrorHost) Name() string                   { return "utun42" }
func (h closeErrorHost) Configure(hosttun.Config) error { return nil }
func (h closeErrorHost) Close() error                   { return h.err }

func TestSupervisorCloseReportsHostCleanupError(t *testing.T) {
	var stderr bytes.Buffer
	s := &supervisor{
		cfg:  daemonConfig{Stderr: &stderr},
		host: closeErrorHost{err: errors.New("route delete failed")},
	}

	err := s.close()
	if err == nil || !strings.Contains(err.Error(), "close host TUN: route delete failed") {
		t.Fatalf("close error = %v, want host cleanup failure", err)
	}
	if !strings.Contains(stderr.String(), "close host TUN: route delete failed") {
		t.Fatalf("stderr = %q, want host cleanup failure", stderr.String())
	}
}
