// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin

package tsnet

import (
	"net"
	"testing"

	"tailscale.com/tstest"
)

func TestRefreshSystemUnderlayPublishesRoutingTableDefault(t *testing.T) {
	tstest.Replace(t, &darwinDefaultRouteInterfaceIndex, func() (int, error) {
		return 12, nil
	})
	tstest.Replace(t, &darwinInterfaceByIndex, func(index int) (*net.Interface, error) {
		if index != 12 {
			t.Fatalf("interface index = %d, want 12", index)
		}
		return &net.Interface{Index: index, Name: "en0"}, nil
	})
	var published string
	tstest.Replace(t, &darwinPublishDefaultInterface, func(name string) {
		published = name
	})

	if err := refreshSystemUnderlay(); err != nil {
		t.Fatal(err)
	}
	if published != "en0" {
		t.Fatalf("published interface = %q, want en0", published)
	}
}
