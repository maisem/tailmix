// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin

package tsnet

import (
	"testing"

	"tailscale.com/tstest"
)

func TestRefreshSystemUnderlayPublishesRoutingTableDefault(t *testing.T) {
	tstest.Replace(t, &darwinDefaultRouteInterfaceIndex, func() (int, error) {
		return 12, nil
	})
	var published int
	tstest.Replace(t, &darwinPublishUnderlayInterface, func(index int) error {
		published = index
		return nil
	})

	if err := refreshSystemUnderlay(); err != nil {
		t.Fatal(err)
	}
	if published != 12 {
		t.Fatalf("published interface index = %d, want 12", published)
	}
}
