// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin

package tsnet

import (
	tailmixnetns "github.com/maisem/tailmix/netns"

	"tailscale.com/net/netmon"
	"tailscale.com/types/logger"
)

var (
	darwinDefaultRouteInterfaceIndex = netmon.DefaultRouteInterfaceIndex
	darwinPublishUnderlayInterface   = tailmixnetns.SetUnderlayInterfaceIndex
)

// trackSystemUnderlay publishes the interface owning the underlying /0 route
// through the local netns fork. A routing overlay can replace the effective
// default with two /1 routes, but control, DERP, magicsock, portmapper, and DNS
// fallback sockets must remain bound to the physical underlay.
func trackSystemUnderlay(netMon *netmon.Monitor, logf logger.Logf) func() {
	refresh := func() {
		if err := refreshSystemUnderlay(); err != nil {
			logf("[v1] netns: refresh Darwin underlay interface: %v", err)
		}
	}
	unregister := netMon.RegisterChangeCallback(func(*netmon.ChangeDelta) {
		refresh()
	})
	refresh()
	return unregister
}

func refreshSystemUnderlay() error {
	index, err := darwinDefaultRouteInterfaceIndex()
	if err != nil {
		return err
	}
	return darwinPublishUnderlayInterface(index)
}
