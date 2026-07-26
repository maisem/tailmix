// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin

package tsnet

import (
	"fmt"
	"net"

	"tailscale.com/net/netmon"
	"tailscale.com/types/logger"
)

var (
	darwinDefaultRouteInterfaceIndex = netmon.DefaultRouteInterfaceIndex
	darwinInterfaceByIndex           = net.InterfaceByIndex
	darwinPublishDefaultInterface    = netmon.UpdateLastKnownDefaultRouteInterface
)

// trackSystemUnderlay publishes the interface owning the underlying /0 route
// as Darwin's OS-provided default. A routing overlay can replace the effective
// default with two /1 routes, leaving netmon's cached default empty. netns
// consults the OS-provided default before that cache when binding control,
// DERP, magicsock, portmapper, and DNS fallback sockets.
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
	iface, err := darwinInterfaceByIndex(index)
	if err != nil {
		return fmt.Errorf("interface %d: %w", index, err)
	}
	darwinPublishDefaultInterface(iface.Name)
	return nil
}
