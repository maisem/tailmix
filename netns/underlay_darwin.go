// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin

package netns

import (
	"fmt"
	"net"

	"tailscale.com/net/netmon"
)

var (
	underlayInterfaceByIndex = net.InterfaceByIndex
	publishUnderlayInterface = netmon.UpdateLastKnownDefaultRouteInterface
)

// SetUnderlayInterfaceIndex publishes index as the OS-provided default used by
// Tailscale's Darwin netns implementation. It lets an embedding process retain
// a physical underlay after installing more-specific aggregate default routes.
func SetUnderlayInterfaceIndex(index int) error {
	iface, err := underlayInterfaceByIndex(index)
	if err != nil {
		return fmt.Errorf("interface %d: %w", index, err)
	}
	publishUnderlayInterface(iface.Name)
	return nil
}
