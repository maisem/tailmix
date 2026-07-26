// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !darwin

package tsnet

import (
	"tailscale.com/net/netmon"
	"tailscale.com/types/logger"
)

func trackSystemUnderlay(*netmon.Monitor, logger.Logf) func() {
	return func() {}
}
