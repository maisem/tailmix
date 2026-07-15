//go:build linux

package dns

import tailscaledns "tailscale.com/net/dns"

const platformGOOS = "linux"

func platformOSConfigurator(configurator tailscaledns.OSConfigurator) tailscaledns.OSConfigurator {
	return configurator
}
