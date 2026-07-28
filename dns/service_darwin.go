//go:build darwin

package dns

import (
	tailscaledns "tailscale.com/net/dns"
)

const platformGOOS = "darwin"

// splitDNSConfigurator makes Manager compile MagicDNS as native split DNS.
// The stock Darwin Manager blends the machine's base resolvers into quad-100
// because some Apple DNS APIs cannot express selective local records. tailmix only
// serves complete tailnet suffixes, so /etc/resolver is the better fit here.
type splitDNSConfigurator struct {
	tailscaledns.OSConfigurator
}

func (*splitDNSConfigurator) GetBaseConfig() (tailscaledns.OSConfig, error) {
	return tailscaledns.OSConfig{}, tailscaledns.ErrGetBaseConfigNotSupported
}

func platformOSConfigurator(configurator tailscaledns.OSConfigurator) tailscaledns.OSConfigurator {
	return &splitDNSConfigurator{OSConfigurator: configurator}
}
