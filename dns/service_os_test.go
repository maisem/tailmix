//go:build darwin || linux

package dns

import (
	"net/netip"
	"testing"

	tailscaledns "tailscale.com/net/dns"
)

type resolverIPCaptureConfigurator struct {
	config tailscaledns.OSConfig
}

func (c *resolverIPCaptureConfigurator) SetDNS(cfg tailscaledns.OSConfig) error {
	c.config = cfg
	return nil
}

func (*resolverIPCaptureConfigurator) SupportsSplitDNS() bool { return true }
func (*resolverIPCaptureConfigurator) GetBaseConfig() (tailscaledns.OSConfig, error) {
	return tailscaledns.OSConfig{}, tailscaledns.ErrGetBaseConfigNotSupported
}
func (*resolverIPCaptureConfigurator) Close() error { return nil }

func TestResolverIPConfiguratorAdvertisesOnlySyntheticResolver(t *testing.T) {
	resolverIP := netip.MustParseAddr("10.250.0.53")
	other := netip.MustParseAddr("192.0.2.53")
	capture := new(resolverIPCaptureConfigurator)
	configurator := resolverIPConfigurator{
		OSConfigurator: capture,
		resolverIP:     resolverIP,
	}
	if err := configurator.SetDNS(tailscaledns.OSConfig{
		Nameservers: []netip.Addr{ServiceIP(), other},
	}); err != nil {
		t.Fatal(err)
	}
	if len(capture.config.Nameservers) != 2 || capture.config.Nameservers[0] != resolverIP || capture.config.Nameservers[1] != other {
		t.Fatalf("OS nameservers = %v, want [%v %v]", capture.config.Nameservers, resolverIP, other)
	}
}
