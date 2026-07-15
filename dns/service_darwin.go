//go:build darwin

package dns

import (
	"errors"
	"fmt"
	"sync"

	"tailscale.com/control/controlknobs"
	"tailscale.com/health"
	tailscaledns "tailscale.com/net/dns"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/util/eventbus"
)

type darwinService struct {
	*packetService
	manager   *tailscaledns.Manager
	dialer    *tsdial.Dialer
	netMon    *netmon.Monitor
	bus       *eventbus.Bus
	closeOnce sync.Once
	closeErr  error
}

// splitDNSConfigurator makes Manager compile MagicDNS as native split DNS.
// The stock Darwin Manager blends the machine's base resolvers into quad-100
// because some Apple DNS APIs cannot express selective local records. tailmix only
// serves complete tailnet suffixes, so /etc/resolver is the better fit here.
type splitDNSConfigurator struct {
	tailscaledns.OSConfigurator
}

func (splitDNSConfigurator) GetBaseConfig() (tailscaledns.OSConfig, error) {
	return tailscaledns.OSConfig{}, tailscaledns.ErrGetBaseConfigNotSupported
}

func StartService(cfg ServiceConfig) (Service, error) {
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	dnsCfg, err := configForService(cfg)
	if err != nil {
		return nil, err
	}
	bus := eventbus.NewWithOptions(eventbus.BusOptions{Logf: cfg.Logf})
	healthTracker := health.NewTracker(bus)
	netMon := netmon.NewStatic()
	dialer := tsdial.NewDialer(netMon)
	dialer.Logf = cfg.Logf
	dialer.SetBus(bus)
	knobs := new(controlknobs.Knobs)
	knobs.ForceRegisterMagicDNSIPv4Only.Store(true)
	osConfigurator, err := tailscaledns.NewOSConfigurator(cfg.Logf, healthTracker, bus, nil, knobs, cfg.TunName)
	if err != nil {
		_ = dialer.Close()
		_ = netMon.Close()
		bus.Close()
		return nil, fmt.Errorf("create Darwin DNS configurator: %w", err)
	}
	manager := tailscaledns.NewManager(cfg.Logf, splitDNSConfigurator{osConfigurator}, healthTracker, dialer, nil, knobs, "darwin", bus)
	if manager == nil {
		_ = osConfigurator.Close()
		_ = dialer.Close()
		_ = netMon.Close()
		bus.Close()
		return nil, errors.New("this build does not include Tailscale DNS support")
	}
	if err := manager.Set(dnsCfg); err != nil {
		_ = manager.Down()
		_ = dialer.Close()
		_ = netMon.Close()
		bus.Close()
		return nil, fmt.Errorf("configure MagicDNS: %w", err)
	}
	packetService, err := newPacketService(manager, cfg.Logf)
	if err != nil {
		_ = manager.Down()
		_ = dialer.Close()
		_ = netMon.Close()
		bus.Close()
		return nil, err
	}
	service := &darwinService{
		packetService: packetService,
		manager:       manager,
		dialer:        dialer,
		netMon:        netMon,
		bus:           bus,
	}
	return service, nil
}

func (s *darwinService) Close() error {
	s.closeOnce.Do(func() {
		s.closeErr = errors.Join(s.packetService.Close(), s.manager.Down(), s.dialer.Close(), s.netMon.Close())
		s.bus.Close()
	})
	return s.closeErr
}
