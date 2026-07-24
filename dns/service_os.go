//go:build darwin || linux

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

type osService struct {
	*packetService
	manager   *tailscaledns.Manager
	dialer    *tsdial.Dialer
	netMon    *netmon.Monitor
	bus       *eventbus.Bus
	closeOnce sync.Once
	closeErr  error
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
		return nil, fmt.Errorf("create %s DNS configurator: %w", platformGOOS, err)
	}
	manager := tailscaledns.NewManager(cfg.Logf, platformOSConfigurator(osConfigurator), healthTracker, dialer, nil, knobs, platformGOOS, bus)
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
	return &osService{
		packetService: packetService,
		manager:       manager,
		dialer:        dialer,
		netMon:        netMon,
		bus:           bus,
	}, nil
}

func (s *osService) Configure(domains []Domain, records []Record) error {
	return s.ConfigureFull(LiveConfig{Domains: domains, Records: records})
}

func (s *osService) ConfigureFull(cfg LiveConfig) error {
	dnsCfg, err := configForService(ServiceConfig{
		Domains:       cfg.Domains,
		Records:       cfg.Records,
		Routes:        cfg.Routes,
		SearchDomains: cfg.SearchDomains,
	})
	if err != nil {
		return err
	}
	if err := s.manager.Set(dnsCfg); err != nil {
		return fmt.Errorf("reconfigure MagicDNS: %w", err)
	}
	return nil
}

func (s *osService) Close() error {
	s.closeOnce.Do(func() {
		s.closeErr = errors.Join(s.packetService.Close(), s.manager.Down(), s.dialer.Close(), s.netMon.Close())
		s.bus.Close()
	})
	return s.closeErr
}
