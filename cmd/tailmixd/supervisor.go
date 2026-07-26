package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/maisem/tailmix/controlapi"
	tailmixdns "github.com/maisem/tailmix/dns"
	"github.com/maisem/tailmix/hosttun"
	"github.com/maisem/tailmix/packetmap"
	tailmixprofile "github.com/maisem/tailmix/profile"
	"github.com/maisem/tailmix/profilesocket"
	"github.com/maisem/tailmix/routingpolicy"
	"github.com/maisem/tailmix/socksproxy"
	"github.com/maisem/tailmix/state"
	"github.com/maisem/tailmix/tunmux"
	"tailscale.com/types/dnstype"
)

type daemonConfig struct {
	Mode         string
	TUNName      string
	SocketDir    string
	SOCKSAddr    string
	Verbose      bool
	LogUpload    bool
	LogUploadURL string
	Stderr       io.Writer
}

type managedProfile struct {
	runtime runtimeProfile
	cancel  context.CancelFunc
	status  tailmixprofile.Status
}

type runtimeUpdate struct {
	profileID string
	err       error
}

// supervisor is the single owner of desired profile state and live aggregate
// networking. The HTTP API serializes mutations through mu; watcher callbacks
// only enqueue observations.
type supervisor struct {
	store *state.JSONStore
	cfg   daemonConfig

	mu            sync.Mutex
	ctx           context.Context
	cancel        context.CancelFunc
	st            state.State
	initial       map[string]runtimeProfile
	runtimes      map[string]*managedProfile
	lastErrors    map[string]string
	updates       chan runtimeUpdate
	profileAPIs   *profileAPIGroup
	control       *controlServer
	ipPolicy      routingpolicy.IPPlan
	dnsPolicy     routingpolicy.DNSPlan
	host          hosttun.Host
	mux           *tunmux.Mux
	dnsService    tailmixdns.Service
	dnsForwarders []*tailmixdns.Forwarder
	socksListener net.Listener
	socksRouter   *socksproxy.DynamicRouter
	networkErr    chan error
	reconcileErr  string
}

func newSupervisor(store *state.JSONStore, st state.State, initial []runtimeProfile, cfg daemonConfig) *supervisor {
	if cfg.Stderr == nil {
		cfg.Stderr = io.Discard
	}
	initialByID := make(map[string]runtimeProfile, len(initial))
	for _, rp := range initial {
		initialByID[rp.State.ID] = rp
	}
	return &supervisor{
		store:      store,
		cfg:        cfg,
		st:         cloneState(st),
		initial:    initialByID,
		runtimes:   map[string]*managedProfile{},
		lastErrors: map[string]string{},
		updates:    make(chan runtimeUpdate, 128),
		networkErr: make(chan error, 4),
	}
}

func (s *supervisor) Run(ctx context.Context) (retErr error) {
	s.mu.Lock()
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.profileAPIs = newProfileAPIGroup(s.ctx, s.cfg.SocketDir, s.cfg.Stderr)
	if err := s.startAggregateLocked(); err != nil {
		s.mu.Unlock()
		return errors.Join(err, s.close())
	}
	for _, configured := range s.st.Profiles {
		if configured.Disabled || configured.Removed {
			continue
		}
		initial := s.initial[configured.ID]
		if err := s.startProfileLocked(configured, "", initial.AuthKeyEnv); err != nil {
			s.lastErrors[configured.ID] = err.Error()
			fmt.Fprintf(s.cfg.Stderr, "profile %s failed to start: %v\n", profileName(configured), err)
		}
	}
	if err := s.reconcileLocked(); err != nil {
		s.mu.Unlock()
		return errors.Join(err, s.close())
	}
	control, err := startControlServer(s.ctx, s.cfg.SocketDir, s)
	if err != nil {
		s.mu.Unlock()
		return errors.Join(err, s.close())
	}
	s.control = control
	fmt.Fprintf(s.cfg.Stderr, "daemon control socket %s\n", profilesocket.ControlPath(s.cfg.SocketDir))
	fmt.Fprintf(s.cfg.Stderr, "started %d enabled profile runtime(s)\n", len(s.runtimes))
	s.mu.Unlock()

	defer func() {
		retErr = errors.Join(retErr, s.close())
	}()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-s.networkErr:
			if err != nil {
				return err
			}
		case err := <-control.Errors():
			if err != nil {
				return fmt.Errorf("daemon control server: %w", err)
			}
			return nil
		case err := <-s.profileAPIs.Errors():
			if err != nil {
				fmt.Fprintf(s.cfg.Stderr, "profile LocalAPI error: %v\n", err)
			}
		case update := <-s.updates:
			s.mu.Lock()
			if update.err != nil {
				s.lastErrors[update.profileID] = update.err.Error()
				fmt.Fprintf(s.cfg.Stderr, "profile %s watcher: %v\n", s.nameForIDLocked(update.profileID), update.err)
			} else if _, ok := s.runtimes[update.profileID]; ok {
				if err := s.reconcileLocked(); err != nil {
					s.lastErrors[update.profileID] = err.Error()
					fmt.Fprintf(s.cfg.Stderr, "profile %s reconcile: %v\n", s.nameForIDLocked(update.profileID), err)
				}
			}
			s.mu.Unlock()
		}
	}
}

func (s *supervisor) startAggregateLocked() error {
	switch s.cfg.Mode {
	case "tun":
		host, err := hosttun.Open(hosttun.OpenConfig{Name: s.cfg.TUNName, Logf: prefixedLogf(s.cfg.Stderr, "tun")})
		if err != nil {
			return err
		}
		s.host = host
		dnsService, err := tailmixdns.StartService(tailmixdns.ServiceConfig{
			TunName: host.Name(),
			Logf:    prefixedLogf(s.cfg.Stderr, "dns"),
		})
		if err != nil {
			_ = host.Close()
			s.host = nil
			return err
		}
		s.dnsService = dnsService
		s.mux = tunmux.NewMux(host.Device(), nil, packetmap.New(packetmap.Table{}), prefixedLogf(s.cfg.Stderr, "tun"))
		s.mux.SetLocalPacketHandler(dnsService)
		go func() {
			if err := s.mux.Run(s.ctx); err != nil && s.ctx.Err() == nil {
				s.networkErr <- fmt.Errorf("TUN multiplexer: %w", err)
			}
		}()
		fmt.Fprintf(s.cfg.Stderr, "TUN %s opened\n", host.Name())
	case "socks":
		router, err := socksproxy.NewRouterWithRoutes(nil, nil, nil)
		if err != nil {
			return err
		}
		s.socksRouter = socksproxy.NewDynamicRouter(router)
		listener, err := net.Listen("tcp", s.cfg.SOCKSAddr)
		if err != nil {
			return err
		}
		s.socksListener = listener
		go func() {
			if err := socksproxy.Serve(s.ctx, listener, s.socksRouter, prefixedLogf(s.cfg.Stderr, "socks")); err != nil && s.ctx.Err() == nil {
				s.networkErr <- fmt.Errorf("SOCKS server: %w", err)
			}
		}()
		fmt.Fprintf(s.cfg.Stderr, "SOCKS listening on %s\n", listener.Addr())
	default:
		return fmt.Errorf("unsupported networking mode %q", s.cfg.Mode)
	}
	return nil
}

func (s *supervisor) startProfileLocked(configured state.Profile, authKey, authKeyEnv string) error {
	if _, ok := s.runtimes[configured.ID]; ok {
		return nil
	}
	runtimeCtx, cancel := context.WithCancel(s.ctx)
	rp := runtimeProfile{State: configured, AuthKeyEnv: authKeyEnv}
	if s.cfg.Mode == "tun" {
		rp.Tun = tunmux.NewChanTUN("tailmix-" + dnsLabel(configured.ID))
	}
	cfg, err := tsnetConfig(rp, s.cfg.Stderr, s.cfg.Verbose, s.cfg.LogUpload, s.cfg.LogUploadURL)
	if err != nil {
		cancel()
		return err
	}
	if authKey != "" {
		cfg.AuthKey = authKey
	}
	rp.Engine = tailmixprofile.NewTSNetEngine(cfg)
	if err := rp.Engine.Start(runtimeCtx); err != nil {
		cancel()
		_ = rp.Engine.Close()
		return fmt.Errorf("start engine: %w", err)
	}
	managed := &managedProfile{runtime: rp, cancel: cancel}
	s.runtimes[configured.ID] = managed
	if s.mux != nil {
		if err := s.mux.AddProfile(configured.ID, rp.Tun); err != nil {
			delete(s.runtimes, configured.ID)
			cancel()
			_ = rp.Engine.Close()
			return err
		}
	}
	if err := s.profileAPIs.Start(rp); err != nil {
		if s.mux != nil {
			s.mux.RemoveProfile(configured.ID)
		}
		delete(s.runtimes, configured.ID)
		cancel()
		_ = rp.Engine.Close()
		return err
	}
	status, err := rp.Engine.Status(runtimeCtx)
	if err == nil {
		managed.status = status
		delete(s.lastErrors, configured.ID)
	} else {
		s.lastErrors[configured.ID] = err.Error()
	}
	go s.watchProfile(runtimeCtx, configured.ID, rp.Engine)
	return nil
}

func (s *supervisor) watchProfile(ctx context.Context, profileID string, engine tailmixprofile.Engine) {
	err := engine.WatchUpdates(ctx, func() {
		select {
		case s.updates <- runtimeUpdate{profileID: profileID}:
		default:
		}
	})
	if err != nil && ctx.Err() == nil {
		select {
		case s.updates <- runtimeUpdate{profileID: profileID, err: err}:
		case <-s.ctx.Done():
		}
	}
}

func (s *supervisor) stopProfileLocked(profileID string) error {
	managed, ok := s.runtimes[profileID]
	if !ok {
		return nil
	}
	delete(s.runtimes, profileID)
	if s.mux != nil {
		s.mux.RemoveProfile(profileID)
	}
	apiErr := s.profileAPIs.Stop(profileID)
	managed.cancel()
	engineErr := managed.runtime.Engine.Close()
	return errors.Join(apiErr, engineErr)
}

func (s *supervisor) reconcileLocked() (err error) {
	defer func() {
		if err != nil {
			s.reconcileErr = err.Error()
		} else {
			s.reconcileErr = ""
		}
	}()
	observedStatuses := s.statusesLocked()
	s.ipPolicy = routingpolicy.BuildIP(s.st, observedStatuses)
	s.dnsPolicy = routingpolicy.BuildDNS(s.st, observedStatuses)
	if err := s.setRoutePreferencesLocked(); err != nil {
		return err
	}
	if err := s.setExitNodePreferencesLocked(observedStatuses); err != nil {
		return err
	}
	// Re-read preferences after applying them. Host default routes must not be
	// published until the selected engine reports the requested stable
	// exit-node ID.
	statuses := usableStatuses(s.statusesLocked())

	if s.cfg.Mode == "tun" {
		plan, err := buildTUNPlan(s.st, statuses)
		if err != nil {
			return fmt.Errorf("build aggregate TUN plan: %w", err)
		}
		// Publish the fail-closed packet policy before changing host routes.
		// Removed routes can only be dropped, and newly installed host routes
		// immediately see their final profile selection.
		s.mux.SetMapper(packetmap.New(plan.Table))
		if err := s.host.Configure(plan.HostConfig); err != nil {
			return fmt.Errorf("configure aggregate TUN: %w", err)
		}
		if err := s.configureDNSLocked(plan.DNSConfig); err != nil {
			return fmt.Errorf("configure aggregate DNS: %w", err)
		}
		s.st = plan.State
		s.ipPolicy = plan.IPPolicy
		s.dnsPolicy = plan.DNSPolicy
	} else {
		next := cloneState(s.st)
		updateProfileMetadata(&next, statuses)
		if err := ensureNATIPs(&next); err != nil {
			return err
		}
		active, all, err := assignEffectiveIPs(next, statuses)
		if err != nil {
			return err
		}
		next.Leases = leasesToState(all)
		profiles := make([]socksproxy.Profile, 0, len(statuses))
		for _, status := range statuses {
			managed := s.runtimes[status.ProfileID]
			if managed == nil {
				continue
			}
			profiles = append(profiles, socksproxy.Profile{
				ID:             status.ProfileID,
				MagicDNSSuffix: status.MagicDNSSuffix,
				Dialer:         managed.runtime.Engine,
			})
		}
		var subnetRoutes []socksproxy.SubnetRoute
		for _, entry := range s.ipPolicy.Exact {
			subnetRoutes = append(subnetRoutes, socksproxy.SubnetRoute{
				Prefix: entry.Prefix, ProfileID: entry.ProfileID, Active: entry.Active, Exact: true,
			})
		}
		for _, entry := range s.ipPolicy.Imported {
			subnetRoutes = append(subnetRoutes, socksproxy.SubnetRoute{
				Prefix: entry.Prefix, ProfileID: entry.ProfileID, Active: entry.Active,
			})
		}
		if exitProfileID := activeExitProfile(s.st, statuses); exitProfileID != "" {
			subnetRoutes = append(subnetRoutes,
				socksproxy.SubnetRoute{
					Prefix:    netip.PrefixFrom(netip.IPv4Unspecified(), 0),
					ProfileID: exitProfileID, Active: true,
				},
				socksproxy.SubnetRoute{
					Prefix:    netip.PrefixFrom(netip.IPv6Unspecified(), 0),
					ProfileID: exitProfileID, Active: true,
				},
			)
		}
		var domainRoutes []socksproxy.DomainRoute
		for _, entry := range s.dnsPolicy.Exact {
			domainRoutes = append(domainRoutes, socksproxy.DomainRoute{
				Suffix: entry.Domain, ProfileID: entry.ProfileID, Active: entry.Active, Exact: true,
			})
		}
		for _, entry := range s.dnsPolicy.Imported {
			domainRoutes = append(domainRoutes, socksproxy.DomainRoute{
				Suffix: entry.Domain, ProfileID: entry.ProfileID, Active: entry.Active,
			})
		}
		for _, entry := range s.dnsPolicy.Automatic {
			domainRoutes = append(domainRoutes, socksproxy.DomainRoute{
				Suffix: entry.Domain, ProfileID: entry.ProfileID, Active: entry.Active, Automatic: true,
			})
		}
		if exitProfileID := activeExitProfile(s.st, statuses); exitProfileID != "" {
			domainRoutes = append(domainRoutes, socksproxy.DomainRoute{
				Suffix: ".", ProfileID: exitProfileID, Active: true, Automatic: true,
			})
		}
		router, err := socksproxy.NewRouterWithPolicies(profiles, active, subnetRoutes, domainRoutes)
		if err != nil {
			return err
		}
		s.socksRouter.Set(router)
		s.st = next
	}
	if err := s.store.Save(s.st); err != nil {
		return fmt.Errorf("save reconciled state: %w", err)
	}
	return nil
}

func usableStatuses(statuses []tailmixprofile.Status) []tailmixprofile.Status {
	out := make([]tailmixprofile.Status, 0, len(statuses))
	for _, status := range statuses {
		if status.BackendState == "" || status.BackendState == "Running" {
			out = append(out, status)
		}
	}
	return out
}

func (s *supervisor) statusesLocked() []tailmixprofile.Status {
	var statuses []tailmixprofile.Status
	for _, configured := range s.st.Profiles {
		if configured.Disabled || configured.Removed {
			continue
		}
		managed := s.runtimes[configured.ID]
		if managed == nil {
			continue
		}
		status, err := managed.runtime.Engine.Status(s.ctx)
		if err != nil {
			s.lastErrors[configured.ID] = err.Error()
			status = managed.status
		} else {
			managed.status = status
			delete(s.lastErrors, configured.ID)
		}
		if status.ProfileID != "" {
			statuses = append(statuses, status)
		}
	}
	sort.Slice(statuses, func(i, j int) bool { return statuses[i].ProfileID < statuses[j].ProfileID })
	return statuses
}

func (s *supervisor) setRoutePreferencesLocked() error {
	for id, managed := range s.runtimes {
		if managed.status.RouteAll {
			continue
		}
		if managed.status.BackendState != "Running" {
			continue
		}
		controller, ok := managed.runtime.Engine.(tailmixprofile.RoutePreferenceController)
		if !ok {
			return fmt.Errorf("profile %q does not support route acceptance", s.nameForIDLocked(id))
		}
		if err := controller.SetRouteAll(s.ctx, true); err != nil {
			s.lastErrors[id] = fmt.Sprintf("set accept-routes: %v", err)
			return fmt.Errorf("enable route acceptance for profile %q: %w", s.nameForIDLocked(id), err)
		}
		managed.status.RouteAll = true
	}
	return nil
}

func (s *supervisor) setExitNodePreferencesLocked(statuses []tailmixprofile.Status) error {
	current := make(map[string]string, len(statuses))
	for _, status := range statuses {
		current[status.ProfileID] = status.ExitNodeID
	}
	for id, managed := range s.runtimes {
		wantID := ""
		var wantIP netip.Addr
		if s.st.ExitNode != nil && s.st.ExitNode.ProfileID == id {
			wantID = s.st.ExitNode.NodeID
			wantIP = s.st.ExitNode.PeerIP
		}
		if current[id] == wantID {
			continue
		}
		if managed.status.BackendState != "Running" {
			continue
		}
		controller, ok := managed.runtime.Engine.(tailmixprofile.ExitNodePreferenceController)
		if !ok {
			if wantID == "" {
				continue
			}
			return fmt.Errorf("profile %q does not support exit nodes", s.nameForIDLocked(id))
		}
		if err := controller.SetExitNodeIP(s.ctx, wantIP); err != nil {
			s.lastErrors[id] = fmt.Sprintf("set exit node: %v", err)
			return fmt.Errorf("set exit node for profile %q: %w", s.nameForIDLocked(id), err)
		}
	}
	return nil
}

func (s *supervisor) configureDNSLocked(cfg tailmixdns.LiveConfig) error {
	nextForwarders := make([]*tailmixdns.Forwarder, 0, len(cfg.Routes))
	for i := range cfg.Routes {
		if len(cfg.Routes[i].Resolvers) == 0 {
			continue
		}
		managed := s.runtimes[cfg.Routes[i].ProfileID]
		if managed == nil {
			closeForwarders(nextForwarders)
			return fmt.Errorf("DNS route %q selected unavailable profile %q", cfg.Routes[i].Suffix, cfg.Routes[i].ProfileID)
		}
		forwarder, err := tailmixdns.StartForwarder(s.ctx, managed.runtime.Engine, cfg.Routes[i].Resolvers)
		if err != nil {
			closeForwarders(nextForwarders)
			return fmt.Errorf("start profile %q DNS forwarder: %w", s.nameForIDLocked(cfg.Routes[i].ProfileID), err)
		}
		nextForwarders = append(nextForwarders, forwarder)
		cfg.Routes[i].Resolvers = []*dnstype.Resolver{forwarder.Resolver()}
	}
	if err := s.dnsService.ConfigureFull(cfg); err != nil {
		closeForwarders(nextForwarders)
		return err
	}
	old := s.dnsForwarders
	s.dnsForwarders = nextForwarders
	closeForwarders(old)
	return nil
}

func closeForwarders(forwarders []*tailmixdns.Forwarder) {
	for _, forwarder := range forwarders {
		_ = forwarder.Close()
	}
}

func (s *supervisor) close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var errs []error
	if s.cancel != nil {
		s.cancel()
	}
	if s.control != nil {
		_ = s.control.Close()
		s.control = nil
	}
	for id := range s.runtimes {
		_ = s.stopProfileLocked(id)
	}
	closeForwarders(s.dnsForwarders)
	s.dnsForwarders = nil
	if s.dnsService != nil {
		_ = s.dnsService.Close()
		s.dnsService = nil
	}
	if s.socksListener != nil {
		_ = s.socksListener.Close()
		s.socksListener = nil
	}
	if s.host != nil {
		if err := s.host.Close(); err != nil {
			err = fmt.Errorf("close host TUN: %w", err)
			fmt.Fprintln(s.cfg.Stderr, err)
			errs = append(errs, err)
		}
		s.host = nil
	}
	if s.profileAPIs != nil {
		_ = s.profileAPIs.Close()
	}
	return errors.Join(errs...)
}

func (s *supervisor) nameForIDLocked(profileID string) string {
	for _, configured := range s.st.Profiles {
		if configured.ID == profileID {
			return profileName(configured)
		}
	}
	return profileID
}

func profileName(configured state.Profile) string {
	if configured.Name != "" {
		return configured.Name
	}
	return configured.ID
}

func cloneState(st state.State) state.State {
	st.Profiles = append([]state.Profile(nil), st.Profiles...)
	st.Leases = append([]state.EffectiveLease(nil), st.Leases...)
	st.IPRouteBindings = append([]state.IPRouteBinding(nil), st.IPRouteBindings...)
	st.DNSRouteBindings = append([]state.DNSRouteBinding(nil), st.DNSRouteBindings...)
	st.SearchDomains = append([]string(nil), st.SearchDomains...)
	if st.ExitNode != nil {
		exitNode := *st.ExitNode
		st.ExitNode = &exitNode
	}
	return st
}

func randomOpaque(prefix string, byteCount int) (string, error) {
	buffer := make([]byte, byteCount)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(buffer), nil
}

func defaultProfileStateDir(storePath, profileID string) string {
	return filepath.Join(filepath.Dir(storePath), "profiles", profileID)
}

func (s *supervisor) configuredByNameLocked(name string) (*state.Profile, error) {
	for i := range s.st.Profiles {
		if profileName(s.st.Profiles[i]) == name {
			return &s.st.Profiles[i], nil
		}
	}
	return nil, controlapi.NewError("profile_not_found", "profile %q not found", name)
}

func validProfileName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for i, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			(i > 0 && (r == '-' || r == '_' || r == '.')) {
			continue
		}
		return false
	}
	return true
}

func (s *supervisor) projectProfileLocked(configured state.Profile) controlapi.Profile {
	result := controlapi.Profile{
		ID:                 configured.ID,
		Name:               profileName(configured),
		StateDir:           configured.StateDir,
		Hostname:           configured.Hostname,
		Enabled:            !configured.Disabled && !configured.Removed,
		Removed:            configured.Removed,
		AcceptAllRoutes:    configured.AcceptAllRoutes,
		AcceptAllDNSRoutes: configured.AcceptAllDNSRoutes,
		LastError:          s.lastErrors[configured.ID],
	}
	switch {
	case configured.Removed:
		result.RuntimeState = "removed"
	case configured.Disabled:
		result.RuntimeState = "disabled"
	default:
		managed := s.runtimes[configured.ID]
		if managed == nil {
			result.RuntimeState = "error"
			break
		}
		status := managed.status
		result.BackendState = status.BackendState
		result.MagicDNSSuffix = status.MagicDNSSuffix
		result.SelfDNSName = status.SelfDNSName
		result.SelfIPs = append([]netip.Addr(nil), status.SelfIPs...)
		result.PeerCount = status.PeerCount
		result.ShieldsUp = status.ShieldsUp
		result.AuthURL = status.AuthURL
		if status.BackendState == "Running" {
			result.RuntimeState = "running"
		} else if status.AuthURL != "" || strings.Contains(strings.ToLower(status.BackendState), "needslogin") {
			result.RuntimeState = "needs-login"
		} else if result.LastError != "" {
			result.RuntimeState = "error"
		} else {
			result.RuntimeState = "starting"
		}
		for _, available := range status.AvailableRoutes {
			result.AvailableRoutes = append(result.AvailableRoutes, controlapi.AvailableIPRoute{
				Prefix:        available.Prefix,
				ProfileID:     configured.ID,
				ProfileName:   result.Name,
				PrimaryRouter: available.PrimaryRouter,
			})
		}
		for _, available := range status.DNSRoutes {
			result.AvailableDNSRoutes = append(result.AvailableDNSRoutes, controlapi.AvailableDNSRoute{
				Domain:      routingpolicy.NormalizeDomain(available.Domain),
				ProfileID:   configured.ID,
				ProfileName: result.Name,
				Source:      available.Source,
				Resolvers:   resolverResourcesForAPI(available.Resolvers),
			})
		}
		for _, domain := range status.SearchDomains {
			domain = routingpolicy.NormalizeDomain(domain)
			if domain == "" || domain == "." {
				continue
			}
			result.AvailableSearchDomains = append(result.AvailableSearchDomains, controlapi.AvailableSearchDomain{
				Domain:      domain,
				ProfileID:   configured.ID,
				ProfileName: result.Name,
			})
		}
	}
	if path, err := profilesocket.Path(s.cfg.SocketDir, configured.ID); err == nil {
		result.LocalAPISocket = path
	}
	return result
}

func resolverResourcesForAPI(resolvers []*dnstype.Resolver) []controlapi.DNSResolver {
	out := make([]controlapi.DNSResolver, 0, len(resolvers))
	for _, resolver := range resolvers {
		if resolver == nil {
			continue
		}
		out = append(out, controlapi.DNSResolver{
			Addr:                resolver.Addr,
			BootstrapResolution: append([]netip.Addr(nil), resolver.BootstrapResolution...),
			UseWithExitNode:     resolver.UseWithExitNode,
		})
	}
	return out
}

func (s *supervisor) ListProfiles(_ context.Context, all bool) (controlapi.Profiles, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := controlapi.Profiles{}
	for _, configured := range s.st.Profiles {
		if configured.Removed && !all {
			continue
		}
		result.Profiles = append(result.Profiles, s.projectProfileLocked(configured))
	}
	sort.Slice(result.Profiles, func(i, j int) bool { return result.Profiles[i].Name < result.Profiles[j].Name })
	return result, nil
}

func (s *supervisor) GetProfile(_ context.Context, name string) (controlapi.Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	configured, err := s.configuredByNameLocked(name)
	if err != nil {
		return controlapi.Profile{}, err
	}
	return s.projectProfileLocked(*configured), nil
}

func (s *supervisor) AddProfile(_ context.Context, request controlapi.AddProfileRequest) (controlapi.Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := cloneState(s.st)
	request.Name = strings.TrimSpace(request.Name)
	if !validProfileName(request.Name) {
		return controlapi.Profile{}, controlapi.NewError("invalid_request", "invalid profile name %q", request.Name)
	}
	if existing, err := s.configuredByNameLocked(request.Name); err == nil {
		if !existing.Removed {
			return controlapi.Profile{}, controlapi.NewError("profile_exists", "profile %q already exists", request.Name)
		}
		existing.Removed = false
		existing.Disabled = request.Disabled
		if request.Hostname != "" {
			existing.Hostname = request.Hostname
		}
		if err := s.store.Save(s.st); err != nil {
			s.st = before
			return controlapi.Profile{}, err
		}
		if !existing.Disabled {
			if err := s.startProfileLocked(*existing, request.AuthKey, ""); err != nil {
				s.lastErrors[existing.ID] = err.Error()
			}
		}
		if err := s.reconcileLocked(); err != nil {
			return controlapi.Profile{}, controlapi.NewError("reconcile_failed", "%v", err)
		}
		return s.projectProfileLocked(*existing), nil
	}

	id, err := randomOpaque("p_", 8)
	if err != nil {
		return controlapi.Profile{}, err
	}
	hostname := strings.TrimSpace(request.Hostname)
	if hostname == "" {
		suffix, err := randomOpaque("", 5)
		if err != nil {
			return controlapi.Profile{}, err
		}
		hostname = "tailmix-" + suffix
	}
	stateDir := strings.TrimSpace(request.StateDir)
	if stateDir == "" {
		stateDir = defaultProfileStateDir(s.store.Path(), id)
	}
	stateDir, err = s.validateNewStateDirLocked(stateDir)
	if err != nil {
		return controlapi.Profile{}, err
	}
	configured := state.Profile{
		ID:       id,
		Name:     request.Name,
		StateDir: stateDir,
		Hostname: hostname,
		Disabled: request.Disabled,
	}
	s.st.Profiles = append(s.st.Profiles, configured)
	state.Normalize(&s.st)
	if err := s.store.Save(s.st); err != nil {
		s.st = before
		return controlapi.Profile{}, err
	}
	if !configured.Disabled {
		if err := s.startProfileLocked(configured, request.AuthKey, ""); err != nil {
			s.lastErrors[configured.ID] = err.Error()
		}
	}
	if err := s.reconcileLocked(); err != nil {
		return controlapi.Profile{}, controlapi.NewError("reconcile_failed", "%v", err)
	}
	return s.projectProfileLocked(configured), nil
}

func (s *supervisor) PatchProfile(_ context.Context, name string, request controlapi.PatchProfileRequest) (controlapi.Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := cloneState(s.st)
	configured, err := s.configuredByNameLocked(name)
	if err != nil {
		return controlapi.Profile{}, err
	}
	restart := false
	if request.Name != nil {
		nextName := strings.TrimSpace(*request.Name)
		if !validProfileName(nextName) {
			return controlapi.Profile{}, controlapi.NewError("invalid_request", "invalid profile name %q", nextName)
		}
		if other, findErr := s.configuredByNameLocked(nextName); findErr == nil && other.ID != configured.ID {
			return controlapi.Profile{}, controlapi.NewError("profile_exists", "profile %q already exists", nextName)
		}
		configured.Name = nextName
	}
	if request.Hostname != nil && configured.Hostname != strings.TrimSpace(*request.Hostname) {
		configured.Hostname = strings.TrimSpace(*request.Hostname)
		restart = true
	}
	if err := s.store.Save(s.st); err != nil {
		s.st = before
		return controlapi.Profile{}, err
	}
	id := configured.ID
	if restart && !configured.Disabled && !configured.Removed {
		_ = s.stopProfileLocked(id)
		if err := s.reconcileLocked(); err != nil {
			return controlapi.Profile{}, controlapi.NewError("reconcile_failed", "%v", err)
		}
		if err := s.startProfileLocked(*configured, "", ""); err != nil {
			s.lastErrors[id] = err.Error()
		}
	}
	if err := s.reconcileLocked(); err != nil {
		return controlapi.Profile{}, controlapi.NewError("reconcile_failed", "%v", err)
	}
	return s.projectProfileLocked(*configured), nil
}

func (s *supervisor) SetProfileEnabled(_ context.Context, name string, enabled bool) (controlapi.Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := cloneState(s.st)
	configured, err := s.configuredByNameLocked(name)
	if err != nil {
		return controlapi.Profile{}, err
	}
	if configured.Removed {
		return controlapi.Profile{}, controlapi.NewError("profile_not_found", "profile %q is removed; add it to restore it", name)
	}
	if configured.Disabled == !enabled {
		return s.projectProfileLocked(*configured), nil
	}
	configured.Disabled = !enabled
	if err := s.store.Save(s.st); err != nil {
		s.st = before
		return controlapi.Profile{}, err
	}
	if enabled {
		if err := s.startProfileLocked(*configured, "", ""); err != nil {
			s.lastErrors[configured.ID] = err.Error()
		}
	} else {
		if err := s.reconcileLocked(); err != nil {
			return controlapi.Profile{}, controlapi.NewError("reconcile_failed", "%v", err)
		}
		if err := s.stopProfileLocked(configured.ID); err != nil {
			s.lastErrors[configured.ID] = err.Error()
		}
	}
	if err := s.reconcileLocked(); err != nil {
		return controlapi.Profile{}, controlapi.NewError("reconcile_failed", "%v", err)
	}
	return s.projectProfileLocked(*configured), nil
}

func (s *supervisor) RestartProfile(_ context.Context, name string) (controlapi.Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	configured, err := s.configuredByNameLocked(name)
	if err != nil {
		return controlapi.Profile{}, err
	}
	if configured.Disabled || configured.Removed {
		return controlapi.Profile{}, controlapi.NewError("profile_disabled", "profile %q is disabled; enable it instead", name)
	}
	_ = s.stopProfileLocked(configured.ID)
	if err := s.reconcileLocked(); err != nil {
		return controlapi.Profile{}, controlapi.NewError("reconcile_failed", "%v", err)
	}
	if err := s.startProfileLocked(*configured, "", ""); err != nil {
		s.lastErrors[configured.ID] = err.Error()
	}
	if err := s.reconcileLocked(); err != nil {
		return controlapi.Profile{}, controlapi.NewError("reconcile_failed", "%v", err)
	}
	return s.projectProfileLocked(*configured), nil
}

func (s *supervisor) RemoveProfile(_ context.Context, name string, purge bool) (controlapi.Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := cloneState(s.st)
	configured, err := s.configuredByNameLocked(name)
	if err != nil {
		return controlapi.Profile{}, err
	}
	if purge && s.profileHasBindingsLocked(configured.ID) {
		return controlapi.Profile{}, controlapi.NewError("profile_has_bindings", "profile %q still has route bindings", name)
	}
	configured.Removed = true
	configured.Disabled = true
	if s.st.ExitNode != nil && s.st.ExitNode.ProfileID == configured.ID {
		s.st.ExitNode = nil
	}
	if err := s.store.Save(s.st); err != nil {
		s.st = before
		return controlapi.Profile{}, err
	}
	if err := s.reconcileLocked(); err != nil {
		return controlapi.Profile{}, controlapi.NewError("reconcile_failed", "%v", err)
	}
	if err := s.stopProfileLocked(configured.ID); err != nil {
		s.lastErrors[configured.ID] = err.Error()
	}
	result := s.projectProfileLocked(*configured)
	if !purge {
		return result, nil
	}
	stateDir := configured.StateDir
	if err := s.validatePurgeLocked(*configured); err != nil {
		return result, err
	}
	if err := os.RemoveAll(stateDir); err != nil {
		return result, controlapi.NewError("purge_failed", "delete profile state %s: %v", stateDir, err)
	}
	id := configured.ID
	s.st.Profiles = deleteProfile(s.st.Profiles, id)
	s.st.Leases = deleteProfileLeases(s.st.Leases, id)
	delete(s.lastErrors, id)
	if err := s.store.Save(s.st); err != nil {
		return result, controlapi.NewError("purge_failed", "save purged profile state: %v", err)
	}
	return result, nil
}

func (s *supervisor) profileHasBindingsLocked(profileID string) bool {
	for _, binding := range s.st.IPRouteBindings {
		if binding.ProfileID == profileID {
			return true
		}
	}
	for _, binding := range s.st.DNSRouteBindings {
		if binding.ProfileID == profileID {
			return true
		}
	}
	return false
}

func (s *supervisor) validatePurgeLocked(configured state.Profile) error {
	target, err := filepath.Abs(configured.StateDir)
	if err != nil || strings.TrimSpace(configured.StateDir) == "" {
		return controlapi.NewError("permission_denied", "profile %q has an unsafe state directory", profileName(configured))
	}
	root, err := filepath.Abs(filepath.Join(filepath.Dir(s.store.Path()), "profiles"))
	if err != nil {
		return controlapi.NewError("permission_denied", "resolve allowed profile-state root: %v", err)
	}
	if resolvedRoot, resolveErr := filepath.EvalSymlinks(root); resolveErr == nil {
		root = resolvedRoot
	}
	if resolvedTarget, resolveErr := filepath.EvalSymlinks(target); resolveErr == nil {
		target = resolvedTarget
	}
	relative, err := filepath.Rel(root, target)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return controlapi.NewError("permission_denied", "profile state directory %s is outside allowed root %s", target, root)
	}
	for _, other := range s.st.Profiles {
		if other.ID == configured.ID {
			continue
		}
		otherDir, _ := filepath.Abs(other.StateDir)
		if otherDir == target {
			return controlapi.NewError("permission_denied", "profile state directory %s is shared", target)
		}
	}
	statePath, _ := filepath.Abs(s.store.Path())
	if relativeToTarget, relErr := filepath.Rel(target, statePath); relErr == nil &&
		relativeToTarget != ".." && !strings.HasPrefix(relativeToTarget, ".."+string(filepath.Separator)) {
		return controlapi.NewError("permission_denied", "profile state directory contains daemon state file")
	}
	return nil
}

func (s *supervisor) validateNewStateDirLocked(raw string) (string, error) {
	target, err := filepath.Abs(strings.TrimSpace(raw))
	if err != nil || strings.TrimSpace(raw) == "" || target == string(filepath.Separator) {
		return "", controlapi.NewError("permission_denied", "unsafe profile state directory %q", raw)
	}
	statePath, _ := filepath.Abs(s.store.Path())
	if relative, relErr := filepath.Rel(target, statePath); relErr == nil &&
		relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", controlapi.NewError("permission_denied", "profile state directory cannot contain the daemon state file")
	}
	for _, configured := range s.st.Profiles {
		existing, _ := filepath.Abs(configured.StateDir)
		if existing == target {
			return "", controlapi.NewError("profile_exists", "profile state directory %s is already used by profile %q", target, profileName(configured))
		}
	}
	return target, nil
}

func deleteProfile(profiles []state.Profile, profileID string) []state.Profile {
	out := profiles[:0]
	for _, configured := range profiles {
		if configured.ID != profileID {
			out = append(out, configured)
		}
	}
	return out
}

func deleteProfileLeases(leases []state.EffectiveLease, profileID string) []state.EffectiveLease {
	out := leases[:0]
	for _, lease := range leases {
		if lease.ProfileID != profileID {
			out = append(out, lease)
		}
	}
	return out
}

var _ controlapi.Backend = (*supervisor)(nil)
