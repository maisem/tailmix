package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/maisem/tailmix/controlapi"
	"github.com/maisem/tailmix/effectiveip"
	tailmixprofile "github.com/maisem/tailmix/profile"
	"github.com/maisem/tailmix/state"
	"github.com/maisem/tailmix/wireguardcfg"
	"github.com/maisem/tailmix/wireguardfilter"
)

func wireGuardApplyDegradedMessage(err error) string {
	return fmt.Sprintf("WireGuard apply left the profile fail-closed; runtime may differ from saved desired state: %v; reapply or restart to retry", err)
}

func (s *supervisor) ApplyWireGuard(_ context.Context, requested wireguardcfg.Config, supplied wireguardcfg.Secrets) (controlapi.WireGuardProfile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireDaemonUpLocked(); err != nil {
		return controlapi.WireGuardProfile{}, err
	}

	config, err := wireguardcfg.NormalizeConfig(requested)
	if err != nil {
		return controlapi.WireGuardProfile{}, controlapi.NewError("invalid_request", "invalid WireGuard configuration: %v", err)
	}
	if s.cfg.Mode != "tun" {
		return controlapi.WireGuardProfile{}, controlapi.NewError("unsupported_mode", "WireGuard profiles require TUN mode")
	}
	if err := validateWireGuardEndpointNames(config); err != nil {
		return controlapi.WireGuardProfile{}, controlapi.NewError("invalid_request", "%v", err)
	}

	before := cloneState(s.st)
	next := cloneState(s.st)
	configured, findErr := profileByName(&next, config.Name)
	create := findErr != nil
	var oldSecrets wireguardcfg.Secrets
	var oldSecretFile string
	wasRunning := false
	if !create {
		if configured.Kind != state.ProfileKindWireGuard {
			return controlapi.WireGuardProfile{}, controlapi.NewError("profile_exists", "profile %q is not a WireGuard profile", config.Name)
		}
		if configured.WireGuard == nil {
			return controlapi.WireGuardProfile{}, controlapi.NewError("invalid_state", "WireGuard profile has no configuration")
		}
		oldSecretFile = configured.WireGuardSecretFile
		oldSecrets, err = readWireGuardSecrets(configured.StateDir, oldSecretFile)
		if err != nil {
			return controlapi.WireGuardProfile{}, controlapi.NewError("invalid_state", "read WireGuard profile secrets: %v", err)
		}
		_, wasRunning = s.runtimes[configured.ID]
	} else {
		id, idErr := randomOpaque("p_", 8)
		if idErr != nil {
			return controlapi.WireGuardProfile{}, idErr
		}
		stateDir, pathErr := s.validateNewStateDirLocked(defaultProfileStateDir(s.store.Path(), id))
		if pathErr != nil {
			return controlapi.WireGuardProfile{}, pathErr
		}
		next.Profiles = append(next.Profiles, state.Profile{
			ID:       id,
			Name:     config.Name,
			Kind:     state.ProfileKindWireGuard,
			StateDir: stateDir,
		})
		configured, _ = profileByName(&next, config.Name)
	}
	profileID := configured.ID
	profileStateDir := configured.StateDir

	secrets, err := completeWireGuardSecrets(config, supplied, oldSecrets, create)
	if err != nil {
		return controlapi.WireGuardProfile{}, controlapi.NewError("invalid_request", "%v", err)
	}
	if err := validateWireGuardKeyOwnership(config, secrets); err != nil {
		return controlapi.WireGuardProfile{}, controlapi.NewError("invalid_request", "%v", err)
	}
	secretFile, err := writeWireGuardSecrets(profileStateDir, secrets)
	if err != nil {
		return controlapi.WireGuardProfile{}, fmt.Errorf("write WireGuard profile secrets: %w", err)
	}
	desiredSaved := false
	defer func() {
		if !desiredSaved {
			_ = removeWireGuardSecrets(profileStateDir, secretFile)
		}
	}()

	configured.Kind = state.ProfileKindWireGuard
	configured.Removed = false
	if create || beforeProfileRemoved(before, configured.ID) {
		configured.Disabled = false
	}
	configured.Hostname = ""
	configured.MagicDNSSuffix = config.DNSSuffix
	configured.WireGuard = configPointer(config)
	configured.WireGuardSecretFile = secretFile
	configured, err = normalizeProfileByID(&next, profileID)
	if err != nil {
		return controlapi.WireGuardProfile{}, controlapi.NewError("invalid_state", "%v", err)
	}

	var engineApply *tailmixprofile.WireGuardApply
	if wasRunning {
		managed := s.runtimes[configured.ID]
		engine, ok := managed.runtime.Engine.(*tailmixprofile.WireGuardEngine)
		if !ok {
			return controlapi.WireGuardProfile{}, controlapi.NewError("invalid_state", "WireGuard profile has an incompatible engine")
		}
		engineApply, err = engine.PrepareApply(s.ctx, config, secrets)
		if err != nil {
			return controlapi.WireGuardProfile{}, controlapi.NewError("apply_failed", "%v", err)
		}
	}

	// Make the complete desired profile and its secrets durable before touching
	// the live dataplane. Once mutation starts, failures are forward-only: the
	// saved desired state is the retry target for reapply, restart, or normal
	// reconciliation.
	if err := s.store.Save(next); err != nil {
		return controlapi.WireGuardProfile{}, err
	}
	s.st = next
	desiredSaved = true
	if oldSecretFile != "" && oldSecretFile != secretFile {
		_ = removeWireGuardSecrets(profileStateDir, oldSecretFile)
	}

	if engineApply != nil {
		if err := engineApply.Apply(); err != nil {
			s.lastErrors[configured.ID] = wireGuardApplyDegradedMessage(err)
			return controlapi.WireGuardProfile{}, controlapi.NewError("apply_failed", "%v", err)
		}
	}

	start := !configured.Disabled && !wasRunning
	var startedEngine *tailmixprofile.WireGuardEngine
	if start {
		if err := s.startProfileLockedWithWireGuardTransition(*configured, "", "", true); err != nil {
			s.lastErrors[configured.ID] = wireGuardApplyDegradedMessage(err)
			return controlapi.WireGuardProfile{}, controlapi.NewError("apply_failed", "start WireGuard profile: %v", err)
		}
		managed := s.runtimes[configured.ID]
		engine, ok := managed.runtime.Engine.(*tailmixprofile.WireGuardEngine)
		if !ok {
			return controlapi.WireGuardProfile{}, controlapi.NewError("invalid_state", "WireGuard profile has an incompatible engine")
		}
		startedEngine = engine
	}
	if !configured.Disabled {
		if err := s.reconcileLocked(); err != nil {
			// reconcileLocked can replace the in-memory state with a derived plan
			// before its final save. Keep memory aligned with the already durable
			// desired profile, but do not compensate mapper, routes, or host state.
			s.st = next
			s.lastErrors[configured.ID] = wireGuardApplyDegradedMessage(err)
			return controlapi.WireGuardProfile{}, controlapi.NewError("reconcile_failed", "%v", err)
		}
	}
	if engineApply != nil {
		if err := engineApply.Commit(); err != nil {
			s.lastErrors[configured.ID] = wireGuardApplyDegradedMessage(err)
			return controlapi.WireGuardProfile{}, controlapi.NewError("apply_failed", "publish WireGuard packet filter: %v", err)
		}
	}
	if startedEngine != nil {
		if err := startedEngine.CommitStartPolicy(); err != nil {
			s.lastErrors[configured.ID] = wireGuardApplyDegradedMessage(err)
			return controlapi.WireGuardProfile{}, controlapi.NewError("apply_failed", "publish WireGuard packet filter: %v", err)
		}
	}
	delete(s.lastErrors, configured.ID)
	return s.wireGuardProfileLocked(*configured)
}

func (s *supervisor) WireGuardProfile(_ context.Context, name string) (controlapi.WireGuardProfile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	configured, err := s.configuredByNameLocked(strings.TrimSpace(name))
	if err != nil {
		return controlapi.WireGuardProfile{}, err
	}
	if configured.Kind != state.ProfileKindWireGuard || configured.WireGuard == nil {
		return controlapi.WireGuardProfile{}, controlapi.NewError("invalid_request", "profile %q is not a WireGuard profile", name)
	}
	return s.wireGuardProfileLocked(*configured)
}

func (s *supervisor) SetWireGuardShieldsUp(_ context.Context, name string, enabled bool) (controlapi.WireGuardProfile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	configured, err := s.configuredByNameLocked(strings.TrimSpace(name))
	if err != nil {
		return controlapi.WireGuardProfile{}, err
	}
	if configured.Removed {
		return controlapi.WireGuardProfile{}, controlapi.NewError("profile_not_found", "profile %q is removed", name)
	}
	if configured.Kind != state.ProfileKindWireGuard || configured.WireGuard == nil {
		return controlapi.WireGuardProfile{}, controlapi.NewError("invalid_request", "profile %q is not a WireGuard profile", name)
	}
	if configured.WireGuardShieldsUp == enabled {
		return s.wireGuardProfileLocked(*configured)
	}

	exitIP := netip.Addr{}
	if s.st.ExitNode != nil && s.st.ExitNode.ProfileID == configured.ID {
		exitIP = s.st.ExitNode.PeerIP
	}
	managed := s.runtimes[configured.ID]
	var update *tailmixprofile.WireGuardShieldsUpdate
	if managed != nil {
		engine, ok := managed.runtime.Engine.(*tailmixprofile.WireGuardEngine)
		if !ok {
			return controlapi.WireGuardProfile{}, controlapi.NewError("invalid_state", "WireGuard profile has an incompatible engine")
		}
		update, err = engine.PrepareShieldsUp(enabled)
	} else {
		_, err = wireguardfilter.Compile(*configured.WireGuard, exitIP, enabled, nil)
	}
	if err != nil {
		return controlapi.WireGuardProfile{}, controlapi.NewError("invalid_state", "compile WireGuard packet filter: %v", err)
	}
	if update != nil {
		if err := update.ApplyBeforeSave(); err != nil {
			return controlapi.WireGuardProfile{}, controlapi.NewError("apply_failed", "enable WireGuard shields-up: %v", err)
		}
	}

	next := cloneState(s.st)
	nextConfigured := profileByID(&next, configured.ID)
	nextConfigured.WireGuardShieldsUp = enabled
	if err := s.store.Save(next); err != nil {
		if update != nil {
			_ = update.Rollback()
		}
		return controlapi.WireGuardProfile{}, err
	}
	s.st = next
	configured = profileByID(&s.st, configured.ID)
	if update != nil {
		if err := update.Commit(); err != nil {
			s.lastErrors[configured.ID] = err.Error()
			return controlapi.WireGuardProfile{}, controlapi.NewError("apply_failed", "publish WireGuard shields-up policy: %v", err)
		}
		if status, statusErr := managed.runtime.Engine.Status(s.ctx); statusErr == nil {
			managed.status = status
		}
		delete(s.lastErrors, configured.ID)
	}
	return s.wireGuardProfileLocked(*configured)
}

func (s *supervisor) wireGuardProfileLocked(configured state.Profile) (controlapi.WireGuardProfile, error) {
	config := configured.WireGuard
	if config == nil {
		return controlapi.WireGuardProfile{}, controlapi.NewError("invalid_state", "WireGuard profile has no configuration")
	}
	resolutions, err := wireguardfilter.DestinationResolutions(*config)
	if err != nil {
		return controlapi.WireGuardProfile{}, controlapi.NewError("invalid_state", "resolve WireGuard packet filter destinations: %v", err)
	}
	result := controlapi.WireGuardProfile{
		Name:         profileName(configured),
		Kind:         state.ProfileKindWireGuard,
		Addresses:    append([]netip.Addr(nil), config.Addresses...),
		DNSSuffix:    config.DNSSuffix,
		PacketFilter: config.PacketFilter.Clone(),
		ShieldsUp:    configured.WireGuardShieldsUp,
		GrantCount:   len(config.PacketFilter.Grants),
	}
	for _, resolution := range resolutions {
		result.DestinationResolutions = append(result.DestinationResolutions, controlapi.WireGuardDestinationResolution{
			GrantIndex: resolution.GrantIndex,
			Selector:   resolution.Selector,
			State:      resolution.State,
			Reason:     resolution.Reason,
		})
	}
	status := tailmixprofile.Status{}
	if managed := s.runtimes[configured.ID]; managed != nil {
		var err error
		status, err = managed.runtime.Engine.Status(s.ctx)
		if err != nil {
			return controlapi.WireGuardProfile{}, err
		}
		result.PublicKey = status.PublicKey
		result.ListenPort = status.ListenPort
	} else if secrets, err := readWireGuardSecrets(configured.StateDir, configured.WireGuardSecretFile); err == nil && secrets.PrivateKey != nil {
		if public, publicErr := secrets.PrivateKey.Public(); publicErr == nil {
			result.PublicKey = public.String()
		}
	}
	statusByName := make(map[string]tailmixprofile.PeerStatus, len(status.Peers))
	for _, peer := range status.Peers {
		statusByName[peer.NodeID] = peer
	}
	leaseByKey := make(map[effectiveip.NodeKey]netip.Addr, len(s.st.Leases))
	for _, lease := range leasesFromState(s.st.Leases) {
		leaseByKey[lease.NodeKey] = lease.EffectiveIP
	}
	for _, peer := range config.Peers {
		observed := statusByName[peer.Name]
		item := controlapi.WireGuardPeer{
			Name:             peer.Name,
			PublicKey:        peer.PublicKey.String(),
			Endpoint:         peer.Endpoint,
			Online:           observed.Online,
			LastHandshake:    observed.LastHandshake,
			ReceiveBytes:     boundedCounter(observed.RxBytes),
			TransmitBytes:    boundedCounter(observed.TxBytes),
			Addresses:        append([]netip.Addr(nil), peer.Addresses...),
			Routes:           append([]netip.Prefix(nil), peer.Routes...),
			ExitNode:         peer.ExitNode,
			ExitNodeSelected: status.ExitNodeID == peer.Name,
		}
		for _, address := range peer.Addresses {
			if effective, ok := leaseByKey[effectiveip.NodeKey{ProfileID: configured.ID, NodeID: peer.Name, CanonicalIP: address}]; ok {
				item.EffectiveAddresses = append(item.EffectiveAddresses, effective)
			}
		}
		result.Peers = append(result.Peers, item)
	}
	sort.Slice(result.Peers, func(i, j int) bool { return result.Peers[i].Name < result.Peers[j].Name })
	return result, nil
}

func configPointer(config wireguardcfg.Config) *wireguardcfg.Config {
	clone := config.Clone()
	return &clone
}

func beforeProfileRemoved(st state.State, profileID string) bool {
	for _, profile := range st.Profiles {
		if profile.ID == profileID {
			return profile.Removed
		}
	}
	return false
}

func profileByID(st *state.State, profileID string) *state.Profile {
	for i := range st.Profiles {
		if st.Profiles[i].ID == profileID {
			return &st.Profiles[i]
		}
	}
	return nil
}

func normalizeProfileByID(st *state.State, profileID string) (*state.Profile, error) {
	state.Normalize(st)
	configured := profileByID(st, profileID)
	if configured == nil {
		return nil, errors.New("profile disappeared during normalization")
	}
	return configured, nil
}

func validateWireGuardKeyOwnership(config wireguardcfg.Config, secrets wireguardcfg.Secrets) error {
	if secrets.PrivateKey == nil {
		return errors.New("WireGuard private key is required")
	}
	public, err := secrets.PrivateKey.Public()
	if err != nil {
		return errors.New("derive WireGuard public key")
	}
	for _, peer := range config.Peers {
		if peer.PublicKey == public {
			return errors.New("a peer public key matches the profile public key")
		}
	}
	return nil
}

func validateWireGuardEndpointNames(config wireguardcfg.Config) error {
	peerNames := make(map[string]bool, len(config.Peers))
	for _, peer := range config.Peers {
		peerNames[strings.ToLower(peer.Name+"."+config.DNSSuffix)] = true
	}
	for _, peer := range config.Peers {
		if peer.Endpoint == "" {
			continue
		}
		host, _, err := net.SplitHostPort(peer.Endpoint)
		if err == nil && peerNames[strings.ToLower(strings.TrimSuffix(host, "."))] {
			return errors.New("a peer endpoint resolves through the profile's own DNS records")
		}
	}
	return nil
}

func boundedCounter(value uint64) int64 {
	if value > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(value)
}
