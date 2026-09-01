package profile

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	goruntime "runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/maisem/tailmix/wireguardcfg"
	"github.com/maisem/tailmix/wireguardfilter"
	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/tsconst"
)

// WireGuardEngineConfig describes a WireGuard profile engine. Bind is
// optional and primarily useful to tests; production engines use the system
// UDP bind.
type WireGuardEngineConfig struct {
	ProfileID string
	Alias     string
	Config    wireguardcfg.Config
	Secrets   wireguardcfg.Secrets
	Tun       tun.Device
	Bind      conn.Bind
	ShieldsUp bool
}

// WireGuardEngine owns one long-lived wireguard-go device. Configuration
// changes are applied to that device through UAPI rather than replacing it.
type WireGuardEngine struct {
	mu sync.Mutex

	profileID   string
	alias       string
	tun         tun.Device
	filteredTun *wireguardfilter.Device
	policy      *wireguardfilter.Policy
	bind        conn.Bind
	bypassMark  bool
	dev         *device.Device
	config      wireguardcfg.Config
	runtime     wireguardcfg.Config
	secrets     wireguardcfg.Secrets
	exitIP      netip.Addr
	shieldsUp   bool
	started     bool
	closed      bool
	updateCh    chan struct{}
}

func NewWireGuardEngine(cfg WireGuardEngineConfig) *WireGuardEngine {
	return &WireGuardEngine{
		profileID: cfg.ProfileID,
		alias:     cfg.Alias,
		tun:       cfg.Tun,
		bind:      cfg.Bind,
		config:    cloneWGConfig(cfg.Config),
		secrets:   cloneWGSecrets(cfg.Secrets),
		shieldsUp: cfg.ShieldsUp,
		updateCh:  make(chan struct{}),
	}
}

func (e *WireGuardEngine) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	runtime, err := resolveWGConfigEndpoints(ctx, e.config)
	if err != nil {
		return err
	}
	policy, err := wireguardfilter.Compile(e.config, netip.Addr{}, e.shieldsUp, nil)
	if err != nil {
		return fmt.Errorf("compile wireguard packet filter: %w", err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return errors.New("wireguard engine is closed")
	}
	if e.started {
		return nil
	}
	if e.tun == nil {
		return errors.New("wireguard engine requires a TUN device")
	}
	filteredTun, err := wireguardfilter.NewDevice(e.tun, policy)
	if err != nil {
		return err
	}
	secrets, err := effectiveWGSecrets(wireguardcfg.Secrets{}, e.config, e.secrets, true)
	if err != nil {
		return err
	}
	bind := e.bind
	bypassMark := goruntime.GOOS == "linux" && bind == nil
	if bind == nil {
		bind = conn.NewDefaultBind()
	}
	dev := device.NewDevice(filteredTun, bind, device.NewLogger(device.LogLevelSilent, ""))
	if err := dev.IpcSet(fullWGConfig(runtime, secrets, netip.Addr{}, bypassMark)); err != nil {
		dev.Close()
		return errors.New("configure wireguard device")
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return errors.New("start wireguard device")
	}
	e.dev = dev
	e.filteredTun = filteredTun
	e.policy = policy
	e.bind = bind
	e.bypassMark = bypassMark
	e.secrets = secrets
	e.runtime = runtime
	e.started = true
	e.notifyLocked()
	return nil
}

func (e *WireGuardEngine) Close() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	e.started = false
	dev := e.dev
	e.dev = nil
	e.filteredTun = nil
	e.policy = nil
	e.notifyLocked()
	e.mu.Unlock()
	if dev != nil {
		dev.Close()
	}
	return nil
}

func (e *WireGuardEngine) Dial(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("dial is not supported by wireguard profiles")
}

// WireGuardApply is a staged update to a running WireGuard engine. Apply
// installs any restrictive transition and changes the device. Commit publishes
// the final policy after external state persistence; Rollback restores the old
// device and policy.
type WireGuardApply struct {
	engine *WireGuardEngine

	oldConfig  wireguardcfg.Config
	oldRuntime wireguardcfg.Config
	oldSecrets wireguardcfg.Secrets
	oldExit    netip.Addr
	oldPolicy  *wireguardfilter.Policy

	newConfig  wireguardcfg.Config
	newRuntime wireguardcfg.Config
	newSecrets wireguardcfg.Secrets
	newExit    netip.Addr

	forward          string
	transition       *wireguardfilter.Policy
	final            *wireguardfilter.Policy
	filterTransition bool
	applied          bool
}

// PrepareApply validates and compiles cfg without changing the running engine.
func (e *WireGuardEngine) PrepareApply(ctx context.Context, cfg wireguardcfg.Config, supplied wireguardcfg.Secrets) (*WireGuardApply, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	runtime, err := resolveWGConfigEndpoints(ctx, cfg)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	if !e.started || e.dev == nil || e.filteredTun == nil || e.policy == nil {
		e.mu.Unlock()
		return nil, errors.New("wireguard engine is not started")
	}
	secrets, err := effectiveWGSecrets(e.secrets, cfg, supplied, false)
	if err != nil {
		e.mu.Unlock()
		return nil, err
	}
	apply := &WireGuardApply{
		engine:     e,
		oldConfig:  cloneWGConfig(e.config),
		oldRuntime: cloneWGConfig(e.runtime),
		oldSecrets: cloneWGSecrets(e.secrets),
		oldExit:    e.exitIP,
		oldPolicy:  e.policy,
		newConfig:  cloneWGConfig(cfg),
		newRuntime: cloneWGConfig(runtime),
		newSecrets: cloneWGSecrets(secrets),
		newExit:    validExitSelection(cfg, e.exitIP),
	}
	apply.forward = diffWGConfig(apply.oldRuntime, apply.oldSecrets, apply.oldExit, apply.newRuntime, apply.newSecrets, apply.newExit)
	identityChanged := !sameWGFilterIdentity(apply.oldConfig, apply.oldSecrets, apply.oldExit, apply.newConfig, apply.newSecrets, apply.newExit)
	policyChanged := !sameWGPacketFilter(apply.oldConfig.PacketFilter, apply.newConfig.PacketFilter)
	apply.filterTransition = identityChanged || policyChanged
	shieldsUp := e.shieldsUp
	e.mu.Unlock()

	if apply.filterTransition {
		share := apply.oldPolicy
		if identityChanged {
			share = nil
		}
		apply.transition, err = wireguardfilter.Compile(apply.newConfig, apply.newExit, true, share)
		if err != nil {
			return nil, fmt.Errorf("compile restrictive wireguard packet filter: %w", err)
		}
		apply.final, err = wireguardfilter.Compile(apply.newConfig, apply.newExit, shieldsUp, apply.transition)
		if err != nil {
			return nil, fmt.Errorf("compile wireguard packet filter: %w", err)
		}
	}
	return apply, nil
}

// Apply installs the staged restrictive transition and WireGuard UAPI.
func (a *WireGuardApply) Apply() error {
	e := a.engine
	e.mu.Lock()
	defer e.mu.Unlock()
	if a.applied {
		return nil
	}
	if !e.started || e.dev == nil || e.filteredTun == nil || e.policy != a.oldPolicy {
		return errors.New("wireguard engine changed while apply was staged")
	}
	if a.filterTransition {
		if err := e.filteredTun.Install(a.transition); err != nil {
			return err
		}
		e.policy = a.transition
	}
	if a.forward != "" {
		if err := e.dev.IpcSet(a.forward); err != nil {
			rollbackErr := e.dev.IpcSet(fullWGConfig(a.oldRuntime, a.oldSecrets, a.oldExit, e.bypassMark))
			if rollbackErr == nil && a.filterTransition {
				_ = e.filteredTun.Install(a.oldPolicy)
				e.policy = a.oldPolicy
			}
			if rollbackErr != nil {
				return errors.Join(errors.New("apply wireguard configuration"), errors.New("restore wireguard configuration"))
			}
			return errors.New("apply wireguard configuration")
		}
	}
	e.config = cloneWGConfig(a.newConfig)
	e.runtime = cloneWGConfig(a.newRuntime)
	e.secrets = cloneWGSecrets(a.newSecrets)
	e.exitIP = a.newExit
	a.applied = true
	e.notifyLocked()
	return nil
}

// Commit publishes the staged final policy after desired state is durable.
func (a *WireGuardApply) Commit() error {
	e := a.engine
	e.mu.Lock()
	defer e.mu.Unlock()
	if !a.applied {
		return errors.New("wireguard apply has not been applied")
	}
	if !a.filterTransition {
		return nil
	}
	if e.policy != a.transition {
		return errors.New("wireguard packet filter changed during apply")
	}
	if err := e.filteredTun.Install(a.final); err != nil {
		return err
	}
	e.policy = a.final
	return nil
}

// Rollback restores the old WireGuard UAPI and publishes the old policy last.
// If device rollback fails, the restrictive transition remains installed.
func (a *WireGuardApply) Rollback() error {
	e := a.engine
	e.mu.Lock()
	defer e.mu.Unlock()
	if !a.applied {
		return nil
	}
	if a.filterTransition {
		if err := e.filteredTun.Install(a.transition); err != nil {
			return err
		}
		e.policy = a.transition
	}
	if err := e.dev.IpcSet(fullWGConfig(a.oldRuntime, a.oldSecrets, a.oldExit, e.bypassMark)); err != nil {
		return errors.New("restore wireguard configuration")
	}
	e.config = cloneWGConfig(a.oldConfig)
	e.runtime = cloneWGConfig(a.oldRuntime)
	e.secrets = cloneWGSecrets(a.oldSecrets)
	e.exitIP = a.oldExit
	if a.filterTransition {
		if err := e.filteredTun.Install(a.oldPolicy); err != nil {
			return err
		}
		e.policy = a.oldPolicy
	}
	a.applied = false
	e.notifyLocked()
	return nil
}

// Apply incrementally reconciles cfg and immediately commits its policy. Daemon
// state transactions should use PrepareApply so persistence precedes Commit.
func (e *WireGuardEngine) Apply(ctx context.Context, cfg wireguardcfg.Config, supplied wireguardcfg.Secrets) error {
	apply, err := e.PrepareApply(ctx, cfg, supplied)
	if err != nil {
		return err
	}
	if err := apply.Apply(); err != nil {
		return err
	}
	if err := apply.Commit(); err != nil {
		_ = apply.Rollback()
		return err
	}
	return nil
}

// WireGuardShieldsUpdate is a staged shields-up policy replacement.
type WireGuardShieldsUpdate struct {
	engine  *WireGuardEngine
	old     *wireguardfilter.Policy
	target  *wireguardfilter.Policy
	enabled bool
	applied bool
	noop    bool
}

// PrepareShieldsUp compiles a shields-up replacement without publishing it.
func (e *WireGuardEngine) PrepareShieldsUp(enabled bool) (*WireGuardShieldsUpdate, error) {
	e.mu.Lock()
	if !e.started || e.dev == nil || e.filteredTun == nil || e.policy == nil {
		e.mu.Unlock()
		return nil, errors.New("wireguard engine is not started")
	}
	update := &WireGuardShieldsUpdate{engine: e, old: e.policy, enabled: enabled, noop: e.shieldsUp == enabled}
	cfg := cloneWGConfig(e.config)
	exitIP := e.exitIP
	e.mu.Unlock()
	if update.noop {
		return update, nil
	}
	policy, err := wireguardfilter.Compile(cfg, exitIP, enabled, update.old)
	if err != nil {
		return nil, fmt.Errorf("compile wireguard packet filter: %w", err)
	}
	update.target = policy
	return update, nil
}

// ApplyBeforeSave publishes an enabling shields-up policy before persistence.
// Disabling remains restrictive until Commit is called after persistence.
func (u *WireGuardShieldsUpdate) ApplyBeforeSave() error {
	if u.noop || !u.enabled {
		return nil
	}
	e := u.engine
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.policy != u.old {
		return errors.New("wireguard packet filter changed while shields-up update was staged")
	}
	if err := e.filteredTun.Install(u.target); err != nil {
		return err
	}
	e.policy = u.target
	u.applied = true
	return nil
}

// Commit publishes a disabling replacement after persistence and records the
// new override state.
func (u *WireGuardShieldsUpdate) Commit() error {
	e := u.engine
	e.mu.Lock()
	defer e.mu.Unlock()
	if u.noop {
		return nil
	}
	if u.enabled {
		if !u.applied || e.policy != u.target {
			return errors.New("shields-up policy was not installed before commit")
		}
	} else {
		if e.policy != u.old {
			return errors.New("wireguard packet filter changed while shields-up update was staged")
		}
		if err := e.filteredTun.Install(u.target); err != nil {
			return err
		}
		e.policy = u.target
	}
	e.shieldsUp = u.enabled
	e.notifyLocked()
	return nil
}

// Rollback restores the old policy after a failed persistence operation.
func (u *WireGuardShieldsUpdate) Rollback() error {
	if u.noop || !u.applied {
		return nil
	}
	e := u.engine
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.policy != u.target {
		return errors.New("wireguard packet filter changed during shields-up rollback")
	}
	if err := e.filteredTun.Install(u.old); err != nil {
		return err
	}
	e.policy = u.old
	u.applied = false
	return nil
}

func (e *WireGuardEngine) SetExitNodeIP(ctx context.Context, ip netip.Addr) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	e.mu.Lock()
	if !e.started || e.dev == nil || e.filteredTun == nil || e.policy == nil {
		e.mu.Unlock()
		return errors.New("wireguard engine is not started")
	}
	if ip.IsValid() && !validExitSelection(e.config, ip).IsValid() {
		e.mu.Unlock()
		return errors.New("address does not identify an eligible exit node")
	}
	if ip == e.exitIP {
		e.mu.Unlock()
		return nil
	}
	cfg := cloneWGConfig(e.config)
	oldExit := e.exitIP
	oldPolicy := e.policy
	shieldsUp := e.shieldsUp
	e.mu.Unlock()

	transition, err := wireguardfilter.Compile(cfg, ip, true, nil)
	if err != nil {
		return fmt.Errorf("compile restrictive wireguard packet filter: %w", err)
	}
	final, err := wireguardfilter.Compile(cfg, ip, shieldsUp, transition)
	if err != nil {
		return fmt.Errorf("compile wireguard packet filter: %w", err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.started || e.dev == nil || e.filteredTun == nil || e.policy != oldPolicy || e.exitIP != oldExit {
		return errors.New("wireguard engine changed while exit-node update was staged")
	}
	if err := e.filteredTun.Install(transition); err != nil {
		return err
	}
	e.policy = transition
	uapi := diffWGConfig(e.runtime, e.secrets, oldExit, e.runtime, e.secrets, ip)
	if err := e.dev.IpcSet(uapi); err != nil {
		rollbackErr := e.dev.IpcSet(fullWGConfig(e.runtime, e.secrets, oldExit, e.bypassMark))
		if rollbackErr == nil {
			_ = e.filteredTun.Install(oldPolicy)
			e.policy = oldPolicy
		}
		if rollbackErr != nil {
			return errors.Join(errors.New("set wireguard exit node"), errors.New("restore wireguard exit node"))
		}
		return errors.New("set wireguard exit node")
	}
	e.exitIP = ip
	if err := e.filteredTun.Install(final); err != nil {
		return err
	}
	e.policy = final
	e.notifyLocked()
	return nil
}

func (e *WireGuardEngine) WatchUpdates(ctx context.Context, notify func()) error {
	if notify == nil {
		return errors.New("nil update callback")
	}
	for {
		e.mu.Lock()
		ch := e.updateCh
		e.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil
		case <-ch:
			notify()
		}
	}
}

func (e *WireGuardEngine) notifyLocked() {
	close(e.updateCh)
	e.updateCh = make(chan struct{})
}

func (e *WireGuardEngine) Status(ctx context.Context) (Status, error) {
	if err := ctx.Err(); err != nil {
		return Status{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	st := Status{
		ProfileID:      e.profileID,
		Alias:          e.alias,
		Kind:           "wireguard",
		MagicDNSSuffix: e.config.DNSSuffix,
		SelfNodeID:     e.config.Name,
		SelfIPs:        slices.Clone(e.config.Addresses),
		RouteAll:       true,
		ShieldsUp:      e.shieldsUp,
	}
	if !e.started || e.dev == nil {
		return st, nil
	}
	uapi, err := e.dev.IpcGet()
	if err != nil {
		return Status{}, errors.New("read wireguard status")
	}
	runtime := parseWGDeviceStatus(uapi)
	st.BackendState = "Running"
	st.ListenPort = runtime.listenPort
	if public, err := e.secrets.PrivateKey.Public(); err == nil {
		st.PublicKey = public.String()
	}
	now := time.Now()
	for _, peer := range e.config.Peers {
		online := false
		peerRuntime := runtime.peers[peer.PublicKey.UAPIHex()]
		if handshake := peerRuntime.lastHandshake; !handshake.IsZero() {
			online = now.Sub(handshake) <= 3*time.Minute
		}
		selected := peerHasAddress(peer, e.exitIP)
		st.Peers = append(st.Peers, PeerStatus{
			NodeID:         peer.Name,
			DNSName:        wgDNSName(peer.Name, e.config.DNSSuffix),
			PublicKey:      peer.PublicKey.String(),
			Endpoint:       peer.Endpoint,
			TailscaleIPs:   slices.Clone(peer.Addresses),
			Online:         online,
			LastHandshake:  peerRuntime.lastHandshake,
			RxBytes:        peerRuntime.rxBytes,
			TxBytes:        peerRuntime.txBytes,
			ExitNode:       selected,
			ExitNodeOption: peer.ExitNode,
		})
		if selected {
			st.ExitNodeID = peer.Name
		}
		for _, prefix := range peer.Routes {
			if prefix.IsValid() && prefix.Bits() != 0 {
				st.AvailableRoutes = append(st.AvailableRoutes, RouteStatus{Prefix: prefix.Masked(), PrimaryRouter: peer.Name})
			}
		}
	}
	sort.Slice(st.Peers, func(i, j int) bool { return st.Peers[i].NodeID < st.Peers[j].NodeID })
	sort.Slice(st.AvailableRoutes, func(i, j int) bool {
		if st.AvailableRoutes[i].Prefix != st.AvailableRoutes[j].Prefix {
			return st.AvailableRoutes[i].Prefix.String() < st.AvailableRoutes[j].Prefix.String()
		}
		return st.AvailableRoutes[i].PrimaryRouter < st.AvailableRoutes[j].PrimaryRouter
	})
	st.PeerCount = len(st.Peers)
	return st, nil
}

func fullWGConfig(cfg wireguardcfg.Config, secrets wireguardcfg.Secrets, exitIP netip.Addr, bypassMark bool) string {
	var b strings.Builder
	if secrets.PrivateKey != nil {
		fmt.Fprintf(&b, "private_key=%s\n", secrets.PrivateKey.UAPIHex())
	}
	if bypassMark {
		fmt.Fprintf(&b, "fwmark=%d\n", tsconst.LinuxBypassMarkNum)
	}
	fmt.Fprintf(&b, "listen_port=%d\nreplace_peers=true\n", cfg.ListenPort)
	allow4, allow6 := wgAddressFamilies(cfg)
	for _, peer := range cfg.Peers {
		writeWGPeer(&b, peer, secrets.PresharedKeyByPeer[peer.Name], peerHasAddress(peer, exitIP), allow4, allow6)
	}
	return b.String()
}

func diffWGConfig(oldCfg wireguardcfg.Config, oldSecrets wireguardcfg.Secrets, oldExit netip.Addr, newCfg wireguardcfg.Config, newSecrets wireguardcfg.Secrets, newExit netip.Addr) string {
	var b strings.Builder
	var removeFirst, removeLast strings.Builder
	if oldSecrets.PrivateKey != nil && newSecrets.PrivateKey != nil && *oldSecrets.PrivateKey != *newSecrets.PrivateKey {
		fmt.Fprintf(&b, "private_key=%s\n", newSecrets.PrivateKey.UAPIHex())
	}
	if oldCfg.ListenPort != newCfg.ListenPort {
		fmt.Fprintf(&b, "listen_port=%d\n", newCfg.ListenPort)
	}
	oldByKey := make(map[wireguardcfg.Key]wireguardcfg.Peer, len(oldCfg.Peers))
	newByKey := make(map[wireguardcfg.Key]wireguardcfg.Peer, len(newCfg.Peers))
	for _, peer := range oldCfg.Peers {
		oldByKey[peer.PublicKey] = peer
	}
	for _, peer := range newCfg.Peers {
		newByKey[peer.PublicKey] = peer
	}
	for key, oldPeer := range oldByKey {
		newPeer, ok := newByKey[key]
		// UAPI cannot clear an endpoint, so replace this one peer.
		if oldPeer.Endpoint != "" && ok && newPeer.Endpoint == "" {
			fmt.Fprintf(&removeFirst, "public_key=%s\nremove=true\n", key.UAPIHex())
		} else if !ok {
			// Remove missing peers after additions, so a public-key rotation
			// never introduces an avoidable connectivity gap.
			fmt.Fprintf(&removeLast, "public_key=%s\nremove=true\n", key.UAPIHex())
		}
	}
	b.WriteString(removeFirst.String())
	allow4, allow6 := wgAddressFamilies(newCfg)
	for key, peer := range newByKey {
		oldPeer, existed := oldByKey[key]
		oldPSK := oldSecrets.PresharedKeyByPeer[oldPeer.Name]
		newPSK := newSecrets.PresharedKeyByPeer[peer.Name]
		oldSelected := existed && peerHasAddress(oldPeer, oldExit)
		newSelected := peerHasAddress(peer, newExit)
		replaced := existed && oldPeer.Endpoint != "" && peer.Endpoint == ""
		if !existed || replaced || !sameWGPeer(oldPeer, peer) || oldPSK != newPSK || oldSelected != newSelected {
			writeWGPeer(&b, peer, newPSK, newSelected, allow4, allow6)
		}
	}
	b.WriteString(removeLast.String())
	return b.String()
}

func writeWGPeer(b *strings.Builder, peer wireguardcfg.Peer, psk wireguardcfg.Key, selected, allow4, allow6 bool) {
	fmt.Fprintf(b, "public_key=%s\n", peer.PublicKey.UAPIHex())
	fmt.Fprintf(b, "preshared_key=%s\n", psk.UAPIHex())
	if peer.Endpoint != "" {
		fmt.Fprintf(b, "endpoint=%s\n", peer.Endpoint)
	}
	fmt.Fprintf(b, "persistent_keepalive_interval=%d\nreplace_allowed_ips=true\n", uint64(peer.Keepalive/time.Second))
	for _, prefix := range wgAllowedIPs(peer, selected, allow4, allow6) {
		fmt.Fprintf(b, "allowed_ip=%s\n", prefix)
	}
}

func wgAllowedIPs(peer wireguardcfg.Peer, selected, allow4, allow6 bool) []netip.Prefix {
	result := slices.Clone(peer.Routes)
	for _, addr := range peer.Addresses {
		result = append(result, netip.PrefixFrom(addr, addr.BitLen()))
	}
	if selected {
		if allow4 {
			result = append(result, netip.MustParsePrefix("0.0.0.0/0"))
		}
		if allow6 {
			result = append(result, netip.MustParsePrefix("::/0"))
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].String() < result[j].String() })
	return slices.Compact(result)
}

func wgAddressFamilies(cfg wireguardcfg.Config) (v4, v6 bool) {
	for _, addr := range cfg.Addresses {
		if addr.Is4() {
			v4 = true
		} else if addr.Is6() {
			v6 = true
		}
	}
	return v4, v6
}

func effectiveWGSecrets(old wireguardcfg.Secrets, cfg wireguardcfg.Config, supplied wireguardcfg.Secrets, initial bool) (wireguardcfg.Secrets, error) {
	result := cloneWGSecrets(supplied)
	if result.PrivateKey == nil && !initial {
		result.PrivateKey = cloneWGSecrets(old).PrivateKey
	}
	if result.PrivateKey == nil {
		return wireguardcfg.Secrets{}, errors.New("wireguard private key is required")
	}
	if result.PresharedKeyByPeer == nil {
		result.PresharedKeyByPeer = map[string]wireguardcfg.Key{}
	}
	for _, peer := range cfg.Peers {
		if !peer.HasPresharedKey {
			delete(result.PresharedKeyByPeer, peer.Name)
			continue
		}
		if _, ok := result.PresharedKeyByPeer[peer.Name]; ok {
			continue
		}
		if key, ok := old.PresharedKeyByPeer[peer.Name]; ok && !initial {
			result.PresharedKeyByPeer[peer.Name] = key
			continue
		}
		return wireguardcfg.Secrets{}, errors.New("wireguard peer preshared key is required")
	}
	return result, nil
}

func cloneWGConfig(cfg wireguardcfg.Config) wireguardcfg.Config {
	return cfg.Clone()
}

func cloneWGSecrets(s wireguardcfg.Secrets) wireguardcfg.Secrets {
	if s.PrivateKey != nil {
		key := *s.PrivateKey
		s.PrivateKey = &key
	}
	s.PresharedKeyByPeer = mapsClone(s.PresharedKeyByPeer)
	return s
}

func mapsClone[K comparable, V any](in map[K]V) map[K]V {
	if in == nil {
		return nil
	}
	out := make(map[K]V, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func sameWGPacketFilter(a, b wireguardcfg.PacketFilter) bool {
	if len(a.Grants) != len(b.Grants) {
		return false
	}
	for i := range a.Grants {
		if !slices.Equal(a.Grants[i].Src, b.Grants[i].Src) || !slices.Equal(a.Grants[i].Dst, b.Grants[i].Dst) || !slices.Equal(a.Grants[i].IP, b.Grants[i].IP) {
			return false
		}
	}
	return true
}

func sameWGFilterIdentity(oldConfig wireguardcfg.Config, oldSecrets wireguardcfg.Secrets, oldExit netip.Addr, newConfig wireguardcfg.Config, newSecrets wireguardcfg.Secrets, newExit netip.Addr) bool {
	if !slices.Equal(oldConfig.Addresses, newConfig.Addresses) || oldExit != newExit || !sameOptionalWGKey(oldSecrets.PrivateKey, newSecrets.PrivateKey) || len(oldConfig.Peers) != len(newConfig.Peers) {
		return false
	}
	for i := range oldConfig.Peers {
		oldPeer, newPeer := oldConfig.Peers[i], newConfig.Peers[i]
		if oldPeer.Name != newPeer.Name || oldPeer.PublicKey != newPeer.PublicKey || oldPeer.ExitNode != newPeer.ExitNode || !slices.Equal(oldPeer.Addresses, newPeer.Addresses) || !slices.Equal(oldPeer.Routes, newPeer.Routes) || oldSecrets.PresharedKeyByPeer[oldPeer.Name] != newSecrets.PresharedKeyByPeer[newPeer.Name] {
			return false
		}
	}
	return true
}

func sameOptionalWGKey(a, b *wireguardcfg.Key) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func sameWGPeer(a, b wireguardcfg.Peer) bool {
	return a.Name == b.Name && a.PublicKey == b.PublicKey && a.HasPresharedKey == b.HasPresharedKey && a.Endpoint == b.Endpoint && a.Keepalive == b.Keepalive && a.ExitNode == b.ExitNode && slices.Equal(a.Addresses, b.Addresses) && slices.Equal(a.Routes, b.Routes)
}

func peerHasAddress(peer wireguardcfg.Peer, ip netip.Addr) bool {
	return ip.IsValid() && slices.Contains(peer.Addresses, ip)
}
func validExitSelection(cfg wireguardcfg.Config, ip netip.Addr) netip.Addr {
	if !ip.IsValid() {
		return netip.Addr{}
	}
	for _, p := range cfg.Peers {
		if p.ExitNode && peerHasAddress(p, ip) {
			return ip
		}
	}
	return netip.Addr{}
}
func wgDNSName(name, suffix string) string {
	if name == "" || suffix == "" {
		return ""
	}
	return strings.TrimSuffix(name, ".") + "." + strings.Trim(suffix, ".")
}

type wgPeerRuntime struct {
	lastHandshake time.Time
	rxBytes       uint64
	txBytes       uint64
}

type wgDeviceRuntime struct {
	listenPort uint16
	peers      map[string]wgPeerRuntime
}

func parseWGDeviceStatus(uapi string) wgDeviceRuntime {
	result := wgDeviceRuntime{peers: map[string]wgPeerRuntime{}}
	var key string
	var peer wgPeerRuntime
	var sec, nsec int64
	flush := func() {
		if key == "" {
			return
		}
		if sec != 0 {
			peer.lastHandshake = time.Unix(sec, nsec)
		}
		result.peers[key] = peer
	}
	s := bufio.NewScanner(strings.NewReader(uapi))
	for s.Scan() {
		name, value, ok := strings.Cut(s.Text(), "=")
		if !ok {
			continue
		}
		switch name {
		case "listen_port":
			port, _ := strconv.ParseUint(value, 10, 16)
			result.listenPort = uint16(port)
		case "public_key":
			flush()
			key, peer, sec, nsec = value, wgPeerRuntime{}, 0, 0
		case "last_handshake_time_sec":
			sec, _ = strconv.ParseInt(value, 10, 64)
		case "last_handshake_time_nsec":
			nsec, _ = strconv.ParseInt(value, 10, 64)
		case "rx_bytes":
			peer.rxBytes, _ = strconv.ParseUint(value, 10, 64)
		case "tx_bytes":
			peer.txBytes, _ = strconv.ParseUint(value, 10, 64)
		}
	}
	flush()
	return result
}

func resolveWGConfigEndpoints(ctx context.Context, cfg wireguardcfg.Config) (wireguardcfg.Config, error) {
	resolved := cloneWGConfig(cfg)
	for i := range resolved.Peers {
		endpoint := resolved.Peers[i].Endpoint
		if endpoint == "" {
			continue
		}
		host, portText, err := net.SplitHostPort(endpoint)
		if err != nil {
			resolved.Peers[i].Endpoint = ""
			continue
		}
		if addr, err := netip.ParseAddr(host); err == nil {
			port, _ := strconv.ParseUint(portText, 10, 16)
			resolved.Peers[i].Endpoint = netip.AddrPortFrom(addr, uint16(port)).String()
			continue
		}
		addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(addrs) == 0 {
			if err := ctx.Err(); err != nil {
				return wireguardcfg.Config{}, err
			}
			// DNS availability is transient. Keep the desired endpoint in the
			// declarative config and run this peer without an endpoint until a
			// subsequent apply can resolve it.
			resolved.Peers[i].Endpoint = ""
			continue
		}
		sort.Slice(addrs, func(i, j int) bool { return addrs[i].Compare(addrs[j]) < 0 })
		port, _ := strconv.ParseUint(portText, 10, 16)
		resolved.Peers[i].Endpoint = netip.AddrPortFrom(addrs[0].Unmap(), uint16(port)).String()
	}
	return resolved, nil
}

var _ Engine = (*WireGuardEngine)(nil)
var _ ExitNodePreferenceController = (*WireGuardEngine)(nil)
