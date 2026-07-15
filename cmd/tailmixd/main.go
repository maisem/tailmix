package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"syscall"

	"github.com/gaissmai/bart"
	tailmixdns "github.com/maisem/tailmix/dns"
	"github.com/maisem/tailmix/effectiveip"
	"github.com/maisem/tailmix/hosttun"
	"github.com/maisem/tailmix/packetmap"
	tailmixprofile "github.com/maisem/tailmix/profile"
	"github.com/maisem/tailmix/profilesocket"
	"github.com/maisem/tailmix/socksproxy"
	"github.com/maisem/tailmix/state"
	"github.com/maisem/tailmix/tunmux"
)

const (
	defaultSyntheticPool   = "100.127.0.0/24"
	defaultSyntheticPoolV6 = "fd6d:6e65:7400::/56"
)

type profileSpec struct {
	ID             string
	Alias          string
	Dir            string
	Hostname       string
	ControlURL     string
	MagicDNSSuffix string
	AuthKeyEnv     string
}

type profileFlag []profileSpec

func (f *profileFlag) String() string {
	return fmt.Sprint([]profileSpec(*f))
}

func (f *profileFlag) Set(raw string) error {
	spec, err := parseProfileSpec(raw)
	if err != nil {
		return err
	}
	*f = append(*f, spec)
	return nil
}

type runtimeProfile struct {
	State      state.Profile
	AuthKeyEnv string
	Engine     tailmixprofile.Engine
	Tun        *tunmux.ChanTUN
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	var profiles profileFlag
	fs := flag.NewFlagSet("tailmixd", flag.ContinueOnError)
	fs.SetOutput(stderr)
	statePath := fs.String("state", defaultStatePath(), "path to tailmix daemon state")
	mode := fs.String("mode", "tun", "networking mode: tun or socks")
	tunName := fs.String("tun-name", defaultTUNName(), "host TUN interface name")
	socketDir := fs.String("socket-dir", profilesocket.DefaultDir(), "directory for per-profile LocalAPI sockets")
	socksAddr := fs.String("socks", "127.0.0.1:1080", "aggregate SOCKS5 listen address")
	syntheticPool := fs.String("synthetic-pool", "", "IPv4 CIDR for effective peer and host NAT addresses (persisted; default "+defaultSyntheticPool+")")
	syntheticPoolV6 := fs.String("synthetic-pool-v6", "", "IPv6 CIDR for effective peer and host NAT addresses (persisted; default "+defaultSyntheticPoolV6+")")
	verbose := fs.Bool("verbose", false, "enable verbose per-profile tsnet logs")
	logUpload := fs.Bool("log-upload", false, "opt in to remote per-profile logtail uploads")
	logUploadURL := fs.String("log-upload-url", "", "replace the remote logtail upload base URL (requires -log-upload)")
	fs.Var(&profiles, "profile", "profile config: id=work,dir=/path,hostname=tailmix-work[,control-url=URL][,suffix=tailnet.ts.net][,auth-key-env=ENV]")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *statePath == "" {
		return fmt.Errorf("state path is required")
	}
	if *mode != "tun" && *mode != "socks" {
		return fmt.Errorf("invalid mode %q; want tun or socks", *mode)
	}
	if *mode == "tun" && *tunName == "" {
		return fmt.Errorf("TUN name is required in tun mode")
	}
	if *socketDir == "" {
		return fmt.Errorf("profile socket directory is required")
	}
	if *logUploadURL != "" && !*logUpload {
		return fmt.Errorf("log upload URL requires -log-upload")
	}
	if *mode == "socks" && *socksAddr == "" {
		return fmt.Errorf("socks listen address is required")
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %s", strings.Join(fs.Args(), " "))
	}

	store := state.NewJSONStore(*statePath)
	st, err := store.Load()
	if err != nil {
		return err
	}
	if err := configureSyntheticPools(&st, *syntheticPool, *syntheticPoolV6); err != nil {
		return err
	}
	runtimeProfiles, err := resolveProfiles(st, profiles, *statePath)
	if err != nil {
		return err
	}
	if len(runtimeProfiles) == 0 {
		return fmt.Errorf("at least one --profile is required unless profiles already exist in state")
	}
	if err := validateAuthKeyEnv(runtimeProfiles); err != nil {
		return err
	}
	st.Profiles = stateProfiles(runtimeProfiles)
	if err := store.Save(st); err != nil {
		return err
	}
	fmt.Fprintf(stderr, "effective IP pools: IPv4 %s, IPv6 %s\n", st.SyntheticPool, st.SyntheticPoolV6)

	mgr := tailmixprofile.NewManager()
	for i := range runtimeProfiles {
		rp := &runtimeProfiles[i]
		if *mode == "tun" {
			rp.Tun = tunmux.NewChanTUN("tailmix-" + dnsLabel(rp.State.ID))
		}
		cfg, err := tsnetConfig(*rp, stderr, *verbose, *logUpload, *logUploadURL)
		if err != nil {
			return err
		}
		rp.Engine = tailmixprofile.NewTSNetEngine(cfg)
		mgr.Add(rp.State.ID, rp.Engine)
	}
	if err := mgr.Start(ctx); err != nil {
		return err
	}
	defer mgr.Close()
	profileAPIs, err := startProfileAPIs(ctx, *socketDir, runtimeProfiles, stderr)
	if err != nil {
		return err
	}
	defer profileAPIs.Close()

	fmt.Fprintf(stderr, "started %d profile(s); waiting for tailnet state\n", len(runtimeProfiles))
	statuses, err := mgr.Status(ctx)
	if err != nil {
		return err
	}
	if *mode == "tun" {
		plan, err := buildTUNPlan(st, statuses)
		if err != nil {
			return err
		}
		if err := store.Save(plan.State); err != nil {
			return err
		}
		return runTUN(ctx, *tunName, runtimeProfiles, mgr, store, plan, profileAPIs.Errors(), stderr)
	}

	updateProfileMetadata(&st, statuses)

	activeLeases, allLeases, err := assignEffectiveIPs(st, statuses)
	if err != nil {
		return err
	}
	st.Leases = leasesToState(allLeases)
	if err := store.Save(st); err != nil {
		return err
	}
	routerProfiles, err := socksProfiles(runtimeProfiles, statuses)
	if err != nil {
		return err
	}
	router, err := socksproxy.NewRouter(routerProfiles, activeLeases)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", *socksAddr)
	if err != nil {
		return err
	}
	fmt.Fprintf(stderr, "SOCKS listening on %s\n", ln.Addr())
	_ = stdout
	serveErr := make(chan error, 1)
	go func() { serveErr <- socksproxy.Serve(ctx, ln, router, prefixedLogf(stderr, "socks")) }()
	select {
	case <-ctx.Done():
		return nil
	case err := <-profileAPIs.Errors():
		return err
	case err := <-serveErr:
		return err
	}
}

func defaultStatePath() string {
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		return filepath.Join(".", "tailmix-state.json")
	}
	return filepath.Join(dir, "tailmix", "state.json")
}

func defaultTUNName() string {
	if runtime.GOOS == "darwin" {
		return "utun"
	}
	return "tailmix0"
}

func configureSyntheticPools(st *state.State, ipv4Override, ipv6Override string) error {
	type familyConfig struct {
		name         string
		override     string
		current      *string
		nat          *netip.Addr
		defaultValue string
		ipv6         bool
	}
	for _, family := range []familyConfig{
		{name: "IPv4", override: ipv4Override, current: &st.SyntheticPool, nat: &st.NATIP, defaultValue: defaultSyntheticPool},
		{name: "IPv6", override: ipv6Override, current: &st.SyntheticPoolV6, nat: &st.NATIPv6, defaultValue: defaultSyntheticPoolV6, ipv6: true},
	} {
		oldValue := *family.current
		selected := strings.TrimSpace(family.override)
		if selected == "" {
			selected = oldValue
		}
		if selected == "" {
			selected = family.defaultValue
		}
		normalized, err := normalizeSyntheticPool(family.name, selected, family.ipv6)
		if err != nil {
			return err
		}

		oldNormalized := ""
		if oldValue != "" {
			if oldPool, err := normalizeSyntheticPool(family.name, oldValue, family.ipv6); err == nil {
				oldNormalized = oldPool
			}
		}
		if strings.TrimSpace(family.override) != "" && oldNormalized != normalized {
			st.Leases = discardSyntheticLeases(st.Leases, family.ipv6)
			*family.nat = netip.Addr{}
		}
		*family.current = normalized
	}
	return nil
}

func normalizeSyntheticPool(name, raw string, ipv6 bool) (string, error) {
	pool, err := netip.ParsePrefix(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("parse effective %s pool %q: %w", name, raw, err)
	}
	if pool.Addr().Is4In6() || pool.Addr().Is6() != ipv6 {
		return "", fmt.Errorf("effective %s pool has wrong address family: %v", name, pool)
	}
	pool = pool.Masked()
	if !pool.Addr().IsGlobalUnicast() {
		return "", fmt.Errorf("effective %s pool must contain unicast addresses: %v", name, pool)
	}
	if !ipv6 && pool.Contains(tailmixdns.ServiceIP()) {
		return "", fmt.Errorf("effective IPv4 pool %v contains MagicDNS service address %v", pool, tailmixdns.ServiceIP())
	}
	return pool.String(), nil
}

func discardSyntheticLeases(leases []state.EffectiveLease, ipv6 bool) []state.EffectiveLease {
	out := make([]state.EffectiveLease, 0, len(leases))
	for _, lease := range leases {
		if lease.EffectiveIP.IsValid() && lease.EffectiveIP.Is6() == ipv6 {
			continue
		}
		out = append(out, lease)
	}
	return out
}

func ensureNATIPs(st *state.State) error {
	used := make(map[netip.Addr]bool, len(st.Leases)+2)
	for _, lease := range st.Leases {
		if lease.EffectiveIP.IsValid() {
			used[lease.EffectiveIP] = true
		}
	}
	for _, family := range []struct {
		name    string
		poolRaw string
		current *netip.Addr
		ipv6    bool
	}{
		{name: "IPv4", poolRaw: st.SyntheticPool, current: &st.NATIP},
		{name: "IPv6", poolRaw: st.SyntheticPoolV6, current: &st.NATIPv6, ipv6: true},
	} {
		pool, err := netip.ParsePrefix(family.poolRaw)
		if err != nil {
			return fmt.Errorf("parse effective %s pool %q: %w", family.name, family.poolRaw, err)
		}
		pool = pool.Masked()
		if current := *family.current; current.IsValid() && current.Is6() == family.ipv6 && pool.Contains(current) && !used[current] {
			used[current] = true
			continue
		}
		*family.current = netip.Addr{}
		for ip := pool.Addr(); pool.Contains(ip); ip = ip.Next() {
			if !ip.IsValid() {
				break
			}
			if used[ip] || ip == tailmixdns.ServiceIP() {
				continue
			}
			*family.current = ip
			used[ip] = true
			break
		}
		if !family.current.IsValid() {
			return fmt.Errorf("effective %s pool %v has no free address for the host NAT", family.name, pool)
		}
	}
	return nil
}

func parseProfileSpec(raw string) (profileSpec, error) {
	var spec profileSpec
	if strings.TrimSpace(raw) == "" {
		return spec, fmt.Errorf("empty profile config")
	}
	for _, part := range strings.Split(raw, ",") {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			return spec, fmt.Errorf("profile field %q must be key=value", part)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if value == "" {
			return spec, fmt.Errorf("profile field %q is empty", key)
		}
		switch key {
		case "id":
			spec.ID = value
		case "alias":
			spec.Alias = value
		case "dir", "state-dir", "statedir":
			spec.Dir = value
		case "hostname":
			spec.Hostname = value
		case "control-url", "controlurl":
			spec.ControlURL = value
		case "suffix", "magicdns-suffix", "magic-dns-suffix":
			spec.MagicDNSSuffix = value
		case "auth-key-env", "authkey-env":
			spec.AuthKeyEnv = value
		default:
			return spec, fmt.Errorf("unknown profile field %q", key)
		}
	}
	if spec.ID == "" {
		spec.ID = spec.Alias
	}
	if spec.Alias == "" {
		spec.Alias = spec.ID
	}
	if spec.ID == "" {
		return spec, fmt.Errorf("profile id or alias is required")
	}
	return spec, nil
}

func resolveProfiles(st state.State, specs []profileSpec, statePath string) ([]runtimeProfile, error) {
	byID := map[string]runtimeProfile{}
	var order []string
	for _, p := range st.Profiles {
		if p.ID == "" {
			return nil, fmt.Errorf("stored profile has empty id")
		}
		if _, ok := byID[p.ID]; !ok {
			order = append(order, p.ID)
		}
		byID[p.ID] = runtimeProfile{State: p}
	}
	for _, spec := range specs {
		rp := byID[spec.ID]
		if rp.State.ID == "" {
			rp.State.ID = spec.ID
			order = append(order, spec.ID)
		}
		if spec.Alias != "" {
			rp.State.Alias = spec.Alias
		}
		if spec.Dir != "" {
			rp.State.StateDir = spec.Dir
		}
		if spec.Hostname != "" {
			rp.State.Hostname = spec.Hostname
		}
		if spec.ControlURL != "" {
			rp.State.ControlURL = spec.ControlURL
		}
		if spec.MagicDNSSuffix != "" {
			rp.State.MagicDNSSuffix = spec.MagicDNSSuffix
		}
		rp.AuthKeyEnv = spec.AuthKeyEnv
		byID[spec.ID] = rp
	}

	var out []runtimeProfile
	baseDir := filepath.Join(filepath.Dir(statePath), "profiles")
	for _, id := range order {
		rp := byID[id]
		if rp.State.Alias == "" {
			rp.State.Alias = rp.State.ID
		}
		if rp.State.StateDir == "" {
			rp.State.StateDir = filepath.Join(baseDir, rp.State.ID)
		}
		if rp.State.Hostname == "" {
			rp.State.Hostname = "tailmix-" + dnsLabel(rp.State.ID)
		}
		out = append(out, rp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].State.ID < out[j].State.ID })
	return out, nil
}

func dnsLabel(s string) string {
	var b strings.Builder
	lastHyphen := false
	for _, r := range strings.ToLower(s) {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if ok {
			b.WriteRune(r)
			lastHyphen = false
			continue
		}
		if !lastHyphen && b.Len() > 0 {
			b.WriteByte('-')
			lastHyphen = true
		}
	}
	label := strings.Trim(b.String(), "-")
	if label == "" {
		label = "profile"
	}
	if len(label) > 58 {
		label = strings.TrimRight(label[:58], "-")
	}
	return label
}

func validateAuthKeyEnv(profiles []runtimeProfile) error {
	if os.Getenv("TS_AUTHKEY") == "" && os.Getenv("TS_AUTH_KEY") == "" {
		return nil
	}
	for _, rp := range profiles {
		if rp.AuthKeyEnv == "" {
			return fmt.Errorf("global TS_AUTHKEY/TS_AUTH_KEY is set; use per-profile auth-key-env or unset it before starting tailmixd")
		}
	}
	return nil
}

func tsnetConfig(rp runtimeProfile, stderr io.Writer, verbose, logUpload bool, logUploadURL string) (tailmixprofile.TSNetConfig, error) {
	authKey := ""
	if rp.AuthKeyEnv != "" {
		authKey = os.Getenv(rp.AuthKeyEnv)
		if authKey == "" {
			return tailmixprofile.TSNetConfig{}, fmt.Errorf("profile %q auth-key-env %s is empty", rp.State.ID, rp.AuthKeyEnv)
		}
	}
	cfg := tailmixprofile.TSNetConfig{
		ProfileID:      rp.State.ID,
		Alias:          rp.State.Alias,
		Dir:            rp.State.StateDir,
		Hostname:       rp.State.Hostname,
		AuthKey:        authKey,
		ControlURL:     rp.State.ControlURL,
		MagicDNSSuffix: rp.State.MagicDNSSuffix,
		UserLogf:       prefixedLogf(stderr, rp.State.ID),
		LogUpload:      logUpload,
		LogUploadURL:   logUploadURL,
		Tun:            rp.Tun,
	}
	if verbose {
		cfg.Logf = prefixedLogf(stderr, rp.State.ID)
	}
	return cfg, nil
}

func prefixedLogf(w io.Writer, prefix string) func(string, ...any) {
	return func(format string, args ...any) {
		msg := strings.TrimRight(fmt.Sprintf(format, args...), "\n")
		fmt.Fprintf(w, "[%s] %s\n", prefix, msg)
	}
}

func stateProfiles(profiles []runtimeProfile) []state.Profile {
	out := make([]state.Profile, 0, len(profiles))
	for _, rp := range profiles {
		out = append(out, rp.State)
	}
	return out
}

func updateProfileMetadata(st *state.State, statuses []tailmixprofile.Status) {
	byID := map[string]tailmixprofile.Status{}
	for _, ps := range statuses {
		byID[ps.ProfileID] = ps
	}
	for i := range st.Profiles {
		if ps, ok := byID[st.Profiles[i].ID]; ok && ps.MagicDNSSuffix != "" {
			st.Profiles[i].MagicDNSSuffix = ps.MagicDNSSuffix
		}
	}
}

func leaseNodes(statuses []tailmixprofile.Status) []effectiveip.Node {
	var nodes []effectiveip.Node
	for _, ps := range statuses {
		for _, peer := range ps.Peers {
			if peer.NodeID == "" {
				continue
			}
			for _, ip := range peer.TailscaleIPs {
				nodes = append(nodes, effectiveip.Node{ProfileID: ps.ProfileID, NodeID: peer.NodeID, CanonicalIP: ip})
			}
		}
	}
	sort.Slice(nodes, func(i, j int) bool {
		a, b := nodes[i], nodes[j]
		if a.ProfileID != b.ProfileID {
			return a.ProfileID < b.ProfileID
		}
		if a.NodeID != b.NodeID {
			return a.NodeID < b.NodeID
		}
		return a.CanonicalIP.Compare(b.CanonicalIP) < 0
	})
	return nodes
}

func leasesFromState(stLeases []state.EffectiveLease) []effectiveip.Lease {
	leases := make([]effectiveip.Lease, 0, len(stLeases))
	for _, lease := range stLeases {
		if lease.ProfileID == "" || lease.NodeID == "" || !lease.CanonicalIP.IsValid() || !lease.EffectiveIP.IsValid() || lease.CanonicalIP.Is6() != lease.EffectiveIP.Is6() {
			continue
		}
		leases = append(leases, effectiveip.Lease{
			NodeKey: effectiveip.NodeKey{
				ProfileID:   lease.ProfileID,
				NodeID:      lease.NodeID,
				CanonicalIP: lease.CanonicalIP,
			},
			EffectiveIP: lease.EffectiveIP,
		})
	}
	return leases
}

func assignEffectiveIPs(st state.State, statuses []tailmixprofile.Status) (active, all []effectiveip.Lease, err error) {
	nodes := leaseNodes(statuses)
	existing := leasesFromState(st.Leases)
	for _, family := range []struct {
		name string
		pool string
		ipv6 bool
	}{
		{name: "IPv4", pool: st.SyntheticPool},
		{name: "IPv6", pool: st.SyntheticPoolV6, ipv6: true},
	} {
		pool, parseErr := netip.ParsePrefix(family.pool)
		if parseErr != nil {
			return nil, nil, fmt.Errorf("parse effective %s pool %q: %w", family.name, family.pool, parseErr)
		}
		if pool.Addr().Is6() != family.ipv6 {
			return nil, nil, fmt.Errorf("effective %s pool has wrong address family: %v", family.name, pool)
		}
		var familyNodes []effectiveip.Node
		for _, node := range nodes {
			if node.CanonicalIP.Is6() == family.ipv6 {
				familyNodes = append(familyNodes, node)
			}
		}
		var familyExisting []effectiveip.Lease
		for _, lease := range existing {
			if lease.NodeKey.CanonicalIP.Is6() == family.ipv6 {
				familyExisting = append(familyExisting, lease)
			}
		}
		reserved := st.NATIP
		if family.ipv6 {
			reserved = st.NATIPv6
		}
		plan, assignErr := effectiveip.NewAllocator(pool, familyExisting, reserved).Assign(familyNodes)
		if assignErr != nil {
			return nil, nil, fmt.Errorf("assign effective %s addresses: %w", family.name, assignErr)
		}
		active = append(active, plan.Leases...)
	}
	all = mergeLeases(existing, active)
	return active, all, nil
}

func mergeLeases(old, active []effectiveip.Lease) []effectiveip.Lease {
	byKey := map[effectiveip.NodeKey]effectiveip.Lease{}
	for _, lease := range old {
		byKey[lease.NodeKey] = lease
	}
	for _, lease := range active {
		byKey[lease.NodeKey] = lease
	}
	out := make([]effectiveip.Lease, 0, len(byKey))
	for _, lease := range byKey {
		out = append(out, lease)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].NodeKey, out[j].NodeKey
		if a.ProfileID != b.ProfileID {
			return a.ProfileID < b.ProfileID
		}
		if a.NodeID != b.NodeID {
			return a.NodeID < b.NodeID
		}
		return a.CanonicalIP.Compare(b.CanonicalIP) < 0
	})
	return out
}

type tunPlan struct {
	State        state.State
	Statuses     []tailmixprofile.Status
	ActiveLeases []effectiveip.Lease
	Table        packetmap.Table
	HostConfig   hosttun.Config
	Domains      []tailmixdns.Domain
	Records      []tailmixdns.Record
}

func buildTUNPlan(st state.State, statuses []tailmixprofile.Status) (tunPlan, error) {
	st.Profiles = slices.Clone(st.Profiles)
	st.Leases = slices.Clone(st.Leases)
	updateProfileMetadata(&st, statuses)
	if err := ensureNATIPs(&st); err != nil {
		return tunPlan{}, err
	}
	activeLeases, allLeases, err := assignEffectiveIPs(st, statuses)
	if err != nil {
		return tunPlan{}, err
	}
	st.Leases = leasesToState(allLeases)
	table, hostCfg, err := tunConfig(st, statuses, activeLeases)
	if err != nil {
		return tunPlan{}, err
	}
	domains, records, err := tunDNSConfig(st, statuses, activeLeases)
	if err != nil {
		return tunPlan{}, err
	}
	return tunPlan{
		State:        st,
		Statuses:     statuses,
		ActiveLeases: activeLeases,
		Table:        table,
		HostConfig:   hostCfg,
		Domains:      domains,
		Records:      records,
	}, nil
}

func runTUN(ctx context.Context, tunName string, profiles []runtimeProfile, mgr *tailmixprofile.Manager, store *state.JSONStore, plan tunPlan, profileAPIErrs <-chan error, stderr io.Writer) error {
	logf := prefixedLogf(stderr, "tun")
	host, err := hosttun.Open(hosttun.OpenConfig{Name: tunName, Logf: logf})
	if err != nil {
		return err
	}
	defer host.Close()
	if err := host.Configure(plan.HostConfig); err != nil {
		return fmt.Errorf("configure host TUN %s: %w", host.Name(), err)
	}
	profileTUNs := make(map[string]*tunmux.ChanTUN, len(profiles))
	for _, rp := range profiles {
		if rp.Tun == nil {
			return fmt.Errorf("profile %q has no packet TUN", rp.State.ID)
		}
		profileTUNs[rp.State.ID] = rp.Tun
	}
	dnsService, err := tailmixdns.StartService(tailmixdns.ServiceConfig{
		TunName: host.Name(),
		Domains: plan.Domains,
		Records: plan.Records,
		Logf:    prefixedLogf(stderr, "dns"),
	})
	if err != nil {
		return err
	}
	defer dnsService.Close()
	fmt.Fprintf(stderr, "TUN %s configured with %d local address(es) and %d peer route(s)\n", host.Name(), len(plan.HostConfig.LocalAddrs), plan.Table.Destinations.Size())
	fmt.Fprintf(stderr, "MagicDNS serving %s inside the TUN for %s\n", dnsService.Addr(), magicDNSSuffixes(plan.Domains))
	logTUNRoutes(stderr, plan.Statuses, plan.ActiveLeases)
	mux := tunmux.NewMux(host.Device(), profileTUNs, packetmap.New(plan.Table), logf)
	mux.SetLocalPacketHandler(dnsService)

	muxErr := make(chan error, 1)
	go func() { muxErr <- mux.Run(ctx) }()
	updates := mgr.WatchUpdates(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-muxErr:
			return err
		case err := <-profileAPIErrs:
			return err
		case update, ok := <-updates:
			if !ok {
				if ctx.Err() != nil {
					return nil
				}
				return errors.New("tailnet update watchers stopped")
			}
			if update.Err != nil {
				return update.Err
			}
			statuses, err := mgr.Status(ctx)
			if err != nil {
				return fmt.Errorf("refresh tailnet state after profile %q update: %w", update.ProfileID, err)
			}
			next, err := buildTUNPlan(plan.State, statuses)
			if err != nil {
				return fmt.Errorf("rebuild TUN config after profile %q update: %w", update.ProfileID, err)
			}
			if err := host.Configure(next.HostConfig); err != nil {
				return fmt.Errorf("reconfigure host TUN %s: %w", host.Name(), err)
			}
			mux.SetMapper(packetmap.New(next.Table))
			if err := dnsService.Configure(next.Domains, next.Records); err != nil {
				return err
			}
			if err := store.Save(next.State); err != nil {
				return fmt.Errorf("save refreshed state: %w", err)
			}
			plan = next
			fmt.Fprintf(stderr, "profile %s updated: TUN now has %d local address(es), %d peer route(s), and %d MagicDNS record(s)\n", update.ProfileID, len(plan.HostConfig.LocalAddrs), plan.Table.Destinations.Size(), len(plan.Records))
		}
	}
}

func tunDNSConfig(st state.State, statuses []tailmixprofile.Status, leases []effectiveip.Lease) ([]tailmixdns.Domain, []tailmixdns.Record, error) {
	byKey := make(map[effectiveip.NodeKey]netip.Addr, len(leases))
	for _, lease := range leases {
		if existing, ok := byKey[lease.NodeKey]; ok && existing != lease.EffectiveIP {
			return nil, nil, fmt.Errorf("node %+v has conflicting effective IP leases %v and %v", lease.NodeKey, existing, lease.EffectiveIP)
		}
		byKey[lease.NodeKey] = lease.EffectiveIP
	}
	var domains []tailmixdns.Domain
	var records []tailmixdns.Record
	for _, ps := range statuses {
		if ps.MagicDNSSuffix == "" {
			return nil, nil, fmt.Errorf("profile %q has no MagicDNS suffix", ps.ProfileID)
		}
		domains = append(domains, tailmixdns.Domain{ProfileID: ps.ProfileID, Suffix: ps.MagicDNSSuffix})
		addRecords := func(nodeID, name string, canonicalIPs []netip.Addr, self bool) error {
			if name == "" {
				return nil
			}
			for _, canonical := range canonicalIPs {
				effective := natIPFor(st, canonical)
				if !self {
					key := effectiveip.NodeKey{ProfileID: ps.ProfileID, NodeID: nodeID, CanonicalIP: canonical}
					var ok bool
					effective, ok = byKey[key]
					if !ok {
						return fmt.Errorf("profile %q MagicDNS name %q IP %v has no effective lease", ps.ProfileID, name, canonical)
					}
				}
				if !effective.IsValid() {
					return fmt.Errorf("profile %q MagicDNS name %q has no host NAT address for %v", ps.ProfileID, name, canonical)
				}
				records = append(records, tailmixdns.Record{ProfileAlias: ps.ProfileID, Name: name, EffectiveIP: effective})
			}
			return nil
		}
		if err := addRecords(ps.SelfNodeID, ps.SelfDNSName, ps.SelfIPs, true); err != nil {
			return nil, nil, err
		}
		for _, peer := range ps.Peers {
			if err := addRecords(peer.NodeID, peer.DNSName, peer.TailscaleIPs, false); err != nil {
				return nil, nil, err
			}
		}
	}
	sort.Slice(domains, func(i, j int) bool {
		if domains[i].Suffix != domains[j].Suffix {
			return domains[i].Suffix < domains[j].Suffix
		}
		return domains[i].ProfileID < domains[j].ProfileID
	})
	sort.Slice(records, func(i, j int) bool {
		if records[i].Name != records[j].Name {
			return records[i].Name < records[j].Name
		}
		return records[i].EffectiveIP.Compare(records[j].EffectiveIP) < 0
	})
	return domains, records, nil
}

func magicDNSSuffixes(domains []tailmixdns.Domain) string {
	suffixes := make([]string, 0, len(domains))
	for _, domain := range domains {
		suffixes = append(suffixes, strings.TrimSuffix(domain.Suffix, "."))
	}
	sort.Strings(suffixes)
	return strings.Join(suffixes, ", ")
}

func logTUNRoutes(w io.Writer, statuses []tailmixprofile.Status, leases []effectiveip.Lease) {
	type route struct {
		profile   string
		name      string
		canonical netip.Addr
		effective netip.Addr
	}
	names := map[effectiveip.NodeKey]string{}
	for _, ps := range statuses {
		for _, peer := range ps.Peers {
			for _, canonical := range peer.TailscaleIPs {
				names[effectiveip.NodeKey{ProfileID: ps.ProfileID, NodeID: peer.NodeID, CanonicalIP: canonical}] = peer.DNSName
			}
		}
	}
	var routes []route
	for _, lease := range leases {
		name, ok := names[lease.NodeKey]
		if !ok {
			continue
		}
		routes = append(routes, route{
			profile:   lease.NodeKey.ProfileID,
			name:      name,
			canonical: lease.NodeKey.CanonicalIP,
			effective: lease.EffectiveIP,
		})
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].profile != routes[j].profile {
			return routes[i].profile < routes[j].profile
		}
		return routes[i].effective.Compare(routes[j].effective) < 0
	})
	for _, route := range routes {
		fmt.Fprintf(w, "route profile=%s name=%s effective=%v canonical=%v\n", route.profile, route.name, route.effective, route.canonical)
	}
}

func tunConfig(st state.State, statuses []tailmixprofile.Status, leases []effectiveip.Lease) (packetmap.Table, hosttun.Config, error) {
	byKey := map[effectiveip.NodeKey]netip.Addr{}
	for _, lease := range leases {
		if existing, ok := byKey[lease.NodeKey]; ok && existing != lease.EffectiveIP {
			return packetmap.Table{}, hosttun.Config{}, fmt.Errorf("node %+v has conflicting effective IP leases %v and %v", lease.NodeKey, existing, lease.EffectiveIP)
		}
		byKey[lease.NodeKey] = lease.EffectiveIP
	}
	table := packetmap.Table{
		Destinations: new(bart.Table[packetmap.Destination]),
		Sources:      map[packetmap.SourceKey]packetmap.Source{},
		InboundPeers: map[string]*bart.Table[netip.Addr]{},
	}
	var hostCfg hosttun.Config
	for _, ps := range statuses {
		for _, canonical := range ps.SelfIPs {
			sourceKey := packetmap.SourceKey{ProfileID: ps.ProfileID, IPv6: canonical.Is6()}
			if existing, ok := table.Sources[sourceKey]; ok && existing.CanonicalIP != canonical {
				return packetmap.Table{}, hosttun.Config{}, fmt.Errorf("profile %q has multiple %s self addresses", ps.ProfileID, ipFamily(canonical))
			}
			hostIP := natIPFor(st, canonical)
			if !hostIP.IsValid() {
				return packetmap.Table{}, hosttun.Config{}, fmt.Errorf("profile %q has no host NAT address for %v", ps.ProfileID, canonical)
			}
			table.Sources[sourceKey] = packetmap.Source{HostIP: hostIP, CanonicalIP: canonical}
		}
		for _, peer := range ps.Peers {
			for _, canonical := range peer.TailscaleIPs {
				key := effectiveip.NodeKey{ProfileID: ps.ProfileID, NodeID: peer.NodeID, CanonicalIP: canonical}
				effective, ok := byKey[key]
				if !ok {
					return packetmap.Table{}, hosttun.Config{}, fmt.Errorf("profile %q peer %q IP %v has no effective lease", ps.ProfileID, peer.NodeID, canonical)
				}
				effectivePrefix := netip.PrefixFrom(effective, effective.BitLen())
				if existing, ok := table.Destinations.Get(effectivePrefix); ok && (existing.ProfileID != ps.ProfileID || existing.CanonicalIP != canonical) {
					return packetmap.Table{}, hosttun.Config{}, fmt.Errorf("effective destination %v maps to multiple peers", effective)
				}
				table.Destinations.Insert(effectivePrefix, packetmap.Destination{ProfileID: ps.ProfileID, CanonicalIP: canonical})
				inbound := table.InboundPeers[ps.ProfileID]
				if inbound == nil {
					inbound = new(bart.Table[netip.Addr])
					table.InboundPeers[ps.ProfileID] = inbound
				}
				canonicalPrefix := netip.PrefixFrom(canonical, canonical.BitLen())
				if existing, ok := inbound.Get(canonicalPrefix); ok && existing != effective {
					return packetmap.Table{}, hosttun.Config{}, fmt.Errorf("profile %q canonical peer IP %v maps to multiple effective IPs", ps.ProfileID, canonical)
				}
				inbound.Insert(canonicalPrefix, effective)
				if _, ok := table.Sources[packetmap.SourceKey{ProfileID: ps.ProfileID, IPv6: canonical.Is6()}]; !ok {
					return packetmap.Table{}, hosttun.Config{}, fmt.Errorf("profile %q peer %v has no matching %s self address", ps.ProfileID, canonical, ipFamily(canonical))
				}
				hostCfg.Routes = append(hostCfg.Routes, hosttun.Route{Destination: effectivePrefix})
			}
		}
	}
	serviceIP := tailmixdns.ServiceIP()
	for key, source := range table.Sources {
		if source.HostIP == serviceIP {
			return packetmap.Table{}, hosttun.Config{}, fmt.Errorf("profile %q host NAT IP conflicts with MagicDNS service IP %v", key.ProfileID, serviceIP)
		}
	}
	if destination, ok := table.Destinations.Lookup(serviceIP); ok {
		return packetmap.Table{}, hosttun.Config{}, fmt.Errorf("profile %q effective peer IP conflicts with MagicDNS service IP %v", destination.ProfileID, serviceIP)
	}
	if !st.NATIP.IsValid() {
		return packetmap.Table{}, hosttun.Config{}, errors.New("host IPv4 NAT address is unavailable")
	}
	hostCfg.LocalAddrs = append(hostCfg.LocalAddrs, netip.PrefixFrom(st.NATIP, st.NATIP.BitLen()))
	for key := range table.Sources {
		if key.IPv6 {
			hostCfg.LocalAddrs = append(hostCfg.LocalAddrs, netip.PrefixFrom(st.NATIPv6, st.NATIPv6.BitLen()))
			break
		}
	}
	hostCfg.Routes = append(hostCfg.Routes, hosttun.Route{Destination: netip.PrefixFrom(serviceIP, serviceIP.BitLen())})
	return table, hostCfg, nil
}

func natIPFor(st state.State, canonical netip.Addr) netip.Addr {
	if canonical.Is6() {
		return st.NATIPv6
	}
	return st.NATIP
}

func ipFamily(ip netip.Addr) string {
	if ip.Is6() {
		return "IPv6"
	}
	return "IPv4"
}

func leasesToState(leases []effectiveip.Lease) []state.EffectiveLease {
	out := make([]state.EffectiveLease, 0, len(leases))
	for _, lease := range leases {
		out = append(out, state.EffectiveLease{
			ProfileID:   lease.NodeKey.ProfileID,
			NodeID:      lease.NodeKey.NodeID,
			CanonicalIP: lease.NodeKey.CanonicalIP,
			EffectiveIP: lease.EffectiveIP,
		})
	}
	return out
}

func socksProfiles(profiles []runtimeProfile, statuses []tailmixprofile.Status) ([]socksproxy.Profile, error) {
	byID := map[string]tailmixprofile.Status{}
	for _, ps := range statuses {
		byID[ps.ProfileID] = ps
	}
	out := make([]socksproxy.Profile, 0, len(profiles))
	for _, rp := range profiles {
		suffix := rp.State.MagicDNSSuffix
		if ps, ok := byID[rp.State.ID]; ok && ps.MagicDNSSuffix != "" {
			suffix = ps.MagicDNSSuffix
		}
		if suffix == "" {
			return nil, fmt.Errorf("profile %q has no MagicDNS suffix", rp.State.ID)
		}
		out = append(out, socksproxy.Profile{
			ID:             rp.State.ID,
			MagicDNSSuffix: suffix,
			Dialer:         rp.Engine,
		})
	}
	return out, nil
}
