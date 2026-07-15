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
	"sort"
	"strings"
	"syscall"

	tailmixdns "github.com/maisem/tailmix/dns"
	"github.com/maisem/tailmix/effectiveip"
	"github.com/maisem/tailmix/hosttun"
	"github.com/maisem/tailmix/packetmap"
	tailmixprofile "github.com/maisem/tailmix/profile"
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
	tunName := fs.String("tun-name", "utun", "Darwin TUN name (utun chooses the next free device)")
	socksAddr := fs.String("socks", "127.0.0.1:1080", "aggregate SOCKS5 listen address")
	syntheticPool := fs.String("synthetic-pool", "", "IPv4 CIDR for colliding effective addresses (persisted; default "+defaultSyntheticPool+")")
	syntheticPoolV6 := fs.String("synthetic-pool-v6", "", "IPv6 CIDR for colliding effective addresses (persisted; default "+defaultSyntheticPoolV6+")")
	verbose := fs.Bool("verbose", false, "enable verbose per-profile tsnet logs")
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
		cfg, err := tsnetConfig(*rp, stderr, *verbose)
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

	fmt.Fprintf(stderr, "started %d profile(s); waiting for tailnet state\n", len(runtimeProfiles))
	statuses, err := mgr.Status(ctx)
	if err != nil {
		return err
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
	if *mode == "tun" {
		return runTUN(ctx, *tunName, runtimeProfiles, statuses, activeLeases, stderr)
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
	return socksproxy.Serve(ctx, ln, router, prefixedLogf(stderr, "socks"))
}

func defaultStatePath() string {
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		return filepath.Join(".", "tailmix-state.json")
	}
	return filepath.Join(dir, "tailmix", "state.json")
}

func configureSyntheticPools(st *state.State, ipv4Override, ipv6Override string) error {
	type familyConfig struct {
		name         string
		override     string
		current      *string
		defaultValue string
		ipv6         bool
	}
	for _, family := range []familyConfig{
		{name: "IPv4", override: ipv4Override, current: &st.SyntheticPool, defaultValue: defaultSyntheticPool},
		{name: "IPv6", override: ipv6Override, current: &st.SyntheticPoolV6, defaultValue: defaultSyntheticPoolV6, ipv6: true},
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
		}
		*family.current = normalized
	}
	return nil
}

func normalizeSyntheticPool(name, raw string, ipv6 bool) (string, error) {
	pool, err := netip.ParsePrefix(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("parse synthetic %s pool %q: %w", name, raw, err)
	}
	if pool.Addr().Is4In6() || pool.Addr().Is6() != ipv6 {
		return "", fmt.Errorf("synthetic %s pool has wrong address family: %v", name, pool)
	}
	pool = pool.Masked()
	if !pool.Addr().IsGlobalUnicast() {
		return "", fmt.Errorf("synthetic %s pool must contain unicast addresses: %v", name, pool)
	}
	if !ipv6 && pool.Contains(tailmixdns.ServiceIP()) {
		return "", fmt.Errorf("synthetic IPv4 pool %v contains MagicDNS service address %v", pool, tailmixdns.ServiceIP())
	}
	return pool.String(), nil
}

func discardSyntheticLeases(leases []state.EffectiveLease, ipv6 bool) []state.EffectiveLease {
	out := make([]state.EffectiveLease, 0, len(leases))
	for _, lease := range leases {
		if lease.EffectiveIP.IsValid() && lease.EffectiveIP.Is6() == ipv6 && lease.EffectiveIP != lease.CanonicalIP {
			continue
		}
		out = append(out, lease)
	}
	return out
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

func tsnetConfig(rp runtimeProfile, stderr io.Writer, verbose bool) (tailmixprofile.TSNetConfig, error) {
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
		if ps.SelfNodeID != "" {
			for _, ip := range ps.SelfIPs {
				nodes = append(nodes, effectiveip.Node{ProfileID: ps.ProfileID, NodeID: ps.SelfNodeID, CanonicalIP: ip})
			}
		}
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
			return nil, nil, fmt.Errorf("parse synthetic %s pool %q: %w", family.name, family.pool, parseErr)
		}
		if pool.Addr().Is6() != family.ipv6 {
			return nil, nil, fmt.Errorf("synthetic %s pool has wrong address family: %v", family.name, pool)
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
		plan, assignErr := effectiveip.NewAllocator(pool, familyExisting).Assign(familyNodes)
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

func runTUN(ctx context.Context, tunName string, profiles []runtimeProfile, statuses []tailmixprofile.Status, leases []effectiveip.Lease, stderr io.Writer) error {
	table, hostCfg, err := tunConfig(statuses, leases)
	if err != nil {
		return err
	}
	domains, records, err := tunDNSConfig(statuses, leases)
	if err != nil {
		return err
	}
	logf := prefixedLogf(stderr, "tun")
	host, err := hosttun.Open(hosttun.OpenConfig{Name: tunName, Logf: logf})
	if err != nil {
		return err
	}
	defer host.Close()
	if err := host.Configure(hostCfg); err != nil {
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
		Domains: domains,
		Records: records,
		Logf:    prefixedLogf(stderr, "dns"),
	})
	if err != nil {
		return err
	}
	defer dnsService.Close()
	fmt.Fprintf(stderr, "TUN %s configured with %d local address(es) and %d peer route(s)\n", host.Name(), len(hostCfg.LocalAddrs), len(hostCfg.Routes))
	fmt.Fprintf(stderr, "MagicDNS serving %s inside the TUN for %s\n", dnsService.Addr(), magicDNSSuffixes(domains))
	logTUNRoutes(stderr, statuses, leases)
	mux := tunmux.NewMux(host.Device(), profileTUNs, packetmap.New(table), logf)
	mux.SetLocalPacketHandler(dnsService)
	return mux.Run(ctx)
}

func tunDNSConfig(statuses []tailmixprofile.Status, leases []effectiveip.Lease) ([]tailmixdns.Domain, []tailmixdns.Record, error) {
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
		addRecords := func(nodeID, name string, canonicalIPs []netip.Addr) error {
			if name == "" {
				return nil
			}
			for _, canonical := range canonicalIPs {
				key := effectiveip.NodeKey{ProfileID: ps.ProfileID, NodeID: nodeID, CanonicalIP: canonical}
				effective, ok := byKey[key]
				if !ok {
					return fmt.Errorf("profile %q MagicDNS name %q IP %v has no effective lease", ps.ProfileID, name, canonical)
				}
				records = append(records, tailmixdns.Record{ProfileAlias: ps.ProfileID, Name: name, EffectiveIP: effective})
			}
			return nil
		}
		if err := addRecords(ps.SelfNodeID, ps.SelfDNSName, ps.SelfIPs); err != nil {
			return nil, nil, err
		}
		for _, peer := range ps.Peers {
			if err := addRecords(peer.NodeID, peer.DNSName, peer.TailscaleIPs); err != nil {
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

func tunConfig(statuses []tailmixprofile.Status, leases []effectiveip.Lease) (packetmap.Table, hosttun.Config, error) {
	byKey := map[effectiveip.NodeKey]netip.Addr{}
	for _, lease := range leases {
		if existing, ok := byKey[lease.NodeKey]; ok && existing != lease.EffectiveIP {
			return packetmap.Table{}, hosttun.Config{}, fmt.Errorf("node %+v has conflicting effective IP leases %v and %v", lease.NodeKey, existing, lease.EffectiveIP)
		}
		byKey[lease.NodeKey] = lease.EffectiveIP
	}
	table := packetmap.Table{
		Destinations: map[netip.Addr]packetmap.Destination{},
		Sources:      map[packetmap.SourceKey]packetmap.Source{},
		InboundPeers: map[packetmap.InboundKey]netip.Addr{},
	}
	var hostCfg hosttun.Config
	for _, ps := range statuses {
		for _, canonical := range ps.SelfIPs {
			key := effectiveip.NodeKey{ProfileID: ps.ProfileID, NodeID: ps.SelfNodeID, CanonicalIP: canonical}
			effective, ok := byKey[key]
			if !ok {
				return packetmap.Table{}, hosttun.Config{}, fmt.Errorf("profile %q self IP %v has no effective lease", ps.ProfileID, canonical)
			}
			sourceKey := packetmap.SourceKey{ProfileID: ps.ProfileID, IPv6: canonical.Is6()}
			if existing, ok := table.Sources[sourceKey]; ok && existing.CanonicalIP != canonical {
				return packetmap.Table{}, hosttun.Config{}, fmt.Errorf("profile %q has multiple %s self addresses", ps.ProfileID, ipFamily(canonical))
			}
			table.Sources[sourceKey] = packetmap.Source{EffectiveIP: effective, CanonicalIP: canonical}
			hostCfg.LocalAddrs = append(hostCfg.LocalAddrs, netip.PrefixFrom(effective, effective.BitLen()))
		}
		for _, peer := range ps.Peers {
			for _, canonical := range peer.TailscaleIPs {
				key := effectiveip.NodeKey{ProfileID: ps.ProfileID, NodeID: peer.NodeID, CanonicalIP: canonical}
				effective, ok := byKey[key]
				if !ok {
					return packetmap.Table{}, hosttun.Config{}, fmt.Errorf("profile %q peer %q IP %v has no effective lease", ps.ProfileID, peer.NodeID, canonical)
				}
				if existing, ok := table.Destinations[effective]; ok && (existing.ProfileID != ps.ProfileID || existing.CanonicalIP != canonical) {
					return packetmap.Table{}, hosttun.Config{}, fmt.Errorf("effective destination %v maps to multiple peers", effective)
				}
				table.Destinations[effective] = packetmap.Destination{ProfileID: ps.ProfileID, CanonicalIP: canonical}
				inboundKey := packetmap.InboundKey{ProfileID: ps.ProfileID, CanonicalIP: canonical}
				if existing, ok := table.InboundPeers[inboundKey]; ok && existing != effective {
					return packetmap.Table{}, hosttun.Config{}, fmt.Errorf("profile %q canonical peer IP %v maps to multiple effective IPs", ps.ProfileID, canonical)
				}
				table.InboundPeers[inboundKey] = effective
				source, ok := table.Sources[packetmap.SourceKey{ProfileID: ps.ProfileID, IPv6: canonical.Is6()}]
				if !ok {
					return packetmap.Table{}, hosttun.Config{}, fmt.Errorf("profile %q peer %v has no matching %s self address", ps.ProfileID, canonical, ipFamily(canonical))
				}
				hostCfg.Routes = append(hostCfg.Routes, hosttun.Route{
					Destination: netip.PrefixFrom(effective, effective.BitLen()),
					Source:      source.EffectiveIP,
				})
			}
		}
	}
	serviceIP := tailmixdns.ServiceIP()
	for key, source := range table.Sources {
		if source.EffectiveIP == serviceIP {
			return packetmap.Table{}, hosttun.Config{}, fmt.Errorf("profile %q effective self IP conflicts with MagicDNS service IP %v", key.ProfileID, serviceIP)
		}
	}
	if destination, ok := table.Destinations[serviceIP]; ok {
		return packetmap.Table{}, hosttun.Config{}, fmt.Errorf("profile %q effective peer IP conflicts with MagicDNS service IP %v", destination.ProfileID, serviceIP)
	}
	hostCfg.LocalAddrs = append(hostCfg.LocalAddrs, netip.PrefixFrom(serviceIP, serviceIP.BitLen()))
	return table, hostCfg, nil
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
