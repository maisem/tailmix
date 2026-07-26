package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
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
	"github.com/maisem/tailmix/routingpolicy"
	"github.com/maisem/tailmix/state"
	"github.com/maisem/tailmix/tunmux"
	"tailscale.com/net/tsaddr"
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
	fs.Var(&profiles, "profile", "profile config: id=work,dir=/path,hostname=tailmix-work[,suffix=tailnet.ts.net][,auth-key-env=ENV]")
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
	st.Profiles = stateProfiles(runtimeProfiles)
	if err := store.Save(st); err != nil {
		return err
	}
	fmt.Fprintf(stderr, "effective IP pools: IPv4 %s, IPv6 %s\n", st.SyntheticPool, st.SyntheticPoolV6)
	_ = stdout
	supervisor := newSupervisor(store, st, runtimeProfiles, daemonConfig{
		Mode:         *mode,
		TUNName:      *tunName,
		SocketDir:    *socketDir,
		SOCKSAddr:    *socksAddr,
		Verbose:      *verbose,
		LogUpload:    *logUpload,
		LogUploadURL: *logUploadURL,
		Stderr:       stderr,
	})
	return supervisor.Run(ctx)
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
		// Keep the prefix base unassigned. In particular, using the IPv4
		// network address as the aggregate TUN's point-to-point identity can
		// make Darwin route packets DNATed to that address back out the TUN
		// instead of delivering them locally.
		if current := *family.current; current.IsValid() && current != pool.Addr() && current.Is6() == family.ipv6 && pool.Contains(current) && !used[current] {
			used[current] = true
			continue
		}
		*family.current = netip.Addr{}
		for ip := pool.Addr().Next(); pool.Contains(ip); ip = ip.Next() {
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
	IPPolicy     routingpolicy.IPPlan
	DNSPolicy    routingpolicy.DNSPlan
	Table        packetmap.Table
	HostConfig   hosttun.Config
	DNSConfig    tailmixdns.LiveConfig
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
	ipPolicy := routingpolicy.BuildIP(st, statuses)
	dnsPolicy := routingpolicy.BuildDNS(st, statuses)
	table, hostCfg, err := tunConfigWithPolicy(st, statuses, activeLeases, ipPolicy)
	if err != nil {
		return tunPlan{}, err
	}
	dnsConfig, err := tunDNSLiveConfig(st, statuses, activeLeases, dnsPolicy)
	if err != nil {
		return tunPlan{}, err
	}
	return tunPlan{
		State:        st,
		Statuses:     statuses,
		ActiveLeases: activeLeases,
		IPPolicy:     ipPolicy,
		DNSPolicy:    dnsPolicy,
		Table:        table,
		HostConfig:   hostCfg,
		DNSConfig:    dnsConfig,
		Domains:      dnsConfig.Domains,
		Records:      dnsConfig.Records,
	}, nil
}

func tunDNSConfig(st state.State, statuses []tailmixprofile.Status, leases []effectiveip.Lease) ([]tailmixdns.Domain, []tailmixdns.Record, error) {
	cfg, err := tunDNSLiveConfig(st, statuses, leases, routingpolicy.BuildDNS(st, statuses))
	if err != nil {
		return nil, nil, err
	}
	return cfg.Domains, cfg.Records, nil
}

func tunDNSLiveConfig(st state.State, statuses []tailmixprofile.Status, leases []effectiveip.Lease, policy routingpolicy.DNSPlan) (tailmixdns.LiveConfig, error) {
	byKey := make(map[effectiveip.NodeKey]netip.Addr, len(leases))
	for _, lease := range leases {
		if existing, ok := byKey[lease.NodeKey]; ok && existing != lease.EffectiveIP {
			return tailmixdns.LiveConfig{}, fmt.Errorf("node %+v has conflicting effective IP leases %v and %v", lease.NodeKey, existing, lease.EffectiveIP)
		}
		byKey[lease.NodeKey] = lease.EffectiveIP
	}
	suffixByProfile := map[string]string{}
	type candidateRecord struct {
		record tailmixdns.Record
		owner  string
	}
	var candidates []candidateRecord
	for _, ps := range statuses {
		if ps.MagicDNSSuffix == "" {
			continue
		}
		suffixByProfile[ps.ProfileID] = ps.MagicDNSSuffix
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
				candidates = append(candidates, candidateRecord{
					owner: ps.ProfileID,
					record: tailmixdns.Record{
						ProfileID:   ps.ProfileID,
						Name:        name,
						EffectiveIP: effective,
					},
				})
			}
			return nil
		}
		if err := addRecords(ps.SelfNodeID, ps.SelfDNSName, ps.SelfIPs, true); err != nil {
			return tailmixdns.LiveConfig{}, err
		}
		for _, peer := range ps.Peers {
			if err := addRecords(peer.NodeID, peer.DNSName, peer.TailscaleIPs, false); err != nil {
				return tailmixdns.LiveConfig{}, err
			}
		}
	}
	var records []tailmixdns.Record
	domainOwners := map[string]bool{}
	sharedByName := map[string]map[string]bool{}
	for _, candidate := range candidates {
		name := routingpolicy.NormalizeDomain(candidate.record.Name)
		entry, matched := policy.Resolve(name)
		if matched {
			if entry.Active && entry.ProfileID == candidate.owner {
				records = append(records, candidate.record)
				domainOwners[candidate.owner] = true
			}
			continue
		}
		owners := sharedByName[name]
		if owners == nil {
			owners = map[string]bool{}
			sharedByName[name] = owners
		}
		owners[candidate.owner] = true
	}
	routeBySuffix := map[string]tailmixdns.Route{}
	addPolicyRoute := func(entry routingpolicy.DNSEntry) {
		resolvers := entry.Resolvers
		if !entry.Active {
			resolvers = nil
		}
		routeBySuffix[entry.Domain] = tailmixdns.Route{Suffix: entry.Domain, ProfileID: entry.ProfileID, Resolvers: resolvers}
		if entry.Active && entry.Source == "magicdns" && entry.ProfileID != "" {
			domainOwners[entry.ProfileID] = true
		}
	}
	for _, entry := range policy.Automatic {
		if coveredByDNSPolicy(entry.Domain, policy.Exact) || coveredByDNSPolicy(entry.Domain, policy.Imported) {
			continue
		}
		addPolicyRoute(entry)
	}
	for _, entry := range policy.Imported {
		if coveredByDNSPolicy(entry.Domain, policy.Exact) {
			continue
		}
		addPolicyRoute(entry)
	}
	for _, entry := range policy.Exact {
		addPolicyRoute(entry)
	}
	for name, owners := range sharedByName {
		if len(owners) != 1 {
			continue
		}
		var owner string
		for owner = range owners {
		}
		for _, candidate := range candidates {
			if candidate.owner == owner && routingpolicy.NormalizeDomain(candidate.record.Name) == name {
				records = append(records, candidate.record)
				domainOwners[owner] = true
			}
		}
		routeBySuffix[name] = tailmixdns.Route{Suffix: name}
	}
	var domains []tailmixdns.Domain
	for profileID := range domainOwners {
		if suffix := suffixByProfile[profileID]; suffix != "" {
			domains = append(domains, tailmixdns.Domain{
				ProfileID:         profileID,
				Suffix:            suffix,
				AuthoritativeOnly: true,
			})
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
	routes := make([]tailmixdns.Route, 0, len(routeBySuffix))
	for _, route := range routeBySuffix {
		routes = append(routes, route)
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].Suffix < routes[j].Suffix })
	searchDomains := make([]string, 0, len(policy.Search.Installed))
	for _, domain := range policy.Search.Installed {
		searchDomains = append(searchDomains, domain.Domain)
	}
	return tailmixdns.LiveConfig{
		Domains:       domains,
		Records:       records,
		Routes:        routes,
		SearchDomains: searchDomains,
	}, nil
}

func coveredByDNSPolicy(domain string, entries []routingpolicy.DNSEntry) bool {
	for _, entry := range entries {
		if routingpolicy.DNSContains(entry.Domain, domain) {
			return true
		}
	}
	return false
}

func tunConfig(st state.State, statuses []tailmixprofile.Status, leases []effectiveip.Lease) (packetmap.Table, hosttun.Config, error) {
	return tunConfigWithPolicy(st, statuses, leases, routingpolicy.BuildIP(st, statuses))
}

func tunConfigWithPolicy(st state.State, statuses []tailmixprofile.Status, leases []effectiveip.Lease, policy routingpolicy.IPPlan) (packetmap.Table, hosttun.Config, error) {
	byKey := map[effectiveip.NodeKey]netip.Addr{}
	for _, lease := range leases {
		if existing, ok := byKey[lease.NodeKey]; ok && existing != lease.EffectiveIP {
			return packetmap.Table{}, hosttun.Config{}, fmt.Errorf("node %+v has conflicting effective IP leases %v and %v", lease.NodeKey, existing, lease.EffectiveIP)
		}
		byKey[lease.NodeKey] = lease.EffectiveIP
	}
	table := packetmap.Table{
		Destinations:   new(bart.Table[packetmap.Destination]),
		ExactRoutes:    new(bart.Table[packetmap.SubnetRoute]),
		ImportedRoutes: new(bart.Table[packetmap.SubnetRoute]),
		ExitRoutes:     new(bart.Table[packetmap.SubnetRoute]),
		Sources:        map[packetmap.SourceKey]packetmap.Source{},
		InboundPeers:   map[string]*bart.Table[netip.Addr]{},
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
				source, ok := table.Sources[packetmap.SourceKey{ProfileID: ps.ProfileID, IPv6: canonical.Is6()}]
				if !ok {
					return packetmap.Table{}, hosttun.Config{}, fmt.Errorf("profile %q peer %v has no matching %s self address", ps.ProfileID, canonical, ipFamily(canonical))
				}
				hostCfg.Routes = append(hostCfg.Routes, hosttun.Route{
					Destination: effectivePrefix,
					Source:      source.HostIP,
				})
			}
		}
	}
	for _, entry := range policy.Exact {
		if routeOverlapsReserved(st, entry.Prefix) {
			return packetmap.Table{}, hosttun.Config{}, fmt.Errorf("bound route %v overlaps a tailmix reserved range", entry.Prefix)
		}
		table.ExactRoutes.Insert(entry.Prefix, packetmap.SubnetRoute{ProfileID: entry.ProfileID, Active: entry.Active})
		if entry.Active {
			if _, ok := table.Sources[packetmap.SourceKey{ProfileID: entry.ProfileID, IPv6: entry.Prefix.Addr().Is6()}]; !ok {
				return packetmap.Table{}, hosttun.Config{}, fmt.Errorf("profile %q route %v has no matching self address", entry.ProfileID, entry.Prefix)
			}
			hostCfg.Routes = append(hostCfg.Routes, hosttun.Route{
				Destination: entry.Prefix,
				Source:      natIPFor(st, entry.Prefix.Addr()),
			})
		}
	}
	for _, entry := range policy.Imported {
		active := entry.Active && !routeOverlapsReserved(st, entry.Prefix)
		table.ImportedRoutes.Insert(entry.Prefix, packetmap.SubnetRoute{ProfileID: entry.ProfileID, Active: active})
		if active {
			if _, ok := table.Sources[packetmap.SourceKey{ProfileID: entry.ProfileID, IPv6: entry.Prefix.Addr().Is6()}]; !ok {
				return packetmap.Table{}, hosttun.Config{}, fmt.Errorf("profile %q imported route %v has no matching self address", entry.ProfileID, entry.Prefix)
			}
			hostCfg.Routes = append(hostCfg.Routes, hosttun.Route{
				Destination: entry.Prefix,
				Source:      natIPFor(st, entry.Prefix.Addr()),
			})
		}
	}
	if exitProfileID := activeExitProfile(st, statuses); exitProfileID != "" {
		for _, ipv6 := range []bool{false, true} {
			if _, ok := table.Sources[packetmap.SourceKey{ProfileID: exitProfileID, IPv6: ipv6}]; !ok {
				continue
			}
			defaultRoute := netip.PrefixFrom(netip.IPv4Unspecified(), 0)
			if ipv6 {
				defaultRoute = netip.PrefixFrom(netip.IPv6Unspecified(), 0)
			}
			table.ExitRoutes.Insert(defaultRoute, packetmap.SubnetRoute{ProfileID: exitProfileID, Active: true})
			for _, route := range splitDefaultRoutes(ipv6) {
				hostCfg.Routes = append(hostCfg.Routes, hosttun.Route{
					Destination: route,
					Source:      natIPFor(st, route.Addr()),
					Exit:        true,
				})
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
	hostCfg.Routes = append(hostCfg.Routes, hosttun.Route{
		Destination: netip.PrefixFrom(serviceIP, serviceIP.BitLen()),
		Source:      st.NATIP,
	})
	return table, hostCfg, nil
}

func activeExitProfile(st state.State, statuses []tailmixprofile.Status) string {
	if st.ExitNode == nil {
		return ""
	}
	for _, status := range statuses {
		if status.ProfileID == st.ExitNode.ProfileID &&
			(status.BackendState == "" || status.BackendState == "Running") &&
			status.ExitNodeID == st.ExitNode.NodeID {
			return status.ProfileID
		}
	}
	return ""
}

// Split defaults take precedence over the host's ordinary default without
// replacing it. The tsnet fork publishes the interface owning the underlying
// /0 route as Darwin's OS-provided default, and the Darwin host router gives
// that interface its own scoped default. Together those keep netns-bound
// underlay sockets out of these aggregate TUN routes.
func splitDefaultRoutes(ipv6 bool) []netip.Prefix {
	if ipv6 {
		return []netip.Prefix{
			netip.MustParsePrefix("::/1"),
			netip.MustParsePrefix("8000::/1"),
		}
	}
	return []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/1"),
		netip.MustParsePrefix("128.0.0.0/1"),
	}
}

func routeOverlapsReserved(st state.State, prefix netip.Prefix) bool {
	for _, reserved := range []netip.Prefix{tsaddr.CGNATRange(), tsaddr.TailscaleULARange()} {
		if prefixesOverlap(prefix, reserved) {
			return true
		}
	}
	for _, raw := range []string{st.SyntheticPool, st.SyntheticPoolV6} {
		pool, err := netip.ParsePrefix(raw)
		if err == nil && prefixesOverlap(prefix, pool) {
			return true
		}
	}
	for _, addr := range []netip.Addr{st.NATIP, st.NATIPv6, tailmixdns.ServiceIP()} {
		if addr.IsValid() && prefix.Addr().Is6() == addr.Is6() && prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func prefixesOverlap(a, b netip.Prefix) bool {
	if !a.IsValid() || !b.IsValid() || a.Addr().BitLen() != b.Addr().BitLen() {
		return false
	}
	a, b = a.Masked(), b.Masked()
	return a.Contains(b.Addr()) || b.Contains(a.Addr())
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
