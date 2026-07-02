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

	"tailscale.com/mnet/effectiveip"
	mnetprofile "tailscale.com/mnet/profile"
	"tailscale.com/mnet/socksproxy"
	"tailscale.com/mnet/state"
)

const defaultSyntheticPool = "100.127.0.0/24"

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
	Engine     mnetprofile.Engine
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
	fs := flag.NewFlagSet("mnetd", flag.ContinueOnError)
	fs.SetOutput(stderr)
	statePath := fs.String("state", defaultStatePath(), "path to mnet daemon state")
	socksAddr := fs.String("socks", "127.0.0.1:1080", "aggregate SOCKS5 listen address")
	verbose := fs.Bool("verbose", false, "enable verbose per-profile tsnet logs")
	fs.Var(&profiles, "profile", "profile config: id=work,dir=/path,hostname=mnet-work[,control-url=URL][,suffix=tailnet.ts.net][,auth-key-env=ENV]")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *statePath == "" {
		return fmt.Errorf("state path is required")
	}
	if *socksAddr == "" {
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
	if st.SyntheticPool == "" {
		st.SyntheticPool = defaultSyntheticPool
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

	mgr := mnetprofile.NewManager()
	for i := range runtimeProfiles {
		rp := &runtimeProfiles[i]
		cfg, err := tsnetConfig(*rp, stderr, *verbose)
		if err != nil {
			return err
		}
		rp.Engine = mnetprofile.NewTSNetEngine(cfg)
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

	pool, err := netip.ParsePrefix(st.SyntheticPool)
	if err != nil {
		return fmt.Errorf("parse synthetic pool %q: %w", st.SyntheticPool, err)
	}
	plan, err := effectiveip.NewAllocator(pool, leasesFromState(st.Leases)).Assign(leaseNodes(statuses))
	if err != nil {
		return err
	}
	st.Leases = leasesToState(plan.Leases)
	if err := store.Save(st); err != nil {
		return err
	}

	routerProfiles, err := socksProfiles(runtimeProfiles, statuses)
	if err != nil {
		return err
	}
	router, err := socksproxy.NewRouter(routerProfiles, plan.Leases)
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
		return filepath.Join(".", "mnet-state.json")
	}
	return filepath.Join(dir, "mnet", "state.json")
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
			rp.State.Hostname = "mnet-" + dnsLabel(rp.State.ID)
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
			return fmt.Errorf("global TS_AUTHKEY/TS_AUTH_KEY is set; use per-profile auth-key-env or unset it before starting mnetd")
		}
	}
	return nil
}

func tsnetConfig(rp runtimeProfile, stderr io.Writer, verbose bool) (mnetprofile.TSNetConfig, error) {
	authKey := ""
	if rp.AuthKeyEnv != "" {
		authKey = os.Getenv(rp.AuthKeyEnv)
		if authKey == "" {
			return mnetprofile.TSNetConfig{}, fmt.Errorf("profile %q auth-key-env %s is empty", rp.State.ID, rp.AuthKeyEnv)
		}
	}
	cfg := mnetprofile.TSNetConfig{
		ProfileID:      rp.State.ID,
		Alias:          rp.State.Alias,
		Dir:            rp.State.StateDir,
		Hostname:       rp.State.Hostname,
		AuthKey:        authKey,
		ControlURL:     rp.State.ControlURL,
		MagicDNSSuffix: rp.State.MagicDNSSuffix,
		UserLogf:       prefixedLogf(stderr, rp.State.ID),
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

func updateProfileMetadata(st *state.State, statuses []mnetprofile.Status) {
	byID := map[string]mnetprofile.Status{}
	for _, ps := range statuses {
		byID[ps.ProfileID] = ps
	}
	for i := range st.Profiles {
		if ps, ok := byID[st.Profiles[i].ID]; ok && ps.MagicDNSSuffix != "" {
			st.Profiles[i].MagicDNSSuffix = ps.MagicDNSSuffix
		}
	}
}

func leaseNodes(statuses []mnetprofile.Status) []effectiveip.Node {
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
		if lease.ProfileID == "" || lease.NodeID == "" || !lease.CanonicalIP.IsValid() || !lease.EffectiveIP.IsValid() {
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

func socksProfiles(profiles []runtimeProfile, statuses []mnetprofile.Status) ([]socksproxy.Profile, error) {
	byID := map[string]mnetprofile.Status{}
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
