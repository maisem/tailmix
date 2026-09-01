package main

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	tailmixprofile "github.com/maisem/tailmix/profile"
	"github.com/maisem/tailmix/state"
	"github.com/maisem/tailmix/tunmux"
	"github.com/maisem/tailmix/wireguardcfg"
	"github.com/tailscale/wireguard-go/conn/bindtest"
)

func TestWireGuardProfileProjectsStableEffectiveAddresses(t *testing.T) {
	canonical := netip.MustParseAddr("10.80.0.2")
	effective := netip.MustParseAddr("100.127.0.7")
	config := wireguardcfg.Config{
		Version: wireguardcfg.Version,
		Name:    "lab", DNSSuffix: "lab.example",
		Addresses: []netip.Addr{netip.MustParseAddr("10.80.0.1")},
		Peers: []wireguardcfg.Peer{{
			Name:      "gateway",
			PublicKey: wireguardcfg.Key{1}, Addresses: []netip.Addr{canonical},
			Routes: []netip.Prefix{netip.MustParsePrefix("10.90.0.0/16")}, ExitNode: true,
		}},
	}
	configured := state.Profile{
		ID: "p_lab", Name: "lab", Kind: state.ProfileKindWireGuard,
		StateDir: t.TempDir(), WireGuard: &config,
		WireGuardSecretFile: "wireguard-secrets-unavailable.json",
	}
	s := &supervisor{
		st: state.State{
			Profiles: []state.Profile{configured},
			Leases: []state.EffectiveLease{{
				ProfileID: configured.ID, NodeID: "gateway",
				CanonicalIP: canonical, EffectiveIP: effective,
			}},
		},
		runtimes: map[string]*managedProfile{},
	}

	got, err := s.wireGuardProfileLocked(configured)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Peers) != 1 || len(got.Peers[0].EffectiveAddresses) != 1 || got.Peers[0].EffectiveAddresses[0] != effective {
		t.Fatalf("profile effective addresses = %+v, want %v", got.Peers, effective)
	}
	if got.Peers[0].Name != "gateway" || got.Peers[0].Addresses[0] != canonical || got.Peers[0].Routes[0] != netip.MustParsePrefix("10.90.0.0/16") || !got.Peers[0].ExitNode {
		t.Fatalf("profile peer projection lost declarative state: %+v", got.Peers[0])
	}
}

func TestWireGuardShieldsUpPersistsWithoutRuntimeAndRemovalClearsIt(t *testing.T) {
	configured := wireGuardFilterTestProfile(t)
	configured.Disabled = true
	st := state.State{
		Down: true, SyntheticPool: "100.127.0.0/24", SyntheticPoolV6: "fd6d:6e65:7400::/56",
		Profiles: []state.Profile{configured},
	}
	s := newLifecycleTestSupervisor(t, st)

	got, err := s.SetWireGuardShieldsUp(context.Background(), "lab", true)
	if err != nil {
		t.Fatal(err)
	}
	if !got.ShieldsUp || !s.st.Profiles[0].WireGuardShieldsUp {
		t.Fatalf("shields-up result = %+v, state = %+v", got, s.st.Profiles[0])
	}
	persisted, err := s.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !persisted.Profiles[0].WireGuardShieldsUp {
		t.Fatal("shields-up was not persisted while daemon and profile were down")
	}

	s.st.Down = false
	if err := s.store.Save(s.st); err != nil {
		t.Fatal(err)
	}
	removed, err := s.RemoveProfile(context.Background(), "lab", false)
	if err != nil {
		t.Fatal(err)
	}
	if removed.ShieldsUp || s.st.Profiles[0].WireGuardShieldsUp {
		t.Fatalf("removal retained shields-up: result = %+v, state = %+v", removed, s.st.Profiles[0])
	}
}

func TestWireGuardApplyPreservesShieldsUpWhileDisabled(t *testing.T) {
	configured := wireGuardFilterTestProfile(t)
	configured.Disabled = true
	configured.WireGuardShieldsUp = true
	private, err := wireguardcfg.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	secretFile, err := writeWireGuardSecrets(configured.StateDir, wireguardcfg.Secrets{PrivateKey: &private})
	if err != nil {
		t.Fatal(err)
	}
	configured.WireGuardSecretFile = secretFile
	st := state.State{
		SyntheticPool: "100.127.0.0/24", SyntheticPoolV6: "fd6d:6e65:7400::/56",
		Profiles: []state.Profile{configured},
	}
	s := newLifecycleTestSupervisor(t, st)
	s.cfg.Mode = "tun"
	updated := configured.WireGuard.Clone()
	updated.ListenPort = 51821
	got, err := s.ApplyWireGuard(context.Background(), updated, wireguardcfg.Secrets{})
	if err != nil {
		t.Fatal(err)
	}
	if !got.ShieldsUp || !s.st.Profiles[0].WireGuardShieldsUp || s.st.Profiles[0].WireGuard.ListenPort != 51821 {
		t.Fatalf("apply did not preserve shields-up: result = %+v, state = %+v", got, s.st.Profiles[0])
	}
}

func TestWireGuardShieldsUpRunningPersistenceFailureRestoresState(t *testing.T) {
	configured := wireGuardFilterTestProfile(t)
	st := state.State{
		SyntheticPool: "100.127.0.0/24", SyntheticPoolV6: "fd6d:6e65:7400::/56",
		Profiles: []state.Profile{configured},
	}
	s := newLifecycleTestSupervisor(t, st)

	private, err := wireguardcfg.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	raw := tunmux.NewChanTUN("shields-test")
	binds := bindtest.NewChannelBinds()
	engine := tailmixprofile.NewWireGuardEngine(tailmixprofile.WireGuardEngineConfig{
		ProfileID: configured.ID, Config: configured.WireGuard.Clone(),
		Secrets: wireguardcfg.Secrets{PrivateKey: &private}, Tun: raw, Bind: binds[0],
	})
	if err := engine.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	status, err := engine.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	s.runtimes[configured.ID] = &managedProfile{
		runtime: runtimeProfile{State: configured, Engine: engine, Tun: raw},
		status:  status,
	}

	if _, err := s.SetWireGuardShieldsUp(context.Background(), "lab", true); err != nil {
		t.Fatal(err)
	}
	if got := s.projectProfileLocked(s.st.Profiles[0]); !got.ShieldsUp {
		t.Fatalf("aggregate profile did not reflect running shields-up: %+v", got)
	}

	goodStore := s.store
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	badStore := state.NewJSONStore(filepath.Join(blocker, "state.json"))
	s.store = badStore
	if _, err := s.SetWireGuardShieldsUp(context.Background(), "lab", false); err == nil {
		t.Fatal("disabling shields-up succeeded despite persistence failure")
	}
	status, err = engine.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !status.ShieldsUp || !s.st.Profiles[0].WireGuardShieldsUp {
		t.Fatalf("failed disable persistence cleared shields-up: status = %+v, state = %+v", status, s.st.Profiles[0])
	}

	s.store = goodStore
	if _, err := s.SetWireGuardShieldsUp(context.Background(), "lab", false); err != nil {
		t.Fatal(err)
	}
	s.store = badStore
	if _, err := s.SetWireGuardShieldsUp(context.Background(), "lab", true); err == nil {
		t.Fatal("enabling shields-up succeeded despite persistence failure")
	}
	status, err = engine.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if status.ShieldsUp || s.st.Profiles[0].WireGuardShieldsUp {
		t.Fatalf("failed persistence changed shields-up: status = %+v, state = %+v", status, s.st.Profiles[0])
	}
}

func TestWireGuardShieldsUpRejectsNonWireGuardProfile(t *testing.T) {
	st := lifecycleTestState()
	s := newLifecycleTestSupervisor(t, st)
	if _, err := s.SetWireGuardShieldsUp(context.Background(), "work", true); err == nil {
		t.Fatal("SetWireGuardShieldsUp accepted a Tailscale profile")
	}
}

func TestWireGuardProfileProjectsFilterStatus(t *testing.T) {
	configured := wireGuardFilterTestProfile(t)
	configured.WireGuardShieldsUp = true
	s := &supervisor{
		st:       state.State{Profiles: []state.Profile{configured}},
		runtimes: map[string]*managedProfile{},
	}
	got, err := s.wireGuardProfileLocked(configured)
	if err != nil {
		t.Fatal(err)
	}
	if !got.ShieldsUp || got.GrantCount != 1 || len(got.PacketFilter.Grants) != 1 {
		t.Fatalf("filter projection = %+v", got)
	}
	if len(got.DestinationResolutions) != 2 || got.DestinationResolutions[0].State != "partial" || got.DestinationResolutions[0].Reason != "forwarding_unavailable" || got.DestinationResolutions[1].State != "active" {
		t.Fatalf("destination resolutions = %+v", got.DestinationResolutions)
	}
}

func wireGuardFilterTestProfile(t *testing.T) state.Profile {
	t.Helper()
	peerPrivate, err := wireguardcfg.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	peerPublic, err := peerPrivate.Public()
	if err != nil {
		t.Fatal(err)
	}
	config := wireguardcfg.Config{
		Version: wireguardcfg.Version, Name: "lab", DNSSuffix: "lab.example",
		Addresses: []netip.Addr{netip.MustParseAddr("10.80.0.1")},
		PacketFilter: wireguardcfg.PacketFilter{Grants: []wireguardcfg.Grant{{
			Src: []string{"peer:gateway"}, Dst: []string{"*", "self"}, IP: []string{"tcp:22"},
		}}},
		Peers: []wireguardcfg.Peer{{
			Name: "gateway", PublicKey: peerPublic, Addresses: []netip.Addr{netip.MustParseAddr("10.80.0.2")},
		}},
	}
	return state.Profile{
		ID: "p_lab", Name: "lab", Kind: state.ProfileKindWireGuard,
		StateDir: t.TempDir(), WireGuard: &config,
		WireGuardSecretFile: "wireguard-secrets-test.json",
	}
}

func TestValidateWireGuardEndpointNamesRejectsProfileDNSRecursion(t *testing.T) {
	config := wireguardcfg.Config{Peers: []wireguardcfg.Peer{{
		Name: "gateway", Endpoint: "gateway.lab.example:51820",
	}}}
	config.DNSSuffix = "lab.example"
	if err := validateWireGuardEndpointNames(config); err == nil {
		t.Fatal("accepted an endpoint served by the same WireGuard profile")
	}
	config.Peers[0].Endpoint = "gateway.example.net:51820"
	if err := validateWireGuardEndpointNames(config); err != nil {
		t.Fatalf("rejected independent endpoint: %v", err)
	}
}

func TestNormalizeProfileByIDReacquiresSortedProfile(t *testing.T) {
	config := wireguardcfg.Config{
		Version: wireguardcfg.Version, Name: "lab", DNSSuffix: "lab.example",
		Addresses: []netip.Addr{netip.MustParseAddr("10.80.0.1")},
	}
	st := state.State{Profiles: []state.Profile{
		{ID: "z_existing", Name: "existing", Kind: state.ProfileKindTailscale},
		{ID: "p_new", Name: "lab", Kind: state.ProfileKindWireGuard, WireGuard: &config},
	}}
	stale := &st.Profiles[1]

	configured, err := normalizeProfileByID(&st, "p_new")
	if err != nil {
		t.Fatal(err)
	}
	if stale.ID != "z_existing" {
		t.Fatalf("test did not force the original pointer to become stale: points to %q", stale.ID)
	}
	if configured.ID != "p_new" || configured.WireGuard == nil || configured.WireGuard.Name != "lab" {
		t.Fatalf("reacquired profile = %+v", configured)
	}
}
