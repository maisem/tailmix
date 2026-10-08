package main

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/maisem/tailmix/controlapi"
	"github.com/maisem/tailmix/effectiveip"
	tailmixprofile "github.com/maisem/tailmix/profile"
	"github.com/maisem/tailmix/profilesocket"
	"github.com/maisem/tailmix/state"
)

func retentionTestLease() state.EffectiveLease {
	return state.EffectiveLease{
		ProfileID: "work", NodeID: "gone",
		CanonicalIP: netip.MustParseAddr("100.64.0.2"),
		EffectiveIP: netip.MustParseAddr("100.127.0.3"),
	}
}

func retentionTestStatus() tailmixprofile.Status {
	return tailmixprofile.Status{
		ProfileID: "work", BackendState: "Running", SelfNodeID: "self",
		SelfIPs: []netip.Addr{netip.MustParseAddr("100.64.0.1")}, RouteAll: true,
	}
}

func TestEffectiveLeaseFullPoolReclaimsAfterOneHour(t *testing.T) {
	st := state.State{
		SyntheticPool: "100.127.0.0/30", SyntheticPoolV6: "fd6d:6e65:7400::/56",
		NATIP: netip.MustParseAddr("100.127.0.1"), DNSIP: netip.MustParseAddr("100.127.0.2"),
		Profiles: []state.Profile{{ID: "work", StateDir: "profiles/work"}},
		Leases:   []state.EffectiveLease{retentionTestLease(), retentionTestLease()},
	}
	st.Leases[1].NodeID = "also-gone"
	st.Leases[1].CanonicalIP = netip.MustParseAddr("100.64.0.3")
	st.Leases[1].EffectiveIP = netip.MustParseAddr("100.127.0.0")
	status := retentionTestStatus()
	status.Peers = []tailmixprofile.PeerStatus{{
		NodeID: "new", TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.9")},
	}}
	s := newLifecycleTestSupervisor(t, st)
	s.runtimes["work"] = &managedProfile{runtime: runtimeProfile{Engine: &lifecycleEngine{status: status}}}
	if err := s.reconcileLocked(); !errors.Is(err, effectiveip.ErrPoolExhausted) {
		t.Fatalf("reconcile = %v, want exhaustion", err)
	}
	// A failed allocation still starts the in-memory absence clock. No
	// periodic work or persisted activity timestamps are needed to recover.
	base := time.Now()
	if err := s.refreshLeasesLocked([]tailmixprofile.Status{status}, base.Add(59*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(s.st.Leases) != 2 {
		t.Fatal("departed leases expired early")
	}
	if err := s.refreshLeasesLocked([]tailmixprofile.Status{status}, base.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.reconcileLocked(); err != nil {
		t.Fatalf("pool did not recover: %v", err)
	}
	if len(s.st.Leases) != 1 || s.st.Leases[0].NodeID != "new" {
		t.Fatalf("recovered leases = %+v", s.st.Leases)
	}
}

func TestEffectiveLeaseRestartGrantsFreshHour(t *testing.T) {
	st := lifecycleTestState()
	st.Leases = []state.EffectiveLease{retentionTestLease()}
	s := newLifecycleTestSupervisor(t, st)
	s.runtimes["work"] = &managedProfile{statusFresh: true}
	status := []tailmixprofile.Status{retentionTestStatus()}
	base := time.Now()
	if err := s.refreshLeasesLocked(status, base); err != nil {
		t.Fatal(err)
	}
	restarted := newLifecycleTestSupervisor(t, s.st)
	restarted.runtimes["work"] = &managedProfile{statusFresh: true}
	start := base.Add(24 * time.Hour)
	if err := restarted.refreshLeasesLocked(status, start); err != nil {
		t.Fatal(err)
	}
	if err := restarted.refreshLeasesLocked(status, start.Add(59*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(restarted.st.Leases) != 1 {
		t.Fatal("restart trusted an earlier process's absence clock")
	}
	if err := restarted.refreshLeasesLocked(status, start.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if len(restarted.st.Leases) != 0 {
		t.Fatal("fresh grace did not expire")
	}
}

type retentionStatusErrorEngine struct{ lifecycleEngine }

func (*retentionStatusErrorEngine) Status(context.Context) (tailmixprofile.Status, error) {
	return tailmixprofile.Status{}, errors.New("status unavailable")
}

func TestEffectiveLeaseUnavailableStatusDoesNotExpire(t *testing.T) {
	st := lifecycleTestState()
	st.Profiles = []state.Profile{{ID: "work", StateDir: "profiles/work"}}
	st.Leases = []state.EffectiveLease{retentionTestLease()}
	s := newLifecycleTestSupervisor(t, st)
	s.runtimes["work"] = &managedProfile{
		runtime: runtimeProfile{Engine: &retentionStatusErrorEngine{}},
		status:  retentionTestStatus(), statusFresh: true,
	}
	base := time.Now()
	if err := s.refreshLeasesLocked([]tailmixprofile.Status{retentionTestStatus()}, base); err != nil {
		t.Fatal(err)
	}
	statuses := usableStatuses(s.statusesLocked())
	if err := s.refreshLeasesLocked(statuses, base.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if len(s.st.Leases) != 1 {
		t.Fatal("failed status read expired lease using cached netmap")
	}
	for _, statuses := range [][]tailmixprofile.Status{nil, {{ProfileID: "work", BackendState: "Running"}}} {
		if err := s.refreshLeasesLocked(statuses, base.Add(3*time.Hour)); err != nil {
			t.Fatal(err)
		}
		if len(s.st.Leases) != 1 {
			t.Fatal("unobserved profile lost lease")
		}
	}
}

func TestEffectiveLeaseFailedSaveDoesNotPublishReclamation(t *testing.T) {
	st := lifecycleTestState()
	st.Leases = []state.EffectiveLease{retentionTestLease()}
	s := newLifecycleTestSupervisor(t, st)
	s.runtimes["work"] = &managedProfile{statusFresh: true}
	statuses := []tailmixprofile.Status{retentionTestStatus()}
	base := time.Now()
	if err := s.refreshLeasesLocked(statuses, base); err != nil {
		t.Fatal(err)
	}
	before := slices.Clone(s.st.Leases)
	s.store = state.NewJSONStore(filepath.Join("/dev/null", "state.json"))
	if err := s.refreshLeasesLocked(statuses, base.Add(time.Hour)); err == nil {
		t.Fatal("expected save error")
	}
	if !slices.Equal(s.st.Leases, before) {
		t.Fatal("failed save released an address")
	}
}
func TestSupervisorStartsControlWithExhaustedPool(t *testing.T) {
	st := state.State{
		SyntheticPool: "100.127.0.0/30", SyntheticPoolV6: "fd6d:6e65:7400::/56",
		NATIP: netip.MustParseAddr("100.127.0.1"), DNSIP: netip.MustParseAddr("100.127.0.2"),
		Profiles: []state.Profile{{ID: "work", StateDir: "profiles/work"}},
		Leases:   []state.EffectiveLease{retentionTestLease(), retentionTestLease()},
	}
	st.Leases[1].NodeID = "also-gone"
	st.Leases[1].CanonicalIP = netip.MustParseAddr("100.64.0.3")
	st.Leases[1].EffectiveIP = netip.MustParseAddr("100.127.0.0")
	dir := t.TempDir()
	store := state.NewJSONStore(filepath.Join(dir, "state.json"))
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}
	s := newSupervisor(store, st, nil, daemonConfig{
		Mode: "socks", SOCKSAddr: "127.0.0.1:0", SocketDir: dir, Stderr: io.Discard,
	})
	status := retentionTestStatus()
	status.Peers = []tailmixprofile.PeerStatus{{
		NodeID: "new", TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.9")},
	}}
	s.runtimes["work"] = &managedProfile{
		runtime: runtimeProfile{State: st.Profiles[0], Engine: &lifecycleEngine{status: status}},
		cancel:  func() {},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run returned %v", err)
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(profilesocket.ControlPath(dir)); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("exhausted daemon did not start control API")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := controlapi.NewClient(dir).Status(ctx); err != nil {
		t.Fatalf("exhausted daemon control API unavailable: %v", err)
	}
	s.mu.Lock()
	err := s.reconcileErr
	s.mu.Unlock()
	if err == "" {
		t.Fatal("pool exhaustion was not reported")
	}
}
