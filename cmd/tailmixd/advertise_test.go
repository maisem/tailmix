package main

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/maisem/tailmix/controlapi"
	tailmixprofile "github.com/maisem/tailmix/profile"
	"github.com/maisem/tailmix/state"
)

type advertiseEngine struct {
	status   tailmixprofile.Status
	changes  [][]netip.Prefix
	closed   bool
	closeErr error
}

func (e *advertiseEngine) Start(context.Context) error { return nil }
func (e *advertiseEngine) Close() error {
	e.closed = true
	return e.closeErr
}
func (e *advertiseEngine) Dial(context.Context, string, string) (net.Conn, error) {
	return nil, net.ErrClosed
}
func (e *advertiseEngine) Status(context.Context) (tailmixprofile.Status, error) {
	return e.status, nil
}
func (e *advertiseEngine) WatchUpdates(context.Context, func()) error { return nil }
func (e *advertiseEngine) SetAdvertiseRoutes(_ context.Context, routes []netip.Prefix) error {
	e.changes = append(e.changes, append([]netip.Prefix(nil), routes...))
	e.status.AdvertisedRoutes = append([]netip.Prefix(nil), routes...)
	return nil
}
func (e *advertiseEngine) SetRouteAll(_ context.Context, enabled bool) error {
	e.status.RouteAll = enabled
	return nil
}

// isolateTailscaledDetection points conflict detection at scratch paths so
// tests do not observe the developer machine's own tailscaled.
func isolateTailscaledDetection(t *testing.T) {
	t.Helper()
	oldSocket, oldIface := tailscaledSocketPath, tailscaleInterfaceSysPath
	tailscaledSocketPath = filepath.Join(t.TempDir(), "no-such.sock")
	tailscaleInterfaceSysPath = filepath.Join(t.TempDir(), "no-such-iface")
	t.Cleanup(func() {
		tailscaledSocketPath, tailscaleInterfaceSysPath = oldSocket, oldIface
	})
}

// staticEngine implements only tailmixprofile.Engine, modeling runtimes
// (such as raw WireGuard profiles) that cannot advertise routes.
type staticEngine struct {
	status tailmixprofile.Status
}

func (e *staticEngine) Start(context.Context) error { return nil }
func (e *staticEngine) Close() error                { return nil }
func (e *staticEngine) Dial(context.Context, string, string) (net.Conn, error) {
	return nil, net.ErrClosed
}
func (e *staticEngine) Status(context.Context) (tailmixprofile.Status, error) {
	return e.status, nil
}
func (e *staticEngine) WatchUpdates(context.Context, func()) error { return nil }

func advertiseTestSupervisor(st state.State, engines map[string]*managedProfile) *supervisor {
	return &supervisor{
		ctx:        context.Background(),
		st:         st,
		runtimes:   engines,
		lastErrors: map[string]string{},
	}
}

func TestValidateAdvertisePrefixAllowsExitDefaults(t *testing.T) {
	st := state.State{
		SyntheticPool:   "100.127.0.0/24",
		SyntheticPoolV6: "fd6d:6e65:7400::/56",
		NATIP:           netip.MustParseAddr("100.127.0.1"),
	}
	for _, raw := range []string{"0.0.0.0/0", "::/0", "192.168.1.0/24", "10.20.3.4/16"} {
		prefix, err := validateAdvertisePrefix(st, netip.MustParsePrefix(raw))
		if err != nil {
			t.Fatalf("validate %q: %v", raw, err)
		}
		if prefix != prefix.Masked() {
			t.Fatalf("validate %q did not mask: %v", raw, prefix)
		}
	}
	for _, raw := range []string{"100.64.0.0/10", "100.127.0.0/26", "100.127.0.1/32"} {
		if _, err := validateAdvertisePrefix(st, netip.MustParsePrefix(raw)); err == nil {
			t.Fatalf("reserved overlap %q was accepted", raw)
		} else if apiErr, ok := err.(*controlapi.Error); !ok || apiErr.Code != "invalid_prefix" {
			t.Fatalf("reserved overlap %q error = %#v, want invalid_prefix", raw, err)
		}
	}
	if _, err := validateAdvertisePrefix(st, netip.Prefix{}); err == nil {
		t.Fatal("invalid prefix was accepted")
	} else if apiErr, ok := err.(*controlapi.Error); !ok || apiErr.Code != "invalid_prefix" {
		t.Fatalf("invalid prefix error = %#v, want invalid_prefix", err)
	}
}

func TestSetAdvertisePreferencesConverge(t *testing.T) {
	isolateTailscaledDetection(t)
	desired := []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}
	engine := &advertiseEngine{status: tailmixprofile.Status{
		ProfileID: "p_work", BackendState: "Running",
	}}
	s := advertiseTestSupervisor(state.State{
		SyntheticPool:   "100.127.0.0/24",
		SyntheticPoolV6: "fd6d:6e65:7400::/56",
		Profiles:        []state.Profile{{ID: "p_work", Name: "work", AdvertiseRoutes: desired}},
	}, map[string]*managedProfile{
		"p_work": {
			runtime: runtimeProfile{State: state.Profile{ID: "p_work"}, Engine: engine},
			status:  engine.status,
		},
	})
	observed := []tailmixprofile.Status{engine.status}
	if err := s.setAdvertisePreferencesLocked(observed); err != nil {
		t.Fatal(err)
	}
	if len(engine.changes) != 1 || !slices.Equal(engine.changes[0], desired) {
		t.Fatalf("advertise changes = %v, want [%v]", engine.changes, desired)
	}
	// Converged state reconciles without further backend writes.
	observed = []tailmixprofile.Status{engine.status}
	if err := s.setAdvertisePreferencesLocked(observed); err != nil {
		t.Fatal(err)
	}
	if len(engine.changes) != 1 {
		t.Fatalf("converged advertise changes = %v, want no further writes", engine.changes)
	}
}

func TestSetAdvertisePreferencesClearOnRemove(t *testing.T) {
	isolateTailscaledDetection(t)
	engine := &advertiseEngine{status: tailmixprofile.Status{
		ProfileID: "p_work", BackendState: "Running",
		AdvertisedRoutes: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
	}}
	s := advertiseTestSupervisor(state.State{
		SyntheticPool:   "100.127.0.0/24",
		SyntheticPoolV6: "fd6d:6e65:7400::/56",
		Profiles:        []state.Profile{{ID: "p_work", Name: "work"}},
	}, map[string]*managedProfile{
		"p_work": {
			runtime: runtimeProfile{State: state.Profile{ID: "p_work"}, Engine: engine},
			status:  engine.status,
		},
	})
	if err := s.setAdvertisePreferencesLocked([]tailmixprofile.Status{engine.status}); err != nil {
		t.Fatal(err)
	}
	if len(engine.changes) != 1 || len(engine.changes[0]) != 0 {
		t.Fatalf("withdrawal changes = %v, want one empty set", engine.changes)
	}
}

func TestSetAdvertisePreferencesSkipsUnavailableBackends(t *testing.T) {
	isolateTailscaledDetection(t)
	desired := []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}
	stopped := &advertiseEngine{status: tailmixprofile.Status{
		ProfileID: "p_work", BackendState: "Stopped",
	}}
	s := advertiseTestSupervisor(state.State{
		SyntheticPool:   "100.127.0.0/24",
		SyntheticPoolV6: "fd6d:6e65:7400::/56",
		Profiles:        []state.Profile{{ID: "p_work", Name: "work", AdvertiseRoutes: desired}},
	}, map[string]*managedProfile{
		"p_work": {
			runtime: runtimeProfile{State: state.Profile{ID: "p_work"}, Engine: stopped},
			status:  stopped.status,
		},
	})
	if err := s.setAdvertisePreferencesLocked([]tailmixprofile.Status{stopped.status}); err != nil {
		t.Fatal(err)
	}
	if len(stopped.changes) != 0 {
		t.Fatalf("stopped backend changes = %v, want none", stopped.changes)
	}
}

func TestSetAdvertisePreferencesRejectsUnsupportedEngine(t *testing.T) {
	isolateTailscaledDetection(t)
	desired := []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}
	engine := &staticEngine{}
	engine.status = tailmixprofile.Status{ProfileID: "p_lab", BackendState: "Running"}
	s := advertiseTestSupervisor(state.State{
		SyntheticPool:   "100.127.0.0/24",
		SyntheticPoolV6: "fd6d:6e65:7400::/56",
		Profiles:        []state.Profile{{ID: "p_lab", Name: "lab", AdvertiseRoutes: desired}},
	}, map[string]*managedProfile{
		"p_lab": {
			runtime: runtimeProfile{State: state.Profile{ID: "p_lab"}, Engine: engine},
			status:  engine.status,
		},
	})
	err := s.setAdvertisePreferencesLocked([]tailmixprofile.Status{engine.status})
	if apiErr, ok := err.(*controlapi.Error); !ok || apiErr.Code != "advertise_unsupported" {
		t.Fatalf("unsupported engine error = %#v, want advertise_unsupported", err)
	}
}

func TestRemoveProfileWithdrawsAdvertisedRoutes(t *testing.T) {
	isolateTailscaledDetection(t)
	engine := &advertiseEngine{status: tailmixprofile.Status{
		ProfileID: "p_work", BackendState: "Running",
		AdvertisedRoutes: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
	}}
	st := state.State{
		SyntheticPool:   "100.127.0.0/24",
		SyntheticPoolV6: "fd6d:6e65:7400::/56",
		Profiles: []state.Profile{{
			ID: "p_work", Name: "work",
			AdvertiseRoutes: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		}},
	}
	s := newLifecycleTestSupervisor(t, st)
	_, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s.runtimes["p_work"] = &managedProfile{
		runtime: runtimeProfile{State: st.Profiles[0], Engine: engine},
		cancel:  cancel,
		status:  engine.status,
	}
	if _, err := s.RemoveProfile(context.Background(), "work", false); err != nil {
		t.Fatal(err)
	}
	if len(s.st.Profiles) != 1 || len(s.st.Profiles[0].AdvertiseRoutes) != 0 {
		t.Fatalf("removal retained advertised routes: %+v", s.st.Profiles)
	}
	if len(engine.changes) == 0 || len(engine.changes[0]) != 0 {
		t.Fatalf("engine changes = %v, want live withdrawal to empty before close", engine.changes)
	}
	if !engine.closed {
		t.Fatal("engine was not closed by removal")
	}
}

func TestAdvertiseAPIRequiresTunOnLinux(t *testing.T) {
	st := state.State{
		SyntheticPool:   "100.127.0.0/24",
		SyntheticPoolV6: "fd6d:6e65:7400::/56",
		Profiles:        []state.Profile{{ID: "p_work", Name: "work"}},
	}
	s := newLifecycleTestSupervisor(t, st)
	if _, err := s.AdvertiseRoutes(context.Background()); err == nil {
		t.Fatal("advertise list succeeded in socks mode")
	} else if apiErr, ok := err.(*controlapi.Error); !ok || apiErr.Code != "unsupported" {
		t.Fatalf("advertise list error = %#v, want unsupported", err)
	}
	setReq := controlapi.PatchAdvertiseRoutesRequest{
		ProfileName: "work",
		Add:         []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		Replace:     true,
	}
	if _, err := s.SetAdvertiseRoutes(context.Background(), setReq); err == nil {
		t.Fatal("advertise set succeeded in socks mode")
	} else if apiErr, ok := err.(*controlapi.Error); !ok || apiErr.Code != "unsupported" {
		t.Fatalf("advertise set error = %#v, want unsupported", err)
	}
	if _, err := s.ClearAdvertiseRoutes(context.Background(), "work"); err == nil {
		t.Fatal("advertise clear succeeded in socks mode")
	} else if apiErr, ok := err.(*controlapi.Error); !ok || apiErr.Code != "unsupported" {
		t.Fatalf("advertise clear error = %#v, want unsupported", err)
	}
}

func TestTailscaledConflictDetection(t *testing.T) {
	dir := t.TempDir()
	oldSocket, oldIface := tailscaledSocketPath, tailscaleInterfaceSysPath
	t.Cleanup(func() {
		tailscaledSocketPath, tailscaleInterfaceSysPath = oldSocket, oldIface
	})
	tailscaledSocketPath = filepath.Join(dir, "no-such.sock")
	tailscaleInterfaceSysPath = filepath.Join(dir, "no-such-iface")
	if conflict := detectTailscaledConflict(); conflict != nil {
		t.Fatalf("conflict without tailscaled = %v", conflict)
	}
	if err := os.WriteFile(tailscaledSocketPath, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	conflict := detectTailscaledConflict()
	if conflict == nil || conflict.Code != "tailscaled_running" {
		t.Fatalf("socket conflict = %#v, want tailscaled_running", conflict)
	}
	if err := os.Remove(tailscaledSocketPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(tailscaleInterfaceSysPath, 0755); err != nil {
		t.Fatal(err)
	}
	if conflict := detectTailscaledConflict(); conflict == nil || conflict.Code != "tailscaled_running" {
		t.Fatalf("interface conflict = %#v, want tailscaled_running", conflict)
	}
}

func TestAdvertisedRoutesLockedReportsStates(t *testing.T) {
	lan := netip.MustParsePrefix("192.168.1.0/24")
	running := &advertiseEngine{status: tailmixprofile.Status{
		ProfileID: "p_work", BackendState: "Running", AdvertisedRoutes: []netip.Prefix{lan},
	}}
	pending := &advertiseEngine{status: tailmixprofile.Status{
		ProfileID: "p_lab", BackendState: "Running",
	}}
	s := advertiseTestSupervisor(state.State{
		SyntheticPool:   "100.127.0.0/24",
		SyntheticPoolV6: "fd6d:6e65:7400::/56",
		Profiles: []state.Profile{
			{ID: "p_work", Name: "work", AdvertiseRoutes: []netip.Prefix{lan}},
			{ID: "p_lab", Name: "lab", AdvertiseRoutes: []netip.Prefix{lan}},
			{ID: "p_idle", Name: "idle"},
			{ID: "p_off", Name: "off", Disabled: true, AdvertiseRoutes: []netip.Prefix{lan}},
		},
	}, map[string]*managedProfile{
		"p_work": {runtime: runtimeProfile{State: state.Profile{ID: "p_work"}, Engine: running}, status: running.status},
		"p_lab":  {runtime: runtimeProfile{State: state.Profile{ID: "p_lab"}, Engine: pending}, status: pending.status},
	})
	result := s.advertisedRoutesLocked([]tailmixprofile.Status{running.status, pending.status})
	byName := map[string]controlapi.ProfileAdvertisedRoutes{}
	for _, entry := range result.Profiles {
		byName[entry.ProfileName] = entry
	}
	if byName["work"].State != "installed" || !slices.Equal(byName["work"].Applied, []netip.Prefix{lan}) {
		t.Fatalf("work entry = %+v, want installed with applied routes", byName["work"])
	}
	if byName["lab"].State != "waiting" {
		t.Fatalf("lab entry = %+v, want waiting", byName["lab"])
	}
	if byName["idle"].State != "off" {
		t.Fatalf("idle entry = %+v, want off", byName["idle"])
	}
	if byName["off"].State != "disabled" || byName["off"].Reason != "profile_disabled" {
		t.Fatalf("off entry = %+v, want disabled", byName["off"])
	}
}
