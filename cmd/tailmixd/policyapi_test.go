package main

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/maisem/tailmix/controlapi"
	tailmixprofile "github.com/maisem/tailmix/profile"
	"github.com/maisem/tailmix/state"
)

type exitPreferenceEngine struct {
	status       tailmixprofile.Status
	changes      []netip.Addr
	routeChanges []bool
}

func (e *exitPreferenceEngine) Start(context.Context) error { return nil }
func (e *exitPreferenceEngine) Close() error                { return nil }
func (e *exitPreferenceEngine) Dial(context.Context, string, string) (net.Conn, error) {
	return nil, net.ErrClosed
}
func (e *exitPreferenceEngine) Status(context.Context) (tailmixprofile.Status, error) {
	return e.status, nil
}
func (e *exitPreferenceEngine) WatchUpdates(context.Context, func()) error { return nil }
func (e *exitPreferenceEngine) SetExitNodeIP(_ context.Context, peerIP netip.Addr) error {
	e.changes = append(e.changes, peerIP)
	e.status.ExitNodeID = ""
	for _, peer := range e.status.Peers {
		if slices.Contains(peer.TailscaleIPs, peerIP) {
			e.status.ExitNodeID = peer.NodeID
			break
		}
	}
	return nil
}
func (e *exitPreferenceEngine) SetRouteAll(_ context.Context, enabled bool) error {
	e.routeChanges = append(e.routeChanges, enabled)
	e.status.RouteAll = enabled
	return nil
}

func testPolicyState() state.State {
	return state.State{
		SyntheticPool:   "100.127.0.0/24",
		SyntheticPoolV6: "fd6d:6e65:7400::/56",
		Profiles: []state.Profile{
			{ID: "p_work", Name: "work"},
			{ID: "p_lab", Name: "lab"},
		},
	}
}

func TestApplyIPPatchPersistsStableProfileIDAndRequiresReplace(t *testing.T) {
	supervisor := &supervisor{}
	st := testPolicyState()
	prefix := netip.MustParsePrefix("10.20.3.4/16")
	err := supervisor.applyIPPatchLocked(&st, controlapi.PatchIPRoutesRequest{
		Bind: []controlapi.IPRouteMutation{{Prefix: prefix, ProfileName: "work"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(st.IPRouteBindings) != 1 ||
		st.IPRouteBindings[0].Prefix != netip.MustParsePrefix("10.20.0.0/16") ||
		st.IPRouteBindings[0].ProfileID != "p_work" {
		t.Fatalf("bindings = %+v", st.IPRouteBindings)
	}
	err = supervisor.applyIPPatchLocked(&st, controlapi.PatchIPRoutesRequest{
		Bind: []controlapi.IPRouteMutation{{Prefix: prefix, ProfileName: "lab"}},
	})
	if apiErr, ok := err.(*controlapi.Error); !ok || apiErr.Code != "route_binding_conflict" {
		t.Fatalf("conflict error = %#v", err)
	}
	err = supervisor.applyIPPatchLocked(&st, controlapi.PatchIPRoutesRequest{
		Replace: true,
		Bind:    []controlapi.IPRouteMutation{{Prefix: prefix, ProfileName: "lab"}},
	})
	if err != nil || st.IPRouteBindings[0].ProfileID != "p_lab" {
		t.Fatalf("replace error = %v, bindings = %+v", err, st.IPRouteBindings)
	}
}

func TestApplyDNSPatchUsesDNSNameCanonicalization(t *testing.T) {
	supervisor := &supervisor{}
	st := testPolicyState()
	err := supervisor.applyDNSPatchLocked(&st, controlapi.PatchDNSRoutesRequest{
		Bind: []controlapi.DNSRouteMutation{{
			Domain: "_Service._TCP.Corp.Example.", ProfileName: "work",
		}},
		AcceptAll: map[string]bool{"lab": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(st.DNSRouteBindings) != 1 ||
		st.DNSRouteBindings[0].Domain != "_service._tcp.corp.example" ||
		st.DNSRouteBindings[0].ProfileID != "p_work" {
		t.Fatalf("DNS bindings = %+v", st.DNSRouteBindings)
	}
	if !st.Profiles[0].AcceptAllDNSRoutes && !st.Profiles[1].AcceptAllDNSRoutes {
		t.Fatal("accept-all DNS policy was not set")
	}
	err = supervisor.applyDNSPatchLocked(&st, controlapi.PatchDNSRoutesRequest{
		Bind: []controlapi.DNSRouteMutation{{Domain: "bad..example", ProfileName: "work"}},
	})
	if apiErr, ok := err.(*controlapi.Error); !ok || apiErr.Code != "invalid_dns_name" {
		t.Fatalf("invalid DNS error = %#v", err)
	}
}

func TestSelectExitNodePeerAcceptsProfileScopedSelectors(t *testing.T) {
	exitIP := netip.MustParseAddr("100.64.0.20")
	status := tailmixprofile.Status{
		Alias: "work",
		Peers: []tailmixprofile.PeerStatus{{
			NodeID: "node-stable-id", DNSName: "gateway.work.ts.net",
			TailscaleIPs: []netip.Addr{exitIP}, ExitNodeOption: true,
		}},
	}
	for _, selector := range []string{"gateway", "gateway.work.ts.net.", "node-stable-id", exitIP.String()} {
		peer, err := selectExitNodePeer(status, selector)
		if err != nil {
			t.Fatalf("select %q: %v", selector, err)
		}
		if peer.NodeID != "node-stable-id" {
			t.Fatalf("select %q returned %+v", selector, peer)
		}
	}
	if _, err := selectExitNodePeer(status, "other"); err == nil {
		t.Fatal("unavailable exit node unexpectedly selected")
	}
}

func TestExitNodeResourceReportsSelectedState(t *testing.T) {
	exitIP := netip.MustParseAddr("100.64.0.20")
	s := &supervisor{st: testPolicyState()}
	s.st.ExitNode = &state.ExitNode{ProfileID: "p_work", NodeID: "node-id", PeerIP: exitIP}
	status := tailmixprofile.Status{
		ProfileID: "p_work", BackendState: "Running", ExitNodeID: "node-id",
		Peers: []tailmixprofile.PeerStatus{{
			NodeID: "node-id", DNSName: "gateway.work.ts.net",
			TailscaleIPs: []netip.Addr{exitIP}, Online: true, ExitNodeOption: true,
		}},
	}
	result := s.exitNodesLocked([]tailmixprofile.Status{status})
	if result.Selected == nil || result.Selected.State != "installed" ||
		result.Selected.ProfileName != "work" || !result.Selected.Online {
		t.Fatalf("exit-node resource = %+v", result)
	}
	if len(result.Available) != 1 || result.Available[0].NodeID != "node-id" {
		t.Fatalf("available exit nodes = %+v", result.Available)
	}

	status.ExitNodeID = ""
	result = s.exitNodesLocked([]tailmixprofile.Status{status})
	if result.Selected == nil || result.Selected.State != "waiting" ||
		result.Selected.Reason != "exit_node_not_applied" {
		t.Fatalf("exit-node resource before preference applies = %+v", result.Selected)
	}
}

func TestExitNodePreferenceReconciliationSelectsOnlyOneProfile(t *testing.T) {
	work := &exitPreferenceEngine{status: tailmixprofile.Status{
		ProfileID: "p_work", BackendState: "Running",
		Peers: []tailmixprofile.PeerStatus{{
			NodeID: "selected-node", TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.20")},
		}},
	}}
	lab := &exitPreferenceEngine{status: tailmixprofile.Status{
		ProfileID: "p_lab", BackendState: "Running", ExitNodeID: "stale-node",
	}}
	s := &supervisor{
		ctx: context.Background(),
		st:  testPolicyState(),
		runtimes: map[string]*managedProfile{
			"p_work": {
				runtime: runtimeProfile{State: state.Profile{ID: "p_work"}, Engine: work},
				status:  work.status,
			},
			"p_lab": {
				runtime: runtimeProfile{State: state.Profile{ID: "p_lab"}, Engine: lab},
				status:  lab.status,
			},
		},
		lastErrors: map[string]string{},
	}
	s.st.ExitNode = &state.ExitNode{
		ProfileID: "p_work", NodeID: "selected-node",
		PeerIP: netip.MustParseAddr("100.64.0.20"),
	}
	if err := s.setExitNodePreferencesLocked([]tailmixprofile.Status{work.status, lab.status}); err != nil {
		t.Fatal(err)
	}
	if len(work.changes) != 1 || work.changes[0] != netip.MustParseAddr("100.64.0.20") {
		t.Fatalf("work preference changes = %v", work.changes)
	}
	if len(lab.changes) != 1 || lab.changes[0].IsValid() {
		t.Fatalf("lab preference changes = %v", lab.changes)
	}
}

func TestRouteAllIsAlwaysEnabled(t *testing.T) {
	work := &exitPreferenceEngine{status: tailmixprofile.Status{
		ProfileID: "p_work", BackendState: "Running",
	}}
	s := &supervisor{
		ctx: context.Background(),
		st:  testPolicyState(),
		runtimes: map[string]*managedProfile{
			"p_work": {
				runtime: runtimeProfile{State: state.Profile{ID: "p_work"}, Engine: work},
				status:  work.status,
			},
		},
		lastErrors: map[string]string{},
	}
	if err := s.setRoutePreferencesLocked(); err != nil {
		t.Fatal(err)
	}
	if len(work.routeChanges) != 1 || work.routeChanges[0] != true {
		t.Fatalf("initial route preference changes = %v, want [true]", work.routeChanges)
	}

	s.st.ExitNode = &state.ExitNode{
		ProfileID: "p_work", NodeID: "selected-node",
		PeerIP: netip.MustParseAddr("100.64.0.20"),
	}
	if err := s.setRoutePreferencesLocked(); err != nil {
		t.Fatal(err)
	}
	s.st.ExitNode = nil
	if err := s.setRoutePreferencesLocked(); err != nil {
		t.Fatal(err)
	}
	if len(work.routeChanges) != 1 {
		t.Fatalf("route preference changed with exit-node selection = %v, want [true]", work.routeChanges)
	}
}
