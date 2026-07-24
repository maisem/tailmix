package main

import (
	"net/netip"
	"testing"

	"github.com/maisem/tailmix/controlapi"
	"github.com/maisem/tailmix/state"
)

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
