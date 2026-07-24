package routingpolicy

import (
	"net/netip"
	"testing"

	"github.com/maisem/tailmix/profile"
	"github.com/maisem/tailmix/state"
)

func TestExplicitIPBindingOverridesAcceptAllAtRuntime(t *testing.T) {
	st := state.State{
		Profiles: []state.Profile{
			{ID: "work-id", Name: "work", AcceptAllRoutes: true},
			{ID: "lab-id", Name: "lab"},
		},
		IPRouteBindings: []state.IPRouteBinding{{
			Prefix: netip.MustParsePrefix("10.20.0.0/16"), ProfileID: "lab-id",
		}},
	}
	statuses := []profile.Status{
		{ProfileID: "work-id", AvailableRoutes: []profile.RouteStatus{{
			Prefix: netip.MustParsePrefix("10.20.0.0/16"), PrimaryRouter: "work-router",
		}}},
		{ProfileID: "lab-id", AvailableRoutes: []profile.RouteStatus{{
			Prefix: netip.MustParsePrefix("10.0.0.0/8"), PrimaryRouter: "lab-router",
		}}},
	}
	plan := BuildIP(st, statuses)
	if len(plan.Exact) != 1 || !plan.Exact[0].Active || plan.Exact[0].ProfileID != "lab-id" {
		t.Fatalf("exact route = %+v", plan.Exact)
	}
	if len(plan.Imported) != 1 || plan.Imported[0].Active ||
		plan.Imported[0].Reason != "explicit_override" ||
		plan.Imported[0].OverriddenBy != netip.MustParsePrefix("10.20.0.0/16") {
		t.Fatalf("imported route = %+v", plan.Imported)
	}
	if got := plan.Resource.Imported[0].State; got != "overridden" {
		t.Fatalf("runtime state = %q, want overridden", got)
	}
	if got := plan.Resource.Imported[0].OverrideProfileName; got != "lab" {
		t.Fatalf("override winner = %q, want lab", got)
	}
}

func TestWaitingExplicitIPBindingIsFailClosedOverride(t *testing.T) {
	st := state.State{
		Profiles: []state.Profile{
			{ID: "work-id", Name: "work", AcceptAllRoutes: true},
			{ID: "lab-id", Name: "lab"},
		},
		IPRouteBindings: []state.IPRouteBinding{{
			Prefix: netip.MustParsePrefix("10.20.0.0/16"), ProfileID: "lab-id",
		}},
	}
	plan := BuildIP(st, []profile.Status{
		{ProfileID: "work-id", AvailableRoutes: []profile.RouteStatus{{
			Prefix: netip.MustParsePrefix("10.20.0.0/16"),
		}}},
		{ProfileID: "lab-id"},
	})
	if plan.Exact[0].Active || plan.Exact[0].Reason != "route_not_advertised" {
		t.Fatalf("exact route = %+v", plan.Exact[0])
	}
	if plan.Imported[0].Active || plan.Imported[0].Reason != "explicit_override" {
		t.Fatalf("waiting binding did not override import: %+v", plan.Imported[0])
	}
}

func TestExplicitDNSBindingOverridesAcceptAllAndAutomatic(t *testing.T) {
	st := state.State{
		Profiles: []state.Profile{
			{ID: "work-id", Name: "work", AcceptAllDNSRoutes: true},
			{ID: "lab-id", Name: "lab"},
		},
		DNSRouteBindings: []state.DNSRouteBinding{{
			Domain: "DEV.Corp.Example.", ProfileID: "lab-id",
		}},
	}
	statuses := []profile.Status{
		{ProfileID: "work-id", MagicDNSSuffix: "corp.example", DNSRoutes: []profile.DNSRouteStatus{{
			Domain: "corp.example", Source: "magicdns",
		}}},
		{ProfileID: "lab-id", DNSRoutes: []profile.DNSRouteStatus{{
			Domain: "corp.example", Source: "split-dns",
		}}},
	}
	plan := BuildDNS(st, statuses)
	resolved, ok := plan.Resolve("host.dev.corp.example")
	if !ok || !resolved.Active || resolved.ProfileID != "lab-id" || resolved.Policy != "bound" {
		t.Fatalf("resolved route = %+v, %v", resolved, ok)
	}
	if len(plan.Imported) != 1 || !plan.Imported[0].Active ||
		plan.Imported[0].Reason != "partially_overridden" {
		t.Fatalf("imported route = %+v", plan.Imported)
	}
	if len(plan.Automatic) != 1 || plan.Automatic[0].Active ||
		plan.Automatic[0].Reason != "policy_override" {
		t.Fatalf("automatic route = %+v", plan.Automatic)
	}
}

func TestDNSContainsUsesTailscaleDNSNameRules(t *testing.T) {
	if !DNSContains("_service._tcp.example.com.", "Node._Service._TCP.Example.COM") {
		t.Fatal("expected dnsname-valid service labels to match case-insensitively")
	}
	if DNSContains("bad..example.com", "node.bad.example.com") {
		t.Fatal("invalid DNS suffix unexpectedly matched")
	}
}

func TestAcceptAllDoesNotImportDirectTailscaleAddressSpace(t *testing.T) {
	st := state.State{Profiles: []state.Profile{{ID: "work-id", Name: "work", AcceptAllRoutes: true}}}
	plan := BuildIP(st, []profile.Status{{
		ProfileID: "work-id",
		AvailableRoutes: []profile.RouteStatus{{
			Prefix: netip.MustParsePrefix("100.64.0.0/10"),
		}},
	}})
	if len(plan.Imported) != 1 || plan.Imported[0].Active || plan.Imported[0].Reason != "host_route_conflict" {
		t.Fatalf("reserved import = %+v", plan.Imported)
	}
}

func TestBuildDNSListsDetectedSearchDomainsByProfile(t *testing.T) {
	st := state.State{Profiles: []state.Profile{
		{ID: "work-id", Name: "work"},
		{ID: "lab-id", Name: "lab"},
	}}
	plan := BuildDNS(st, []profile.Status{
		{ProfileID: "work-id", SearchDomains: []string{"Corp.Example.", "corp.example", "."}},
		{ProfileID: "lab-id", SearchDomains: []string{"Lab.Example."}},
	})
	if len(plan.Search.Available) != 2 {
		t.Fatalf("available search domains = %+v", plan.Search.Available)
	}
	if got := plan.Search.Available[0]; got.Domain != "corp.example" || got.ProfileName != "work" {
		t.Fatalf("first available search domain = %+v", got)
	}
	if got := plan.Search.Available[1]; got.Domain != "lab.example" || got.ProfileName != "lab" {
		t.Fatalf("second available search domain = %+v", got)
	}
}
