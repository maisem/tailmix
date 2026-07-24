package dns

import (
	"net/netip"
	"testing"

	"tailscale.com/util/dnsname"
)

func TestConfigForServiceUsesEffectiveHostsAndScopedDomains(t *testing.T) {
	dnsCfg, err := configForService(ServiceConfig{
		Domains: []Domain{
			{ProfileID: "home", Suffix: "home.ts.net"},
			{ProfileID: "work", Suffix: "work.ts.net"},
		},
		Records: []Record{
			{ProfileID: "work", Name: "db.work.ts.net", EffectiveIP: netip.MustParseAddr("100.127.0.7")},
			{ProfileID: "work", Name: "db.work.ts.net", EffectiveIP: netip.MustParseAddr("fd6d:6e65:7400::7")},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	workName, err := dnsname.ToFQDN("db.work.ts.net")
	if err != nil {
		t.Fatal(err)
	}
	if got := dnsCfg.Hosts[workName]; len(got) != 2 || got[0] != netip.MustParseAddr("100.127.0.7") || got[1] != netip.MustParseAddr("fd6d:6e65:7400::7") {
		t.Fatalf("effective hosts = %v", got)
	}
	if len(dnsCfg.Routes) != 2 {
		t.Fatalf("authoritative routes = %v", dnsCfg.Routes)
	}
	for _, suffix := range []string{"home.ts.net", "work.ts.net"} {
		fqdn, err := dnsname.ToFQDN(suffix)
		if err != nil {
			t.Fatal(err)
		}
		resolvers, ok := dnsCfg.Routes[fqdn]
		if !ok || len(resolvers) != 0 {
			t.Fatalf("route %q = %v, present=%v; want local authoritative route", fqdn, resolvers, ok)
		}
	}
	if len(dnsCfg.SearchDomains) != 0 {
		t.Fatalf("unexpected search domains: %v", dnsCfg.SearchDomains)
	}
}

func TestConfigForServiceRejectsDuplicateSuffixes(t *testing.T) {
	_, err := configForService(ServiceConfig{Domains: []Domain{
		{ProfileID: "home", Suffix: "same.ts.net"},
		{ProfileID: "work", Suffix: "same.ts.net"},
	}})
	if err == nil {
		t.Fatal("expected duplicate MagicDNS suffix to fail")
	}
}

func TestConfigForServiceRoutesSharedPeerByExactFQDN(t *testing.T) {
	sharedName, err := dnsname.ToFQDN("external-node.shared.example")
	if err != nil {
		t.Fatal(err)
	}
	dnsCfg, err := configForService(ServiceConfig{
		Domains: []Domain{{ProfileID: "home", Suffix: "home.example"}},
		Records: []Record{{
			ProfileID:   "home",
			Name:        sharedName.WithoutTrailingDot(),
			EffectiveIP: netip.MustParseAddr("100.127.0.7"),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := dnsCfg.Hosts[sharedName]; !ok {
		t.Fatalf("shared peer %q is missing from hosts: %v", sharedName, dnsCfg.Hosts)
	}
	if resolvers, ok := dnsCfg.Routes[sharedName]; !ok || len(resolvers) != 0 {
		t.Fatalf("shared peer route = %v, present=%v; want exact authoritative route", resolvers, ok)
	}
	foreignSuffix, err := dnsname.ToFQDN("shared.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := dnsCfg.Routes[foreignSuffix]; ok {
		t.Fatalf("shared peer unexpectedly made tailmix authoritative for %q", foreignSuffix)
	}
}
