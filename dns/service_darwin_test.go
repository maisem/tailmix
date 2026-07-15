//go:build darwin

package dns

import (
	"context"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/control/controlknobs"
	"tailscale.com/health"
	tailscaledns "tailscale.com/net/dns"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/types/logger"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/eventbus"
)

type captureOSConfigurator struct {
	config tailscaledns.OSConfig
}

func (c *captureOSConfigurator) SetDNS(cfg tailscaledns.OSConfig) error {
	c.config = cfg
	return nil
}

func (*captureOSConfigurator) SupportsSplitDNS() bool { return true }

func (*captureOSConfigurator) GetBaseConfig() (tailscaledns.OSConfig, error) {
	return tailscaledns.OSConfig{Nameservers: []netip.Addr{netip.MustParseAddr("192.0.2.53")}}, nil
}

func (*captureOSConfigurator) Close() error { return nil }

func TestManagerUsesNativeSplitDNSAndAnswersEffectiveIP(t *testing.T) {
	wantIP := netip.MustParseAddr("100.127.0.7")
	const sharedName = "external-node.shared.example"
	dnsCfg, err := configForService(ServiceConfig{
		Domains: []Domain{{ProfileID: "home", Suffix: "home.example"}},
		Records: []Record{{ProfileAlias: "home", Name: sharedName, EffectiveIP: wantIP}},
	})
	if err != nil {
		t.Fatal(err)
	}

	bus := eventbus.NewWithOptions(eventbus.BusOptions{Logf: logger.Discard})
	defer bus.Close()
	netMon := netmon.NewStatic()
	defer netMon.Close()
	dialer := tsdial.NewDialer(netMon)
	dialer.Logf = logger.Discard
	dialer.SetBus(bus)
	defer dialer.Close()
	knobs := new(controlknobs.Knobs)
	knobs.ForceRegisterMagicDNSIPv4Only.Store(true)
	capture := new(captureOSConfigurator)
	manager := tailscaledns.NewManager(logger.Discard, splitDNSConfigurator{capture}, health.NewTracker(bus), dialer, nil, knobs, "darwin", bus)
	defer manager.Down()
	if err := manager.Set(dnsCfg); err != nil {
		t.Fatal(err)
	}

	wantDomain, err := dnsname.ToFQDN("home.example")
	if err != nil {
		t.Fatal(err)
	}
	wantSharedName, err := dnsname.ToFQDN(sharedName)
	if err != nil {
		t.Fatal(err)
	}
	if len(capture.config.Nameservers) != 1 || capture.config.Nameservers[0] != ServiceIP() {
		t.Fatalf("OS nameservers = %v, want %v", capture.config.Nameservers, ServiceIP())
	}
	if len(capture.config.MatchDomains) != 2 || capture.config.MatchDomains[0] != wantSharedName || capture.config.MatchDomains[1] != wantDomain {
		t.Fatalf("OS match domains = %v, want [%v %v]", capture.config.MatchDomains, wantSharedName, wantDomain)
	}
	if len(capture.config.SearchDomains) != 0 {
		t.Fatalf("OS search domains = %v, want none", capture.config.SearchDomains)
	}

	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, RecursionDesired: true})
	if err := builder.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := builder.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName(sharedName + "."),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		t.Fatal(err)
	}
	query, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	response, err := manager.Query(context.Background(), query, "udp", netip.MustParseAddrPort("127.0.0.1:12345"))
	if err != nil {
		t.Fatal(err)
	}
	var parser dnsmessage.Parser
	if _, err := parser.Start(response); err != nil {
		t.Fatal(err)
	}
	if err := parser.SkipAllQuestions(); err != nil {
		t.Fatal(err)
	}
	header, err := parser.AnswerHeader()
	if err != nil {
		t.Fatal(err)
	}
	if header.Type != dnsmessage.TypeA {
		t.Fatalf("answer type = %v, want A", header.Type)
	}
	answer, err := parser.AResource()
	if err != nil {
		t.Fatal(err)
	}
	if got := netip.AddrFrom4(answer.A); got != wantIP {
		t.Fatalf("MagicDNS answer = %v, want effective IP %v", got, wantIP)
	}

	const addedName = "peer.home.example"
	addedIP := netip.MustParseAddr("10.250.0.7")
	service := &osService{manager: manager}
	if err := service.Configure(
		[]Domain{{ProfileID: "home", Suffix: "home.example"}},
		[]Record{{ProfileAlias: "home", Name: addedName, EffectiveIP: addedIP}},
	); err != nil {
		t.Fatal(err)
	}
	if len(capture.config.MatchDomains) != 1 || capture.config.MatchDomains[0] != wantDomain {
		t.Fatalf("updated OS match domains = %v, want [%v]", capture.config.MatchDomains, wantDomain)
	}

	builder = dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 2, RecursionDesired: true})
	if err := builder.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := builder.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName(addedName + "."),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		t.Fatal(err)
	}
	query, err = builder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	response, err = manager.Query(context.Background(), query, "udp", netip.MustParseAddrPort("127.0.0.1:12345"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parser.Start(response); err != nil {
		t.Fatal(err)
	}
	if err := parser.SkipAllQuestions(); err != nil {
		t.Fatal(err)
	}
	header, err = parser.AnswerHeader()
	if err != nil {
		t.Fatal(err)
	}
	answer, err = parser.AResource()
	if err != nil {
		t.Fatal(err)
	}
	if got := netip.AddrFrom4(answer.A); got != addedIP {
		t.Fatalf("updated MagicDNS answer = %v, want %v", got, addedIP)
	}
}
