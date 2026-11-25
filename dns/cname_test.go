package dns

import (
	"context"
	"net/netip"
	"slices"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// upstreamAnswer builds the response an upstream resolver gives for name:
// a CNAME chain followed by address records for the last name.
func upstreamAnswer(t *testing.T, id uint16, name string, typ dnsmessage.Type, cnames []string, addrs ...netip.Addr) []byte {
	t.Helper()
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, Response: true, RecursionAvailable: true, AuthenticData: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET}},
	}
	owner := name
	for _, target := range cnames {
		msg.Answers = append(msg.Answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(owner), Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 3600},
			Body:   &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(target)},
		})
		owner = target
	}
	for _, addr := range addrs {
		header := dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(owner), Class: dnsmessage.ClassINET, TTL: 3600}
		if addr.Is4() {
			header.Type = dnsmessage.TypeA
			msg.Answers = append(msg.Answers, dnsmessage.Resource{Header: header, Body: &dnsmessage.AResource{A: addr.As4()}})
		} else {
			header.Type = dnsmessage.TypeAAAA
			msg.Answers = append(msg.Answers, dnsmessage.Resource{Header: header, Body: &dnsmessage.AAAAResource{AAAA: addr.As16()}})
		}
	}
	wire, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

// resolvedAddrs returns the addresses a client would connect to, and the
// response, for a query through the forwarder.
func resolvedAddrs(t *testing.T, f *Forwarder, name string, typ dnsmessage.Type) ([]netip.Addr, dnsmessage.Message) {
	t.Helper()
	query, err := (&dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 0x1234, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET}},
	}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	conn := testDNSConn(t, f, "udp")
	writeDNSQuery(t, conn, "udp", query)
	reply := readDNSReply(t, conn, "udp")
	var addrs []netip.Addr
	for _, rr := range reply.Answers {
		switch body := rr.Body.(type) {
		case *dnsmessage.AResource:
			addrs = append(addrs, netip.AddrFrom4(body.A))
		case *dnsmessage.AAAAResource:
			addrs = append(addrs, netip.AddrFrom16(body.AAAA))
		}
	}
	return addrs, reply
}

func TestForwarderAnswersCNAMEsToMagicDNSNamesWithEffectiveIPs(t *testing.T) {
	canonical4 := netip.MustParseAddr("100.101.102.103")
	canonical6 := netip.MustParseAddr("fd7a:115c:a1e0::103")
	effective4 := netip.MustParseAddr("100.127.0.9")
	effective6 := netip.MustParseAddr("fd6d:6e65:7400::9")
	names := NewMagicDNSNames(
		[]Domain{{ProfileID: "home", Suffix: "home.ts.net"}},
		[]Record{
			{ProfileID: "home", Name: "server.home.ts.net", EffectiveIP: effective4},
			{ProfileID: "home", Name: "server.home.ts.net", EffectiveIP: effective6},
		},
	)
	upstream := map[string]func(uint16, dnsmessage.Type) []byte{
		// The usual setup: the resolver follows its own CNAME and adds the
		// node's canonical tailnet address, which tailmix does not route.
		"app.corp.example.": func(id uint16, typ dnsmessage.Type) []byte {
			addr := canonical4
			if typ == dnsmessage.TypeAAAA {
				addr = canonical6
			}
			return upstreamAnswer(t, id, "app.corp.example.", typ, []string{"server.home.ts.net."}, addr)
		},
		// A resolver that cannot resolve the target returns only the CNAME.
		"bare.corp.example.": func(id uint16, typ dnsmessage.Type) []byte {
			return upstreamAnswer(t, id, "bare.corp.example.", typ, []string{"server.home.ts.net."})
		},
		"chain.corp.example.": func(id uint16, typ dnsmessage.Type) []byte {
			return upstreamAnswer(t, id, "chain.corp.example.", typ, []string{"lb.corp.example.", "server.home.ts.net."}, canonical4)
		},
		"gone.corp.example.": func(id uint16, typ dnsmessage.Type) []byte {
			return upstreamAnswer(t, id, "gone.corp.example.", typ, []string{"removed.home.ts.net."}, canonical4)
		},
		// Addresses carry no tailnet identity, so they are left alone.
		"literal.corp.example.": func(id uint16, typ dnsmessage.Type) []byte {
			return upstreamAnswer(t, id, "literal.corp.example.", typ, nil, canonical4)
		},
		"cdn.corp.example.": func(id uint16, typ dnsmessage.Type) []byte {
			return upstreamAnswer(t, id, "cdn.corp.example.", typ, []string{"edge.cdn.example."}, netip.MustParseAddr("192.0.2.7"))
		},
	}
	f, err := StartProfileDNSForwarder(context.Background(), functionQueryer(func(name string, typ dnsmessage.Type) ([]byte, error) {
		return upstream[name](0, typ), nil
	}), names)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	for _, tc := range []struct {
		name  string
		typ   dnsmessage.Type
		want  []netip.Addr
		rcode dnsmessage.RCode
	}{
		{"app.corp.example.", dnsmessage.TypeA, []netip.Addr{effective4}, dnsmessage.RCodeSuccess},
		{"app.corp.example.", dnsmessage.TypeAAAA, []netip.Addr{effective6}, dnsmessage.RCodeSuccess},
		{"bare.corp.example.", dnsmessage.TypeA, []netip.Addr{effective4}, dnsmessage.RCodeSuccess},
		{"chain.corp.example.", dnsmessage.TypeA, []netip.Addr{effective4}, dnsmessage.RCodeSuccess},
		{"gone.corp.example.", dnsmessage.TypeA, nil, dnsmessage.RCodeNameError},
		{"literal.corp.example.", dnsmessage.TypeA, []netip.Addr{canonical4}, dnsmessage.RCodeSuccess},
		{"cdn.corp.example.", dnsmessage.TypeA, []netip.Addr{netip.MustParseAddr("192.0.2.7")}, dnsmessage.RCodeSuccess},
	} {
		got, reply := resolvedAddrs(t, f, tc.name, tc.typ)
		if !slices.Equal(got, tc.want) || reply.RCode != tc.rcode {
			t.Errorf("%s %v resolved to %v (%v), want %v (%v)", tc.name, tc.typ, got, reply.RCode, tc.want, tc.rcode)
		}
		if reply.Header.ID != 0x1234 {
			t.Errorf("%s %v: reply ID %#x does not match the query", tc.name, tc.typ, reply.Header.ID)
		}
		rewritten := tc.name != "literal.corp.example." && tc.name != "cdn.corp.example."
		if rewritten && reply.AuthenticData {
			t.Errorf("%s %v: tailmix's records are marked DNSSEC-validated", tc.name, tc.typ)
		}
	}
}
