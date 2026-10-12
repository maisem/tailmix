package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/types/dnstype"
)

type networkDialer struct {
	mu    sync.Mutex
	addrs []string
}

func (d *networkDialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.addrs = append(d.addrs, address)
	d.mu.Unlock()
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

type recordingDNSQueryer struct {
	name      string
	queryType dnsmessage.Type
	response  []byte
}

func (q *recordingDNSQueryer) QueryDNS(name string, queryType dnsmessage.Type) ([]byte, error) {
	q.name = name
	q.queryType = queryType
	return append([]byte(nil), q.response...), nil
}

func TestForwarderUsesEffectiveProfileDNSAndRestoresQueryID(t *testing.T) {
	name := dnsmessage.MustNewName("example.com.")
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:               0xbeef,
		RecursionDesired: true,
	})
	if err := builder.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := builder.Question(dnsmessage.Question{
		Name: name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET,
	}); err != nil {
		t.Fatal(err)
	}
	query, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}

	queryer := &recordingDNSQueryer{
		response: []byte{0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0},
	}
	forwarder := &Forwarder{queryer: queryer}
	response, err := forwarder.exchange(context.Background(), "udp", query)
	if err != nil {
		t.Fatal(err)
	}
	if queryer.name != "example.com." || queryer.queryType != dnsmessage.TypeAAAA {
		t.Fatalf("profile DNS query = %q %v", queryer.name, queryer.queryType)
	}
	if got := binary.BigEndian.Uint16(response[:2]); got != 0xbeef {
		t.Fatalf("response ID = %#x, want %#x", got, 0xbeef)
	}
}

func TestForwarderDoHUsesProfileDialerAndBootstrapResolution(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Content-Type"); got != "application/dns-message" {
			t.Errorf("Content-Type = %q", got)
		}
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(append([]byte("response:"), body...))
	})}
	go server.Serve(listener)
	defer server.Close()

	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	dialer := &networkDialer{}
	forwarder := &Forwarder{dialer: dialer}
	got, err := forwarder.exchangeHTTP(context.Background(), &dnstype.Resolver{
		Addr:                "http://resolver.invalid:" + port + "/dns-query",
		BootstrapResolution: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
	}, []byte("query"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "response:query" {
		t.Fatalf("response = %q", got)
	}
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	if len(dialer.addrs) == 0 || !strings.HasPrefix(dialer.addrs[0], "127.0.0.1:") {
		t.Fatalf("profile dial addresses = %q", dialer.addrs)
	}
}

type failingDNSQueryer struct{}

func (failingDNSQueryer) QueryDNS(string, dnsmessage.Type) ([]byte, error) {
	return nil, errors.New("profile DNS unavailable")
}

func buildForwarderTestQuery(t *testing.T, name dnsmessage.Name, queryType dnsmessage.Type) []byte {
	t.Helper()
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0xbeef, RecursionDesired: true})
	if err := builder.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := builder.Question(dnsmessage.Question{
		Name: name, Type: queryType, Class: dnsmessage.ClassINET,
	}); err != nil {
		t.Fatal(err)
	}
	query, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return query
}

func queryForwarder(t *testing.T, addr netip.AddrPort, query []byte) dnsmessage.Header {
	t.Helper()
	conn, err := net.Dial("udp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(query); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 512)
	n, err := conn.Read(buffer)
	if err != nil {
		t.Fatalf("no DNS response: %v", err)
	}
	var parser dnsmessage.Parser
	header, err := parser.Start(buffer[:n])
	if err != nil {
		t.Fatal(err)
	}
	return header
}

func TestForwarderAnswersSERVFAILWhenProfileDNSFails(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	forwarder, err := StartProfileDNSForwarder(ctx, failingDNSQueryer{})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()

	header := queryForwarder(t, forwarder.addr, buildForwarderTestQuery(t, dnsmessage.MustNewName("example.com."), dnsmessage.TypeA))
	if header.ID != 0xbeef {
		t.Fatalf("response ID = %#x, want %#x", header.ID, 0xbeef)
	}
	if !header.Response || header.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("response header = %+v, want SERVFAIL", header)
	}
}

func TestForwarderAnswersSERVFAILWhenResolverIsUnreachable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	forwarder, err := StartForwarder(ctx, &networkDialer{}, []*dnstype.Resolver{{Addr: "127.0.0.1:1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()

	header := queryForwarder(t, forwarder.addr, buildForwarderTestQuery(t, dnsmessage.MustNewName("example.com."), dnsmessage.TypeA))
	if !header.Response || header.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("response header = %+v, want SERVFAIL", header)
	}
}

// blockingDNSQueryer models a profile whose DNS manager never answers.
type blockingDNSQueryer struct{}

func (blockingDNSQueryer) QueryDNS(string, dnsmessage.Type) ([]byte, error) {
	select {}
}

func TestForwarderAbandonsProfileDNSQueryAtDeadline(t *testing.T) {
	forwarder := &Forwarder{queryer: blockingDNSQueryer{}}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	query := buildForwarderTestQuery(t, dnsmessage.MustNewName("example.com."), dnsmessage.TypeA)
	start := time.Now()
	if _, err := forwarder.exchangeProfileDNS(ctx, query); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("exchangeProfileDNS error = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("exchangeProfileDNS returned after %v", elapsed)
	}
}
