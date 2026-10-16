package profile

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type socksQuestion struct {
	name string
	typ  dnsmessage.Type
}

type socksDialCall struct{ network, address string }

type socksTestEngine struct {
	Engine
	query func(context.Context, string, dnsmessage.Type) ([]byte, error)
	dial  func(context.Context, string, string) (net.Conn, error)
	mu    sync.Mutex
	qs    []socksQuestion
	calls []socksDialCall
}

func (e *socksTestEngine) QueryDNSContext(ctx context.Context, name string, typ dnsmessage.Type) ([]byte, error) {
	e.mu.Lock()
	e.qs = append(e.qs, socksQuestion{name, typ})
	e.mu.Unlock()
	return e.query(ctx, name, typ)
}

func (e *socksTestEngine) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	e.mu.Lock()
	e.calls = append(e.calls, socksDialCall{network, address})
	e.mu.Unlock()
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return nil, errors.New("test forbids backend hostname dialing")
	}
	if e.dial != nil {
		return e.dial(ctx, network, address)
	}
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func (e *socksTestEngine) snapshot() ([]socksQuestion, []socksDialCall) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]socksQuestion(nil), e.qs...), append([]socksDialCall(nil), e.calls...)
}

func socksFixtureEngine(fixtures map[socksQuestion][]byte) *socksTestEngine {
	return &socksTestEngine{query: func(_ context.Context, name string, typ dnsmessage.Type) ([]byte, error) {
		wire, ok := fixtures[socksQuestion{name, typ}]
		if !ok {
			return nil, errors.New("resolver failed for private.corp.test at 192.0.2.1")
		}
		return wire, nil
	}}
}

func socksResponse(t *testing.T, name string, typ dnsmessage.Type, answers ...dnsmessage.Resource) []byte {
	t.Helper()
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 1, Response: true, RecursionAvailable: true},
		Questions: []dnsmessage.Question{{
			Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET,
		}},
		Answers: answers,
	}
	return socksPack(t, msg)
}

func socksPack(t *testing.T, msg dnsmessage.Message) []byte {
	t.Helper()
	wire, err := msg.Pack()
	if err != nil {
		t.Fatal("could not encode DNS fixture")
	}
	return wire
}

func socksAddress(name, address string) dnsmessage.Resource {
	ip := netip.MustParseAddr(address)
	r := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{
		Name: dnsmessage.MustNewName(name), Class: dnsmessage.ClassINET,
	}}
	if ip.Is4() {
		r.Body = &dnsmessage.AResource{A: ip.As4()}
	} else {
		r.Body = &dnsmessage.AAAAResource{AAAA: ip.As16()}
	}
	return r
}

func socksCNAME(name, target string) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name), Class: dnsmessage.ClassINET},
		Body:   &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(target)},
	}
}

// The fixtures fake only DNS. Successful connection tests exchange bytes with a
// real TCP endpoint, and the engine rejects every nonliteral dial destination.
func socksEndpoint(t *testing.T, network string) (host, port string) {
	t.Helper()
	ip := "127.0.0.1"
	if network == "tcp6" {
		ip = "::1"
	}
	listener, err := net.Listen(network, net.JoinHostPort(ip, "0"))
	if err != nil {
		if network == "tcp6" {
			t.Skip("IPv6 loopback is unavailable")
		}
		t.Fatal("could not create loopback listener")
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	host, port, err = net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal("could not parse loopback listener address")
	}
	return host, port
}

func socksExchange(t *testing.T, conn net.Conn) {
	t.Helper()
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("ok")); err != nil {
		t.Fatal("could not write TCP exchange")
	}
	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil || string(reply[:]) != "ok" {
		t.Fatal("TCP exchange failed or returned unexpected data")
	}
}

func TestSOCKSDialerMixedAnswersAndCNAME(t *testing.T) {
	host, port := socksEndpoint(t, "tcp4")
	const name, alias = "service.corp.test.", "target.corp.test."
	engine := socksFixtureEngine(map[socksQuestion][]byte{
		{name, dnsmessage.TypeA}: socksResponse(t, name, dnsmessage.TypeA,
			socksAddress("unrelated.corp.test.", "192.0.2.1"),
			socksCNAME(name, alias), socksAddress(alias, host)),
		{name, dnsmessage.TypeAAAA}: socksResponse(t, name, dnsmessage.TypeAAAA,
			socksCNAME(name, alias), socksAddress(alias, "::1")),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := (SOCKSDialer{Engine: engine}).Dial(ctx, "tcp", net.JoinHostPort("service.corp.test", port))
	if err != nil {
		t.Fatal("could not connect through profile DNS")
	}
	socksExchange(t, conn)
	qs, calls := engine.snapshot()
	if len(qs) != 2 {
		t.Fatalf("DNS query count = %d, want 2", len(qs))
	}
	for _, call := range calls {
		ip, _, _ := net.SplitHostPort(call.address)
		if ip != host && ip != "::1" {
			t.Fatal("dialed an unrelated DNS answer")
		}
	}
}

func TestSOCKSDialerFamilyFilter(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			host, port := socksEndpoint(t, network)
			typ := dnsmessage.TypeA
			if network == "tcp6" {
				typ = dnsmessage.TypeAAAA
			}
			const name = "service.corp.test."
			engine := socksFixtureEngine(map[socksQuestion][]byte{
				{name, typ}: socksResponse(t, name, typ,
					socksAddress(name, "192.0.2.1"), socksAddress(name, "2001:db8::1"),
					socksAddress(name, host)),
			})
			// The non-loopback address stalls, exercising within-family racing.
			engine.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
				ip, _, _ := net.SplitHostPort(address)
				if ip != host {
					<-ctx.Done()
					return nil, ctx.Err()
				}
				return (&net.Dialer{}).DialContext(ctx, network, address)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, err := (SOCKSDialer{Engine: engine}).Dial(ctx, network, net.JoinHostPort(name, port))
			if err != nil {
				t.Fatal("could not connect through the requested address family")
			}
			socksExchange(t, conn)
			qs, calls := engine.snapshot()
			if len(qs) != 1 || qs[0].typ != typ {
				t.Fatal("DNS queries did not retain the address-family restriction")
			}
			for _, call := range calls {
				ip, _, _ := net.SplitHostPort(call.address)
				if netip.MustParseAddr(ip).Is4() != (network == "tcp4") || call.network != network {
					t.Fatal("backend dial lost the address-family restriction")
				}
			}
		})
	}
}

func TestSOCKSDialerHealthyFamilyWinsHangingQuery(t *testing.T) {
	for _, healthy := range []string{"tcp4", "tcp6"} {
		t.Run(healthy, func(t *testing.T) {
			host, port := socksEndpoint(t, healthy)
			typ := dnsmessage.TypeA
			if healthy == "tcp6" {
				typ = dnsmessage.TypeAAAA
			}
			const name = "service.corp.test."
			wire := socksResponse(t, name, typ, socksAddress(name, host))
			started, canceled := make(chan struct{}), make(chan struct{})
			engine := &socksTestEngine{query: func(ctx context.Context, _ string, qt dnsmessage.Type) ([]byte, error) {
				if qt == typ {
					<-started
					return wire, nil
				}
				close(started)
				<-ctx.Done()
				close(canceled)
				return nil, ctx.Err()
			}}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err := (SOCKSDialer{Engine: engine}).Dial(ctx, "tcp", net.JoinHostPort(name, port))
			if err != nil {
				t.Fatal("healthy address family was blocked by the other DNS query")
			}
			socksExchange(t, conn)
			select {
			case <-canceled:
			case <-ctx.Done():
				t.Fatal("losing DNS query was not canceled")
			}
		})
	}
}

type socksTrackedConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *socksTrackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}

func TestSOCKSDialerClosesLosingConnections(t *testing.T) {
	for _, late := range []bool{false, true} {
		t.Run(map[bool]string{false: "simultaneous_success", true: "late_success_after_cancellation"}[late], func(t *testing.T) {
			host, port := socksEndpoint(t, "tcp4")
			const name = "service.corp.test."
			engine := socksFixtureEngine(map[socksQuestion][]byte{
				{name, dnsmessage.TypeA}:    socksResponse(t, name, dnsmessage.TypeA, socksAddress(name, host)),
				{name, dnsmessage.TypeAAAA}: socksResponse(t, name, dnsmessage.TypeAAAA, socksAddress(name, "::1")),
			})
			attempts := make(chan *socksTrackedConn, 2)
			release := make(chan struct{})
			engine.dial = func(ctx context.Context, _ string, literal string) (net.Conn, error) {
				// Map both fixture families to a real loopback endpoint. Hold
				// successful handshakes to control the winner/loser race.
				conn, err := (&net.Dialer{}).DialContext(ctx, "tcp4", net.JoinHostPort(host, port))
				if err != nil {
					return nil, err
				}
				tracked := &socksTrackedConn{Conn: conn, closed: make(chan struct{})}
				t.Cleanup(func() { tracked.Close() })
				attempts <- tracked
				ip, _, _ := net.SplitHostPort(literal)
				if late && ip == "::1" {
					<-ctx.Done()
				} else {
					select {
					case <-release:
					case <-ctx.Done():
					}
				}
				// A successful handshake can race cancellation even when the
				// dialer otherwise observes context cancellation correctly.
				return tracked, nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			type outcome struct {
				conn net.Conn
				err  error
			}
			done := make(chan outcome, 1)
			go func() {
				conn, err := (SOCKSDialer{Engine: engine}).Dial(ctx, "tcp", net.JoinHostPort(name, port))
				done <- outcome{conn, err}
			}()
			var connected []*socksTrackedConn
			for range 2 {
				select {
				case conn := <-attempts:
					connected = append(connected, conn)
				case <-ctx.Done():
					t.Fatal("both connection attempts did not reach the handshake barrier")
				}
			}
			close(release)
			var winner net.Conn
			select {
			case result := <-done:
				if result.err != nil || result.conn == nil {
					t.Fatal("racing successful connections did not produce a winner")
				}
				winner = result.conn
			case <-ctx.Done():
				t.Fatal("connection race did not return a winner")
			}
			for _, conn := range connected {
				if conn == winner {
					continue
				}
				select {
				case <-conn.closed:
				case <-ctx.Done():
					t.Fatal("losing successful connection was not closed")
				}
			}
			socksExchange(t, winner)
		})
	}
}

func TestSOCKSDialerFollowsCNAMEOnlyResponse(t *testing.T) {
	host, port := socksEndpoint(t, "tcp4")
	const name, alias = "alias.corp.test.", "target.corp.test."
	engine := socksFixtureEngine(map[socksQuestion][]byte{
		{name, dnsmessage.TypeA}:  socksResponse(t, name, dnsmessage.TypeA, socksCNAME(name, alias)),
		{alias, dnsmessage.TypeA}: socksResponse(t, alias, dnsmessage.TypeA, socksAddress(alias, host)),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := (SOCKSDialer{Engine: engine}).Dial(ctx, "tcp", net.JoinHostPort(name, port))
	if err != nil {
		t.Fatal("could not connect through a CNAME-only DNS response")
	}
	socksExchange(t, conn)
	qs, _ := engine.snapshot()
	found := false
	for _, q := range qs {
		found = found || q == (socksQuestion{alias, dnsmessage.TypeA})
	}
	if !found {
		t.Fatal("CNAME terminal name was not queried through the profile")
	}
}

func TestSOCKSDialerIPv6SurvivesFailedAFamily(t *testing.T) {
	host, port := socksEndpoint(t, "tcp6")
	const name = "service.corp.test."
	engine := socksFixtureEngine(map[socksQuestion][]byte{
		{name, dnsmessage.TypeAAAA}: socksResponse(t, name, dnsmessage.TypeAAAA, socksAddress(name, host)),
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := (SOCKSDialer{Engine: engine}).Dial(ctx, "tcp", net.JoinHostPort(name, port))
	if err != nil {
		t.Fatal("IPv6 connection failed when the IPv4 DNS query failed")
	}
	socksExchange(t, conn)
}

func TestSOCKSDialerCNAMEQueriesAreBounded(t *testing.T) {
	fixtures := make(map[socksQuestion][]byte)
	for i := range 12 {
		name := fmt.Sprintf("alias%d.corp.test.", i)
		target := fmt.Sprintf("alias%d.corp.test.", i+1)
		fixtures[socksQuestion{name, dnsmessage.TypeA}] = socksResponse(t, name, dnsmessage.TypeA, socksCNAME(name, target))
	}
	engine := socksFixtureEngine(fixtures)
	_, err := (SOCKSDialer{Engine: engine}).Dial(context.Background(), "tcp4", "alias0.corp.test:80")
	qs, calls := engine.snapshot()
	if !errors.Is(err, errSOCKSDNS) || len(qs) != 8 || len(calls) != 0 {
		t.Fatalf("CNAME bound failed: queries=%d backend dials=%d", len(qs), len(calls))
	}
}

func TestSOCKSDialerDNSFailsClosed(t *testing.T) {
	const name = "private.corp.test."
	base := dnsmessage.Message{
		Header: dnsmessage.Header{Response: true},
		Questions: []dnsmessage.Question{{
			Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET,
		}},
	}
	tests := []struct {
		name   string
		mutate func(*dnsmessage.Message)
	}{
		{"NXDOMAIN", func(m *dnsmessage.Message) { m.RCode = dnsmessage.RCodeNameError }},
		{"SERVFAIL", func(m *dnsmessage.Message) { m.RCode = dnsmessage.RCodeServerFailure }},
		{"no answer", func(*dnsmessage.Message) {}},
		{"not response", func(m *dnsmessage.Message) { m.Response = false }},
		{"truncated", func(m *dnsmessage.Message) { m.Truncated = true }},
		{"wrong opcode", func(m *dnsmessage.Message) { m.OpCode = 1 }},
		{"wrong question", func(m *dnsmessage.Message) { m.Questions[0].Name = dnsmessage.MustNewName("other.corp.test.") }},
		{"wrong type", func(m *dnsmessage.Message) { m.Questions[0].Type = dnsmessage.TypeAAAA }},
		{"wrong class", func(m *dnsmessage.Message) { m.Questions[0].Class = dnsmessage.ClassCHAOS }},
		{"unrelated answer", func(m *dnsmessage.Message) {
			m.Answers = []dnsmessage.Resource{socksAddress("other.corp.test.", "127.0.0.1")}
		}},
		{"glue only", func(m *dnsmessage.Message) { m.Additionals = []dnsmessage.Resource{socksAddress(name, "127.0.0.1")} }},
		{"CNAME cycle", func(m *dnsmessage.Message) {
			m.Answers = []dnsmessage.Resource{socksCNAME(name, "alias.corp.test."), socksCNAME("alias.corp.test.", name)}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := base
			msg.Questions = append([]dnsmessage.Question(nil), base.Questions...)
			tt.mutate(&msg)
			engine := socksFixtureEngine(map[socksQuestion][]byte{{name, dnsmessage.TypeA}: socksPack(t, msg)})
			conn, err := (SOCKSDialer{Engine: engine}).Dial(context.Background(), "tcp4", name+":80")
			if conn != nil || !errors.Is(err, errSOCKSDNS) {
				t.Fatal("DNS failure did not return the expected resolution error")
			}
			_, calls := engine.snapshot()
			if len(calls) != 0 || strings.Contains(err.Error(), "private") {
				t.Fatalf("DNS failure leaked identifiers or fell back: backend dials=%d", len(calls))
			}
		})
	}
	for _, wire := range [][]byte{nil, {0, 1, 2}} {
		engine := socksFixtureEngine(map[socksQuestion][]byte{{name, dnsmessage.TypeA}: wire})
		if _, err := (SOCKSDialer{Engine: engine}).Dial(context.Background(), "tcp4", name+":80"); !errors.Is(err, errSOCKSDNS) {
			t.Fatal("malformed DNS did not return the expected resolution error")
		}
	}
}

func TestSOCKSDialerCancellationAndDNSFailure(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		t.Run(map[bool]string{false: "failure", true: "timeout"}[timeout], func(t *testing.T) {
			engine := &socksTestEngine{query: func(ctx context.Context, _ string, _ dnsmessage.Type) ([]byte, error) {
				if timeout {
					<-ctx.Done()
					return nil, ctx.Err()
				}
				return nil, errors.New("private.corp.test DNS at 192.0.2.1 failed")
			}}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			_, err := (SOCKSDialer{Engine: engine}).Dial(ctx, "tcp", "private.corp.test:80")
			want := errSOCKSDNS
			if timeout {
				want = context.DeadlineExceeded
			}
			if !errors.Is(err, want) {
				t.Fatal("DNS failure or timeout returned the wrong error category")
			}
			_, calls := engine.snapshot()
			if len(calls) != 0 {
				t.Fatalf("DNS failure reached backend Dial: count=%d", len(calls))
			}
		})
	}
}

func TestSOCKSDialerContextCancellation(t *testing.T) {
	started := make(chan struct{}, 2)
	engine := &socksTestEngine{query: func(ctx context.Context, _ string, _ dnsmessage.Type) ([]byte, error) {
		started <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := (SOCKSDialer{Engine: engine}).Dial(ctx, "tcp", "private.corp.test:80")
		done <- err
	}()
	for range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("DNS queries did not start")
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("Dial did not return context cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("Dial ignored cancellation")
	}
	_, calls := engine.snapshot()
	if len(calls) != 0 {
		t.Fatalf("canceled DNS reached backend Dial: count=%d", len(calls))
	}
}

type socksNoDNS struct {
	Engine
	calls atomic.Int32
}

func (e *socksNoDNS) Dial(context.Context, string, string) (net.Conn, error) {
	e.calls.Add(1)
	return nil, errors.New("backend dial reached")
}

func TestSOCKSDialerWithoutDNSCapabilityFailsClosed(t *testing.T) {
	engine := new(socksNoDNS)
	_, err := (SOCKSDialer{Engine: engine}).Dial(context.Background(), "tcp", "localhost:80")
	if !errors.Is(err, errSOCKSDNS) || engine.calls.Load() != 0 {
		t.Fatalf("missing-queryer fail-closed check failed: backend dials=%d", engine.calls.Load())
	}
}

func TestSOCKSDialerLiteralsBypassDNS(t *testing.T) {
	for _, network := range []string{"tcp", "tcp4", "tcp6"} {
		for _, address := range []string{"127.0.0.1:80", "[::1]:80", "[fe80::1%lo]:80"} {
			engine := &socksTestEngine{dial: func(_ context.Context, gotNetwork, gotAddress string) (net.Conn, error) {
				if gotNetwork != network || gotAddress != address {
					t.Error("literal dial changed the network or destination")
				}
				return nil, errors.New("literal dial sentinel")
			}}
			_, err := (SOCKSDialer{Engine: engine}).Dial(context.Background(), network, address)
			if err == nil || err.Error() != "literal dial sentinel" {
				t.Fatal("literal dial did not preserve the backend error")
			}
			qs, calls := engine.snapshot()
			if len(qs) != 0 || len(calls) != 1 {
				t.Fatalf("literal bypass failed: DNS queries=%d backend dials=%d", len(qs), len(calls))
			}
		}
	}
}

func TestSOCKSDialerRejectsInvalidTargets(t *testing.T) {
	for _, target := range []struct{ network, address string }{
		{"udp", "127.0.0.1:53"}, {"tcp", "missing-port"}, {"tcp", ":80"}, {"tcp", "private.corp.test:not-a-port"},
	} {
		engine := &socksTestEngine{}
		if _, err := (SOCKSDialer{Engine: engine}).Dial(context.Background(), target.network, target.address); !errors.Is(err, errSOCKSTarget) {
			t.Fatal("invalid target did not return the expected error category")
		}
	}
}
