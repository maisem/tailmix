package socksproxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/maisem/tailmix/effectiveip"
)

// These are wire-level tests, not tailnet integration tests: profile dialers
// reach real loopback TCP servers, with explicit mappings for synthetic DNS.
const wireTimeout = 10 * time.Second

type wireDial struct{ network, addr string }

type wireDialer struct {
	mu      sync.Mutex
	calls   []wireDial
	mapping map[string]string // nil means dial the router's canonical address.
}

func (d *wireDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.calls = append(d.calls, wireDial{network, addr})
	d.mu.Unlock()
	if d.mapping != nil {
		var ok bool
		addr, ok = d.mapping[addr]
		if !ok {
			return nil, net.ErrClosed
		}
	}
	return (&net.Dialer{Timeout: wireTimeout}).DialContext(ctx, network, addr)
}

func (d *wireDialer) check(t *testing.T, want ...wireDial) {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.calls) != len(want) {
		t.Fatalf("backend dial count = %d, want %d", len(d.calls), len(want))
	}
	for i := range want {
		if d.calls[i] != want[i] {
			t.Fatalf("backend dial %d did not match expected network and destination", i)
		}
	}
}

func wireDeadline(t *testing.T) time.Time {
	t.Helper()
	deadline := time.Now().Add(wireTimeout)
	if testDeadline, ok := t.Deadline(); ok && testDeadline.Before(deadline) {
		deadline = testDeadline
	}
	return deadline
}

func wireListen(t *testing.T, network string) *net.TCPListener {
	t.Helper()
	host := "127.0.0.1"
	if network == "tcp6" {
		host = "::1"
	}
	addr := &net.TCPAddr{IP: net.ParseIP(host)}
	ln, err := net.ListenTCP(network, addr)
	if err != nil {
		if network == "tcp6" {
			t.Skip("IPv6 loopback is unavailable")
		}
		t.Fatal("could not create loopback listener")
	}
	if err := ln.SetDeadline(wireDeadline(t)); err != nil {
		ln.Close()
		t.Fatal("could not bound listener lifetime")
	}
	return ln
}

func wireBackend(t *testing.T, network string, handle func(*net.TCPConn)) string {
	t.Helper()
	ln := wireListen(t, network)
	deadline := wireDeadline(t)
	var mu sync.Mutex
	var conns []*net.TCPConn
	var handlers sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := ln.AcceptTCP()
			if err != nil {
				return
			}
			_ = conn.SetDeadline(deadline)
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
			handlers.Add(1)
			go func() {
				defer handlers.Done()
				defer conn.Close()
				handle(conn)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-acceptDone // No handlers can be added after this barrier.
		mu.Lock()
		for _, conn := range conns {
			_ = conn.Close()
		}
		mu.Unlock()
		handlers.Wait()
	})
	return ln.Addr().String()
}

func wireEcho(t *testing.T, network string, marker byte) string {
	t.Helper()
	return wireBackend(t, network, func(conn *net.TCPConn) {
		if _, err := conn.Write([]byte{marker}); err == nil {
			_, _ = io.Copy(conn, conn)
		}
	})
}

func wireRouter(t *testing.T, profiles []Profile, leases []effectiveip.Lease, policies ...DomainRoute) *Router {
	t.Helper()
	r, err := NewRouterWithPolicies(profiles, leases, nil, policies)
	if err != nil {
		t.Fatal("could not construct test router")
	}
	return r
}

type wireServer struct {
	ln     *net.TCPListener
	router *DynamicRouter
	cancel context.CancelFunc
	done   chan struct{}
	err    error // Read only after done closes.
}

func wireServe(t *testing.T, router *Router) *wireServer {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	s := &wireServer{
		ln: wireListen(t, "tcp4"), router: NewDynamicRouter(router),
		cancel: cancel, done: make(chan struct{}),
	}
	go func() {
		// Discard upstream diagnostics: they can contain destinations.
		s.err = Serve(ctx, s.ln, s.router, func(string, ...any) {})
		close(s.done)
	}()
	t.Cleanup(func() {
		s.cancel()
		select {
		case <-s.done:
			if s.err != nil {
				t.Error("Serve returned an error after cancellation")
			}
		case <-time.After(wireTimeout):
			t.Error("Serve did not stop after cancellation")
		}
	})
	return s
}

func (s *wireServer) client(t *testing.T, greeting ...byte) *net.TCPConn {
	t.Helper()
	c, err := net.DialTimeout("tcp4", s.ln.Addr().String(), wireTimeout)
	if err != nil {
		t.Fatal("could not connect to SOCKS listener")
	}
	conn := c.(*net.TCPConn)
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(wireDeadline(t)); err != nil {
		t.Fatal("could not bound client I/O")
	}
	if len(greeting) == 0 {
		greeting = []byte{5, 2, 2, 0} // Offer password and no-auth; select no-auth.
	}
	wireWrite(t, conn, greeting)
	return conn
}

func wireWrite(t *testing.T, conn net.Conn, data []byte) {
	t.Helper()
	if n, err := conn.Write(data); err != nil || n != len(data) {
		t.Fatal("SOCKS stream write failed")
	}
}

func wireRead(t *testing.T, conn net.Conn, size int) []byte {
	t.Helper()
	buf := make([]byte, size)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal("SOCKS stream read failed")
	}
	return buf
}

func wireGreeting(t *testing.T, conn net.Conn, method byte) {
	t.Helper()
	if !bytes.Equal(wireRead(t, conn, 2), []byte{5, method}) {
		t.Fatal("incorrect SOCKS version or authentication method")
	}
}

func wireRequest(t *testing.T, conn net.Conn, command byte, target string) (reply, atyp byte) {
	t.Helper()
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatal("invalid test destination")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatal("invalid test port")
	}
	buf := []byte{5, command, 0}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Is4() {
			buf = append(buf, 1)
		} else {
			buf = append(buf, 4)
		}
		buf = append(buf, ip.AsSlice()...)
	} else {
		buf = append(buf, 3, byte(len(host)))
		buf = append(buf, host...)
	}
	buf = binary.BigEndian.AppendUint16(buf, uint16(port))
	wireWrite(t, conn, buf)
	header := wireRead(t, conn, 4)
	if header[0] != 5 || header[2] != 0 {
		t.Fatal("invalid SOCKS reply version or reserved field")
	}
	switch header[3] {
	case 1:
		wireRead(t, conn, 4+2)
	case 4:
		wireRead(t, conn, 16+2)
	case 3:
		wireRead(t, conn, int(wireRead(t, conn, 1)[0])+2)
	default:
		t.Fatal("invalid SOCKS reply address type")
	}
	return header[1], header[3]
}

func wireConnect(t *testing.T, s *wireServer, target string, marker byte) *net.TCPConn {
	t.Helper()
	conn := s.client(t)
	wireGreeting(t, conn, 0)
	if reply, _ := wireRequest(t, conn, 1, target); reply != 0 {
		t.Fatalf("CONNECT reply = %d, want success", reply)
	}
	if wireRead(t, conn, 1)[0] != marker {
		t.Fatal("connection reached the wrong backend")
	}
	return conn
}

func wireExchange(t *testing.T, conn net.Conn, payload []byte) {
	t.Helper()
	// Read while writing so data larger than socket/copy buffers exercises
	// both relay directions without relying on available kernel buffering.
	written := make(chan bool, 1)
	go func() {
		n, err := conn.Write(payload)
		written <- err == nil && n == len(payload)
	}()
	if !bytes.Equal(wireRead(t, conn, len(payload)), payload) {
		t.Fatal("relayed payload differed")
	}
	if !<-written {
		t.Fatal("large payload write failed")
	}
}

func TestServeEffectiveAddresses(t *testing.T) {
	for _, tt := range []struct {
		name, network, effective string
		atyp                     byte
	}{
		{"IPv4", "tcp4", "100.127.0.10", 1},
		{"IPv6", "tcp6", "fd7a:115c:a1e0:ffff::10", 4},
	} {
		t.Run(tt.name, func(t *testing.T) {
			backend := wireEcho(t, tt.network, 'A')
			host, port, _ := net.SplitHostPort(backend)
			dialer := new(wireDialer)
			router := wireRouter(t, []Profile{{ID: "a", Dialer: dialer}}, []effectiveip.Lease{{
				NodeKey: effectiveip.NodeKey{
					ProfileID: "a", NodeID: "node", CanonicalIP: netip.MustParseAddr(host),
				},
				EffectiveIP: netip.MustParseAddr(tt.effective),
			}})
			s := wireServe(t, router)
			conn := s.client(t)
			wireGreeting(t, conn, 0)
			if reply, atyp := wireRequest(t, conn, 1, net.JoinHostPort(tt.effective, port)); reply != 0 || atyp != tt.atyp {
				t.Fatalf("CONNECT reply = %d, address type = %d; want success and matching family", reply, atyp)
			}
			if wireRead(t, conn, 1)[0] != 'A' {
				t.Fatal("connection reached the wrong backend")
			}
			wireExchange(t, conn, bytes.Repeat([]byte("payload\x00\xff"), 64*1024))
			dialer.check(t, wireDial{"tcp", backend})
		})
	}
}

func TestServeMagicDNSProfileSelection(t *testing.T) {
	a := wireEcho(t, "tcp4", 'A')
	b := wireEcho(t, "tcp4", 'B')
	da := &wireDialer{mapping: map[string]string{"service.alpha.test:443": a}}
	db := &wireDialer{mapping: map[string]string{"service.beta.test:443": b}}
	s := wireServe(t, wireRouter(t, []Profile{
		{ID: "a", MagicDNSSuffix: "alpha.test", Dialer: da},
		{ID: "b", MagicDNSSuffix: "beta.test", Dialer: db},
	}, nil))
	ca := wireConnect(t, s, "SERVICE.ALPHA.TEST.:443", 'A')
	cb := wireConnect(t, s, "service.beta.test:443", 'B')
	wireExchange(t, ca, []byte("request to first profile"))
	wireExchange(t, cb, []byte("request to second profile"))
	da.check(t, wireDial{"tcp", "service.alpha.test:443"})
	db.check(t, wireDial{"tcp", "service.beta.test:443"})
}

func TestServeRejectsUnroutableTargets(t *testing.T) {
	dialer := new(wireDialer)
	s := wireServe(t, wireRouter(t, []Profile{
		{ID: "a", MagicDNSSuffix: "alpha.test", Dialer: dialer},
	}, []effectiveip.Lease{{
		NodeKey: effectiveip.NodeKey{
			ProfileID: "a", NodeID: "node", CanonicalIP: netip.MustParseAddr("100.64.0.1"),
		},
		EffectiveIP: netip.MustParseAddr("100.127.0.1"),
	}}))
	for _, tt := range []struct{ name, target string }{
		{"canonical", "100.64.0.1:443"},
		{"unbound_IPv4", "192.0.2.1:443"},
		{"unbound_IPv6", "[2001:db8::1]:443"},
		{"short_name", "service:443"},
		{"unbound_domain", "service.other.test:443"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			conn := s.client(t)
			wireGreeting(t, conn, 0)
			if reply, _ := wireRequest(t, conn, 1, tt.target); reply != 1 {
				t.Fatalf("CONNECT reply = %d, want general failure", reply)
			}
			dialer.check(t)
		})
	}
}

func TestServeRejectsUnsupportedCommands(t *testing.T) {
	dialer := new(wireDialer)
	s := wireServe(t, wireRouter(t, []Profile{
		{ID: "a", MagicDNSSuffix: "alpha.test", Dialer: dialer},
	}, nil))
	for _, tt := range []struct {
		name    string
		command byte
	}{{"BIND", 2}, {"unknown", 0xff}} {
		t.Run(tt.name, func(t *testing.T) {
			conn := s.client(t)
			wireGreeting(t, conn, 0)
			if reply, _ := wireRequest(t, conn, tt.command, "service.alpha.test:443"); reply != 7 {
				t.Fatalf("unsupported command reply = %d, want command not supported", reply)
			}
			dialer.check(t)
		})
	}
}

func TestServeRejectsUnsupportedAuthentication(t *testing.T) {
	dialer := new(wireDialer)
	s := wireServe(t, wireRouter(t, []Profile{{ID: "a", Dialer: dialer}}, nil))
	for _, tt := range []struct {
		name     string
		greeting []byte
	}{
		{"password_only", []byte{5, 1, 2}},
		{"wrong_version", []byte{4, 1, 0}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			conn := s.client(t, tt.greeting...)
			wireGreeting(t, conn, 0xff)
			dialer.check(t)
		})
	}
}

func TestServeBackendDialFailure(t *testing.T) {
	// Reserve then close a real loopback listener to get a refused TCP dial.
	ln := wireListen(t, "tcp4")
	backend := ln.Addr().String()
	_ = ln.Close()
	dialer := &wireDialer{mapping: map[string]string{"service.alpha.test:443": backend}}
	s := wireServe(t, wireRouter(t, []Profile{
		{ID: "a", MagicDNSSuffix: "alpha.test", Dialer: dialer},
	}, nil))
	conn := s.client(t)
	wireGreeting(t, conn, 0)
	if reply, _ := wireRequest(t, conn, 1, "service.alpha.test:443"); reply != 1 {
		t.Fatalf("failed backend CONNECT reply = %d, want general failure", reply)
	}
	dialer.check(t, wireDial{"tcp", "service.alpha.test:443"})
}

func TestServeRouterReplacementKeepsStreamsAndFailsClosed(t *testing.T) {
	const target = "service.alpha.test:443"
	da := &wireDialer{mapping: map[string]string{target: wireEcho(t, "tcp4", 'A')}}
	db := &wireDialer{mapping: map[string]string{target: wireEcho(t, "tcp4", 'B')}}
	profiles := []Profile{
		{ID: "a", Dialer: da},
		{ID: "b", MagicDNSSuffix: "alpha.test", Dialer: db},
	}
	route := func(id string, active bool) *Router {
		return wireRouter(t, profiles, nil, DomainRoute{
			Suffix: "service.alpha.test", ProfileID: id, Active: active, Exact: true,
		})
	}
	s := wireServe(t, route("a", true))
	old := wireConnect(t, s, target, 'A')
	s.router.Set(route("b", true))
	current := wireConnect(t, s, target, 'B')
	wireExchange(t, old, []byte("old stream remains on first backend"))
	wireExchange(t, current, []byte("new stream uses replacement backend"))

	// An inactive exact policy must not fall back to the active MagicDNS
	// suffix, and replacing the snapshot must not revoke existing streams.
	s.router.Set(route("a", false))
	rejected := s.client(t)
	wireGreeting(t, rejected, 0)
	if reply, _ := wireRequest(t, rejected, 1, target); reply != 1 {
		t.Fatalf("inactive policy CONNECT reply = %d, want general failure", reply)
	}
	wireExchange(t, old, []byte("old stream survives inactive policy"))
	wireExchange(t, current, []byte("current stream survives inactive policy"))
	da.check(t, wireDial{"tcp", target})
	db.check(t, wireDial{"tcp", target})
}

func TestServeClientHalfCloseDeliversBackendReply(t *testing.T) {
	request := bytes.Repeat([]byte("request"), 16*1024)
	reply := bytes.Repeat([]byte("response"), 32*1024)
	backend := wireBackend(t, "tcp4", func(conn *net.TCPConn) {
		data, err := io.ReadAll(conn)
		if err == nil && bytes.Equal(data, request) {
			_, _ = conn.Write(reply)
		}
	})
	dialer := &wireDialer{mapping: map[string]string{"service.alpha.test:443": backend}}
	s := wireServe(t, wireRouter(t, []Profile{
		{ID: "a", MagicDNSSuffix: "alpha.test", Dialer: dialer},
	}, nil))
	conn := s.client(t)
	wireGreeting(t, conn, 0)
	if code, _ := wireRequest(t, conn, 1, "service.alpha.test:443"); code != 0 {
		t.Fatal("half-close test CONNECT did not succeed")
	}
	wireWrite(t, conn, request)
	if err := conn.CloseWrite(); err != nil {
		t.Fatal("client half-close failed")
	}
	data, err := io.ReadAll(conn)
	if err != nil || !bytes.Equal(data, reply) {
		t.Fatal("client half-close did not deliver complete backend reply followed by EOF")
	}
	dialer.check(t, wireDial{"tcp", "service.alpha.test:443"})
}

func TestServeCancellationClosesListener(t *testing.T) {
	dialer := new(wireDialer)
	s := wireServe(t, wireRouter(t, []Profile{{ID: "a", Dialer: dialer}}, nil))
	conn := s.client(t)
	wireGreeting(t, conn, 0) // Barrier: Serve has accepted a real connection.
	s.cancel()
	select {
	case <-s.done:
		if s.err != nil {
			t.Fatal("Serve did not return nil after context cancellation")
		}
	case <-time.After(wireTimeout):
		t.Fatal("Serve did not return after context cancellation")
	}
	if _, err := s.ln.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatal("cancellation did not close the listener")
	}
	// Cancellation promises listener shutdown, not active-stream shutdown.
	dialer.check(t)
}
