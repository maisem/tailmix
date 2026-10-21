package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/types/dnstype"
)

func collideForwarderTCP(t *testing.T, network string, addr *net.TCPAddr) (*net.TCPListener, error) {
	t.Helper()
	blocker, err := net.ListenTCP(network, addr)
	if err != nil {
		if !errors.Is(err, errAddrInUse) {
			t.Fatal(err)
		}
		return nil, err
	}
	t.Cleanup(func() { blocker.Close() })
	return net.ListenTCP(network, addr)
}

func checkForwarderUDPClosed(t *testing.T, udp *net.UDPConn) {
	t.Helper()
	if err := udp.SetReadDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("rejected UDP listener still open: %v", err)
	}
}

func TestListenForwarderRetriesTCPPortCollision(t *testing.T) {
	var candidates []*net.UDPConn
	attempts := 0
	udp, tcp, err := listenForwarder(context.Background(),
		func(network string, addr *net.UDPAddr) (*net.UDPConn, error) {
			for _, candidate := range candidates {
				checkForwarderUDPClosed(t, candidate)
			}
			conn, err := net.ListenUDP(network, addr)
			if err == nil {
				candidates = append(candidates, conn)
				t.Cleanup(func() { conn.Close() })
			}
			return conn, err
		},
		func(network string, addr *net.TCPAddr) (*net.TCPListener, error) {
			attempts++
			if attempts == 1 {
				return collideForwarderTCP(t, network, addr)
			}
			return net.ListenTCP(network, addr)
		})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tcp.Close() })
	if attempts < 2 {
		t.Fatalf("TCP bind attempts = %d, want at least 2", attempts)
	}
	if got, want := tcp.Addr().String(), udp.LocalAddr().String(); got != want {
		t.Fatalf("TCP address = %q, want UDP address %q", got, want)
	}
	if err := udp.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("successful UDP listener closed: %v", err)
	}
}

func TestListenForwarderFailures(t *testing.T) {
	udpErr := errors.New("UDP bind failed")
	tcpErr := &net.OpError{Op: "listen", Net: "tcp", Err: syscall.EACCES}
	for _, tt := range []struct {
		name         string
		udpErr       error
		tcpErr       error
		wantAttempts int
	}{
		{"exhausted", nil, errAddrInUse, forwarderListenAttempts},
		{"TCP error", nil, tcpErr, 1},
		{"UDP error", udpErr, nil, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var candidates []*net.UDPConn
			udpAttempts, tcpAttempts := 0, 0
			udp, tcp, err := listenForwarder(context.Background(),
				func(network string, addr *net.UDPAddr) (*net.UDPConn, error) {
					udpAttempts++
					for _, candidate := range candidates {
						checkForwarderUDPClosed(t, candidate)
					}
					if tt.udpErr != nil {
						return nil, tt.udpErr
					}
					conn, err := net.ListenUDP(network, addr)
					if err == nil {
						candidates = append(candidates, conn)
						t.Cleanup(func() { conn.Close() })
					}
					return conn, err
				},
				func(network string, addr *net.TCPAddr) (*net.TCPListener, error) {
					tcpAttempts++
					if tt.tcpErr == errAddrInUse {
						return collideForwarderTCP(t, network, addr)
					}
					return nil, tt.tcpErr
				})
			wantErr := tt.tcpErr
			wantUDPAttempts := tt.wantAttempts
			if tt.udpErr != nil {
				wantErr = tt.udpErr
				wantUDPAttempts = 1
			}
			if !errors.Is(err, wantErr) {
				t.Fatalf("error = %v, want %v", err, wantErr)
			}
			if wantErr != errAddrInUse && err != wantErr {
				t.Fatalf("error = %v, want original error", err)
			}
			if udp != nil || tcp != nil {
				t.Fatal("failed bind returned a listener")
			}
			if udpAttempts != wantUDPAttempts || tcpAttempts != tt.wantAttempts {
				t.Fatalf("UDP/TCP attempts = %d/%d, want %d/%d", udpAttempts, tcpAttempts, wantUDPAttempts, tt.wantAttempts)
			}
			for _, candidate := range candidates {
				checkForwarderUDPClosed(t, candidate)
			}
		})
	}
}

func TestListenForwarderCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	udp, tcp, err := listenForwarder(ctx,
		func(string, *net.UDPAddr) (*net.UDPConn, error) {
			t.Fatal("UDP bind called with canceled context")
			return nil, nil
		},
		func(string, *net.TCPAddr) (*net.TCPListener, error) {
			t.Fatal("TCP bind called with canceled context")
			return nil, nil
		})
	if !errors.Is(err, context.Canceled) || udp != nil || tcp != nil {
		t.Fatalf("listenForwarder = %v, %v, %v; want nil, nil, context.Canceled", udp, tcp, err)
	}
}

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
		response: testDNSMessage(t, true, dnsmessage.TypeAAAA),
	}
	forwarder := &Forwarder{queryer: queryer, querySlots: make(chan struct{}, 16)}
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

func testDNSMessage(t *testing.T, response bool, typ dnsmessage.Type) []byte {
	t.Helper()
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 0xbeef, Response: response, RecursionDesired: true, CheckingDisabled: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("example.com."), Type: typ, Class: dnsmessage.ClassINET}},
	}
	wire, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

type functionQueryer func(string, dnsmessage.Type) ([]byte, error)

func (q functionQueryer) QueryDNS(name string, typ dnsmessage.Type) ([]byte, error) {
	return q(name, typ)
}

type contextQueryer struct {
	functionQueryer
	query func(context.Context) ([]byte, error)
}

func (q contextQueryer) QueryDNSContext(ctx context.Context, _ string, _ dnsmessage.Type) ([]byte, error) {
	return q.query(ctx)
}

func testDNSConn(t *testing.T, f *Forwarder, network string) net.Conn {
	t.Helper()
	conn, err := net.Dial(network, f.Resolver().Addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return conn
}

func writeDNSQuery(t *testing.T, conn net.Conn, network string, query []byte) {
	t.Helper()
	if network == "tcp" {
		if err := binary.Write(conn, binary.BigEndian, uint16(len(query))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := conn.Write(query); err != nil {
		t.Fatal(err)
	}
}

func readDNSReply(t *testing.T, conn net.Conn, network string) dnsmessage.Message {
	t.Helper()
	wire := make([]byte, 65535)
	var err error
	if network == "tcp" {
		var size uint16
		if err = binary.Read(conn, binary.BigEndian, &size); err != nil {
			t.Fatal(err)
		}
		wire = wire[:size]
		_, err = io.ReadFull(conn, wire)
	} else {
		var n int
		n, err = conn.Read(wire)
		wire = wire[:n]
	}
	if err != nil {
		t.Fatal(err)
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(wire); err != nil {
		t.Fatal(err)
	}
	return msg
}

func TestForwarderServfailForUpstreamErrorsAndInvalidResponses(t *testing.T) {
	for _, network := range []string{"udp", "tcp"} {
		for _, failure := range []string{"error", "short-header", "missing-question", "wrong-question", "not-response"} {
			t.Run(network+"/"+failure, func(t *testing.T) {
				response := testDNSMessage(t, true, dnsmessage.TypeAAAA)
				var err error
				switch failure {
				case "error":
					err = errors.New("unavailable")
				case "short-header":
					response = []byte{1, 2}
				case "missing-question":
					response = []byte{0, 1, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0}
				case "wrong-question":
					response = testDNSMessage(t, true, dnsmessage.TypeA)
				case "not-response":
					response = testDNSMessage(t, false, dnsmessage.TypeAAAA)
				}
				f, startErr := StartProfileDNSForwarder(context.Background(), functionQueryer(func(string, dnsmessage.Type) ([]byte, error) { return response, err }))
				if startErr != nil {
					t.Fatal(startErr)
				}
				defer f.Close()
				conn := testDNSConn(t, f, network)
				writeDNSQuery(t, conn, network, testDNSMessage(t, false, dnsmessage.TypeAAAA))
				msg := readDNSReply(t, conn, network)
				if !msg.Header.Response || msg.Header.ID != 0xbeef || msg.Header.RCode != dnsmessage.RCodeServerFailure || !msg.Header.RecursionDesired || !msg.Header.CheckingDisabled || len(msg.Questions) != 1 || msg.Questions[0].Type != dnsmessage.TypeAAAA {
					t.Fatalf("SERVFAIL = %+v", msg)
				}
				// TCP must remain usable after an upstream failure.
				if network == "tcp" {
					writeDNSQuery(t, conn, network, testDNSMessage(t, false, dnsmessage.TypeAAAA))
					readDNSReply(t, conn, network)
				}
			})
		}
	}
}

func TestForwarderRequestBudgetAndContextTrait(t *testing.T) {
	q := contextQueryer{functionQueryer: func(string, dnsmessage.Type) ([]byte, error) {
		t.Error("legacy method called")
		return nil, errors.New("wrong method")
	}, query: func(ctx context.Context) ([]byte, error) { <-ctx.Done(); return nil, ctx.Err() }}
	f, err := StartProfileDNSForwarder(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	conns := []net.Conn{testDNSConn(t, f, "udp"), testDNSConn(t, f, "tcp")}
	start := time.Now()
	for i, network := range []string{"udp", "tcp"} {
		writeDNSQuery(t, conns[i], network, testDNSMessage(t, false, dnsmessage.TypeA))
	}
	for i, network := range []string{"udp", "tcp"} {
		if msg := readDNSReply(t, conns[i], network); msg.Header.RCode != dnsmessage.RCodeServerFailure {
			t.Fatalf("rcode = %v", msg.Header.RCode)
		}
	}
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Fatalf("request took %v", elapsed)
	}
}

func TestForwarderRetireDrainsUDPAndTCP(t *testing.T) {
	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			response := testDNSMessage(t, true, dnsmessage.TypeA)
			q := functionQueryer(func(string, dnsmessage.Type) ([]byte, error) { close(entered); <-release; return response, nil })
			f, err := StartProfileDNSForwarder(context.Background(), q)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			conn := testDNSConn(t, f, network)
			writeDNSQuery(t, conn, network, testDNSMessage(t, false, dnsmessage.TypeA))
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("query did not start")
			}
			f.Retire()
			// Further generations retire independently, not by closing their predecessor.
			for i := 0; i < 2; i++ {
				next, err := StartProfileDNSForwarder(context.Background(), q)
				if err != nil {
					t.Fatal(err)
				}
				next.Retire()
				next.Close()
			}
			close(release)
			if msg := readDNSReply(t, conn, network); msg.Header.RCode != dnsmessage.RCodeSuccess {
				t.Fatalf("rcode = %v", msg.Header.RCode)
			}
			select {
			case <-f.done:
			case <-time.After(time.Second):
				t.Fatal("retired forwarder did not close")
			}
		})
	}
}

func TestForwarderParentCancellationClosesIdleTCP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f, err := StartProfileDNSForwarder(ctx, functionQueryer(func(string, dnsmessage.Type) ([]byte, error) { return nil, errors.New("unused") }))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	conn := testDNSConn(t, f, "tcp")
	cancel()
	select {
	case <-f.done:
	case <-time.After(time.Second):
		t.Fatal("cancellation did not close idle TCP")
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("TCP connection remained open")
	}
}

func TestForwarderLegacyWorkerBoundSurvivesTimeouts(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 16)
	finished := make(chan struct{}, 16)
	q := functionQueryer(func(string, dnsmessage.Type) ([]byte, error) {
		started <- struct{}{}
		<-release
		finished <- struct{}{}
		return nil, errors.New("released")
	})
	f, err := StartProfileDNSForwarder(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	query := testDNSMessage(t, false, dnsmessage.TypeA)
	for i := 0; i < 20; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		_, err := f.exchange(ctx, "udp", query)
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("error = %v", err)
		}
	}
	if len(started) != 16 {
		t.Fatalf("started %d workers, want 16", len(started))
	}
	close(release)
	for i := 0; i < 16; i++ {
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Fatal("worker did not finish")
		}
	}
}

type pipeDNSDialer struct{ done chan struct{} }

func (d pipeDNSDialer) Dial(context.Context, string, string) (net.Conn, error) {
	client, server := net.Pipe()
	go func() { defer close(d.done); defer server.Close(); io.Copy(io.Discard, server) }()
	return client, nil
}

func TestForwarderClassicIOHonorsContextDeadlineAndCancellation(t *testing.T) {
	for _, network := range []string{"udp", "tcp"} {
		for _, cancelOnly := range []bool{false, true} {
			t.Run(network+"/cancel="+fmt.Sprint(cancelOnly), func(t *testing.T) {
				done := make(chan struct{})
				f := &Forwarder{dialer: pipeDNSDialer{done}}
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
				if cancelOnly {
					cancel()
					ctx, cancel = context.WithCancel(context.Background())
					timer := time.AfterFunc(20*time.Millisecond, cancel)
					defer timer.Stop()
				}
				defer cancel()
				start := time.Now()
				_, err := f.exchangeClassic(ctx, network, &dnstype.Resolver{Addr: "127.0.0.1:53"}, testDNSMessage(t, false, dnsmessage.TypeA))
				if err == nil {
					t.Fatal("exchange succeeded")
				}
				if time.Since(start) > time.Second {
					t.Fatal("exchange ignored request context")
				}
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("upstream did not close")
				}
			})
		}
	}
}

func TestForwarderRejectsMalformedQueries(t *testing.T) {
	f := &Forwarder{ctx: context.Background(), queryer: functionQueryer(func(string, dnsmessage.Type) ([]byte, error) { t.Error("malformed query forwarded"); return nil, nil })}
	for _, query := range [][]byte{{1, 2}, testDNSMessage(t, true, dnsmessage.TypeA), testDNSMessage(t, false, dnsmessage.TypeA)[:13]} {
		if reply := f.answer("udp", query); reply != nil {
			t.Fatalf("malformed query generated response %x", reply)
		}
	}
}

func TestForwarderRetireClosesPartialTCPReads(t *testing.T) {
	f, err := StartProfileDNSForwarder(context.Background(), functionQueryer(func(string, dnsmessage.Type) ([]byte, error) {
		t.Error("partial query reached upstream")
		return nil, errors.New("unused")
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	conn := testDNSConn(t, f, "tcp")
	// Stop halfway through the two-byte length prefix.
	if _, err := conn.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	f.Retire()
	f.Retire() // idempotent; do not extend a draining generation's deadlines.
	select {
	case <-f.done:
	case <-time.After(time.Second):
		t.Fatal("partial TCP read prevented retirement")
	}
}
