package dns

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/types/dnstype"
)

type ProfileDialer interface {
	Dial(context.Context, string, string) (net.Conn, error)
}

type ProfileDNSQueryer interface {
	QueryDNS(string, dnsmessage.Type) ([]byte, error)
}

// ProfileDNSContextQueryer optionally supports bounded, cancellable requests.
// Implementations must bound outstanding work even if their backend cannot cancel.
type ProfileDNSContextQueryer interface {
	QueryDNSContext(context.Context, string, dnsmessage.Type) ([]byte, error)
}

const requestTimeout = 3 * time.Second

// Forwarder exposes one loopback classic-DNS endpoint and sends every upstream
// query through a selected profile dialer.
type Forwarder struct {
	ctx        context.Context
	cancel     context.CancelFunc
	dialer     ProfileDialer
	queryer    ProfileDNSQueryer
	resolvers  []*dnstype.Resolver
	udp        *net.UDPConn
	tcp        net.Listener
	addr       netip.AddrPort
	wg         sync.WaitGroup
	closeOnce  sync.Once
	mu         sync.Mutex
	retired    bool
	conns      map[net.Conn]struct{}
	done       chan struct{}
	querySlots chan struct{}
}

func StartForwarder(ctx context.Context, dialer ProfileDialer, resolvers []*dnstype.Resolver) (*Forwarder, error) {
	if dialer == nil {
		return nil, errors.New("profile DNS forwarder requires a dialer")
	}
	if len(resolvers) == 0 {
		return nil, errors.New("profile DNS forwarder requires at least one resolver")
	}
	return startForwarder(ctx, dialer, nil, resolvers)
}

// StartProfileDNSForwarder exposes a loopback classic-DNS endpoint backed by a
// profile's effective Tailscale DNS configuration.
func StartProfileDNSForwarder(ctx context.Context, queryer ProfileDNSQueryer) (*Forwarder, error) {
	if queryer == nil {
		return nil, errors.New("profile DNS forwarder requires a queryer")
	}
	return startForwarder(ctx, nil, queryer, nil)
}

func startForwarder(ctx context.Context, dialer ProfileDialer, queryer ProfileDNSQueryer, resolvers []*dnstype.Resolver) (*Forwarder, error) {
	udp, tcp, err := listenForwarder(ctx, net.ListenUDP, net.ListenTCP)
	if err != nil {
		return nil, err
	}
	port := udp.LocalAddr().(*net.UDPAddr).Port
	forwarderCtx, cancel := context.WithCancel(ctx)
	f := &Forwarder{
		ctx:        forwarderCtx,
		cancel:     cancel,
		dialer:     dialer,
		queryer:    queryer,
		resolvers:  cloneDNSResolvers(resolvers),
		udp:        udp,
		tcp:        tcp,
		conns:      make(map[net.Conn]struct{}),
		done:       make(chan struct{}),
		querySlots: make(chan struct{}, 16),
		addr:       netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", port)),
	}
	f.wg.Add(2)
	go f.serveUDP()
	go f.serveTCP()
	stopParent := context.AfterFunc(ctx, f.stop)
	go func() {
		f.wg.Wait()
		stopParent()
		f.stop()
		close(f.done)
	}()
	return f, nil
}

const forwarderListenAttempts = 10

func listenForwarder(ctx context.Context,
	listenUDP func(string, *net.UDPAddr) (*net.UDPConn, error),
	listenTCP func(string, *net.TCPAddr) (*net.TCPListener, error),
) (*net.UDPConn, *net.TCPListener, error) {
	var err error
	for range forwarderListenAttempts {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		udp, udpErr := listenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if udpErr != nil {
			return nil, nil, udpErr
		}
		port := udp.LocalAddr().(*net.UDPAddr).Port
		var tcp *net.TCPListener
		tcp, err = listenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		if err == nil {
			return udp, tcp, nil
		}
		_ = udp.Close()
		// UDP's ephemeral port can already be occupied in the TCP port space.
		if !errors.Is(err, errAddrInUse) {
			return nil, nil, err
		}
	}
	return nil, nil, err
}

func (f *Forwarder) Resolver() *dnstype.Resolver {
	return &dnstype.Resolver{Addr: f.addr.String()}
}

// Retire stops accepting queries while allowing already accepted work to reply.
// It is nonblocking; Close or cancellation of the startup context forces shutdown.
func (f *Forwarder) Retire() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.retired {
		return
	}
	f.retired = true
	_ = f.udp.SetReadDeadline(time.Now())
	_ = f.udp.SetWriteDeadline(time.Now().Add(requestTimeout + 100*time.Millisecond))
	_ = f.tcp.Close()
	for conn := range f.conns {
		_ = conn.SetReadDeadline(time.Now())
	}
}

func (f *Forwarder) stop() {
	f.closeOnce.Do(func() {
		f.cancel()
		f.mu.Lock()
		defer f.mu.Unlock()
		f.retired = true
		_ = f.udp.Close()
		_ = f.tcp.Close()
		for conn := range f.conns {
			_ = conn.Close()
		}
	})
}

func (f *Forwarder) Close() error {
	f.stop()
	<-f.done
	return nil
}

func (f *Forwarder) serveUDP() {
	defer f.wg.Done()
	buffer := make([]byte, 64<<10)
	for {
		n, peer, err := f.udp.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		query := append([]byte(nil), buffer[:n]...)
		f.mu.Lock()
		if f.retired {
			f.mu.Unlock()
			return
		}
		f.wg.Add(1)
		f.mu.Unlock()
		go func() {
			defer f.wg.Done()
			if response := f.answer("udp", query); response != nil {
				_, _ = f.udp.WriteToUDP(response, peer)
			}
		}()
	}
}

func (f *Forwarder) serveTCP() {
	defer f.wg.Done()
	for {
		conn, err := f.tcp.Accept()
		if err != nil {
			return
		}
		f.mu.Lock()
		if f.retired {
			f.mu.Unlock()
			_ = conn.Close()
			return
		}
		f.conns[conn] = struct{}{}
		f.wg.Add(1)
		f.mu.Unlock()
		go func() {
			defer f.wg.Done()
			defer func() {
				_ = conn.Close()
				f.mu.Lock()
				delete(f.conns, conn)
				f.mu.Unlock()
			}()
			for {
				f.mu.Lock()
				if f.retired {
					f.mu.Unlock()
					return
				}
				_ = conn.SetReadDeadline(time.Now().Add(requestTimeout))
				f.mu.Unlock()
				var size uint16
				if err := binary.Read(conn, binary.BigEndian, &size); err != nil {
					return
				}
				query := make([]byte, size)
				if _, err := io.ReadFull(conn, query); err != nil {
					return
				}
				response := f.answer("tcp", query)
				if response == nil {
					return
				}
				// A client that stops reading must not prevent retirement.
				_ = conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
				if err := binary.Write(conn, binary.BigEndian, uint16(len(response))); err != nil {
					return
				}
				if _, err := conn.Write(response); err != nil {
					return
				}
			}
		}()
	}
}

func parseQuery(query []byte) (dnsmessage.Message, error) {
	var msg dnsmessage.Message
	if err := msg.Unpack(query); err != nil {
		return msg, err
	}
	if msg.Header.Response || msg.Header.OpCode != 0 || len(msg.Questions) != 1 || msg.Questions[0].Class != dnsmessage.ClassINET {
		return msg, errors.New("unsupported DNS query")
	}
	return msg, nil
}

func (f *Forwarder) answer(network string, query []byte) []byte {
	if _, err := parseQuery(query); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(f.ctx, requestTimeout)
	defer cancel()
	response, err := f.exchange(ctx, network, query)
	if err == nil {
		return response
	}
	return failureResponse(query)
}

func failureResponse(query []byte) []byte {
	msg, err := parseQuery(query)
	if err != nil {
		return nil
	}
	// Never reflect untrusted answers or query sections other than the question.
	header := msg.Header
	header.Response = true
	header.Authoritative = false
	header.Truncated = false
	header.AuthenticData = false
	header.RecursionAvailable = true
	header.RCode = dnsmessage.RCodeServerFailure
	response, _ := (&dnsmessage.Message{Header: header, Questions: msg.Questions}).Pack()
	return response
}

func validateResponse(query, response []byte) error {
	request, err := parseQuery(query)
	if err != nil {
		return err
	}
	var reply dnsmessage.Message
	if len(response) > 65535 {
		return errors.New("DNS response is too large")
	}
	if err := reply.Unpack(response); err != nil {
		return err
	}
	if !reply.Header.Response || reply.Header.ID != request.Header.ID || reply.Header.OpCode != request.Header.OpCode || len(reply.Questions) != 1 {
		return errors.New("DNS response does not match query")
	}
	a, b := request.Questions[0], reply.Questions[0]
	if !strings.EqualFold(a.Name.String(), b.Name.String()) || a.Type != b.Type || a.Class != b.Class {
		return errors.New("DNS response question does not match query")
	}
	return nil
}

func (f *Forwarder) exchange(ctx context.Context, network string, query []byte) ([]byte, error) {
	if _, err := parseQuery(query); err != nil {
		return nil, err
	}
	if f.queryer != nil {
		response, err := f.exchangeProfileDNS(ctx, query)
		if err == nil {
			err = validateResponse(query, response)
		}
		return response, err
	}
	var lastErr error
	for _, resolver := range f.resolvers {
		if resolver == nil || resolver.Addr == "" {
			continue
		}
		var response []byte
		var err error
		if strings.HasPrefix(resolver.Addr, "http://") || strings.HasPrefix(resolver.Addr, "https://") {
			response, err = f.exchangeHTTP(ctx, resolver, query)
		} else {
			response, err = f.exchangeClassic(ctx, network, resolver, query)
		}
		if err == nil {
			err = validateResponse(query, response)
		}
		if err == nil {
			return response, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no usable profile DNS resolver")
	}
	return nil, lastErr
}

func (f *Forwarder) exchangeProfileDNS(ctx context.Context, query []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	msg, err := parseQuery(query)
	if err != nil {
		return nil, err
	}
	question := msg.Questions[0]
	var response []byte
	if queryer, ok := f.queryer.(ProfileDNSContextQueryer); ok {
		response, err = queryer.QueryDNSContext(ctx, question.Name.String(), question.Type)
	} else {
		// Legacy implementations cannot cancel. Keep their slot until they exit,
		// not merely until the caller times out, bounding abandoned work.
		select {
		case f.querySlots <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		type result struct {
			response []byte
			err      error
		}
		done := make(chan result, 1)
		go func() {
			defer func() { <-f.querySlots }()
			response, err := f.queryer.QueryDNS(question.Name.String(), question.Type)
			done <- result{response, err}
		}()
		select {
		case res := <-done:
			response, err = res.response, res.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err != nil {
		return nil, err
	}
	if len(response) < 2 {
		return nil, errors.New("profile DNS resolver returned a truncated header")
	}
	response = append([]byte(nil), response...)
	binary.BigEndian.PutUint16(response[:2], msg.Header.ID)
	return response, nil
}

func (f *Forwarder) exchangeClassic(ctx context.Context, network string, resolver *dnstype.Resolver, query []byte) ([]byte, error) {
	address := resolver.Addr
	if ip, err := netip.ParseAddr(address); err == nil {
		address = netip.AddrPortFrom(ip, 53).String()
	}
	conn, err := f.dialer.Dial(ctx, network, address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if network == "tcp" {
		if len(query) > 65535 {
			return nil, errors.New("DNS query is too large")
		}
		if err := binary.Write(conn, binary.BigEndian, uint16(len(query))); err != nil {
			return nil, err
		}
		if _, err := conn.Write(query); err != nil {
			return nil, err
		}
		var size uint16
		if err := binary.Read(conn, binary.BigEndian, &size); err != nil {
			return nil, err
		}
		response := make([]byte, size)
		_, err = io.ReadFull(conn, response)
		return response, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	response := make([]byte, 64<<10)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}
	return response[:n], nil
}

func (f *Forwarder) exchangeHTTP(ctx context.Context, resolver *dnstype.Resolver, query []byte) ([]byte, error) {
	endpoint, err := url.Parse(resolver.Addr)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if len(resolver.BootstrapResolution) != 0 {
				_, port, err := net.SplitHostPort(address)
				if err != nil {
					return nil, err
				}
				var lastErr error
				for _, ip := range resolver.BootstrapResolution {
					conn, err := f.dialer.Dial(ctx, network, net.JoinHostPort(ip.String(), port))
					if err == nil {
						return conn, nil
					}
					lastErr = err
				}
				return nil, lastErr
			}
			return f.dialer.Dial(ctx, network, address)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/dns-message")
	request.Header.Set("Content-Type", "application/dns-message")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH resolver returned %s", response.Status)
	}
	return io.ReadAll(io.LimitReader(response.Body, 64<<10))
}
