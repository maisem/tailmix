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

// Forwarder exposes one loopback classic-DNS endpoint and sends every upstream
// query through a selected profile dialer.
type Forwarder struct {
	ctx       context.Context
	cancel    context.CancelFunc
	dialer    ProfileDialer
	queryer   ProfileDNSQueryer
	resolvers []*dnstype.Resolver
	udp       *net.UDPConn
	tcp       net.Listener
	addr      netip.AddrPort
	wg        sync.WaitGroup
	closeOnce sync.Once
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
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	port := udp.LocalAddr().(*net.UDPAddr).Port
	tcp, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		_ = udp.Close()
		return nil, err
	}
	forwarderCtx, cancel := context.WithCancel(ctx)
	f := &Forwarder{
		ctx:       forwarderCtx,
		cancel:    cancel,
		dialer:    dialer,
		queryer:   queryer,
		resolvers: cloneDNSResolvers(resolvers),
		udp:       udp,
		tcp:       tcp,
		addr:      netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", port)),
	}
	f.wg.Add(2)
	go f.serveUDP()
	go f.serveTCP()
	return f, nil
}

func (f *Forwarder) Resolver() *dnstype.Resolver {
	return &dnstype.Resolver{Addr: f.addr.String()}
}

func (f *Forwarder) Close() error {
	var result error
	f.closeOnce.Do(func() {
		f.cancel()
		result = errors.Join(f.udp.Close(), f.tcp.Close())
		f.wg.Wait()
	})
	return result
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
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
			defer cancel()
			response, err := f.exchange(ctx, "udp", query)
			if err == nil {
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
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
			for {
				var size uint16
				if err := binary.Read(conn, binary.BigEndian, &size); err != nil {
					return
				}
				query := make([]byte, size)
				if _, err := io.ReadFull(conn, query); err != nil {
					return
				}
				ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
				response, err := f.exchange(ctx, "tcp", query)
				cancel()
				if err != nil || len(response) > 65535 {
					return
				}
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

func (f *Forwarder) exchange(ctx context.Context, network string, query []byte) ([]byte, error) {
	if f.queryer != nil {
		return f.exchangeProfileDNS(ctx, query)
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
	var parser dnsmessage.Parser
	header, err := parser.Start(query)
	if err != nil {
		return nil, fmt.Errorf("parse profile DNS query header: %w", err)
	}
	if header.Response {
		return nil, errors.New("profile DNS forwarder received a response")
	}
	questions, err := parser.AllQuestions()
	if err != nil {
		return nil, fmt.Errorf("parse profile DNS question: %w", err)
	}
	if len(questions) != 1 {
		return nil, fmt.Errorf("profile DNS query has %d questions; want 1", len(questions))
	}
	if questions[0].Class != dnsmessage.ClassINET {
		return nil, fmt.Errorf("profile DNS query uses unsupported class %v", questions[0].Class)
	}
	response, err := f.queryer.QueryDNS(questions[0].Name.String(), questions[0].Type)
	if err != nil {
		return nil, err
	}
	if len(response) < 2 {
		return nil, errors.New("profile DNS resolver returned a truncated header")
	}
	response = append([]byte(nil), response...)
	binary.BigEndian.PutUint16(response[:2], header.ID)
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
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
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
