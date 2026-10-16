package profile

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/net/netx"
)

// SOCKSDialer resolves SOCKS names through the selected profile's effective DNS
// configuration. Do not use it for the DNS forwarder's own upstream connections:
// those may need Engine.Dial to bootstrap a resolver's hostname.
type SOCKSDialer struct {
	Engine Engine
}

type socksDNSQueryer interface {
	QueryDNSContext(context.Context, string, dnsmessage.Type) ([]byte, error)
}

var (
	errSOCKSTarget = errors.New("invalid SOCKS TCP target")
	errSOCKSDNS    = errors.New("profile SOCKS DNS resolution failed")
	errSOCKSDial   = errors.New("profile SOCKS connection failed")
)

const socksFallbackDelay = 250 * time.Millisecond

func (d SOCKSDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if d.Engine == nil || (network != "tcp" && network != "tcp4" && network != "tcp6") {
		return nil, errSOCKSTarget
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, errSOCKSTarget
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return d.Engine.Dial(ctx, network, addr)
	}
	queryer, ok := d.Engine.(socksDNSQueryer)
	if !ok {
		return nil, errSOCKSDNS
	}
	portNum, err := strconv.ParseUint(port, 10, 16)
	if err != nil || host == "" {
		return nil, errSOCKSTarget
	}
	// The router has already validated and qualified the name. Make the wire
	// question absolute without consulting search domains or the host resolver.
	name := strings.TrimSuffix(host, ".") + "."
	if _, err := dnsmessage.NewName(name); err != nil {
		return nil, errSOCKSTarget
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		conn net.Conn
		err  error
	}
	results := make(chan result)
	fallback := make(chan struct{})
	types := []dnsmessage.Type{dnsmessage.TypeAAAA, dnsmessage.TypeA}
	if network == "tcp4" {
		types = []dnsmessage.Type{dnsmessage.TypeA}
	} else if network == "tcp6" {
		types = []dnsmessage.Type{dnsmessage.TypeAAAA}
	}
	for _, typ := range types {
		go func() {
			if typ == dnsmessage.TypeAAAA {
				// An unavailable IPv6 family should not delay IPv4.
				defer close(fallback)
			}
			ips, err := socksLookup(ctx, queryer, name, typ)
			var conn net.Conn
			if err == nil {
				if typ == dnsmessage.TypeA && network == "tcp" {
					timer := time.NewTimer(socksFallbackDelay)
					select {
					case <-timer.C:
					case <-fallback:
					case <-ctx.Done():
					}
					timer.Stop()
				}
				addrs := make([]netip.AddrPort, 0, len(ips))
				for _, ip := range ips {
					addrs = append(addrs, netip.AddrPortFrom(ip, uint16(portNum)))
				}
				conn, err = netx.RaceDial(ctx, addrs, func(ctx context.Context, _ string, literal string) (net.Conn, error) {
					// RaceDial uses "tcp"; retain the caller's family restriction.
					if err := ctx.Err(); err != nil {
						return nil, err
					}
					return d.Engine.Dial(ctx, network, literal)
				}, socksFallbackDelay)
				if err != nil {
					err = errSOCKSDial
				}
			}
			select {
			case results <- result{conn, err}:
			case <-ctx.Done():
				if conn != nil {
					conn.Close()
				}
			}
		}()
	}
	var lastErr error
	for range types {
		select {
		case res := <-results:
			if err := ctx.Err(); err != nil {
				if res.conn != nil {
					res.conn.Close()
				}
				return nil, err
			}
			if res.err == nil {
				return res.conn, nil
			}
			lastErr = res.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, lastErr
}

// socksLookup accepts only addresses owned by the question name or its CNAME
// chain, never unrelated answers or additional-section glue. Follow CNAME-only
// replies through the same profile, with one shared bound for hops and queries.
func socksLookup(ctx context.Context, queryer socksDNSQueryer, name string, typ dnsmessage.Type) ([]netip.Addr, error) {
	seen := make(map[string]bool)
	for hops := 0; hops < 8; {
		wire, err := queryer.QueryDNSContext(ctx, name, typ)
		if err != nil || ctx.Err() != nil || len(wire) > 65535 {
			return nil, errSOCKSDNS
		}
		var msg dnsmessage.Message
		if err := msg.Unpack(wire); err != nil || !msg.Response || msg.Truncated ||
			msg.OpCode != 0 || msg.RCode != dnsmessage.RCodeSuccess || len(msg.Questions) != 1 {
			return nil, errSOCKSDNS
		}
		// QueryDNSContext owns the transaction ID; its API exposes no request
		// ID to compare. Validate the question instead (backend IDs may vary).
		q := msg.Questions[0]
		if !strings.EqualFold(q.Name.String(), name) || q.Type != typ || q.Class != dnsmessage.ClassINET {
			return nil, errSOCKSDNS
		}
		for hops < 8 {
			key := strings.ToLower(name)
			if seen[key] {
				return nil, errSOCKSDNS
			}
			seen[key] = true
			hops++
			var ips []netip.Addr
			var cname string
			for _, answer := range msg.Answers {
				if answer.Header.Class != dnsmessage.ClassINET || !strings.EqualFold(answer.Header.Name.String(), name) {
					continue
				}
				switch body := answer.Body.(type) {
				case *dnsmessage.AResource:
					if typ == dnsmessage.TypeA {
						ips = append(ips, netip.AddrFrom4(body.A))
					}
				case *dnsmessage.AAAAResource:
					ip := netip.AddrFrom16(body.AAAA)
					if typ == dnsmessage.TypeAAAA && !ip.Is4In6() {
						ips = append(ips, ip)
					}
				case *dnsmessage.CNAMEResource:
					cname = body.CNAME.String()
				}
			}
			if len(ips) != 0 {
				return ips, nil
			}
			if cname == "" {
				if !strings.EqualFold(name, q.Name.String()) {
					// This response ended at an alias; query its terminal name.
					delete(seen, key)
					hops--
					break
				}
				return nil, errSOCKSDNS
			}
			name = cname
		}
	}
	return nil, errSOCKSDNS
}
