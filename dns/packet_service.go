package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
	tailscaledns "tailscale.com/net/dns"
	"tailscale.com/net/packet"
	"tailscale.com/types/logger"
)

const (
	dnsNICID     tcpip.NICID = 1
	dnsQueueSize int         = 512
	dnsMTU       uint32      = 1280
)

// netstackClock keeps gVisor's monotonic time nondecreasing on virtualized hosts.
type netstackClock struct {
	start  time.Time
	latest atomic.Int64
}

func newNetstackClock() *netstackClock {
	return &netstackClock{start: time.Now()}
}

func (*netstackClock) Now() time.Time { return time.Now() }

func (c *netstackClock) NowMonotonic() tcpip.MonotonicTime {
	elapsed := time.Since(c.start)
	if elapsed < 0 {
		elapsed = 0
	}
	for {
		latest := c.latest.Load()
		if int64(elapsed) <= latest {
			return (tcpip.MonotonicTime{}).Add(time.Duration(latest))
		}
		if c.latest.CompareAndSwap(latest, int64(elapsed)) {
			return (tcpip.MonotonicTime{}).Add(elapsed)
		}
	}
}

func (*netstackClock) AfterFunc(d time.Duration, f func()) tcpip.Timer {
	return &netstackTimer{timer: time.AfterFunc(d, f)}
}

type netstackTimer struct {
	timer *time.Timer
}

func (t *netstackTimer) Stop() bool { return t.timer.Stop() }
func (t *netstackTimer) Reset(d time.Duration) {
	t.timer.Reset(d)
}

type dnsEndpoint struct {
	ip  netip.Addr
	udp *gonet.UDPConn
}

type packetTCPConn struct {
	net.Conn
	closeOnce sync.Once
	closeErr  error
}

func (c *packetTCPConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.Conn.Close()
	})
	return c.closeErr
}

// packetService terminates tailmix's synthetic resolver address and the
// Tailscale service IP in a small gVisor stack. It has no kernel listeners;
// packets enter and leave through HandlePacket and Outbound, which are wired
// to the shared host TUN by tunmux.
type packetService struct {
	manager     *tailscaledns.Manager
	stack       *stack.Stack
	linkEP      *channel.Endpoint
	primaryIP   netip.Addr
	serviceIPs  map[netip.Addr]bool
	endpoints   []dnsEndpoint
	tcpListener *gonet.TCPListener
	logf        logger.Logf

	ctx      context.Context
	cancel   context.CancelFunc
	outbound chan []byte
	wg       sync.WaitGroup
	sessions sync.WaitGroup

	connectionsMu sync.Mutex
	connections   map[*packetTCPConn]struct{}

	errMu sync.Mutex
	err   error

	closeOnce sync.Once
}

func newPacketService(manager *tailscaledns.Manager, resolverIP netip.Addr, logf logger.Logf) (*packetService, error) {
	if manager == nil {
		return nil, errors.New("nil DNS manager")
	}
	if !resolverIP.Is4() {
		return nil, fmt.Errorf("MagicDNS resolver IP must be IPv4: %v", resolverIP)
	}
	if logf == nil {
		logf = logger.Discard
	}
	ipstack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		Clock:              newNetstackClock(),
	})
	linkEP := channel.New(dnsQueueSize, dnsMTU, "")
	if err := ipstack.CreateNIC(dnsNICID, linkEP); err != nil {
		ipstack.Destroy()
		return nil, fmt.Errorf("create MagicDNS netstack NIC: %v", err)
	}
	serviceIPs := []netip.Addr{resolverIP}
	if resolverIP != ServiceIP() {
		serviceIPs = append(serviceIPs, ServiceIP())
	}
	for _, ip := range serviceIPs {
		serviceAddr := tcpip.AddrFrom4(ip.As4())
		if err := ipstack.AddProtocolAddress(dnsNICID, tcpip.ProtocolAddress{
			Protocol:          ipv4.ProtocolNumber,
			AddressWithPrefix: serviceAddr.WithPrefix(),
		}, stack.AddressProperties{}); err != nil {
			ipstack.Destroy()
			return nil, fmt.Errorf("add MagicDNS netstack address %v: %v", ip, err)
		}
	}
	defaultSubnet, err := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{}), tcpip.MaskFromBytes([]byte{0, 0, 0, 0}))
	if err != nil {
		ipstack.Destroy()
		return nil, fmt.Errorf("create MagicDNS default route: %v", err)
	}
	ipstack.SetRouteTable([]tcpip.Route{{Destination: defaultSubnet, NIC: dnsNICID}})

	endpoints := make([]dnsEndpoint, 0, len(serviceIPs))
	for _, ip := range serviceIPs {
		var udpWQ waiter.Queue
		udpEP, tcpipErr := ipstack.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &udpWQ)
		if tcpipErr != nil {
			closeDNSEndpoints(endpoints)
			ipstack.Destroy()
			return nil, fmt.Errorf("create MagicDNS UDP endpoint for %v: %v", ip, tcpipErr)
		}
		localAddr := tcpip.FullAddress{NIC: dnsNICID, Addr: tcpip.AddrFrom4(ip.As4()), Port: 53}
		if tcpipErr := udpEP.Bind(localAddr); tcpipErr != nil {
			udpEP.Close()
			closeDNSEndpoints(endpoints)
			ipstack.Destroy()
			return nil, fmt.Errorf("bind MagicDNS UDP endpoint on %v: %v", ip, tcpipErr)
		}
		endpoints = append(endpoints, dnsEndpoint{ip: ip, udp: gonet.NewUDPConn(&udpWQ, udpEP)})
	}
	tcpListener, err := gonet.ListenTCP(ipstack, tcpip.FullAddress{NIC: dnsNICID, Port: 53}, ipv4.ProtocolNumber)
	if err != nil {
		closeDNSEndpoints(endpoints)
		ipstack.Destroy()
		return nil, fmt.Errorf("listen on MagicDNS TCP endpoints: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &packetService{
		manager:     manager,
		stack:       ipstack,
		linkEP:      linkEP,
		primaryIP:   resolverIP,
		serviceIPs:  make(map[netip.Addr]bool, len(serviceIPs)),
		endpoints:   endpoints,
		tcpListener: tcpListener,
		logf:        logf,
		ctx:         ctx,
		cancel:      cancel,
		outbound:    make(chan []byte, dnsQueueSize),
		connections: make(map[*packetTCPConn]struct{}),
	}
	for _, ip := range serviceIPs {
		s.serviceIPs[ip] = true
	}
	s.start("packet pump", s.pumpOutbound)
	for i := range s.endpoints {
		endpoint := &s.endpoints[i]
		s.start("UDP "+endpoint.ip.String(), func() error { return s.serveUDP(endpoint.udp) })
	}
	s.start("TCP", func() error { return s.serveTCP(s.tcpListener) })
	return s, nil
}

func closeDNSEndpoints(endpoints []dnsEndpoint) {
	for i := range endpoints {
		_ = endpoints[i].udp.Close()
	}
}

func (s *packetService) start(name string, f func() error) {
	s.wg.Go(func() {
		if err := f(); err != nil && s.ctx.Err() == nil {
			s.errMu.Lock()
			if s.err == nil {
				s.err = fmt.Errorf("MagicDNS %s: %w", name, err)
			}
			s.errMu.Unlock()
			s.cancel()
		}
	})
}

func (s *packetService) Addr() netip.AddrPort {
	return netip.AddrPortFrom(s.primaryIP, 53)
}

func (s *packetService) HandlePacket(pkt []byte) bool {
	var parsed packet.Parsed
	parsed.Decode(pkt)
	if !s.serviceIPs[parsed.Dst.Addr()] {
		return false
	}
	if s.ctx.Err() != nil {
		return true
	}
	packetBuffer := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(append([]byte(nil), pkt...)),
	})
	s.linkEP.InjectInbound(ipv4.ProtocolNumber, packetBuffer)
	packetBuffer.DecRef()
	return true
}

func (s *packetService) Outbound() <-chan []byte { return s.outbound }

func (s *packetService) Err() error {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	return s.err
}

func (s *packetService) pumpOutbound() error {
	defer close(s.outbound)
	for {
		packetBuffer := s.linkEP.ReadContext(s.ctx)
		if packetBuffer == nil {
			return nil
		}
		view := packetBuffer.ToView()
		pkt := append([]byte(nil), view.AsSlice()...)
		view.Release()
		packetBuffer.DecRef()
		select {
		case s.outbound <- pkt:
		case <-s.ctx.Done():
			return nil
		}
	}
}

func (s *packetService) serveUDP(conn *gonet.UDPConn) error {
	buf := make([]byte, 64<<10)
	for {
		n, remote, err := conn.ReadFrom(buf)
		if err != nil {
			return err
		}
		udpRemote, ok := remote.(*net.UDPAddr)
		if !ok {
			return fmt.Errorf("unexpected UDP remote address %T", remote)
		}
		query := append([]byte(nil), buf[:n]...)
		s.sessions.Go(func() {
			response, err := s.manager.Query(s.ctx, query, "udp", udpRemote.AddrPort())
			if err != nil {
				if s.ctx.Err() == nil {
					s.logf("MagicDNS UDP query from %v: %v", udpRemote, err)
				}
				return
			}
			if _, err := conn.WriteTo(response, udpRemote); err != nil && s.ctx.Err() == nil {
				s.logf("MagicDNS UDP response to %v: %v", udpRemote, err)
			}
		})
	}
}

func (s *packetService) serveTCP(listener *gonet.TCPListener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		remote, ok := conn.RemoteAddr().(*net.TCPAddr)
		if !ok {
			_ = conn.Close()
			return fmt.Errorf("unexpected TCP remote address %T", conn.RemoteAddr())
		}
		tracked := &packetTCPConn{Conn: conn}
		s.connectionsMu.Lock()
		s.connections[tracked] = struct{}{}
		s.connectionsMu.Unlock()
		s.sessions.Go(func() {
			defer func() {
				s.connectionsMu.Lock()
				delete(s.connections, tracked)
				s.connectionsMu.Unlock()
			}()
			s.manager.HandleTCPConn(tracked, remote.AddrPort())
		})
	}
}

func (s *packetService) closeTCPConnections() {
	s.connectionsMu.Lock()
	connections := make([]*packetTCPConn, 0, len(s.connections))
	for conn := range s.connections {
		connections = append(connections, conn)
	}
	s.connectionsMu.Unlock()
	for _, conn := range connections {
		_ = conn.Close()
	}
}

func (s *packetService) Close() error {
	s.closeOnce.Do(func() {
		s.cancel()
		_ = s.tcpListener.Close()
		closeDNSEndpoints(s.endpoints)
		s.wg.Wait()
		s.closeTCPConnections()
		s.sessions.Wait()
		s.stack.Destroy()
	})
	return s.Err()
}
