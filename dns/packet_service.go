package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

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

// packetService terminates the Tailscale service IP in a small gVisor stack.
// It has no kernel listeners; packets enter and leave through HandlePacket and
// Outbound, which are wired to the shared host TUN by tunmux.
type packetService struct {
	manager *tailscaledns.Manager
	stack   *stack.Stack
	linkEP  *channel.Endpoint
	tcp     *gonet.TCPListener
	udp     *gonet.UDPConn
	logf    logger.Logf

	ctx      context.Context
	cancel   context.CancelFunc
	outbound chan []byte
	wg       sync.WaitGroup
	sessions sync.WaitGroup

	errMu sync.Mutex
	err   error

	closeOnce sync.Once
}

func newPacketService(manager *tailscaledns.Manager, logf logger.Logf) (*packetService, error) {
	if manager == nil {
		return nil, errors.New("nil DNS manager")
	}
	if logf == nil {
		logf = logger.Discard
	}
	ipstack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	linkEP := channel.New(dnsQueueSize, dnsMTU, "")
	if err := ipstack.CreateNIC(dnsNICID, linkEP); err != nil {
		ipstack.Destroy()
		return nil, fmt.Errorf("create MagicDNS netstack NIC: %v", err)
	}
	serviceAddr := tcpip.AddrFrom4(ServiceIP().As4())
	if err := ipstack.AddProtocolAddress(dnsNICID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: serviceAddr.WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		ipstack.Destroy()
		return nil, fmt.Errorf("add MagicDNS netstack address: %v", err)
	}
	defaultSubnet, err := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{}), tcpip.MaskFromBytes([]byte{0, 0, 0, 0}))
	if err != nil {
		ipstack.Destroy()
		return nil, fmt.Errorf("create MagicDNS default route: %v", err)
	}
	ipstack.SetRouteTable([]tcpip.Route{{Destination: defaultSubnet, NIC: dnsNICID}})

	var udpWQ waiter.Queue
	udpEP, tcpipErr := ipstack.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &udpWQ)
	if tcpipErr != nil {
		ipstack.Destroy()
		return nil, fmt.Errorf("create MagicDNS UDP endpoint: %v", tcpipErr)
	}
	localAddr := tcpip.FullAddress{NIC: dnsNICID, Addr: serviceAddr, Port: 53}
	if tcpipErr := udpEP.Bind(localAddr); tcpipErr != nil {
		udpEP.Close()
		ipstack.Destroy()
		return nil, fmt.Errorf("bind MagicDNS UDP endpoint: %v", tcpipErr)
	}
	udpConn := gonet.NewUDPConn(&udpWQ, udpEP)
	tcpListener, err := gonet.ListenTCP(ipstack, localAddr, ipv4.ProtocolNumber)
	if err != nil {
		_ = udpConn.Close()
		ipstack.Destroy()
		return nil, fmt.Errorf("listen on MagicDNS TCP endpoint: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &packetService{
		manager:  manager,
		stack:    ipstack,
		linkEP:   linkEP,
		tcp:      tcpListener,
		udp:      udpConn,
		logf:     logf,
		ctx:      ctx,
		cancel:   cancel,
		outbound: make(chan []byte, dnsQueueSize),
	}
	s.start("packet pump", s.pumpOutbound)
	s.start("UDP", s.serveUDP)
	s.start("TCP", s.serveTCP)
	return s, nil
}

func (s *packetService) start(name string, f func() error) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := f(); err != nil && s.ctx.Err() == nil {
			s.errMu.Lock()
			if s.err == nil {
				s.err = fmt.Errorf("MagicDNS %s: %w", name, err)
			}
			s.errMu.Unlock()
			s.cancel()
		}
	}()
}

func (s *packetService) Addr() netip.AddrPort {
	return netip.AddrPortFrom(ServiceIP(), 53)
}

func (s *packetService) HandlePacket(pkt []byte) bool {
	var parsed packet.Parsed
	parsed.Decode(pkt)
	if parsed.Dst.Addr() != ServiceIP() {
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

func (s *packetService) serveUDP() error {
	buf := make([]byte, 64<<10)
	for {
		n, remote, err := s.udp.ReadFrom(buf)
		if err != nil {
			return err
		}
		udpRemote, ok := remote.(*net.UDPAddr)
		if !ok {
			return fmt.Errorf("unexpected UDP remote address %T", remote)
		}
		query := append([]byte(nil), buf[:n]...)
		s.sessions.Add(1)
		go func() {
			defer s.sessions.Done()
			response, err := s.manager.Query(s.ctx, query, "udp", udpRemote.AddrPort())
			if err != nil {
				if s.ctx.Err() == nil {
					s.logf("MagicDNS UDP query from %v: %v", udpRemote, err)
				}
				return
			}
			if _, err := s.udp.WriteTo(response, udpRemote); err != nil && s.ctx.Err() == nil {
				s.logf("MagicDNS UDP response to %v: %v", udpRemote, err)
			}
		}()
	}
}

func (s *packetService) serveTCP() error {
	for {
		conn, err := s.tcp.Accept()
		if err != nil {
			return err
		}
		remote, ok := conn.RemoteAddr().(*net.TCPAddr)
		if !ok {
			_ = conn.Close()
			return fmt.Errorf("unexpected TCP remote address %T", conn.RemoteAddr())
		}
		s.sessions.Add(1)
		go func() {
			defer s.sessions.Done()
			s.manager.HandleTCPConn(conn, remote.AddrPort())
		}()
	}
}

func (s *packetService) Close() error {
	s.closeOnce.Do(func() {
		s.cancel()
		_ = s.tcp.Close()
		_ = s.udp.Close()
		s.stack.Destroy()
		s.wg.Wait()
		s.sessions.Wait()
	})
	return s.Err()
}
