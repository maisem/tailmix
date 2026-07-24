package dns

import (
	"context"
	"encoding/binary"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"tailscale.com/control/controlknobs"
	"tailscale.com/health"
	tailscaledns "tailscale.com/net/dns"
	"tailscale.com/net/netmon"
	"tailscale.com/net/packet"
	"tailscale.com/net/tsdial"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
)

type packetTestOSConfigurator struct{}

func (*packetTestOSConfigurator) SetDNS(tailscaledns.OSConfig) error { return nil }
func (*packetTestOSConfigurator) SupportsSplitDNS() bool             { return true }
func (*packetTestOSConfigurator) GetBaseConfig() (tailscaledns.OSConfig, error) {
	return tailscaledns.OSConfig{}, tailscaledns.ErrGetBaseConfigNotSupported
}
func (*packetTestOSConfigurator) Close() error { return nil }

func newTestPacketService(t *testing.T, name string, wantIP netip.Addr) *packetService {
	t.Helper()
	dnsCfg, err := configForService(ServiceConfig{
		Domains: []Domain{{ProfileID: "work", Suffix: "work.ts.net"}},
		Records: []Record{{ProfileID: "work", Name: name, EffectiveIP: wantIP}},
	})
	if err != nil {
		t.Fatal(err)
	}
	bus := eventbus.NewWithOptions(eventbus.BusOptions{Logf: logger.Discard})
	netMon := netmon.NewStatic()
	dialer := tsdial.NewDialer(netMon)
	dialer.Logf = logger.Discard
	dialer.SetBus(bus)
	knobs := new(controlknobs.Knobs)
	knobs.ForceRegisterMagicDNSIPv4Only.Store(true)
	manager := tailscaledns.NewManager(logger.Discard, new(packetTestOSConfigurator), health.NewTracker(bus), dialer, nil, knobs, "linux", bus)
	if err := manager.Set(dnsCfg); err != nil {
		t.Fatal(err)
	}
	service, err := newPacketService(manager, logger.Discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = service.Close()
		_ = manager.Down()
		_ = dialer.Close()
		_ = netMon.Close()
		bus.Close()
	})
	return service
}

func dnsAQuery(t *testing.T, name string) []byte {
	t.Helper()
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, RecursionDesired: true})
	if err := builder.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := builder.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName(name + "."),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		t.Fatal(err)
	}
	query, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return query
}

func dnsAResponse(t *testing.T, response []byte) netip.Addr {
	t.Helper()
	var parser dnsmessage.Parser
	if _, err := parser.Start(response); err != nil {
		t.Fatal(err)
	}
	if err := parser.SkipAllQuestions(); err != nil {
		t.Fatal(err)
	}
	header, err := parser.AnswerHeader()
	if err != nil {
		t.Fatal(err)
	}
	if header.Type != dnsmessage.TypeA {
		t.Fatalf("answer type = %v, want A", header.Type)
	}
	answer, err := parser.AResource()
	if err != nil {
		t.Fatal(err)
	}
	return netip.AddrFrom4(answer.A)
}

func TestPacketServiceAnswersUDPFromTUN(t *testing.T) {
	const name = "db.work.ts.net"
	wantIP := netip.MustParseAddr("100.127.0.7")
	clientIP := netip.MustParseAddr("100.127.0.10")
	service := newTestPacketService(t, name, wantIP)
	query := packet.Generate(packet.UDP4Header{
		IP4Header: packet.IP4Header{Src: clientIP, Dst: ServiceIP()},
		SrcPort:   54321,
		DstPort:   53,
	}, dnsAQuery(t, name))
	if !service.HandlePacket(query) {
		t.Fatal("quad-100 UDP packet was not consumed")
	}
	select {
	case raw := <-service.Outbound():
		var parsed packet.Parsed
		parsed.Decode(raw)
		if parsed.Src != netip.AddrPortFrom(ServiceIP(), 53) || parsed.Dst != netip.AddrPortFrom(clientIP, 54321) {
			t.Fatalf("UDP response flow = %v > %v", parsed.Src, parsed.Dst)
		}
		if got := dnsAResponse(t, parsed.Payload()); got != wantIP {
			t.Fatalf("UDP MagicDNS answer = %v, want %v", got, wantIP)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for UDP MagicDNS response")
	}
}

type packetTestClient struct {
	stack  *stack.Stack
	linkEP *channel.Endpoint
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func newPacketTestClient(t *testing.T, service *packetService, clientIP netip.Addr) *packetTestClient {
	t.Helper()
	ipstack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	linkEP := channel.New(dnsQueueSize, dnsMTU, "")
	if err := ipstack.CreateNIC(dnsNICID, linkEP); err != nil {
		t.Fatal(err)
	}
	if err := ipstack.AddProtocolAddress(dnsNICID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4(clientIP.As4()).WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	defaultSubnet, err := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{}), tcpip.MaskFromBytes([]byte{0, 0, 0, 0}))
	if err != nil {
		t.Fatal(err)
	}
	ipstack.SetRouteTable([]tcpip.Route{{Destination: defaultSubnet, NIC: dnsNICID}})
	ctx, cancel := context.WithCancel(context.Background())
	c := &packetTestClient{stack: ipstack, linkEP: linkEP, cancel: cancel}
	c.wg.Add(2)
	go func() {
		defer c.wg.Done()
		for {
			packetBuffer := linkEP.ReadContext(ctx)
			if packetBuffer == nil {
				return
			}
			view := packetBuffer.ToView()
			raw := append([]byte(nil), view.AsSlice()...)
			view.Release()
			packetBuffer.DecRef()
			if !service.HandlePacket(raw) {
				t.Errorf("packet to MagicDNS was not consumed")
				return
			}
		}
	}()
	go func() {
		defer c.wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case raw, ok := <-service.Outbound():
				if !ok {
					return
				}
				packetBuffer := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: buffer.MakeWithData(append([]byte(nil), raw...)),
				})
				linkEP.InjectInbound(ipv4.ProtocolNumber, packetBuffer)
				packetBuffer.DecRef()
			}
		}
	}()
	t.Cleanup(func() {
		cancel()
		ipstack.Destroy()
		c.wg.Wait()
	})
	return c
}

func TestPacketServiceAnswersTCPFromTUN(t *testing.T) {
	const name = "db.work.ts.net"
	wantIP := netip.MustParseAddr("100.127.0.7")
	clientIP := netip.MustParseAddr("100.127.0.10")
	service := newTestPacketService(t, name, wantIP)
	client := newPacketTestClient(t, service, clientIP)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := gonet.DialContextTCP(ctx, client.stack, tcpip.FullAddress{
		NIC:  dnsNICID,
		Addr: tcpip.AddrFrom4(ServiceIP().As4()),
		Port: 53,
	}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	query := dnsAQuery(t, name)
	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed, uint16(len(query)))
	copy(framed[2:], query)
	if _, err := conn.Write(framed); err != nil {
		t.Fatal(err)
	}
	var length [2]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, binary.BigEndian.Uint16(length[:]))
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatal(err)
	}
	if got := dnsAResponse(t, response); got != wantIP {
		t.Fatalf("TCP MagicDNS answer = %v, want %v", got, wantIP)
	}
}
