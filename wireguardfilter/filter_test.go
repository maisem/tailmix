package wireguardfilter

import (
	"io"
	"net/netip"
	"os"
	"slices"
	"testing"

	"github.com/maisem/tailmix/wireguardcfg"
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/net/packet"
	"tailscale.com/types/ipproto"
	"tailscale.com/wgengine/filter"
)

func TestCompileEnforcesSelectorsAndLongestPrefixOwnership(t *testing.T) {
	cfg := filterTestConfig()
	cfg.PacketFilter = wireguardcfg.PacketFilter{Grants: []wireguardcfg.Grant{
		{Src: []string{"routes:alpha"}, Dst: []string{"self"}, IP: []string{"udp:53"}},
		{Src: []string{"peer:beta"}, Dst: []string{"self"}, IP: []string{"tcp:22"}},
	}}
	policy := mustCompile(t, cfg, netip.Addr{}, false, nil)

	tests := []struct {
		name string
		pkt  packet.Parsed
		want filter.Response
	}{
		{"unshadowed route", parsedPacket(ipproto.UDP, "192.168.2.1", "10.0.0.1", 40000, 53, 0), filter.Accept},
		{"route shadowed by beta", parsedPacket(ipproto.UDP, "192.168.1.20", "10.0.0.1", 40000, 53, 0), filter.Drop},
		{"route selector excludes direct peer address", parsedPacket(ipproto.UDP, "10.0.0.2", "10.0.0.1", 40000, 53, 0), filter.Drop},
		{"named peer", parsedPacket(ipproto.TCP, "10.0.0.3", "10.0.0.1", 40000, 22, packet.TCPSyn), filter.Accept},
		{"wrong destination port", parsedPacket(ipproto.TCP, "10.0.0.3", "10.0.0.1", 40000, 23, packet.TCPSyn), filter.Drop},
		{"non-local destination", parsedPacket(ipproto.TCP, "10.0.0.3", "10.0.0.9", 40000, 22, packet.TCPSyn), filter.Drop},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := policy.filter.RunIn(&test.pkt, 0); got != test.want {
				t.Fatalf("RunIn() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestCompileInactiveDestinationsAndExplicitSourceValidation(t *testing.T) {
	cfg := filterTestConfig()
	cfg.PacketFilter = wireguardcfg.PacketFilter{Grants: []wireguardcfg.Grant{{
		Src: []string{"peer:*"}, Dst: []string{"peer:alpha", "routes:*", "internet"}, IP: []string{"*"},
	}}}
	policy := mustCompile(t, cfg, netip.Addr{}, false, nil)
	pkt := parsedPacket(ipproto.TCP, "10.0.0.2", "10.0.0.1", 40000, 22, packet.TCPSyn)
	if got := policy.filter.RunIn(&pkt, 0); got != filter.Drop {
		t.Fatalf("inactive destination grant accepted packet: %v", got)
	}

	cfg.PacketFilter.Grants[0].Src = []string{"203.0.113.7"}
	cfg.PacketFilter.Grants[0].Dst = []string{"self"}
	if _, err := Compile(cfg, netip.Addr{}, false, nil); err == nil {
		t.Fatal("Compile succeeded for source selector with no configured owner")
	}
}

func TestPolicyStateSharingAndIsolation(t *testing.T) {
	cfg := filterTestConfig()
	cfg.PacketFilter = wireguardcfg.PacketFilter{Grants: []wireguardcfg.Grant{}}
	base := mustCompile(t, cfg, netip.Addr{}, false, nil)
	outbound := parsedPacket(ipproto.UDP, "10.0.0.1", "10.0.0.2", 41000, 53, 0)
	if got, _ := base.filter.RunOut(&outbound, 0); got != filter.Accept {
		t.Fatalf("RunOut() = %v, want accept", got)
	}
	reply := parsedPacket(ipproto.UDP, "10.0.0.2", "10.0.0.1", 53, 41000, 0)
	if got := base.filter.RunIn(&reply, 0); got != filter.Accept {
		t.Fatalf("reply through base = %v, want accept", got)
	}

	shared := mustCompile(t, cfg, netip.Addr{}, true, base)
	if got := shared.filter.RunIn(&reply, 0); got != filter.Accept {
		t.Fatalf("reply through shared restrictive policy = %v, want accept", got)
	}
	isolated := mustCompile(t, cfg, netip.Addr{}, true, nil)
	if got := isolated.filter.RunIn(&reply, 0); got != filter.Drop {
		t.Fatalf("reply through isolated restrictive policy = %v, want drop", got)
	}
	otherProfile := mustCompile(t, cfg, netip.Addr{}, false, nil)
	if got := otherProfile.filter.RunIn(&reply, 0); got != filter.Drop {
		t.Fatalf("independent profile reused flow state: %v", got)
	}
}

func TestPolicyPreservesUpstreamTCPAndICMPSemantics(t *testing.T) {
	cfg := filterTestConfig()
	cfg.PacketFilter = wireguardcfg.PacketFilter{Grants: []wireguardcfg.Grant{}}
	policy := mustCompile(t, cfg, netip.Addr{}, false, nil)

	tcpContinuation := parsedPacket(ipproto.TCP, "10.0.0.2", "10.0.0.1", 22, 40000, packet.TCPAck)
	if got := policy.filter.RunIn(&tcpContinuation, 0); got != filter.Accept {
		t.Fatalf("TCP continuation = %v, want accept", got)
	}
	tcpSYN := parsedPacket(ipproto.TCP, "10.0.0.2", "10.0.0.1", 22, 40000, packet.TCPSyn)
	if got := policy.filter.RunIn(&tcpSYN, 0); got != filter.Drop {
		t.Fatalf("TCP SYN = %v, want drop", got)
	}
	icmpReply := parsedPacket(ipproto.ICMPv4, "10.0.0.2", "10.0.0.1", 0, 0, 0)
	icmpReply.StuffForTesting(28)
	// ICMP echo reply type.
	icmpReplyBytes := icmp4Packet(0, "10.0.0.2", "10.0.0.1")
	icmpReply.Decode(icmpReplyBytes)
	if got := policy.filter.RunIn(&icmpReply, 0); got != filter.Accept {
		t.Fatalf("ICMP response = %v, want accept", got)
	}
}

func TestDeviceFiltersBatchesAndSwapsAtomically(t *testing.T) {
	cfg := filterTestConfig()
	cfg.PacketFilter = wireguardcfg.PacketFilter{Grants: []wireguardcfg.Grant{}}
	restrictive := mustCompile(t, cfg, netip.Addr{}, true, nil)
	underlying := newTestTUN()
	device, err := NewDevice(underlying, restrictive)
	if err != nil {
		t.Fatal(err)
	}

	allowedReply := udp4Packet("10.0.0.2", "10.0.0.1", 53, 42000)
	newInbound := udp4Packet("10.0.0.2", "10.0.0.1", 53000, 53)
	outbound := udp4Packet("10.0.0.1", "10.0.0.2", 42000, 53)
	underlying.outbound <- []byte{1, 2, 3}
	underlying.outbound <- outbound
	buf := make([]byte, 1500)
	sizes := make([]int, 1)
	if n, err := device.Read([][]byte{buf}, sizes, 0); err != nil || n != 1 || !slices.Equal(buf[:sizes[0]], outbound) {
		t.Fatalf("Read() = (%d, %v), packet %v", n, err, buf[:sizes[0]])
	}

	if n, err := device.Write([][]byte{allowedReply, newInbound}, 0); err != nil || n != 2 {
		t.Fatalf("Write() = (%d, %v), want (2, nil)", n, err)
	}
	if len(underlying.inbound) != 1 || !slices.Equal(underlying.inbound[0], allowedReply) {
		t.Fatalf("underlying inbound = %d packets, want only recorded reply", len(underlying.inbound))
	}

	cfg.PacketFilter = wireguardcfg.PacketFilter{Grants: []wireguardcfg.Grant{{Src: []string{"peer:alpha"}, Dst: []string{"self"}, IP: []string{"udp:53"}}}}
	permissive := mustCompile(t, cfg, netip.Addr{}, false, restrictive)
	if err := device.Install(permissive); err != nil {
		t.Fatal(err)
	}
	underlying.inbound = nil
	if n, err := device.Write([][]byte{newInbound}, 0); err != nil || n != 1 || len(underlying.inbound) != 1 {
		t.Fatalf("Write after swap = (%d, %v), underlying packets %d", n, err, len(underlying.inbound))
	}
	if err := device.Install(nil); err == nil {
		t.Fatal("Install(nil) succeeded")
	}
}

func filterTestConfig() wireguardcfg.Config {
	return wireguardcfg.Config{
		Version:   1,
		Name:      "test",
		Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.1")},
		Peers: []wireguardcfg.Peer{
			{Name: "alpha", Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.2")}, Routes: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}},
			{Name: "beta", Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.3")}, Routes: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}},
		},
	}
}

func mustCompile(t *testing.T, cfg wireguardcfg.Config, exitIP netip.Addr, restrictive bool, shared *Policy) *Policy {
	t.Helper()
	policy, err := Compile(cfg, exitIP, restrictive, shared)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func parsedPacket(proto ipproto.Proto, src, dst string, srcPort, dstPort uint16, flags packet.TCPFlag) packet.Parsed {
	var parsed packet.Parsed
	parsed.StuffForTesting(60)
	parsed.IPVersion = 4
	parsed.IPProto = proto
	parsed.Src = netip.AddrPortFrom(netip.MustParseAddr(src), srcPort)
	parsed.Dst = netip.AddrPortFrom(netip.MustParseAddr(dst), dstPort)
	parsed.TCPFlags = flags
	return parsed
}

func udp4Packet(src, dst string, srcPort, dstPort uint16) []byte {
	return packet.Generate(packet.UDP4Header{
		IP4Header: packet.IP4Header{Src: netip.MustParseAddr(src), Dst: netip.MustParseAddr(dst)},
		SrcPort:   srcPort,
		DstPort:   dstPort,
	}, []byte("payload"))
}

func icmp4Packet(typ byte, src, dst string) []byte {
	buf := make([]byte, 28)
	buf[0] = 0x45
	buf[2] = 0
	buf[3] = 28
	buf[9] = byte(ipproto.ICMPv4)
	copy(buf[12:16], netip.MustParseAddr(src).AsSlice())
	copy(buf[16:20], netip.MustParseAddr(dst).AsSlice())
	buf[20] = typ
	return buf
}

type testTUN struct {
	outbound chan []byte
	inbound  [][]byte
	events   chan tun.Event
	closed   bool
}

func newTestTUN() *testTUN {
	return &testTUN{outbound: make(chan []byte, 8), events: make(chan tun.Event, 1)}
}

func (t *testTUN) File() *os.File { return nil }
func (t *testTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	pkt, ok := <-t.outbound
	if !ok {
		return 0, io.EOF
	}
	sizes[0] = copy(bufs[0][offset:], pkt)
	return 1, nil
}
func (t *testTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		t.inbound = append(t.inbound, slices.Clone(buf[offset:]))
	}
	return len(bufs), nil
}
func (t *testTUN) MTU() (int, error)        { return 1280, nil }
func (t *testTUN) Name() (string, error)    { return "test", nil }
func (t *testTUN) Events() <-chan tun.Event { return t.events }
func (t *testTUN) Close() error {
	if !t.closed {
		close(t.outbound)
		t.closed = true
	}
	return nil
}
func (t *testTUN) BatchSize() int { return 1 }
