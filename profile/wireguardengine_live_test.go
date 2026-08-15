package profile

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/maisem/tailmix/wireguardcfg"
	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/tun/tuntest"
)

// TestWireGuardEngineMultiPeerLiveReconfiguration exercises the actual
// wireguard-go encryption, handshake, routing, and TUN paths. The fabric is a
// deterministic in-memory UDP network that supports more than the two
// endpoints provided by wireguard-go's bindtest package.
func TestWireGuardEngineMultiPeerLiveReconfiguration(t *testing.T) {
	fabric := newWGTestFabric()
	nodes := make([]wgLiveNode, 3)
	for i := range nodes {
		private, err := wireguardcfg.GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		public, err := private.Public()
		if err != nil {
			t.Fatal(err)
		}
		nodes[i] = wgLiveNode{
			name:       fmt.Sprintf("node-%d", i+1),
			ip:         netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)}),
			port:       uint16(12001 + i),
			privateKey: private,
			publicKey:  public,
			tun:        tuntest.NewChannelTUN(),
		}
	}

	// The first node has two independently configured peers. Each leaf needs
	// only the first node as a peer.
	nodes[0].cfg = wgLiveConfig(nodes[0], nodes[1], nodes[2])
	nodes[1].cfg = wgLiveConfig(nodes[1], nodes[0])
	nodes[2].cfg = wgLiveConfig(nodes[2], nodes[0])
	for i := range nodes {
		n := &nodes[i]
		n.engine = NewWireGuardEngine(WireGuardEngineConfig{
			ProfileID: n.name,
			Config:    n.cfg,
			Secrets:   wireguardcfg.Secrets{PrivateKey: &n.privateKey},
			Tun:       n.tun.TUN(),
			Bind:      fabric.newBind(),
		})
		if err := n.engine.Start(t.Context()); err != nil {
			t.Fatalf("start node %d: %v", i+1, err)
		}
		t.Cleanup(func() { n.engine.Close() })
	}

	assertWGPacket(t, &nodes[1], &nodes[0])
	assertWGPacket(t, &nodes[2], &nodes[0])

	// Remove node 2 live. Traffic from the unrelated node 3 must continue
	// through its existing session and the same central Device.
	centralDevice := nodes[0].engine.dev
	nodes[0].cfg.Peers = nodes[0].cfg.Peers[1:]
	if err := nodes[0].engine.Apply(t.Context(), nodes[0].cfg, wireguardcfg.Secrets{}); err != nil {
		t.Fatalf("remove node 2: %v", err)
	}
	if nodes[0].engine.dev != centralDevice {
		t.Fatal("peer removal replaced central WireGuard device")
	}
	assertWGPacket(t, &nodes[2], &nodes[0])
	state, err := nodes[0].engine.dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains([]byte(state), []byte(nodes[1].publicKey.UAPIHex())) {
		t.Fatal("removed peer remains in central device")
	}

	// Rotate node 2's private/public key and add it back. Both sides are
	// updated in place; the next packet must establish a fresh session.
	rotatedPrivate, err := wireguardcfg.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	rotatedPublic, err := rotatedPrivate.Public()
	if err != nil {
		t.Fatal(err)
	}
	nodes[1].privateKey, nodes[1].publicKey = rotatedPrivate, rotatedPublic
	if err := nodes[1].engine.Apply(t.Context(), nodes[1].cfg, wireguardcfg.Secrets{PrivateKey: &rotatedPrivate}); err != nil {
		t.Fatalf("rotate node 2 key: %v", err)
	}
	nodes[0].cfg.Peers = append(nodes[0].cfg.Peers, wgLivePeer(nodes[1]))
	if err := nodes[0].engine.Apply(t.Context(), nodes[0].cfg, wireguardcfg.Secrets{}); err != nil {
		t.Fatalf("add rotated node 2: %v", err)
	}
	if nodes[0].engine.dev != centralDevice {
		t.Fatal("peer re-add replaced central WireGuard device")
	}
	assertWGPacket(t, &nodes[1], &nodes[0])
}

type wgLiveNode struct {
	name                  string
	ip                    netip.Addr
	port                  uint16
	privateKey, publicKey wireguardcfg.Key
	cfg                   wireguardcfg.Config
	tun                   *tuntest.ChannelTUN
	engine                *WireGuardEngine
}

func wgLiveConfig(self wgLiveNode, peers ...wgLiveNode) wireguardcfg.Config {
	cfg := wireguardcfg.Config{
		Version: wireguardcfg.Version,
		Name:    self.name, DNSSuffix: "wg.test", ListenPort: self.port,
		Addresses: []netip.Addr{self.ip},
	}
	for _, peer := range peers {
		cfg.Peers = append(cfg.Peers, wgLivePeer(peer))
	}
	return cfg
}

func wgLivePeer(peer wgLiveNode) wireguardcfg.Peer {
	return wireguardcfg.Peer{
		Name:      peer.name,
		PublicKey: peer.publicKey,
		Endpoint:  netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), peer.port).String(),
		Addresses: []netip.Addr{peer.ip},
	}
}

func assertWGPacket(t *testing.T, from, to *wgLiveNode) {
	t.Helper()
	pkt := tuntest.Ping(to.ip, from.ip)
	select {
	case from.tun.Outbound <- pkt:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out injecting packet")
	}
	select {
	case got := <-to.tun.Inbound:
		if !bytes.Equal(got, pkt) {
			t.Fatal("packet changed in transit")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for WireGuard packet")
	}
}

type wgTestDatagram struct {
	payload []byte
	source  wgTestEndpoint
}

type wgTestFabric struct {
	mu    sync.RWMutex
	binds map[uint16]*wgTestBind
}

func newWGTestFabric() *wgTestFabric {
	return &wgTestFabric{binds: map[uint16]*wgTestBind{}}
}

func (f *wgTestFabric) newBind() conn.Bind {
	return &wgTestBind{fabric: f}
}

type wgTestBind struct {
	fabric *wgTestFabric
	mu     sync.Mutex
	port   uint16
	rx     chan wgTestDatagram
	closed chan struct{}
}

func (b *wgTestBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.fabric.mu.Lock()
	defer b.fabric.mu.Unlock()
	if port == 0 {
		for port = 20000; b.fabric.binds[port] != nil; port++ {
		}
	}
	if b.fabric.binds[port] != nil {
		return nil, 0, fmt.Errorf("test port already open")
	}
	b.mu.Lock()
	b.port = port
	b.rx = make(chan wgTestDatagram, 64)
	b.closed = make(chan struct{})
	rx, closed := b.rx, b.closed
	b.mu.Unlock()
	b.fabric.binds[port] = b
	receive := func(packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
		select {
		case <-closed:
			return 0, net.ErrClosed
		case datagram := <-rx:
			sizes[0] = copy(packets[0], datagram.payload)
			endpoints[0] = datagram.source
			return 1, nil
		}
	}
	return []conn.ReceiveFunc{receive}, port, nil
}

func (b *wgTestBind) Close() error {
	b.mu.Lock()
	port, closed := b.port, b.closed
	b.port, b.closed = 0, nil
	b.mu.Unlock()
	if closed == nil {
		return nil
	}
	b.fabric.mu.Lock()
	if b.fabric.binds[port] == b {
		delete(b.fabric.binds, port)
	}
	b.fabric.mu.Unlock()
	close(closed)
	return nil
}

func (*wgTestBind) SetMark(uint32) error { return nil }
func (*wgTestBind) BatchSize() int       { return 1 }

func (b *wgTestBind) Send(bufs [][]byte, endpoint conn.Endpoint, offset int) error {
	dst, ok := endpoint.(wgTestEndpoint)
	if !ok {
		return fmt.Errorf("unexpected test endpoint")
	}
	b.fabric.mu.RLock()
	target := b.fabric.binds[dst.addr.Port()]
	b.fabric.mu.RUnlock()
	if target == nil {
		return net.ErrClosed
	}
	b.mu.Lock()
	sourcePort := b.port
	b.mu.Unlock()
	for _, buf := range bufs {
		datagram := wgTestDatagram{
			payload: bytes.Clone(buf[offset:]),
			source:  wgTestEndpoint{addr: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), sourcePort)},
		}
		target.mu.Lock()
		rx, closed := target.rx, target.closed
		target.mu.Unlock()
		select {
		case <-closed:
			return net.ErrClosed
		case rx <- datagram:
		}
	}
	return nil
}

func (*wgTestBind) ParseEndpoint(value string) (conn.Endpoint, error) {
	addr, err := netip.ParseAddrPort(value)
	if err != nil {
		return nil, err
	}
	return wgTestEndpoint{addr: addr}, nil
}

type wgTestEndpoint struct{ addr netip.AddrPort }

func (e wgTestEndpoint) ClearSrc()           {}
func (e wgTestEndpoint) SrcToString() string { return "" }
func (e wgTestEndpoint) DstToString() string { return e.addr.String() }
func (e wgTestEndpoint) DstToBytes() []byte  { return []byte(e.addr.String()) }
func (e wgTestEndpoint) DstIP() netip.Addr   { return e.addr.Addr() }
func (e wgTestEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

var _ conn.Bind = (*wgTestBind)(nil)
var _ conn.Endpoint = wgTestEndpoint{}
