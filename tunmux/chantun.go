package tunmux

import (
	"errors"
	"io"
	"os"
	"sync"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
)

const (
	chanTUNQueueSize = 1024
	chanTUNMTU       = 1280
)

type ChanTUN struct {
	inbound  chan Packet
	outbound chan Packet
	events   chan tun.Event
	closed   chan struct{}
	pool     *packetPool
	name     string
	mtu      int

	closeOnce sync.Once
	sendMu    sync.Mutex
	senders   sync.WaitGroup
	isClosed  bool
}

func NewChanTUN(name string) *ChanTUN {
	t := &ChanTUN{
		inbound:  make(chan Packet, chanTUNQueueSize),
		outbound: make(chan Packet, chanTUNQueueSize),
		events:   make(chan tun.Event, 1),
		closed:   make(chan struct{}),
		pool:     newPacketPool(device.MessageTransportHeaderSize, chanTUNMTU),
		name:     name,
		mtu:      chanTUNMTU,
	}
	t.events <- tun.EventUp
	return t
}

func (t *ChanTUN) File() *os.File { return nil }

func (t *ChanTUN) Close() error {
	t.closeOnce.Do(func() {
		t.sendMu.Lock()
		t.isClosed = true
		close(t.closed)
		t.sendMu.Unlock()
		t.senders.Wait()
		close(t.inbound)
		close(t.outbound)
		for packet := range t.inbound {
			packet.Release()
		}
		for packet := range t.outbound {
			packet.Release()
		}
	})
	return nil
}

func (t *ChanTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	batchSize := min(len(bufs), len(sizes), conn.IdealBatchSize)
	if batchSize == 0 {
		return 0, nil
	}
	packet, ok := <-t.outbound
	if !ok {
		return 0, io.EOF
	}
	copyPacket := func(i int, packet Packet) {
		sizes[i] = copy(bufs[i][offset:], packet.Bytes())
		packet.Release()
	}
	copyPacket(0, packet)
	n := 1
	for n < batchSize {
		select {
		case packet, ok = <-t.outbound:
			if !ok {
				return n, nil
			}
			copyPacket(n, packet)
			n++
		default:
			return n, nil
		}
	}
	return n, nil
}

func (t *ChanTUN) Write(bufs [][]byte, offset int) (int, error) {
	if !t.beginSend() {
		return 0, errors.New("tun closed")
	}
	defer t.senders.Done()
	for _, buf := range bufs {
		data := buf[offset:]
		if len(data) == 0 {
			continue
		}
		packet := t.pool.copy(data)
		select {
		case <-t.closed:
			packet.Release()
			return 0, errors.New("tun closed")
		case t.inbound <- packet:
		default:
			packet.Release()
		}
	}
	return len(bufs), nil
}

// InjectOutbound copies borrowed packet bytes into owned storage and blocks
// until ownership transfers to the outbound queue or the TUN closes.
func (t *ChanTUN) InjectOutbound(pkt []byte) error {
	packet := t.pool.copy(pkt)
	if err := t.injectOutboundPacket(packet); err != nil {
		packet.Release()
		return err
	}
	return nil
}

// TryInjectOutbound copies borrowed packet bytes into owned storage and tries
// to transfer ownership without blocking. It reports whether the transfer
// succeeded.
func (t *ChanTUN) TryInjectOutbound(pkt []byte) bool {
	packet := t.pool.copy(pkt)
	if !t.beginSend() {
		packet.Release()
		return false
	}
	defer t.senders.Done()
	select {
	case <-t.closed:
		packet.Release()
		return false
	case t.outbound <- packet:
		return true
	default:
		packet.Release()
		return false
	}
}

// Inbound returns packets written by the profile engine. Receiving transfers
// ownership to the caller, which must release or forward each Packet.
func (t *ChanTUN) Inbound() <-chan Packet { return t.inbound }

func (t *ChanTUN) injectOutboundPacket(packet Packet) error {
	if !t.beginSend() {
		return errors.New("tun closed")
	}
	defer t.senders.Done()
	select {
	case <-t.closed:
		return errors.New("tun closed")
	case t.outbound <- packet:
		return nil
	}
}

func (t *ChanTUN) tryInjectInboundPacket(packet Packet) (bool, error) {
	if !t.beginSend() {
		return false, errors.New("tun closed")
	}
	defer t.senders.Done()
	select {
	case <-t.closed:
		return false, errors.New("tun closed")
	case t.inbound <- packet:
		return true, nil
	default:
		return false, nil
	}
}

func (t *ChanTUN) beginSend() bool {
	t.sendMu.Lock()
	defer t.sendMu.Unlock()
	if t.isClosed {
		return false
	}
	t.senders.Add(1)
	return true
}

func (t *ChanTUN) MTU() (int, error)        { return t.mtu, nil }
func (t *ChanTUN) Name() (string, error)    { return t.name, nil }
func (t *ChanTUN) Events() <-chan tun.Event { return t.events }
func (t *ChanTUN) BatchSize() int           { return conn.IdealBatchSize }
