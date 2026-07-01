package tunmux

import (
	"errors"
	"io"
	"os"
	"slices"

	"github.com/tailscale/wireguard-go/tun"
)

type ChanTUN struct {
	Inbound  chan []byte
	Outbound chan []byte
	events   chan tun.Event
	closed   chan struct{}
	name     string
	mtu      int
}

func NewChanTUN(name string) *ChanTUN {
	t := &ChanTUN{
		Inbound:  make(chan []byte, 1024),
		Outbound: make(chan []byte, 1024),
		events:   make(chan tun.Event, 1),
		closed:   make(chan struct{}),
		name:     name,
		mtu:      1280,
	}
	t.events <- tun.EventUp
	return t
}

func (t *ChanTUN) File() *os.File { return nil }

func (t *ChanTUN) Close() error {
	select {
	case <-t.closed:
	default:
		close(t.closed)
		close(t.Inbound)
	}
	return nil
}

func (t *ChanTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-t.closed:
		return 0, io.EOF
	case pkt := <-t.Outbound:
		sizes[0] = copy(bufs[0][offset:], pkt)
		return 1, nil
	}
}

func (t *ChanTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		pkt := buf[offset:]
		if len(pkt) == 0 {
			continue
		}
		select {
		case <-t.closed:
			return 0, errors.New("tun closed")
		case t.Inbound <- slices.Clone(pkt):
		}
	}
	return len(bufs), nil
}

func (t *ChanTUN) MTU() (int, error)        { return t.mtu, nil }
func (t *ChanTUN) Name() (string, error)    { return t.name, nil }
func (t *ChanTUN) Events() <-chan tun.Event { return t.events }
func (t *ChanTUN) BatchSize() int           { return 1 }
