package tunmux

import (
	"fmt"
	"sync"
	"sync/atomic"
)

// Packet is an exclusively owned IP packet. Sending a Packet through a
// ChanTUN stage transfers ownership. The receiver must forward it or call
// Release exactly once. Bytes is valid only while the caller owns the Packet.
type Packet struct {
	buffer     *packetBuffer
	generation uint64
	offset     int
	size       int
}

type packetBuffer struct {
	data       []byte
	owner      *packetPool
	pooled     bool
	generation atomic.Uint64
	inUse      atomic.Bool
}

type packetPool struct {
	headroom int
	mtu      int
	buffers  sync.Pool
}

func newPacketPool(headroom, mtu int) *packetPool {
	p := &packetPool{headroom: headroom, mtu: mtu}
	p.buffers.New = func() any {
		return &packetBuffer{
			data:   make([]byte, headroom+mtu),
			owner:  p,
			pooled: true,
		}
	}
	return p
}

func (p *packetPool) acquire(size int) Packet {
	if size < 0 {
		panic("negative packet size")
	}
	var buffer *packetBuffer
	if size <= p.mtu {
		buffer = p.buffers.Get().(*packetBuffer)
	} else {
		buffer = &packetBuffer{
			data:  make([]byte, p.headroom+size),
			owner: p,
		}
	}
	if !buffer.inUse.CompareAndSwap(false, true) {
		panic("packet pool returned an owned buffer")
	}
	generation := buffer.generation.Add(1)
	return Packet{
		buffer:     buffer,
		generation: generation,
		offset:     p.headroom,
		size:       size,
	}
}

func (p *packetPool) copy(data []byte) Packet {
	packet := p.acquire(len(data))
	copy(packet.Bytes(), data)
	return packet
}

// Bytes returns the mutable packet bytes while the caller owns p.
func (p *Packet) Bytes() []byte {
	p.validate()
	return p.buffer.data[p.offset : p.offset+p.size]
}

// Release returns p's storage to its origin pool. It panics on invalid or
// duplicate release so ownership bugs fail close to their source.
func (p *Packet) Release() {
	p.validate()
	buffer := p.buffer
	if !buffer.inUse.CompareAndSwap(true, false) {
		panic("release of unowned packet")
	}
	p.buffer = nil
	p.generation = 0
	p.offset = 0
	p.size = 0
	if buffer.pooled {
		buffer.owner.buffers.Put(buffer)
	}
}

func (p *Packet) validate() {
	if p == nil || p.buffer == nil {
		panic("use of released packet")
	}
	if p.generation != p.buffer.generation.Load() || !p.buffer.inUse.Load() {
		panic("use of stale packet ownership")
	}
	if p.offset < 0 || p.size < 0 || p.offset+p.size > len(p.buffer.data) {
		panic(fmt.Sprintf("invalid packet bounds offset=%d size=%d capacity=%d", p.offset, p.size, len(p.buffer.data)))
	}
}

func (p *Packet) readBuffer() []byte {
	p.validate()
	return p.buffer.data
}

func (p *Packet) writeBuffer() ([]byte, int) {
	p.validate()
	return p.buffer.data[:p.offset+p.size], p.offset
}

func (p *Packet) setSize(size int) {
	p.validate()
	if size < 0 || p.offset+size > len(p.buffer.data) {
		panic(fmt.Sprintf("invalid packet size %d for capacity %d", size, len(p.buffer.data)-p.offset))
	}
	p.size = size
}
