package tunmux

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"

	"github.com/maisem/tailmix/packetmap"
	"tailscale.com/types/logger"
)

type Mux struct {
	host   tun.Device
	pool   *packetPool
	mapper atomic.Pointer[packetmap.Mapper]
	local  LocalPacketHandler
	logf   logger.Logf

	mu       sync.RWMutex
	profiles map[string]*ChanTUN
	workers  map[string]profileWorker
	runCtx   context.Context
	errCh    chan error
}

type profileWorker struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// LocalPacketHandler terminates packets addressed to a service implemented
// inside the shared TUN. HandlePacket reports whether it consumed pkt.
type LocalPacketHandler interface {
	HandlePacket(pkt []byte) bool
	Outbound() <-chan []byte
	Err() error
}

func NewMux(host tun.Device, profiles map[string]*ChanTUN, mapper *packetmap.Mapper, logf logger.Logf) *Mux {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if mapper == nil {
		mapper = packetmap.New(packetmap.Table{})
	}
	m := &Mux{
		host:     host,
		pool:     newPacketPool(device.MessageTransportHeaderSize, chanTUNMTU),
		profiles: make(map[string]*ChanTUN, len(profiles)),
		workers:  map[string]profileWorker{},
		logf:     logf,
	}
	for profileID, profileTun := range profiles {
		m.profiles[profileID] = profileTun
	}
	m.mapper.Store(mapper)
	return m
}

// SetMapper atomically replaces the packet mapping used for subsequent
// packets. In-flight packets finish with the previous immutable mapper.
func (m *Mux) SetMapper(mapper *packetmap.Mapper) {
	if mapper == nil {
		panic("nil packet mapper")
	}
	m.mapper.Store(mapper)
}

// SetLocalPacketHandler installs h. It must be called before Run.
func (m *Mux) SetLocalPacketHandler(h LocalPacketHandler) {
	m.local = h
}

func (m *Mux) AddProfile(profileID string, profileTun *ChanTUN) error {
	if profileID == "" || profileTun == nil {
		return fmt.Errorf("profile ID and TUN are required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.profiles[profileID]; ok {
		return fmt.Errorf("profile %q already has a TUN", profileID)
	}
	m.profiles[profileID] = profileTun
	if m.runCtx != nil {
		m.startProfileWorkerLocked(profileID, profileTun)
	}
	return nil
}

func (m *Mux) RemoveProfile(profileID string) {
	m.mu.Lock()
	delete(m.profiles, profileID)
	worker, ok := m.workers[profileID]
	if ok {
		delete(m.workers, profileID)
		worker.cancel()
	}
	m.mu.Unlock()
	if ok {
		<-worker.done
	}
}

// Run forwards packets in both directions until ctx is canceled or the host
// TUN fails. The caller owns all TUN devices and must close the host device to
// unblock its Read when canceling the context.
func (m *Mux) Run(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	m.mu.Lock()
	if m.runCtx != nil {
		m.mu.Unlock()
		return fmt.Errorf("TUN mux is already running")
	}
	m.runCtx = runCtx
	workerCount := len(m.profiles) + 2
	if m.local != nil {
		workerCount++
	}
	m.errCh = make(chan error, workerCount)
	for profileID, profileTun := range m.profiles {
		m.startProfileWorkerLocked(profileID, profileTun)
	}
	errCh := m.errCh
	m.mu.Unlock()
	go func() { errCh <- m.runHostToProfiles(runCtx) }()
	if m.local != nil {
		go func() { errCh <- m.runLocalToHost(runCtx) }()
	}

	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		if ctx.Err() != nil || err == nil {
			return nil
		}
		return err
	}
}

func (m *Mux) startProfileWorkerLocked(profileID string, profileTun *ChanTUN) {
	workerCtx, cancel := context.WithCancel(m.runCtx)
	done := make(chan struct{})
	m.workers[profileID] = profileWorker{cancel: cancel, done: done}
	go func() {
		defer close(done)
		err := m.runProfileToHost(workerCtx, profileID, profileTun)
		if err == nil || workerCtx.Err() != nil {
			return
		}
		select {
		case m.errCh <- err:
		case <-m.runCtx.Done():
		}
	}()
}

func (m *Mux) runHostToProfiles(ctx context.Context) error {
	mtu, err := m.host.MTU()
	if err != nil {
		return fmt.Errorf("read host TUN MTU: %w", err)
	}
	batchSize := max(1, m.host.BatchSize())
	const offset = device.MessageTransportHeaderSize
	packets := make([]Packet, batchSize)
	bufs := make([][]byte, batchSize)
	sizes := make([]int, batchSize)

	for {
		for i := range packets {
			packets[i] = m.pool.acquire(mtu)
			bufs[i] = packets[i].readBuffer()
		}
		n, readErr := m.host.Read(bufs, sizes, offset)
		for i := n; i < len(packets); i++ {
			packets[i].Release()
			packets[i] = Packet{}
		}
		for i := range n {
			packet := packets[i]
			packets[i] = Packet{}
			packet.setSize(sizes[i])
			pkt := packet.Bytes()
			if m.local != nil && m.local.HandlePacket(pkt) {
				packet.Release()
				continue
			}
			_, route, err := m.mapper.Load().Outbound(pkt)
			if err != nil {
				m.logf("drop outbound packet: %v", err)
				packet.Release()
				continue
			}
			m.mu.RLock()
			profileTun := m.profiles[route.ProfileID]
			m.mu.RUnlock()
			if profileTun == nil {
				m.logf("drop outbound packet: missing profile TUN %q", route.ProfileID)
				packet.Release()
				continue
			}
			if err := profileTun.injectOutboundPacket(packet); err != nil {
				packet.Release()
				if ctx.Err() != nil {
					return nil
				}
				return fmt.Errorf("inject outbound packet into profile %q: %w", route.ProfileID, err)
			}
		}
		if readErr != nil {
			if ctx.Err() != nil || readErr == io.EOF {
				return nil
			}
			return fmt.Errorf("read host TUN: %w", readErr)
		}
	}
}

func (m *Mux) runLocalToHost(ctx context.Context) error {
	batchSize := max(1, m.host.BatchSize())
	packets := make([]Packet, 0, batchSize)
	bufs := make([][]byte, 0, batchSize)
	outbound := m.local.Outbound()
	for {
		packets = packets[:0]
		select {
		case <-ctx.Done():
			return nil
		case pkt, ok := <-outbound:
			if !ok {
				if ctx.Err() != nil {
					return nil
				}
				if err := m.local.Err(); err != nil {
					return fmt.Errorf("local packet handler: %w", err)
				}
				return fmt.Errorf("local packet handler stopped")
			}
			packets = append(packets, m.pool.copy(pkt))
		}

		closed := false
	drain:
		for len(packets) < batchSize {
			select {
			case pkt, ok := <-outbound:
				if !ok {
					closed = true
					break drain
				}
				packets = append(packets, m.pool.copy(pkt))
			default:
				break drain
			}
		}

		bufs = bufs[:0]
		var offset int
		for i := range packets {
			var buf []byte
			buf, offset = packets[i].writeBuffer()
			bufs = append(bufs, buf)
		}
		_, err := m.host.Write(bufs, offset)
		for i := range packets {
			packets[i].Release()
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("write local service packet to host TUN: %w", err)
		}
		if closed {
			if ctx.Err() != nil {
				return nil
			}
			if err := m.local.Err(); err != nil {
				return fmt.Errorf("local packet handler: %w", err)
			}
			return fmt.Errorf("local packet handler stopped")
		}
	}
}

func (m *Mux) runProfileToHost(ctx context.Context, profileID string, profileTun *ChanTUN) error {
	batchSize := max(1, m.host.BatchSize())
	packets := make([]Packet, 0, batchSize)
	accepted := make([]Packet, 0, batchSize)
	bufs := make([][]byte, 0, batchSize)
	inbound := profileTun.Inbound()
	for {
		packets = packets[:0]
		select {
		case <-ctx.Done():
			return nil
		case packet, ok := <-inbound:
			if !ok {
				if ctx.Err() != nil {
					return nil
				}
				return fmt.Errorf("profile %q TUN inbound channel closed", profileID)
			}
			packets = append(packets, packet)
		}

		closed := false
	drain:
		for len(packets) < batchSize {
			select {
			case packet, ok := <-inbound:
				if !ok {
					closed = true
					break drain
				}
				packets = append(packets, packet)
			default:
				break drain
			}
		}

		accepted = accepted[:0]
		bufs = bufs[:0]
		var offset int
		for i := range packets {
			packet := packets[i]
			if _, err := m.mapper.Load().Inbound(profileID, packet.Bytes()); err != nil {
				m.logf("drop inbound packet from profile %q: %v", profileID, err)
				packet.Release()
				continue
			}
			buf, packetOffset := packet.writeBuffer()
			offset = packetOffset
			accepted = append(accepted, packet)
			bufs = append(bufs, buf)
		}
		if len(bufs) > 0 {
			_, err := m.host.Write(bufs, offset)
			for i := range accepted {
				accepted[i].Release()
			}
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return fmt.Errorf("write inbound packet from profile %q to host TUN: %w", profileID, err)
			}
		}
		if closed {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("profile %q TUN inbound channel closed", profileID)
		}
	}
}
