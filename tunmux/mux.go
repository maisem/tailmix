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
	bufs := make([][]byte, batchSize)
	sizes := make([]int, batchSize)
	for i := range bufs {
		bufs[i] = make([]byte, offset+mtu)
	}

	for {
		n, err := m.host.Read(bufs, sizes, offset)
		if err != nil {
			if ctx.Err() != nil || err == io.EOF {
				return nil
			}
			return fmt.Errorf("read host TUN: %w", err)
		}
		for i := range n {
			pkt := bufs[i][offset : offset+sizes[i]]
			if m.local != nil && m.local.HandlePacket(pkt) {
				continue
			}
			translated, route, err := m.mapper.Load().Outbound(pkt)
			if err != nil {
				m.logf("drop outbound packet: %v", err)
				continue
			}
			m.mu.RLock()
			profileTun := m.profiles[route.ProfileID]
			m.mu.RUnlock()
			if profileTun == nil {
				m.logf("drop outbound packet: missing profile TUN %q", route.ProfileID)
				continue
			}
			if err := profileTun.InjectOutbound(translated); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return fmt.Errorf("inject outbound packet into profile %q: %w", route.ProfileID, err)
			}
		}
	}
}

func (m *Mux) runLocalToHost(ctx context.Context) error {
	const offset = device.MessageTransportHeaderSize
	for {
		select {
		case <-ctx.Done():
			return nil
		case pkt, ok := <-m.local.Outbound():
			if !ok {
				if ctx.Err() != nil {
					return nil
				}
				if err := m.local.Err(); err != nil {
					return fmt.Errorf("local packet handler: %w", err)
				}
				return fmt.Errorf("local packet handler stopped")
			}
			buf := make([]byte, offset+len(pkt))
			copy(buf[offset:], pkt)
			if _, err := m.host.Write([][]byte{buf}, offset); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return fmt.Errorf("write local service packet to host TUN: %w", err)
			}
		}
	}
}

func (m *Mux) runProfileToHost(ctx context.Context, profileID string, profileTun *ChanTUN) error {
	const offset = device.MessageTransportHeaderSize
	for {
		select {
		case <-ctx.Done():
			return nil
		case pkt, ok := <-profileTun.Inbound:
			if !ok {
				if ctx.Err() != nil {
					return nil
				}
				return fmt.Errorf("profile %q TUN inbound channel closed", profileID)
			}
			translated, err := m.mapper.Load().Inbound(profileID, pkt)
			if err != nil {
				m.logf("drop inbound packet from profile %q: %v", profileID, err)
				continue
			}
			buf := make([]byte, offset+len(translated))
			copy(buf[offset:], translated)
			if _, err := m.host.Write([][]byte{buf}, offset); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return fmt.Errorf("write inbound packet from profile %q to host TUN: %w", profileID, err)
			}
		}
	}
}
