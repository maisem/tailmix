package tunmux

import (
	"context"
	"fmt"
	"io"

	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"

	"github.com/maisem/tailmix/packetmap"
	"tailscale.com/types/logger"
)

type Mux struct {
	host     tun.Device
	profiles map[string]*ChanTUN
	mapper   *packetmap.Mapper
	local    LocalPacketHandler
	logf     logger.Logf
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
	return &Mux{host: host, profiles: profiles, mapper: mapper, logf: logf}
}

// SetLocalPacketHandler installs h. It must be called before Run.
func (m *Mux) SetLocalPacketHandler(h LocalPacketHandler) {
	m.local = h
}

// Run forwards packets in both directions until ctx is canceled or the host
// TUN fails. The caller owns all TUN devices and must close the host device to
// unblock its Read when canceling the context.
func (m *Mux) Run(ctx context.Context) error {
	workerCount := len(m.profiles) + 1
	if m.local != nil {
		workerCount++
	}
	errCh := make(chan error, workerCount)
	go func() { errCh <- m.runHostToProfiles(ctx) }()
	for profileID, profileTun := range m.profiles {
		go func() { errCh <- m.runProfileToHost(ctx, profileID, profileTun) }()
	}
	if m.local != nil {
		go func() { errCh <- m.runLocalToHost(ctx) }()
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
			translated, route, err := m.mapper.Outbound(pkt)
			if err != nil {
				m.logf("drop outbound packet: %v", err)
				continue
			}
			profileTun := m.profiles[route.ProfileID]
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
		case pkt := <-profileTun.Inbound:
			translated, err := m.mapper.Inbound(profileID, pkt)
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
