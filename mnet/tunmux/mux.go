package tunmux

import (
	"context"
	"log"

	"tailscale.com/mnet/packetmap"
)

type Mux struct {
	host     *ChanTUN
	profiles map[string]*ChanTUN
	mapper   *packetmap.Mapper
}

func NewMux(host *ChanTUN, profiles map[string]*ChanTUN, mapper *packetmap.Mapper) *Mux {
	return &Mux{host: host, profiles: profiles, mapper: mapper}
}

func (m *Mux) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case pkt := <-m.host.Outbound:
			translated, route, err := m.mapper.Outbound(pkt)
			if err != nil {
				log.Printf("mnet mux outbound: %v", err)
				continue
			}
			profileTun := m.profiles[route.ProfileID]
			if profileTun == nil {
				log.Printf("mnet mux outbound: missing profile tun %q", route.ProfileID)
				continue
			}
			profileTun.Outbound <- translated
		}
	}
}
