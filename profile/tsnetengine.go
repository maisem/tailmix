package profile

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/maisem/tailmix/tsnet"
	"github.com/tailscale/wireguard-go/tun"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/logger"
	"tailscale.com/util/dnsname"
)

type TSNetConfig struct {
	ProfileID      string
	Alias          string
	Dir            string
	Hostname       string
	AuthKey        string
	MagicDNSSuffix string
	UserLogf       logger.Logf
	Logf           logger.Logf
	LogUpload      bool
	LogUploadURL   string
	Tun            tun.Device
}

type TSNetEngine struct {
	cfg    TSNetConfig
	server *tsnet.Server
}

func NewTSNetEngine(cfg TSNetConfig) *TSNetEngine {
	return &TSNetEngine{cfg: cfg}
}

func (e *TSNetEngine) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s := &tsnet.Server{
		Dir:          e.cfg.Dir,
		Hostname:     e.cfg.Hostname,
		UserLogf:     e.cfg.UserLogf,
		Logf:         e.cfg.Logf,
		LogUpload:    e.cfg.LogUpload,
		LogUploadURL: e.cfg.LogUploadURL,
		AuthKey:      e.cfg.AuthKey,
		Tun:          e.cfg.Tun,
	}
	if err := s.Start(); err != nil {
		s.AuthKey = ""
		e.cfg.AuthKey = ""
		_ = s.Close()
		return err
	}
	// Auth keys are one-shot bootstrap credentials. Do not retain them in the
	// long-lived engine configuration after the server has consumed them.
	s.AuthKey = ""
	e.cfg.AuthKey = ""
	e.server = s
	return nil
}

func (e *TSNetEngine) Close() error {
	if e.server == nil {
		return nil
	}
	return e.server.Close()
}

func (e *TSNetEngine) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if e.server == nil {
		if err := e.Start(ctx); err != nil {
			return nil, err
		}
	}
	return e.server.Dial(ctx, network, addr)
}

func (e *TSNetEngine) LocalBackend() (*ipnlocal.LocalBackend, error) {
	if e.server == nil {
		return nil, fmt.Errorf("tsnet server is not started")
	}
	return e.server.LocalBackend()
}

func (e *TSNetEngine) WatchUpdates(ctx context.Context, notify func()) error {
	if notify == nil {
		return fmt.Errorf("nil update callback")
	}
	if e.server == nil {
		if err := e.Start(ctx); err != nil {
			return err
		}
	}
	lc, err := e.server.LocalClient()
	if err != nil {
		return err
	}
	watcher, err := lc.WatchIPNBus(ctx,
		ipn.NotifyInitialStatus|
			ipn.NotifyPeerChanges|
			ipn.NotifyPeerPatches|
			ipn.NotifyNoNetMap)
	if err != nil {
		return err
	}
	defer watcher.Close()
	for {
		n, err := watcher.Next()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if n.ErrMessage != nil {
			return fmt.Errorf("backend: %s", *n.ErrMessage)
		}
		changed := n.InitialStatus != nil || n.SelfChange != nil || len(n.PeersChanged) != 0 || len(n.PeersRemoved) != 0
		if n.State != nil && *n.State == ipn.Running {
			changed = true
		}
		if changed {
			notify()
		}
	}
}

func (e *TSNetEngine) Status(ctx context.Context) (Status, error) {
	if e.server == nil {
		return Status{ProfileID: e.cfg.ProfileID, Alias: e.cfg.Alias, MagicDNSSuffix: e.cfg.MagicDNSSuffix}, nil
	}
	lc, err := e.server.LocalClient()
	if err != nil {
		return Status{}, err
	}
	st, err := lc.Status(ctx)
	if err != nil {
		return Status{}, err
	}
	ips := slices.Clone(st.TailscaleIPs)
	suffix := e.cfg.MagicDNSSuffix
	if st.CurrentTailnet != nil && st.CurrentTailnet.MagicDNSSuffix != "" {
		suffix = st.CurrentTailnet.MagicDNSSuffix
	}
	selfNode := ""
	selfDNSName := ""
	if st.Self != nil {
		selfNode = nodeIDString(st.Self.ID, st.Self.NodeID)
		selfDNSName = normalizeDNSRoute(st.Self.DNSName)
	}
	var peers []PeerStatus
	var availableRoutes []RouteStatus
	for _, peer := range st.Peer {
		nodeID := nodeIDString(peer.ID, peer.NodeID)
		if nodeID == "" {
			continue
		}
		advertiser := routeAdvertiserName(peer.HostName, peer.DNSName, nodeID)
		peers = append(peers, PeerStatus{
			NodeID:       nodeID,
			DNSName:      normalizeDNSRoute(peer.DNSName),
			TailscaleIPs: append([]netip.Addr(nil), peer.TailscaleIPs...),
		})
		if peer.PrimaryRoutes != nil {
			for _, prefix := range peer.PrimaryRoutes.All() {
				if !prefix.IsValid() || prefix.Bits() == 0 {
					continue
				}
				availableRoutes = append(availableRoutes, RouteStatus{
					Prefix:        prefix.Masked(),
					PrimaryRouter: advertiser,
				})
			}
		}
	}
	sort.Slice(peers, func(i, j int) bool {
		if peers[i].NodeID != peers[j].NodeID {
			return peers[i].NodeID < peers[j].NodeID
		}
		return peers[i].DNSName < peers[j].DNSName
	})
	sort.Slice(availableRoutes, func(i, j int) bool {
		if availableRoutes[i].Prefix != availableRoutes[j].Prefix {
			return availableRoutes[i].Prefix.String() < availableRoutes[j].Prefix.String()
		}
		return availableRoutes[i].PrimaryRouter < availableRoutes[j].PrimaryRouter
	})
	shieldsUp := false
	if prefs, err := lc.GetPrefs(ctx); err == nil {
		shieldsUp = prefs.ShieldsUp
	}
	var dnsRoutes []DNSRouteStatus
	var searchDomains []string
	if backend, err := e.LocalBackend(); err == nil {
		if nm := backend.NetMapNoPeers(); nm != nil {
			if suffix != "" && nm.DNS.Proxied {
				dnsRoutes = append(dnsRoutes, DNSRouteStatus{Domain: normalizeDNSRoute(suffix), Source: "magicdns"})
			}
			for domain, resolvers := range nm.DNS.Routes {
				normalizedDomain := normalizeDNSRoute(domain)
				if nm.DNS.Proxied && len(resolvers) == 0 && normalizedDomain == normalizeDNSRoute(suffix) {
					continue
				}
				dnsRoutes = append(dnsRoutes, DNSRouteStatus{
					Domain:    normalizedDomain,
					Source:    "split-dns",
					Resolvers: cloneResolvers(resolvers),
				})
			}
			defaultResolvers := nm.DNS.Resolvers
			if len(defaultResolvers) == 0 {
				defaultResolvers = nm.DNS.FallbackResolvers
			}
			if len(defaultResolvers) != 0 {
				dnsRoutes = append(dnsRoutes, DNSRouteStatus{
					Domain:    ".",
					Source:    "default",
					Resolvers: cloneResolvers(defaultResolvers),
				})
			}
			seenSearchDomains := map[string]bool{}
			for _, raw := range nm.DNS.Domains {
				domain := normalizeDNSRoute(raw)
				if domain == "" || domain == "." || seenSearchDomains[domain] {
					continue
				}
				seenSearchDomains[domain] = true
				searchDomains = append(searchDomains, domain)
			}
		}
	}
	sort.Slice(dnsRoutes, func(i, j int) bool {
		if dnsRoutes[i].Domain != dnsRoutes[j].Domain {
			return dnsRoutes[i].Domain < dnsRoutes[j].Domain
		}
		return dnsRoutes[i].Source < dnsRoutes[j].Source
	})
	sort.Strings(searchDomains)
	return Status{
		ProfileID:       e.cfg.ProfileID,
		Alias:           e.cfg.Alias,
		MagicDNSSuffix:  suffix,
		BackendState:    st.BackendState,
		AuthURL:         st.AuthURL,
		SelfNodeID:      selfNode,
		SelfDNSName:     selfDNSName,
		SelfIPs:         ips,
		Peers:           peers,
		PeerCount:       len(peers),
		ShieldsUp:       shieldsUp,
		AvailableRoutes: availableRoutes,
		DNSRoutes:       dnsRoutes,
		SearchDomains:   searchDomains,
	}, nil
}

func (e *TSNetEngine) SetRouteAll(ctx context.Context, enabled bool) error {
	if e.server == nil {
		return fmt.Errorf("tsnet server is not started")
	}
	lc, err := e.server.LocalClient()
	if err != nil {
		return err
	}
	_, err = lc.EditPrefs(ctx, &ipn.MaskedPrefs{
		Prefs:       ipn.Prefs{RouteAll: enabled},
		RouteAllSet: true,
	})
	return err
}

func normalizeDNSRoute(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return ""
	}
	parsed, err := dnsname.ToFQDN(domain)
	if err != nil {
		return ""
	}
	if parsed == dnsname.FQDN(".") {
		return "."
	}
	return parsed.WithoutTrailingDot()
}

func routeAdvertiserName(hostName, dnsName, nodeID string) string {
	if hostName = strings.TrimSpace(hostName); hostName != "" {
		return hostName
	}
	if dnsName = normalizeDNSRoute(dnsName); dnsName != "" && dnsName != "." {
		return dnsname.FirstLabel(dnsName)
	}
	return nodeID
}

func cloneResolvers(in []*dnstype.Resolver) []*dnstype.Resolver {
	out := make([]*dnstype.Resolver, 0, len(in))
	for _, resolver := range in {
		if resolver != nil {
			out = append(out, resolver.Clone())
		}
	}
	return out
}

func nodeIDString(stable tailcfg.StableNodeID, numeric tailcfg.NodeID) string {
	if stable != "" {
		return string(stable)
	}
	if !numeric.IsZero() {
		return numeric.String()
	}
	return ""
}
