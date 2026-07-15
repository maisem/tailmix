package profile

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/tailscale/wireguard-go/tun"

	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/types/logger"
)

type TSNetConfig struct {
	ProfileID      string
	Alias          string
	Dir            string
	Hostname       string
	AuthKey        string
	ControlURL     string
	MagicDNSSuffix string
	UserLogf       logger.Logf
	Logf           logger.Logf
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
		Dir:        e.cfg.Dir,
		Hostname:   e.cfg.Hostname,
		UserLogf:   e.cfg.UserLogf,
		Logf:       e.cfg.Logf,
		AuthKey:    e.cfg.AuthKey,
		ControlURL: e.cfg.ControlURL,
		Tun:        e.cfg.Tun,
	}
	if err := s.Start(); err != nil {
		return err
	}
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

func (e *TSNetEngine) Status(ctx context.Context) (Status, error) {
	if e.server == nil {
		return Status{ProfileID: e.cfg.ProfileID, Alias: e.cfg.Alias, MagicDNSSuffix: e.cfg.MagicDNSSuffix}, nil
	}
	st, err := e.server.Up(ctx)
	if err != nil {
		return Status{}, err
	}
	var ips []netip.Addr
	for _, ip := range st.TailscaleIPs {
		ips = append(ips, ip)
	}
	suffix := e.cfg.MagicDNSSuffix
	if st.CurrentTailnet != nil && st.CurrentTailnet.MagicDNSSuffix != "" {
		suffix = st.CurrentTailnet.MagicDNSSuffix
	} else if st.MagicDNSSuffix != "" {
		suffix = st.MagicDNSSuffix
	}
	selfNode := ""
	selfDNSName := ""
	if st.Self != nil {
		selfNode = nodeIDString(st.Self.ID, st.Self.NodeID)
		selfDNSName = strings.TrimSuffix(st.Self.DNSName, ".")
	}
	var peers []PeerStatus
	for _, peer := range st.Peer {
		nodeID := nodeIDString(peer.ID, peer.NodeID)
		if nodeID == "" {
			continue
		}
		peers = append(peers, PeerStatus{
			NodeID:       nodeID,
			DNSName:      strings.TrimSuffix(peer.DNSName, "."),
			TailscaleIPs: append([]netip.Addr(nil), peer.TailscaleIPs...),
		})
	}
	sort.Slice(peers, func(i, j int) bool {
		if peers[i].NodeID != peers[j].NodeID {
			return peers[i].NodeID < peers[j].NodeID
		}
		return peers[i].DNSName < peers[j].DNSName
	})
	shieldsUp := false
	if lc, err := e.server.LocalClient(); err == nil {
		if prefs, err := lc.GetPrefs(ctx); err == nil {
			shieldsUp = prefs.ShieldsUp
		}
	}
	return Status{
		ProfileID:      e.cfg.ProfileID,
		Alias:          e.cfg.Alias,
		MagicDNSSuffix: suffix,
		BackendState:   st.BackendState,
		AuthURL:        st.AuthURL,
		SelfNodeID:     selfNode,
		SelfDNSName:    selfDNSName,
		SelfIPs:        ips,
		Peers:          peers,
		PeerCount:      len(peers),
		ShieldsUp:      shieldsUp,
	}, nil
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
