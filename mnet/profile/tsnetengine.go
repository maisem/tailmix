package profile

import (
	"context"
	"net/netip"

	"github.com/tailscale/wireguard-go/tun"

	"tailscale.com/tsnet"
)

type TSNetConfig struct {
	ProfileID  string
	Alias      string
	Dir        string
	Hostname   string
	AuthKey    string
	ControlURL string
	Tun        tun.Device
}

type TSNetEngine struct {
	cfg    TSNetConfig
	server *tsnet.Server
}

func NewTSNetEngine(cfg TSNetConfig) *TSNetEngine {
	return &TSNetEngine{cfg: cfg}
}

func (e *TSNetEngine) Start(ctx context.Context) error {
	s := &tsnet.Server{
		Dir:        e.cfg.Dir,
		Hostname:   e.cfg.Hostname,
		AuthKey:    e.cfg.AuthKey,
		ControlURL: e.cfg.ControlURL,
		Tun:        e.cfg.Tun,
	}
	if _, err := s.Up(ctx); err != nil {
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

func (e *TSNetEngine) Status(ctx context.Context) (Status, error) {
	if e.server == nil {
		return Status{ProfileID: e.cfg.ProfileID, Alias: e.cfg.Alias}, nil
	}
	st, err := e.server.Up(ctx)
	if err != nil {
		return Status{}, err
	}
	var ips []netip.Addr
	for _, ip := range st.TailscaleIPs {
		ips = append(ips, ip)
	}
	return Status{
		ProfileID: e.cfg.ProfileID,
		Alias:     e.cfg.Alias,
		SelfIPs:   ips,
		PeerCount: len(st.Peer),
	}, nil
}
