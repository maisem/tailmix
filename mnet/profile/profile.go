package profile

import (
	"context"
	"net/netip"
)

type Engine interface {
	Start(context.Context) error
	Close() error
	Status(context.Context) (Status, error)
}

type Status struct {
	ProfileID  string
	Alias      string
	SelfNodeID string
	SelfIPs    []netip.Addr
	PeerCount  int
	ShieldsUp  bool
}
