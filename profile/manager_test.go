package profile

import (
	"context"
	"net"
	"net/netip"
	"testing"
)

type fakeEngine struct {
	id      string
	started bool
	status  Status
}

func (f *fakeEngine) Start(context.Context) error {
	f.started = true
	return nil
}

func (f *fakeEngine) Close() error {
	f.started = false
	return nil
}

func (f *fakeEngine) Dial(context.Context, string, string) (net.Conn, error) {
	return nil, nil
}

func (f *fakeEngine) Status(context.Context) (Status, error) {
	return f.status, nil
}

func TestManagerStartsProfilesIndependently(t *testing.T) {
	work := &fakeEngine{id: "work", status: Status{ProfileID: "work", SelfNodeID: "work-self", SelfIPs: []netip.Addr{netip.MustParseAddr("100.64.0.10")}}}
	home := &fakeEngine{id: "home", status: Status{ProfileID: "home", SelfNodeID: "home-self", SelfIPs: []netip.Addr{netip.MustParseAddr("100.64.0.10")}}}
	m := NewManager()
	m.Add("work", work)
	m.Add("home", home)
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !work.started || !home.started {
		t.Fatalf("profiles not started independently: work=%v home=%v", work.started, home.started)
	}
	st, err := m.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(st) != 2 {
		t.Fatalf("status count = %d, want 2", len(st))
	}
}
