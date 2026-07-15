package profile

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

type fakeEngine struct {
	id      string
	started bool
	status  Status
	updates chan struct{}
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

func (f *fakeEngine) WatchUpdates(ctx context.Context, notify func()) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-f.updates:
			notify()
		}
	}
}

func TestManagerStartsProfilesIndependently(t *testing.T) {
	work := &fakeEngine{id: "work", status: Status{ProfileID: "work", SelfNodeID: "work-self", SelfIPs: []netip.Addr{netip.MustParseAddr("100.64.0.10")}}, updates: make(chan struct{})}
	home := &fakeEngine{id: "home", status: Status{ProfileID: "home", SelfNodeID: "home-self", SelfIPs: []netip.Addr{netip.MustParseAddr("100.64.0.10")}}, updates: make(chan struct{})}
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

func TestManagerWatchesProfileUpdates(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine := &fakeEngine{id: "home", updates: make(chan struct{}, 1)}
	m := NewManager()
	m.Add("home", engine)
	updates := m.WatchUpdates(ctx)
	engine.updates <- struct{}{}
	select {
	case update := <-updates:
		if update.ProfileID != "home" || update.Err != nil {
			t.Fatalf("update = %+v", update)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for profile update")
	}
}
