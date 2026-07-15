package profile

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

type Manager struct {
	engines map[string]Engine
}

// WatchUpdates reports profile changes that can affect addressing, routes, or
// DNS. Events are coalesced because every event causes the daemon to fetch a
// fresh aggregate status for all profiles.
func (m *Manager) WatchUpdates(ctx context.Context) <-chan Update {
	updates := make(chan Update, max(1, len(m.engines)))
	var wg sync.WaitGroup
	for id, engine := range m.engines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := engine.WatchUpdates(ctx, func() {
				select {
				case updates <- Update{ProfileID: id}:
				default:
				}
			})
			if err != nil && ctx.Err() == nil {
				select {
				case updates <- Update{ProfileID: id, Err: fmt.Errorf("watch profile %q: %w", id, err)}:
				case <-ctx.Done():
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(updates)
	}()
	return updates
}

func NewManager() *Manager {
	return &Manager{engines: map[string]Engine{}}
}

func (m *Manager) Add(profileID string, engine Engine) {
	m.engines[profileID] = engine
}

func (m *Manager) Start(ctx context.Context) error {
	for id, engine := range m.engines {
		if err := engine.Start(ctx); err != nil {
			return fmt.Errorf("start profile %q: %w", id, err)
		}
	}
	return nil
}

func (m *Manager) Close() error {
	var first error
	for id, engine := range m.engines {
		if err := engine.Close(); err != nil && first == nil {
			first = fmt.Errorf("close profile %q: %w", id, err)
		}
	}
	return first
}

func (m *Manager) Status(ctx context.Context) ([]Status, error) {
	var out []Status
	for id, engine := range m.engines {
		st, err := engine.Status(ctx)
		if err != nil {
			return nil, fmt.Errorf("status profile %q: %w", id, err)
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ProfileID < out[j].ProfileID })
	return out, nil
}
