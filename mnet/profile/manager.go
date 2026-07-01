package profile

import (
	"context"
	"fmt"
	"sort"
)

type Manager struct {
	engines map[string]Engine
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
