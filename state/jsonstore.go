package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/maisem/tailmix/wireguardcfg"
)

type JSONStore struct {
	path string
}

func NewJSONStore(path string) *JSONStore {
	return &JSONStore{path: path}
}

func (s *JSONStore) Path() string {
	return s.path
}

func (s *JSONStore) Load() (State, error) {
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return State{}, nil
	}
	if err != nil {
		return State{}, err
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return State{}, fmt.Errorf("load tailmix state %s: %w", s.path, err)
	}
	Normalize(&st)
	if err := validateProfiles(&st); err != nil {
		return State{}, fmt.Errorf("load tailmix state %s: %w", s.path, err)
	}
	return st, nil
}

func (s *JSONStore) Save(st State) error {
	Normalize(&st)
	if err := validateProfiles(&st); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func validateProfiles(st *State) error {
	for i := range st.Profiles {
		profile := &st.Profiles[i]
		switch profile.Kind {
		case ProfileKindTailscale:
			if profile.WireGuard != nil || profile.WireGuardSecretFile != "" {
				return fmt.Errorf("profile %q has WireGuard state but is a Tailscale profile", profile.Name)
			}
		case ProfileKindWireGuard:
			if profile.WireGuard == nil {
				return fmt.Errorf("WireGuard profile %q has no configuration", profile.Name)
			}
			normalized, err := wireguardcfg.NormalizeConfig(*profile.WireGuard)
			if err != nil {
				return fmt.Errorf("WireGuard profile %q: %w", profile.Name, err)
			}
			if normalized.Name != profile.Name {
				return fmt.Errorf("WireGuard profile name %q does not match configuration name %q", profile.Name, normalized.Name)
			}
			if profile.WireGuardSecretFile == "" {
				return fmt.Errorf("WireGuard profile %q has no secret file", profile.Name)
			}
			if filepath.Base(profile.WireGuardSecretFile) != profile.WireGuardSecretFile ||
				!strings.HasPrefix(profile.WireGuardSecretFile, "wireguard-secrets-") ||
				!strings.HasSuffix(profile.WireGuardSecretFile, ".json") {
				return fmt.Errorf("WireGuard profile %q has an invalid secret file reference", profile.Name)
			}
			profile.WireGuard = &normalized
		default:
			return fmt.Errorf("profile %q has unsupported kind %q", profile.Name, profile.Kind)
		}
	}
	return nil
}
