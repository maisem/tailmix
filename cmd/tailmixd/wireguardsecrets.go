package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/maisem/tailmix/wireguardcfg"
)

const wireGuardSecretPrefix = "wireguard-secrets-"

func completeWireGuardSecrets(config wireguardcfg.Config, supplied, existing wireguardcfg.Secrets, create bool) (wireguardcfg.Secrets, error) {
	result := wireguardcfg.Secrets{PresharedKeyByPeer: map[string]wireguardcfg.Key{}}
	switch {
	case supplied.PrivateKey != nil:
		key := *supplied.PrivateKey
		result.PrivateKey = &key
	case existing.PrivateKey != nil:
		key := *existing.PrivateKey
		result.PrivateKey = &key
	case create:
		key, err := wireguardcfg.GeneratePrivateKey()
		if err != nil {
			return wireguardcfg.Secrets{}, err
		}
		result.PrivateKey = &key
	default:
		return wireguardcfg.Secrets{}, errors.New("WireGuard profile private key is missing")
	}
	for _, peer := range config.Peers {
		if !peer.HasPresharedKey {
			continue
		}
		key, ok := supplied.PresharedKeyByPeer[peer.Name]
		if !ok {
			key, ok = existing.PresharedKeyByPeer[peer.Name]
		}
		if !ok {
			return wireguardcfg.Secrets{}, errors.New("WireGuard peer preshared key is missing")
		}
		result.PresharedKeyByPeer[peer.Name] = key
	}
	return result, nil
}

func writeWireGuardSecrets(stateDir string, secrets wireguardcfg.Secrets) (string, error) {
	if secrets.PrivateKey == nil {
		return "", errors.New("WireGuard private key is required")
	}
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return "", err
	}
	suffix, err := randomOpaque("", 8)
	if err != nil {
		return "", err
	}
	name := wireGuardSecretPrefix + suffix + ".json"
	path := filepath.Join(stateDir, name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	data, marshalErr := json.Marshal(secrets)
	if marshalErr == nil {
		_, marshalErr = f.Write(append(data, '\n'))
	}
	if marshalErr == nil {
		marshalErr = f.Sync()
	}
	closeErr := f.Close()
	if marshalErr != nil || closeErr != nil {
		_ = os.Remove(path)
		return "", errors.Join(marshalErr, closeErr)
	}
	return name, nil
}

func readWireGuardSecrets(stateDir, name string) (wireguardcfg.Secrets, error) {
	if filepath.Base(name) != name || !strings.HasPrefix(name, wireGuardSecretPrefix) {
		return wireguardcfg.Secrets{}, errors.New("invalid WireGuard secret file reference")
	}
	data, err := os.ReadFile(filepath.Join(stateDir, name))
	if err != nil {
		return wireguardcfg.Secrets{}, err
	}
	var secrets wireguardcfg.Secrets
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&secrets); err != nil {
		return wireguardcfg.Secrets{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return wireguardcfg.Secrets{}, errors.New("WireGuard secret file has trailing data")
	}
	if secrets.PrivateKey == nil {
		return wireguardcfg.Secrets{}, errors.New("WireGuard secret file has no private key")
	}
	if secrets.PresharedKeyByPeer == nil {
		secrets.PresharedKeyByPeer = map[string]wireguardcfg.Key{}
	}
	return secrets, nil
}

func removeWireGuardSecrets(stateDir, name string) error {
	if filepath.Base(name) != name || !strings.HasPrefix(name, wireGuardSecretPrefix) {
		return nil
	}
	err := os.Remove(filepath.Join(stateDir, name))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
