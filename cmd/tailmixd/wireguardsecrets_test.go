package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/maisem/tailmix/wireguardcfg"
)

func TestWireGuardSecretsRoundTripUsesPrivateFile(t *testing.T) {
	dir := t.TempDir()
	private := wireguardcfg.Key{1}
	psk := wireguardcfg.Key{2}
	want := wireguardcfg.Secrets{
		PrivateKey: &private, PresharedKeyByPeer: map[string]wireguardcfg.Key{"peer": psk},
	}
	name, err := writeWireGuardSecrets(dir, want)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(name) != name || !strings.HasPrefix(name, wireGuardSecretPrefix) {
		t.Fatalf("unsafe secret filename %q", name)
	}
	info, err := os.Stat(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("secret mode = %04o, want 0600", got)
	}
	got, err := readWireGuardSecrets(dir, name)
	if err != nil {
		t.Fatal(err)
	}
	if got.PrivateKey == nil || *got.PrivateKey != private || got.PresharedKeyByPeer["peer"] != psk {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if err := removeWireGuardSecrets(dir, name); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
		t.Fatalf("secret remains after removal: %v", err)
	}
}

func TestCompleteWireGuardSecretsPreservesOnlyRequestedKeys(t *testing.T) {
	oldPrivate := wireguardcfg.Key{1}
	oldPSK := wireguardcfg.Key{2}
	newPSK := wireguardcfg.Key{3}
	config := wireguardcfg.Config{Peers: []wireguardcfg.Peer{
		{Name: "kept", HasPresharedKey: true},
		{Name: "plain"},
	}}
	existing := wireguardcfg.Secrets{PrivateKey: &oldPrivate, PresharedKeyByPeer: map[string]wireguardcfg.Key{"kept": oldPSK, "stale": oldPSK}}
	supplied := wireguardcfg.Secrets{PresharedKeyByPeer: map[string]wireguardcfg.Key{"kept": newPSK, "plain": newPSK}}
	got, err := completeWireGuardSecrets(config, supplied, existing, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.PrivateKey == nil || *got.PrivateKey != oldPrivate || len(got.PresharedKeyByPeer) != 1 || got.PresharedKeyByPeer["kept"] != newPSK {
		t.Fatalf("unexpected completed secrets: %+v", got)
	}
	got.PresharedKeyByPeer["kept"] = wireguardcfg.Key{8}
	if existing.PresharedKeyByPeer["kept"] != oldPSK || supplied.PresharedKeyByPeer["kept"] != newPSK {
		t.Fatal("completed secrets alias caller maps")
	}
}

func TestCompleteWireGuardSecretsGeneratesManagedKey(t *testing.T) {
	got, err := completeWireGuardSecrets(wireguardcfg.Config{}, wireguardcfg.Secrets{}, wireguardcfg.Secrets{}, true)
	if err != nil {
		t.Fatal(err)
	}
	if got.PrivateKey == nil || *got.PrivateKey == (wireguardcfg.Key{}) {
		t.Fatal("managed private key was not generated")
	}
}

func TestReadWireGuardSecretsFailsClosed(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name, reference, contents, want string
	}{
		{"traversal", "../wireguard-secrets-key.json", "", "invalid WireGuard secret file reference"},
		{"wrong prefix", "other.json", "", "invalid WireGuard secret file reference"},
		{"missing private", wireGuardSecretPrefix + "missing.json", `{}`, "no private key"},
		{"unknown field", wireGuardSecretPrefix + "unknown.json", `{"privateKey":"` + (wireguardcfg.Key{1}).String() + `","unexpected":true}`, "unknown field"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.contents != "" {
				if err := os.WriteFile(filepath.Join(dir, tt.reference), []byte(tt.contents), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			_, err := readWireGuardSecrets(dir, tt.reference)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got error %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestWireGuardSecretJSONContainsOnlyKeys(t *testing.T) {
	private := wireguardcfg.Key{1}
	data, err := json.Marshal(wireguardcfg.Secrets{PrivateKey: &private})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "File") || strings.Contains(string(data), "Path") {
		t.Fatalf("secret JSON contains a path: %s", data)
	}
}
