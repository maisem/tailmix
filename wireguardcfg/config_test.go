package wireguardcfg

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func testKey(fill byte) string {
	var key Key
	for i := range key {
		key[i] = fill
	}
	return key.String()
}

func validManifest() string {
	return `version: 1
name: office
dnsSuffix: wg.example.com.
addresses: [10.0.0.1, "fd00::1"]
privateKeyFile: private.key
listenPort: 51820
peers:
  - name: alice
    publicKey: ` + testKey(1) + `
    presharedKeyFile: alice.psk
    endpoint: alice.example.com:51820
    keepalive: 25s
    addresses: [10.0.0.2, "fd00::2"]
    routes: [192.168.0.0/16]
    exitNode: true
`
}

func TestParse(t *testing.T) {
	files := map[string][]byte{"private.key": []byte(testKey(2) + "\n"), "alice.psk": []byte(testKey(3))}
	config, secrets, err := Parse([]byte(validManifest()), func(path string) ([]byte, error) { return files[path], nil })
	if err != nil {
		t.Fatal(err)
	}
	if config.Name != "office" || config.DNSSuffix != "wg.example.com" || config.ListenPort != 51820 {
		t.Fatalf("unexpected config: %+v", config)
	}
	peer := config.Peers[0]
	if peer.Name != "alice" || !peer.HasPresharedKey || peer.Keepalive != 25*time.Second || len(peer.Addresses) != 2 || len(peer.Routes) != 1 || !peer.ExitNode {
		t.Fatalf("unexpected peer: %+v", peer)
	}
	if secrets.PrivateKey == nil || secrets.PrivateKey.String() != testKey(2) || secrets.PresharedKeyByPeer["alice"].String() != testKey(3) {
		t.Fatalf("unexpected secrets: %+v", secrets)
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"private.key", "alice.psk", testKey(2), testKey(3)} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("config JSON contains secret %q: %s", forbidden, encoded)
		}
	}
	if strings.Contains(string(encoded), "dnsName") {
		t.Fatalf("config JSON duplicates the derived peer DNS name: %s", encoded)
	}
}

func TestParseRejectsUnknownField(t *testing.T) {
	_, _, err := Parse([]byte(validManifest()+"mystery: true\n"), nil)
	if err == nil || !strings.Contains(err.Error(), "field mystery not found") {
		t.Fatalf("got error %v", err)
	}
}

func TestParseManagedKeyNeedsNoReader(t *testing.T) {
	manifest := strings.ReplaceAll(validManifest(), "privateKeyFile: private.key\n", "")
	manifest = strings.ReplaceAll(manifest, "    presharedKeyFile: alice.psk\n", "")
	_, secrets, err := Parse([]byte(manifest), nil)
	if err != nil {
		t.Fatal(err)
	}
	if secrets.PrivateKey != nil || len(secrets.PresharedKeyByPeer) != 0 {
		t.Fatalf("unexpected secrets: %+v", secrets)
	}
}

func TestValidation(t *testing.T) {
	tests := []struct {
		name    string
		replace string
		with    string
		want    string
	}{
		{"version", "version: 1", "version: 2", "version: got 2"},
		{"profile name", "name: office", "name: Not_DNS", "lowercase DNS label"},
		{"duplicate family", `addresses: [10.0.0.1, "fd00::1"]`, "addresses: [10.0.0.1, 10.1.0.1]", "more than one address"},
		{"bad public key", "publicKey: " + testKey(1), "publicKey: c2hvcnQ=", "is 5 bytes"},
		{"zero public key", "publicKey: " + testKey(1), "publicKey: " + testKey(0), "must not be all zero"},
		{"family mismatch", `addresses: [10.0.0.1, "fd00::1"]`, "addresses: [10.0.0.1]", "no profile address for this address family"},
		{"unspecified self", "10.0.0.1,", "0.0.0.0,", "must not be unspecified"},
		{"multicast peer", "10.0.0.2,", "224.0.0.1,", "must not be multicast"},
		{"mapped address", "addresses: [10.0.0.2,", `addresses: ["::ffff:10.0.0.2",`, "native IPv4 or IPv6"},
		{"default route", "routes: [192.168.0.0/16]", "routes: [0.0.0.0/0]", "represented by exitNode"},
		{"bad endpoint", "endpoint: alice.example.com:51820", "endpoint: missing-port", "missing port"},
		{"fractional keepalive", "keepalive: 25s", "keepalive: 1500ms", "whole number of seconds"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest := strings.Replace(validManifest(), tt.replace, tt.with, 1)
			_, _, err := Parse([]byte(manifest), func(string) ([]byte, error) { return []byte(testKey(2)), nil })
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got error %v; want substring %q", err, tt.want)
			}
		})
	}
}

func TestRejectsDuplicates(t *testing.T) {
	base := strings.ReplaceAll(validManifest(), "privateKeyFile: private.key\n", "")
	base = strings.ReplaceAll(base, "    presharedKeyFile: alice.psk\n", "")
	peer := `  - name: bob
    publicKey: %s
    addresses: [%s]
    routes: [%s]
`
	tests := []struct{ name, addition, want string }{
		{"name", strings.Replace(fmtPeer(peer, testKey(2), "10.0.0.3", "172.16.0.0/12"), "name: bob", "name: alice", 1), "duplicate \"alice\""},
		{"key", fmtPeer(peer, testKey(1), "10.0.0.3", "172.16.0.0/12"), "duplicate key"},
		{"address", fmtPeer(peer, testKey(2), "10.0.0.2", "172.16.0.0/12"), "also assigned"},
		{"route", fmtPeer(peer, testKey(2), "10.0.0.3", "192.168.0.0/16"), "also assigned"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := Parse([]byte(base+tt.addition), nil)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got error %v; want substring %q", err, tt.want)
			}
		})
	}
}

func fmtPeer(format, key, address, route string) string {
	return fmt.Sprintf(format, key, address, route)
}

func TestKeyHelpers(t *testing.T) {
	private, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := private.Public(); err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseKey(private.String())
	if err != nil || parsed != private {
		t.Fatalf("round trip: key=%v err=%v", parsed, err)
	}
	if len(private.UAPIHex()) != 64 {
		t.Fatalf("UAPI hex has length %d", len(private.UAPIHex()))
	}
}

func TestSecretsJSONRoundTrip(t *testing.T) {
	private, psk := Key{1}, Key{2}
	want := Secrets{PrivateKey: &private, PresharedKeyByPeer: map[string]Key{"alice": psk}}
	encoded, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"privateKey"`) || strings.Contains(string(encoded), `"PrivateKey"`) {
		t.Fatalf("unexpected JSON field names: %s", encoded)
	}
	var got Secrets
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if got.PrivateKey == nil || *got.PrivateKey != private || got.PresharedKeyByPeer["alice"] != psk {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestRejectsZeroKeyFiles(t *testing.T) {
	_, _, err := Parse([]byte(validManifest()), func(string) ([]byte, error) { return []byte(testKey(0)), nil })
	if err == nil || !strings.Contains(err.Error(), "must not be all zero") {
		t.Fatalf("got error %v", err)
	}
}

func TestNormalizeConfigAndClone(t *testing.T) {
	config, _, err := Parse([]byte(strings.ReplaceAll(strings.ReplaceAll(validManifest(), "privateKeyFile: private.key\n", ""), "    presharedKeyFile: alice.psk\n", "")), nil)
	if err != nil {
		t.Fatal(err)
	}
	config.DNSSuffix += "."
	config.Peers[0].Routes[0] = netip.MustParsePrefix("192.168.0.1/24")
	normalized, err := NormalizeConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.DNSSuffix != "wg.example.com" || normalized.Peers[0].Routes[0].String() != "192.168.0.0/24" {
		t.Fatalf("not normalized: %+v", normalized)
	}
	clone := normalized.Clone()
	clone.Addresses[0] = clone.Addresses[1]
	clone.Peers[0].Addresses[0] = clone.Peers[0].Addresses[1]
	clone.Peers[0].Routes[0] = netip.MustParsePrefix("192.168.0.0/32")
	if normalized.Addresses[0] == clone.Addresses[0] || normalized.Peers[0].Addresses[0] == clone.Peers[0].Addresses[0] || normalized.Peers[0].Routes[0] == clone.Peers[0].Routes[0] {
		t.Fatal("Clone shares slice storage with original")
	}
}
