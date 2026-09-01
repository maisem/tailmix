package wireguardcfg

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func manifestWithPacketFilter(filter string) string {
	return strings.Replace(validManifest(), "peers:\n", filter+"peers:\n", 1)
}

func TestPacketFilterEmptyForms(t *testing.T) {
	forms := []string{
		"",
		"packetFilter: null\n",
		"packetFilter: {}\n",
		"packetFilter:\n  grants: null\n",
		"packetFilter:\n  grants: []\n",
	}
	for _, form := range forms {
		t.Run(strings.ReplaceAll(strings.TrimSpace(form), "\n", "/"), func(t *testing.T) {
			config, _, err := Parse([]byte(manifestWithPacketFilter(form)), func(string) ([]byte, error) { return []byte(testKey(2)), nil })
			if err != nil {
				t.Fatal(err)
			}
			if config.PacketFilter.Grants == nil || len(config.PacketFilter.Grants) != 0 {
				t.Fatalf("packet filter = %#v; want non-nil empty grants", config.PacketFilter)
			}
			encoded, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(encoded), `"packetFilter":{"grants":[]}`) {
				t.Fatalf("JSON does not contain canonical empty filter: %s", encoded)
			}
		})
	}
}

func TestPacketFilterNormalizes(t *testing.T) {
	manifest := manifestWithPacketFilter(`packetFilter:
  grants:
    - src: ["peer:alice", "peer:*", "routes:alice", "routes:*", "*", 192.0.2.1, 192.0.2.129/25, "peer:alice"]
      dst: [self, "*", "peer:alice", "routes:alice", internet, 10.0.0.1, 203.0.113.129/24]
      ip: [22, 100-101, tcp:22, udp:22, ip-in-ip:*, 4:*, dccp:*, 33:*, sctp:443, 132:443, 200:*]
`)
	config, _, err := Parse([]byte(manifest), func(string) ([]byte, error) { return []byte(testKey(2)), nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(config.PacketFilter.Grants) != 1 {
		t.Fatalf("grants = %#v", config.PacketFilter.Grants)
	}
	grant := config.PacketFilter.Grants[0]
	wantSrc := []string{"*", "192.0.2.1", "192.0.2.128/25", "peer:*", "peer:alice", "routes:*", "routes:alice"}
	wantDst := []string{"*", "10.0.0.1", "203.0.113.0/24", "internet", "peer:alice", "routes:alice", "self"}
	wantIP := []string{"200:*", "dccp:*", "ipv4:*", "sctp:443", "tcp:100-101", "tcp:22", "udp:100-101", "udp:22"}
	if !slices.Equal(grant.Src, wantSrc) || !slices.Equal(grant.Dst, wantDst) || !slices.Equal(grant.IP, wantIP) {
		t.Fatalf("grant = %#v\nwant src=%v\ndst=%v\nip=%v", grant, wantSrc, wantDst, wantIP)
	}

	clone := config.Clone()
	clone.PacketFilter.Grants[0].Src[0] = "changed"
	if config.PacketFilter.Grants[0].Src[0] == "changed" {
		t.Fatal("Config.Clone shares packet-filter storage")
	}
}

func TestPacketFilterRejectsNullGrantFields(t *testing.T) {
	filters := map[string]string{
		"src": "    - src: null\n      dst: [self]\n      ip: [\"*\"]",
		"dst": "    - src: [\"*\"]\n      dst: null\n      ip: [\"*\"]",
		"ip":  "    - src: [\"*\"]\n      dst: [self]\n      ip: null",
	}
	for field, grant := range filters {
		t.Run(field, func(t *testing.T) {
			filter := "packetFilter:\n  grants:\n" + grant + "\n"
			_, _, err := Parse([]byte(manifestWithPacketFilter(filter)), func(string) ([]byte, error) { return []byte(testKey(2)), nil })
			if err == nil || !strings.Contains(err.Error(), field+": at least one") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestPacketFilterValidation(t *testing.T) {
	tests := []struct {
		name   string
		filter string
		want   string
	}{
		{"missing src", "    - dst: [self]\n      ip: [\"*\"]", "src: at least one"},
		{"missing dst", "    - src: [\"*\"]\n      ip: [\"*\"]", "dst: at least one"},
		{"missing ip", "    - src: [\"*\"]\n      dst: [self]", "ip: at least one"},
		{"source self", "    - src: [self]\n      dst: [self]\n      ip: [\"*\"]", "self is only a destination"},
		{"source internet", "    - src: [internet]\n      dst: [self]\n      ip: [\"*\"]", "internet is only a destination"},
		{"unknown peer", "    - src: [peer:missing]\n      dst: [self]\n      ip: [\"*\"]", `peer "missing" not found`},
		{"source default", "    - src: [0.0.0.0/0]\n      dst: [self]\n      ip: [\"*\"]", "literal /0"},
		{"destination default", "    - src: [\"*\"]\n      dst: [\"::/0\"]\n      ip: [\"*\"]", "literal /0"},
		{"uppercase protocol", "    - src: [\"*\"]\n      dst: [self]\n      ip: [TCP:22]", "lowercase"},
		{"dccp port", "    - src: [\"*\"]\n      dst: [self]\n      ip: [dccp:22]", "does not support port"},
		{"numeric dccp port", "    - src: [\"*\"]\n      dst: [self]\n      ip: [33:22]", "does not support port"},
		{"reserved protocol", "    - src: [\"*\"]\n      dst: [self]\n      ip: [99:*]", "unsupported protocol"},
		{"comma ports", "    - src: [\"*\"]\n      dst: [self]\n      ip: [\"tcp:80,443\"]", "comma-separated"},
		{"descending ports", "    - src: [\"*\"]\n      dst: [self]\n      ip: [443-80]", "ascending range"},
		{"unknown grant field", "    - src: [\"*\"]\n      dst: [self]\n      ip: [\"*\"]\n      action: accept", "field action not found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := "packetFilter:\n  grants:\n" + tt.filter + "\n"
			_, _, err := Parse([]byte(manifestWithPacketFilter(filter)), func(string) ([]byte, error) { return []byte(testKey(2)), nil })
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v; want %q", err, tt.want)
			}
		})
	}
}

func TestRejectsEqualAllowedIPOwners(t *testing.T) {
	manifest := strings.Replace(validManifest(), "peers:\n", `peers:
  - name: bob
    publicKey: `+testKey(4)+`
    addresses: [10.0.0.3]
    routes: [10.0.0.2/32]
`, 1)
	_, _, err := Parse([]byte(manifest), func(string) ([]byte, error) { return []byte(testKey(2)), nil })
	if err == nil || !strings.Contains(err.Error(), "AllowedIP 10.0.0.2/32 is also assigned") {
		t.Fatalf("error = %v", err)
	}
}

func TestParsePermission(t *testing.T) {
	tests := map[string]Permission{
		"*":            {AnyProtocol: true},
		"tcp:22":       {Protocol: 6, HasPorts: true, FirstPort: 22, LastPort: 22},
		"udp:*":        {Protocol: 17},
		"sctp:100-200": {Protocol: 132, HasPorts: true, FirstPort: 100, LastPort: 200},
		"dccp:*":       {Protocol: 33},
		"ipv6-icmp:*":  {Protocol: 58},
		"200:*":        {Protocol: 200},
	}
	for input, want := range tests {
		t.Run(input, func(t *testing.T) {
			got, err := ParsePermission(input)
			if err != nil || got != want {
				t.Fatalf("ParsePermission(%q) = %+v, %v; want %+v", input, got, err, want)
			}
		})
	}
}
