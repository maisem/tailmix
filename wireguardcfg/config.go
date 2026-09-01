// Package wireguardcfg parses and validates tailmix WireGuard profile files.
package wireguardcfg

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v2"
)

const Version = 1

// ReadFile reads a key file. Callers can enforce their own path and access
// policy by supplying this function rather than allowing this package to read
// the filesystem directly.
type ReadFile func(path string) ([]byte, error)

// Manifest is the on-disk representation of a WireGuard profile.
type Manifest struct {
	Version        int                   `yaml:"version"`
	Name           string                `yaml:"name"`
	DNSSuffix      string                `yaml:"dnsSuffix"`
	Addresses      []string              `yaml:"addresses"`
	PrivateKeyFile string                `yaml:"privateKeyFile,omitempty"`
	ListenPort     *uint16               `yaml:"listenPort,omitempty"`
	PacketFilter   *PacketFilterManifest `yaml:"packetFilter"`
	Peers          []PeerManifest        `yaml:"peers"`
}

// PeerManifest is the on-disk representation of a peer.
type PeerManifest struct {
	Name             string   `yaml:"name"`
	PublicKey        string   `yaml:"publicKey"`
	PresharedKeyFile string   `yaml:"presharedKeyFile,omitempty"`
	Endpoint         string   `yaml:"endpoint,omitempty"`
	Keepalive        Duration `yaml:"keepalive,omitempty"`
	Addresses        []string `yaml:"addresses"`
	Routes           []string `yaml:"routes,omitempty"`
	ExitNode         bool     `yaml:"exitNode,omitempty"`
}

// Duration accepts either a Go duration string or an integer number of
// seconds in YAML.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(unmarshal func(any) error) error {
	var value any
	if err := unmarshal(&value); err != nil {
		return err
	}
	switch v := value.(type) {
	case nil:
		*d = 0
		return nil
	case int:
		if v < 0 {
			return errors.New("duration must not be negative")
		}
		*d = Duration(time.Duration(v) * time.Second)
		return nil
	case string:
		parsed, err := time.ParseDuration(v)
		if err != nil {
			return err
		}
		if parsed < 0 {
			return errors.New("duration must not be negative")
		}
		*d = Duration(parsed)
		return nil
	default:
		return fmt.Errorf("duration must be a string or integer seconds, got %T", value)
	}
}

// Config is the validated, normalized form of a Manifest. It deliberately
// contains no private or preshared key material, nor paths to such material.
type Config struct {
	Version      int          `json:"version"`
	Name         string       `json:"name"`
	DNSSuffix    string       `json:"dnsSuffix"`
	Addresses    []netip.Addr `json:"addresses"`
	ListenPort   uint16       `json:"listenPort,omitempty"`
	PacketFilter PacketFilter `json:"packetFilter"`
	Peers        []Peer       `json:"peers"`
}

// Peer is a validated, normalized peer.
type Peer struct {
	Name            string         `json:"name"`
	PublicKey       Key            `json:"publicKey"`
	HasPresharedKey bool           `json:"hasPresharedKey,omitempty"`
	Endpoint        string         `json:"endpoint,omitempty"`
	Keepalive       time.Duration  `json:"keepalive,omitempty"`
	Addresses       []netip.Addr   `json:"addresses"`
	Routes          []netip.Prefix `json:"routes,omitempty"`
	ExitNode        bool           `json:"exitNode,omitempty"`
}

// Clone returns a deep copy suitable for transaction snapshots.
func (c Config) Clone() Config {
	clone := c
	clone.Addresses = append([]netip.Addr(nil), c.Addresses...)
	clone.PacketFilter = c.PacketFilter.Clone()
	clone.Peers = make([]Peer, len(c.Peers))
	for i, peer := range c.Peers {
		clone.Peers[i] = peer
		clone.Peers[i].Addresses = append([]netip.Addr(nil), peer.Addresses...)
		clone.Peers[i].Routes = append([]netip.Prefix(nil), peer.Routes...)
	}
	return clone
}

// NormalizeConfig returns a canonical deep copy of a persisted Config and
// validates it. DNS names are derived and route prefixes are masked.
func NormalizeConfig(c Config) (Config, error) {
	c = c.Clone()
	suffix, err := normalizeDNSSuffix(c.DNSSuffix)
	if err != nil {
		return Config{}, fmt.Errorf("dnsSuffix: %w", err)
	}
	c.DNSSuffix = suffix
	for i := range c.Peers {
		for j := range c.Peers[i].Routes {
			c.Peers[i].Routes[j] = c.Peers[i].Routes[j].Masked()
		}
	}
	packetFilter, err := NormalizePacketFilter(c.PacketFilter, c.Peers)
	if err != nil {
		return Config{}, fmt.Errorf("packetFilter: %w", err)
	}
	c.PacketFilter = packetFilter
	sortConfig(&c)
	if err := Validate(c); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Validate checks a normalized Config loaded from persisted state.
func Validate(c Config) error {
	if c.Version != Version {
		return fmt.Errorf("version: got %d, want %d", c.Version, Version)
	}
	if err := validateDNSLabel(c.Name); err != nil {
		return fmt.Errorf("name: %w", err)
	}
	suffix, err := normalizeDNSSuffix(c.DNSSuffix)
	if err != nil {
		return fmt.Errorf("dnsSuffix: %w", err)
	}
	if suffix != c.DNSSuffix {
		return errors.New("dnsSuffix: is not normalized")
	}
	families := make(map[bool]bool)
	for i, address := range c.Addresses {
		if err := validateAddress(address); err != nil {
			return fmt.Errorf("addresses[%d]: %w", i, err)
		}
		if families[address.Is4()] {
			return fmt.Errorf("addresses[%d]: more than one address for the same family", i)
		}
		families[address.Is4()] = true
	}
	if len(c.Addresses) == 0 {
		return errors.New("addresses: at least one address is required")
	}
	names := make(map[string]bool)
	publicKeys := make(map[Key]bool)
	addresses := make(map[netip.Addr]string)
	for _, address := range c.Addresses {
		addresses[address] = "profile " + c.Name
	}
	routes := make(map[netip.Prefix]string)
	allowedPrefixes := make(map[netip.Prefix]string)
	for i, peer := range c.Peers {
		if err := validateDNSLabel(peer.Name); err != nil {
			return fmt.Errorf("peers[%d].name: %w", i, err)
		}
		if names[peer.Name] {
			return fmt.Errorf("peers[%d].name: duplicate %q", i, peer.Name)
		}
		names[peer.Name] = true
		if publicKeys[peer.PublicKey] {
			return fmt.Errorf("peers[%d].publicKey: duplicate key", i)
		}
		if peer.PublicKey.isZero() {
			return fmt.Errorf("peers[%d].publicKey: must not be all zero", i)
		}
		publicKeys[peer.PublicKey] = true
		if peer.Endpoint != "" {
			if err := validateEndpoint(peer.Endpoint); err != nil {
				return fmt.Errorf("peers[%d].endpoint: %w", i, err)
			}
		}
		if peer.Keepalive < 0 || peer.Keepalive%time.Second != 0 || peer.Keepalive > 65535*time.Second {
			return fmt.Errorf("peers[%d].keepalive: must be a whole number of seconds between 0 and 65535", i)
		}
		for j, address := range peer.Addresses {
			if err := validateAddress(address); err != nil {
				return fmt.Errorf("peers[%d].addresses[%d]: %w", i, j, err)
			}
			if !families[address.Is4()] {
				return fmt.Errorf("peers[%d].addresses[%d]: no profile address for this address family", i, j)
			}
			if owner, ok := addresses[address]; ok {
				return fmt.Errorf("peers[%d].addresses[%d]: %s is also assigned to peer %q", i, j, address, owner)
			}
			prefix := netip.PrefixFrom(address, address.BitLen())
			if owner, ok := allowedPrefixes[prefix]; ok && owner != peer.Name {
				return fmt.Errorf("peers[%d].addresses[%d]: AllowedIP %s is also assigned to peer %q", i, j, prefix, owner)
			}
			addresses[address] = peer.Name
			allowedPrefixes[prefix] = peer.Name
		}
		for j, route := range peer.Routes {
			if !route.IsValid() || route.Bits() == 0 {
				return fmt.Errorf("peers[%d].routes[%d]: invalid or default route", i, j)
			}
			if route != route.Masked() {
				return fmt.Errorf("peers[%d].routes[%d]: is not normalized", i, j)
			}
			if !families[route.Addr().Is4()] {
				return fmt.Errorf("peers[%d].routes[%d]: no profile address for this address family", i, j)
			}
			if owner, ok := routes[route]; ok {
				return fmt.Errorf("peers[%d].routes[%d]: %s is also assigned to peer %q", i, j, route, owner)
			}
			if owner, ok := allowedPrefixes[route]; ok && owner != peer.Name {
				return fmt.Errorf("peers[%d].routes[%d]: AllowedIP %s is also assigned to peer %q", i, j, route, owner)
			}
			routes[route] = peer.Name
			allowedPrefixes[route] = peer.Name
		}
	}
	normalizedFilter, err := NormalizePacketFilter(c.PacketFilter, c.Peers)
	if err != nil {
		return fmt.Errorf("packetFilter: %w", err)
	}
	if !packetFiltersEqual(c.PacketFilter, normalizedFilter) {
		return errors.New("packetFilter: is not normalized")
	}
	return nil
}

// Secrets contains key material loaded while parsing. It must not be
// persisted. A nil PrivateKey requests a managed key.
type Secrets struct {
	PrivateKey         *Key           `json:"privateKey,omitempty"`
	PresharedKeyByPeer map[string]Key `json:"presharedKeyByPeer,omitempty"`
}

// Key is a WireGuard Curve25519 key.
type Key [32]byte

func ParseKey(s string) (Key, error) {
	var key Key
	b, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(s))
	if err != nil {
		return key, fmt.Errorf("decode WireGuard key: %w", err)
	}
	if len(b) != len(key) {
		return key, fmt.Errorf("WireGuard key is %d bytes; want %d", len(b), len(key))
	}
	copy(key[:], b)
	if key.isZero() {
		return Key{}, errors.New("WireGuard key must not be all zero")
	}
	return key, nil
}

func (k Key) isZero() bool { return k == Key{} }

func (k Key) String() string { return base64.StdEncoding.EncodeToString(k[:]) }

func (k Key) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

func (k *Key) UnmarshalText(text []byte) error {
	parsed, err := ParseKey(string(text))
	if err != nil {
		return err
	}
	*k = parsed
	return nil
}

func (k *Key) UnmarshalJSON(data []byte) error {
	var encoded string
	if err := json.Unmarshal(data, &encoded); err != nil {
		return err
	}
	return k.UnmarshalText([]byte(encoded))
}

func (k Key) MarshalJSON() ([]byte, error) { return json.Marshal(k.String()) }

// UAPIHex returns the key in the hexadecimal form used by WireGuard UAPI.
func (k Key) UAPIHex() string { return hex.EncodeToString(k[:]) }

// Public derives the public key corresponding to a private key.
func (k Key) Public() (Key, error) {
	var public Key
	private, err := ecdh.X25519().NewPrivateKey(k[:])
	if err != nil {
		return public, fmt.Errorf("create WireGuard private key: %w", err)
	}
	copy(public[:], private.PublicKey().Bytes())
	return public, nil
}

// GeneratePrivateKey returns a new WireGuard private key.
func GeneratePrivateKey() (Key, error) {
	var key Key
	if _, err := rand.Read(key[:]); err != nil {
		return key, fmt.Errorf("generate WireGuard private key: %w", err)
	}
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64
	return key, nil
}

var dnsLabelRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// Parse strictly decodes a profile, validates it, and resolves any key files.
func Parse(data []byte, readFile ReadFile) (Config, Secrets, error) {
	var manifest Manifest
	if err := yaml.UnmarshalStrict(data, &manifest); err != nil {
		return Config{}, Secrets{}, fmt.Errorf("decode WireGuard profile: %w", err)
	}
	return Normalize(manifest, readFile)
}

// Normalize validates and normalizes an already-decoded manifest.
func Normalize(m Manifest, readFile ReadFile) (Config, Secrets, error) {
	var config Config
	secrets := Secrets{PresharedKeyByPeer: make(map[string]Key)}
	if m.Version != Version {
		return config, secrets, fmt.Errorf("version: got %d, want %d", m.Version, Version)
	}
	if err := validateDNSLabel(m.Name); err != nil {
		return config, secrets, fmt.Errorf("name: %w", err)
	}
	suffix, err := normalizeDNSSuffix(m.DNSSuffix)
	if err != nil {
		return config, secrets, fmt.Errorf("dnsSuffix: %w", err)
	}
	config = Config{Version: m.Version, Name: m.Name, DNSSuffix: suffix, Peers: make([]Peer, 0, len(m.Peers))}
	if m.ListenPort != nil {
		if *m.ListenPort == 0 {
			return Config{}, secrets, errors.New("listenPort: must be between 1 and 65535")
		}
		config.ListenPort = *m.ListenPort
	}
	families := make(map[bool]bool)
	for i, raw := range m.Addresses {
		address, err := netip.ParseAddr(raw)
		if err != nil {
			return Config{}, secrets, fmt.Errorf("addresses[%d]: %w", i, err)
		}
		if err := validateAddress(address); err != nil {
			return Config{}, secrets, fmt.Errorf("addresses[%d]: %w", i, err)
		}
		family := address.Is4()
		if families[family] {
			return Config{}, secrets, fmt.Errorf("addresses[%d]: more than one address for the same family", i)
		}
		families[family] = true
		config.Addresses = append(config.Addresses, address)
	}
	if len(config.Addresses) == 0 {
		return Config{}, secrets, errors.New("addresses: at least one address is required")
	}
	if m.PrivateKeyFile != "" {
		key, err := readKeyFile(readFile, m.PrivateKeyFile)
		if err != nil {
			return Config{}, secrets, fmt.Errorf("privateKeyFile: %w", err)
		}
		secrets.PrivateKey = &key
	}

	names := make(map[string]bool)
	publicKeys := make(map[Key]bool)
	addresses := make(map[netip.Addr]string)
	for _, address := range config.Addresses {
		addresses[address] = "profile " + config.Name
	}
	routes := make(map[netip.Prefix]string)
	for i, rawPeer := range m.Peers {
		peer, psk, err := normalizePeer(rawPeer, families, readFile)
		if err != nil {
			return Config{}, secrets, fmt.Errorf("peers[%d]: %w", i, err)
		}
		if names[peer.Name] {
			return Config{}, secrets, fmt.Errorf("peers[%d].name: duplicate %q", i, peer.Name)
		}
		names[peer.Name] = true
		if publicKeys[peer.PublicKey] {
			return Config{}, secrets, fmt.Errorf("peers[%d].publicKey: duplicate key", i)
		}
		publicKeys[peer.PublicKey] = true
		for _, address := range peer.Addresses {
			if owner, ok := addresses[address]; ok {
				return Config{}, secrets, fmt.Errorf("peers[%d].addresses: %s is also assigned to peer %q", i, address, owner)
			}
			addresses[address] = peer.Name
		}
		for _, route := range peer.Routes {
			if owner, ok := routes[route]; ok {
				return Config{}, secrets, fmt.Errorf("peers[%d].routes: %s is also assigned to peer %q", i, route, owner)
			}
			routes[route] = peer.Name
		}
		if psk != nil {
			secrets.PresharedKeyByPeer[peer.Name] = *psk
		}
		config.Peers = append(config.Peers, peer)
	}
	packetFilter, err := NormalizePacketFilterManifest(m.PacketFilter, config.Peers)
	if err != nil {
		return Config{}, secrets, fmt.Errorf("packetFilter: %w", err)
	}
	config.PacketFilter = packetFilter
	sortConfig(&config)
	if err := Validate(config); err != nil {
		return Config{}, secrets, err
	}
	return config, secrets, nil
}

func normalizePeer(p PeerManifest, families map[bool]bool, readFile ReadFile) (Peer, *Key, error) {
	var peer Peer
	if err := validateDNSLabel(p.Name); err != nil {
		return peer, nil, fmt.Errorf("name: %w", err)
	}
	publicKey, err := ParseKey(p.PublicKey)
	if err != nil {
		return peer, nil, fmt.Errorf("publicKey: %w", err)
	}
	peer = Peer{Name: p.Name, PublicKey: publicKey, HasPresharedKey: p.PresharedKeyFile != "", Endpoint: p.Endpoint, Keepalive: time.Duration(p.Keepalive), ExitNode: p.ExitNode}
	if p.Endpoint != "" {
		if err := validateEndpoint(p.Endpoint); err != nil {
			return Peer{}, nil, fmt.Errorf("endpoint: %w", err)
		}
	}
	if peer.Keepalive < 0 || peer.Keepalive%time.Second != 0 || peer.Keepalive > 65535*time.Second {
		return Peer{}, nil, errors.New("keepalive: must be a whole number of seconds between 0 and 65535")
	}
	seenAddresses := make(map[netip.Addr]bool)
	for i, raw := range p.Addresses {
		address, err := netip.ParseAddr(raw)
		if err != nil {
			return Peer{}, nil, fmt.Errorf("addresses[%d]: expected an IP address without a prefix: %w", i, err)
		}
		if err := validateAddress(address); err != nil {
			return Peer{}, nil, fmt.Errorf("addresses[%d]: %w", i, err)
		}
		if !families[address.Is4()] {
			return Peer{}, nil, fmt.Errorf("addresses[%d]: no profile address for this address family", i)
		}
		if seenAddresses[address] {
			return Peer{}, nil, fmt.Errorf("addresses[%d]: duplicate %s", i, address)
		}
		seenAddresses[address] = true
		peer.Addresses = append(peer.Addresses, address)
	}
	seenRoutes := make(map[netip.Prefix]bool)
	for i, raw := range p.Routes {
		route, err := netip.ParsePrefix(raw)
		if err != nil {
			return Peer{}, nil, fmt.Errorf("routes[%d]: %w", i, err)
		}
		route = route.Masked()
		if route.Bits() == 0 {
			return Peer{}, nil, fmt.Errorf("routes[%d]: default routes are represented by exitNode", i)
		}
		if !families[route.Addr().Is4()] {
			return Peer{}, nil, fmt.Errorf("routes[%d]: no profile address for this address family", i)
		}
		if seenRoutes[route] {
			return Peer{}, nil, fmt.Errorf("routes[%d]: duplicate %s", i, route)
		}
		seenRoutes[route] = true
		peer.Routes = append(peer.Routes, route)
	}
	var psk *Key
	if p.PresharedKeyFile != "" {
		key, err := readKeyFile(readFile, p.PresharedKeyFile)
		if err != nil {
			return Peer{}, nil, fmt.Errorf("presharedKeyFile: %w", err)
		}
		psk = &key
	}
	return peer, psk, nil
}

func validateDNSLabel(label string) error {
	if !dnsLabelRE.MatchString(label) {
		return errors.New("must be a lowercase DNS label")
	}
	return nil
}

func validateAddress(address netip.Addr) error {
	if !address.IsValid() || (!address.Is4() && !address.Is6()) || address.Is4In6() {
		return errors.New("address must be native IPv4 or IPv6")
	}
	if address.IsUnspecified() {
		return errors.New("address must not be unspecified")
	}
	if address.IsMulticast() {
		return errors.New("address must not be multicast")
	}
	return nil
}

func sortConfig(config *Config) {
	slices.SortFunc(config.Addresses, func(a, b netip.Addr) int { return a.Compare(b) })
	slices.SortFunc(config.Peers, func(a, b Peer) int { return strings.Compare(a.Name, b.Name) })
	for i := range config.Peers {
		peer := &config.Peers[i]
		slices.SortFunc(peer.Addresses, func(a, b netip.Addr) int { return a.Compare(b) })
		slices.SortFunc(peer.Routes, func(a, b netip.Prefix) int {
			if order := a.Addr().Compare(b.Addr()); order != 0 {
				return order
			}
			return a.Bits() - b.Bits()
		})
	}
}

func normalizeDNSSuffix(suffix string) (string, error) {
	suffix = strings.TrimSuffix(suffix, ".")
	if suffix == "" || len(suffix) > 253 {
		return "", errors.New("must be a valid DNS suffix")
	}
	for _, label := range strings.Split(suffix, ".") {
		if err := validateDNSLabel(label); err != nil {
			return "", err
		}
	}
	return suffix, nil
}

func validateEndpoint(endpoint string) error {
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil {
		return err
	}
	if host == "" {
		return errors.New("host is required")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return errors.New("port must be between 1 and 65535")
	}
	if address, err := netip.ParseAddr(host); err == nil {
		if !address.Is4() && !address.Is6() {
			return errors.New("host must be an IPv4, IPv6, or DNS name")
		}
		return nil
	}
	if _, err := normalizeDNSSuffix(host); err != nil {
		return errors.New("host must be an IPv4, IPv6, or DNS name")
	}
	return nil
}

func readKeyFile(readFile ReadFile, path string) (Key, error) {
	if readFile == nil {
		return Key{}, errors.New("a key file reader is required")
	}
	b, err := readFile(path)
	if err != nil {
		return Key{}, err
	}
	return ParseKey(string(b))
}
