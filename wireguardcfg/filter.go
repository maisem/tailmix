package wireguardcfg

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// PacketFilterManifest is the YAML representation of a raw WireGuard packet
// filter. A nil manifest or grant list is an empty, outbound-only policy.
type PacketFilterManifest struct {
	Grants []GrantManifest `yaml:"grants"`
}

// GrantManifest is the YAML representation of one allow-only packet grant.
type GrantManifest struct {
	Src []string `yaml:"src"`
	Dst []string `yaml:"dst"`
	IP  []string `yaml:"ip"`
}

// PacketFilter is the normalized, persisted form of a raw WireGuard packet
// filter. Grants is always non-nil.
type PacketFilter struct {
	Grants []Grant `json:"grants"`
}

// Grant is one normalized allow-only packet grant.
type Grant struct {
	Src []string `json:"src"`
	Dst []string `json:"dst"`
	IP  []string `json:"ip"`
}

// SelectorKind identifies a normalized source or destination selector.
type SelectorKind uint8

const (
	SelectorAll SelectorKind = iota + 1
	SelectorSelf
	SelectorPeerAll
	SelectorPeer
	SelectorRoutesAll
	SelectorRoutes
	SelectorInternet
	SelectorPrefix
)

// Selector is a parsed normalized source or destination selector.
type Selector struct {
	Kind   SelectorKind
	Peer   string
	Prefix netip.Prefix
}

// Permission is one normalized IP protocol and destination-port permission.
// AnyProtocol is exclusive with Protocol. Ports is meaningful only when
// HasPorts is true.
type Permission struct {
	AnyProtocol bool
	Protocol    uint8
	HasPorts    bool
	FirstPort   uint16
	LastPort    uint16
}

// Clone returns an independent canonical packet filter.
func (f PacketFilter) Clone() PacketFilter {
	clone := PacketFilter{Grants: make([]Grant, len(f.Grants))}
	for i := range f.Grants {
		clone.Grants[i] = f.Grants[i].Clone()
	}
	return clone
}

// Clone returns an independent grant.
func (g Grant) Clone() Grant {
	return Grant{
		Src: slices.Clone(g.Src),
		Dst: slices.Clone(g.Dst),
		IP:  slices.Clone(g.IP),
	}
}

// NormalizePacketFilterManifest validates and canonicalizes a YAML packet
// filter. Nil is an empty, outbound-only policy.
func NormalizePacketFilterManifest(m *PacketFilterManifest, peers []Peer) (PacketFilter, error) {
	if m == nil {
		return PacketFilter{Grants: []Grant{}}, nil
	}
	grants := make([]Grant, len(m.Grants))
	for i := range m.Grants {
		grant, err := normalizeGrant(Grant{Src: m.Grants[i].Src, Dst: m.Grants[i].Dst, IP: m.Grants[i].IP}, peers)
		if err != nil {
			return PacketFilter{}, fmt.Errorf("grants[%d]: %w", i, err)
		}
		grants[i] = grant
	}
	return canonicalPacketFilter(grants), nil
}

// NormalizePacketFilter validates and canonicalizes a persisted packet filter.
func NormalizePacketFilter(f PacketFilter, peers []Peer) (PacketFilter, error) {
	grants := make([]Grant, len(f.Grants))
	for i := range f.Grants {
		grant, err := normalizeGrant(f.Grants[i], peers)
		if err != nil {
			return PacketFilter{}, fmt.Errorf("grants[%d]: %w", i, err)
		}
		grants[i] = grant
	}
	return canonicalPacketFilter(grants), nil
}

func normalizeGrant(g Grant, peers []Peer) (Grant, error) {
	if len(g.Src) == 0 {
		return Grant{}, errors.New("src: at least one selector is required")
	}
	if len(g.Dst) == 0 {
		return Grant{}, errors.New("dst: at least one selector is required")
	}
	if len(g.IP) == 0 {
		return Grant{}, errors.New("ip: at least one permission is required")
	}
	peerByName := make(map[string]Peer, len(peers))
	for _, peer := range peers {
		peerByName[peer.Name] = peer
	}

	src := make([]string, len(g.Src))
	for i, raw := range g.Src {
		selector, err := normalizeSelector(raw, true, peerByName)
		if err != nil {
			return Grant{}, fmt.Errorf("src[%d]: %w", i, err)
		}
		parsed, err := ParseSourceSelector(selector)
		if err != nil {
			return Grant{}, fmt.Errorf("src[%d]: %w", i, err)
		}
		if parsed.Kind == SelectorPrefix && !sourcePrefixHasPossibleOwner(parsed.Prefix, peers) {
			return Grant{}, fmt.Errorf("src[%d]: selector has no configured or exit-eligible owner", i)
		}
		src[i] = selector
	}
	dst := make([]string, len(g.Dst))
	for i, raw := range g.Dst {
		selector, err := normalizeSelector(raw, false, peerByName)
		if err != nil {
			return Grant{}, fmt.Errorf("dst[%d]: %w", i, err)
		}
		dst[i] = selector
	}
	permissions, err := normalizePermissions(g.IP)
	if err != nil {
		return Grant{}, err
	}
	slices.Sort(src)
	src = slices.Compact(src)
	slices.Sort(dst)
	dst = slices.Compact(dst)
	return Grant{Src: src, Dst: dst, IP: permissions}, nil
}

func normalizeSelector(raw string, source bool, peers map[string]Peer) (string, error) {
	if raw == "" {
		return "", errors.New("selector is empty")
	}
	if raw != strings.TrimSpace(raw) {
		return "", errors.New("selector must not contain surrounding whitespace")
	}
	if addr, err := netip.ParseAddr(raw); err == nil {
		if addr.Is4In6() {
			return "", errors.New("selector must use native IPv4 or IPv6")
		}
		return addr.String(), nil
	}
	if prefix, err := netip.ParsePrefix(raw); err == nil {
		if prefix.Addr().Is4In6() {
			return "", errors.New("selector must use native IPv4 or IPv6")
		}
		prefix = prefix.Masked()
		if prefix.Bits() == 0 {
			return "", errors.New("literal /0 selectors are invalid; use * or internet")
		}
		return prefix.String(), nil
	}
	if raw != strings.ToLower(raw) {
		return "", errors.New("selector keywords and peer names must be lowercase")
	}
	switch raw {
	case "*":
		return raw, nil
	case "peer:*":
		return raw, nil
	case "routes:*":
		return raw, nil
	case "self":
		if source {
			return "", errors.New("self is only a destination selector")
		}
		return raw, nil
	case "internet":
		if source {
			return "", errors.New("internet is only a destination selector")
		}
		return raw, nil
	}
	if kind, name, ok := strings.Cut(raw, ":"); ok && (kind == "peer" || kind == "routes") {
		if name == "" || name == "*" {
			return "", errors.New("named selector requires a peer name")
		}
		peer, ok := peers[name]
		if !ok {
			return "", fmt.Errorf("peer %q not found", name)
		}
		if kind == "routes" && len(peer.Routes) == 0 {
			return "", fmt.Errorf("peer %q has no non-default routes", name)
		}
		return kind + ":" + name, nil
	}
	return "", errors.New("expected *, a supported alias, an IP address, or a CIDR")
}

func sourcePrefixHasPossibleOwner(prefix netip.Prefix, peers []Peer) bool {
	for _, peer := range peers {
		for _, addr := range peer.Addresses {
			if prefix.Contains(addr) {
				return true
			}
			if peer.ExitNode && addr.BitLen() == prefix.Addr().BitLen() {
				return true
			}
		}
		for _, route := range peer.Routes {
			if prefixesOverlap(prefix, route) {
				return true
			}
		}
	}
	return false
}

func prefixesOverlap(a, b netip.Prefix) bool {
	return a.Addr().BitLen() == b.Addr().BitLen() && (a.Contains(b.Addr()) || b.Contains(a.Addr()))
}

func normalizePermissions(raw []string) ([]string, error) {
	result := make([]string, 0, len(raw))
	for i, value := range raw {
		permissions, err := normalizePermission(value)
		if err != nil {
			return nil, fmt.Errorf("ip[%d]: %w", i, err)
		}
		result = append(result, permissions...)
	}
	slices.Sort(result)
	return slices.Compact(result), nil
}

func normalizePermission(raw string) ([]string, error) {
	if raw == "" {
		return nil, errors.New("permission is empty")
	}
	if raw != strings.TrimSpace(raw) {
		return nil, errors.New("permission must not contain surrounding whitespace")
	}
	if raw != strings.ToLower(raw) {
		return nil, errors.New("protocol names must be lowercase")
	}
	if raw == "*" {
		return []string{"*"}, nil
	}
	protoRaw, portRaw, hasProto := strings.Cut(raw, ":")
	if !hasProto {
		ports, err := normalizePortRange(raw)
		if err != nil {
			return nil, err
		}
		return []string{"tcp:" + ports, "udp:" + ports}, nil
	}
	if protoRaw == "" || portRaw == "" || strings.Contains(portRaw, ":") {
		return nil, errors.New("permission must be protocol:* or protocol:port[-port]")
	}
	proto, portBearing, err := normalizeProtocol(protoRaw)
	if err != nil {
		return nil, err
	}
	if portRaw == "*" {
		return []string{proto + ":*"}, nil
	}
	if !portBearing {
		return nil, fmt.Errorf("protocol %s does not support port matching", proto)
	}
	ports, err := normalizePortRange(portRaw)
	if err != nil {
		return nil, err
	}
	return []string{proto + ":" + ports}, nil
}

var namedProtocols = map[string]struct {
	number      uint8
	canonical   string
	portBearing bool
}{
	"icmp":      {1, "icmp", false},
	"igmp":      {2, "igmp", false},
	"ipv4":      {4, "ipv4", false},
	"ip-in-ip":  {4, "ipv4", false},
	"tcp":       {6, "tcp", true},
	"egp":       {8, "egp", false},
	"igp":       {9, "igp", false},
	"udp":       {17, "udp", true},
	"dccp":      {33, "dccp", false},
	"gre":       {47, "gre", false},
	"esp":       {50, "esp", false},
	"ah":        {51, "ah", false},
	"ipv6-icmp": {58, "ipv6-icmp", false},
	"sctp":      {132, "sctp", true},
}

var canonicalProtocolByNumber = map[uint8]struct {
	name        string
	portBearing bool
}{
	1:   {"icmp", false},
	2:   {"igmp", false},
	4:   {"ipv4", false},
	6:   {"tcp", true},
	8:   {"egp", false},
	9:   {"igp", false},
	17:  {"udp", true},
	33:  {"dccp", false},
	47:  {"gre", false},
	50:  {"esp", false},
	51:  {"ah", false},
	58:  {"ipv6-icmp", false},
	132: {"sctp", true},
}

func normalizeProtocol(raw string) (name string, portBearing bool, err error) {
	if proto, ok := namedProtocols[raw]; ok {
		return proto.canonical, proto.portBearing, nil
	}
	n, err := strconv.ParseUint(raw, 10, 8)
	if err != nil || n == 0 || n == 99 || n == 255 {
		return "", false, fmt.Errorf("unsupported protocol %q", raw)
	}
	if proto, ok := canonicalProtocolByNumber[uint8(n)]; ok {
		return proto.name, proto.portBearing, nil
	}
	return strconv.FormatUint(n, 10), false, nil
}

func normalizePortRange(raw string) (string, error) {
	if strings.Contains(raw, ",") {
		return "", errors.New("comma-separated ports are not supported")
	}
	firstRaw, lastRaw, ranged := strings.Cut(raw, "-")
	if firstRaw == "" || (ranged && lastRaw == "") || (ranged && strings.Contains(lastRaw, "-")) {
		return "", errors.New("port must be 0-65535 or an ascending range")
	}
	first, err := strconv.ParseUint(firstRaw, 10, 16)
	if err != nil {
		return "", errors.New("port must be 0-65535 or an ascending range")
	}
	last := first
	if ranged {
		last, err = strconv.ParseUint(lastRaw, 10, 16)
		if err != nil || last < first {
			return "", errors.New("port must be 0-65535 or an ascending range")
		}
	}
	if first == last {
		return strconv.FormatUint(first, 10), nil
	}
	return strconv.FormatUint(first, 10) + "-" + strconv.FormatUint(last, 10), nil
}

func canonicalPacketFilter(grants []Grant) PacketFilter {
	sort.Slice(grants, func(i, j int) bool { return grantKey(grants[i]) < grantKey(grants[j]) })
	grants = slices.CompactFunc(grants, func(a, b Grant) bool { return grantKey(a) == grantKey(b) })
	if grants == nil {
		grants = []Grant{}
	}
	return PacketFilter{Grants: grants}
}

func grantKey(g Grant) string {
	return strings.Join(g.Src, "\x00") + "\x01" + strings.Join(g.Dst, "\x00") + "\x01" + strings.Join(g.IP, "\x00")
}

func packetFiltersEqual(a, b PacketFilter) bool {
	if len(a.Grants) != len(b.Grants) {
		return false
	}
	for i := range a.Grants {
		if !slices.Equal(a.Grants[i].Src, b.Grants[i].Src) || !slices.Equal(a.Grants[i].Dst, b.Grants[i].Dst) || !slices.Equal(a.Grants[i].IP, b.Grants[i].IP) {
			return false
		}
	}
	return true
}

// ParseSourceSelector parses a normalized source selector.
func ParseSourceSelector(value string) (Selector, error) {
	return parseSelector(value, true)
}

// ParseDestinationSelector parses a normalized destination selector.
func ParseDestinationSelector(value string) (Selector, error) {
	return parseSelector(value, false)
}

func parseSelector(value string, source bool) (Selector, error) {
	switch value {
	case "*":
		return Selector{Kind: SelectorAll}, nil
	case "self":
		if source {
			return Selector{}, errors.New("self is not a source selector")
		}
		return Selector{Kind: SelectorSelf}, nil
	case "peer:*":
		return Selector{Kind: SelectorPeerAll}, nil
	case "routes:*":
		return Selector{Kind: SelectorRoutesAll}, nil
	case "internet":
		if source {
			return Selector{}, errors.New("internet is not a source selector")
		}
		return Selector{Kind: SelectorInternet}, nil
	}
	if kind, peer, ok := strings.Cut(value, ":"); ok {
		switch kind {
		case "peer":
			return Selector{Kind: SelectorPeer, Peer: peer}, nil
		case "routes":
			return Selector{Kind: SelectorRoutes, Peer: peer}, nil
		}
	}
	if addr, err := netip.ParseAddr(value); err == nil {
		return Selector{Kind: SelectorPrefix, Prefix: netip.PrefixFrom(addr, addr.BitLen())}, nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return Selector{}, err
	}
	return Selector{Kind: SelectorPrefix, Prefix: prefix.Masked()}, nil
}

// ParsePermission parses one normalized permission. Bare port syntax is
// expanded during normalization, so a normalized value yields one permission.
func ParsePermission(value string) (Permission, error) {
	if value == "*" {
		return Permission{AnyProtocol: true}, nil
	}
	protoRaw, portRaw, ok := strings.Cut(value, ":")
	if !ok {
		return Permission{}, errors.New("permission is not normalized")
	}
	protoName, portBearing, err := normalizeProtocol(protoRaw)
	if err != nil || protoName != protoRaw {
		return Permission{}, errors.New("permission is not normalized")
	}
	var proto uint8
	if named, ok := namedProtocols[protoName]; ok {
		proto = named.number
	} else {
		n, parseErr := strconv.ParseUint(protoName, 10, 8)
		if parseErr != nil {
			return Permission{}, errors.New("permission is not normalized")
		}
		proto = uint8(n)
	}
	if portRaw == "*" {
		return Permission{Protocol: proto, HasPorts: false}, nil
	}
	if !portBearing {
		return Permission{}, errors.New("permission is not normalized")
	}
	firstRaw, lastRaw, ranged := strings.Cut(portRaw, "-")
	first, err := strconv.ParseUint(firstRaw, 10, 16)
	if err != nil {
		return Permission{}, err
	}
	last := first
	if ranged {
		last, err = strconv.ParseUint(lastRaw, 10, 16)
		if err != nil {
			return Permission{}, err
		}
	}
	return Permission{Protocol: proto, HasPorts: true, FirstPort: uint16(first), LastPort: uint16(last)}, nil
}
