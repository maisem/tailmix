// Package wireguardfilter compiles and enforces packet filters for raw
// WireGuard profiles.
package wireguardfilter

import (
	"fmt"
	"net/netip"
	"os"
	"slices"
	"sync/atomic"

	"github.com/maisem/tailmix/wireguardcfg"
	"github.com/tailscale/wireguard-go/tun"
	"go4.org/netipx"
	"tailscale.com/net/packet"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/logger"
	"tailscale.com/types/views"
	"tailscale.com/wgengine/filter"
)

// DestinationResolution describes how one normalized destination selector is
// represented by the currently implemented local delivery path.
type DestinationResolution struct {
	GrantIndex int    `json:"grantIndex"`
	Selector   string `json:"selector"`
	State      string `json:"state"`
	Reason     string `json:"reason,omitempty"`
}

const forwardingUnavailable = "forwarding_unavailable"

// DestinationResolutions returns one deterministic status entry per
// destination selector in cfg.
func DestinationResolutions(cfg wireguardcfg.Config) ([]DestinationResolution, error) {
	local, err := selfSet(cfg)
	if err != nil {
		return nil, err
	}
	var result []DestinationResolution
	for grantIndex, grant := range cfg.PacketFilter.Grants {
		for _, value := range grant.Dst {
			selector, err := wireguardcfg.ParseDestinationSelector(value)
			if err != nil {
				return nil, fmt.Errorf("grants[%d]: destination %q: %w", grantIndex, value, err)
			}
			resolution := DestinationResolution{GrantIndex: grantIndex, Selector: value}
			switch selector.Kind {
			case wireguardcfg.SelectorSelf:
				resolution.State = "active"
			case wireguardcfg.SelectorAll:
				resolution.State = "partial"
				resolution.Reason = forwardingUnavailable
			case wireguardcfg.SelectorPrefix:
				state, err := prefixDestinationState(selector.Prefix, local)
				if err != nil {
					return nil, err
				}
				resolution.State = state
				if state != "active" {
					resolution.Reason = forwardingUnavailable
				}
			default:
				resolution.State = "inactive"
				resolution.Reason = forwardingUnavailable
			}
			result = append(result, resolution)
		}
	}
	return result, nil
}

func prefixDestinationState(prefix netip.Prefix, local *netipx.IPSet) (string, error) {
	var matching netipx.IPSetBuilder
	matching.AddPrefix(prefix)
	matching.Intersect(local)
	active, err := matching.IPSet()
	if err != nil {
		return "", err
	}
	if len(active.Prefixes()) == 0 {
		return "inactive", nil
	}
	var unavailable netipx.IPSetBuilder
	unavailable.AddPrefix(prefix)
	unavailable.RemoveSet(local)
	remainder, err := unavailable.IPSet()
	if err != nil {
		return "", err
	}
	if len(remainder.Prefixes()) == 0 {
		return "active", nil
	}
	return "partial", nil
}

// Policy is an immutable compiled packet filter. Policies can share their
// outbound-flow state across ordinary policy replacements.
type Policy struct {
	filter *filter.Filter
}

// Compile compiles cfg into an inbound allow policy. When restrictive is true,
// grants are suppressed while outbound traffic and replies remain permitted.
// If shareStateWith is non-nil, the new policy preserves its flow state.
func Compile(cfg wireguardcfg.Config, exitIP netip.Addr, restrictive bool, shareStateWith *Policy) (*Policy, error) {
	ownership, err := buildOwnership(cfg, exitIP)
	if err != nil {
		return nil, err
	}
	localNets, err := selfSet(cfg)
	if err != nil {
		return nil, err
	}

	var matches []filter.Match
	if !restrictive {
		matches, err = compileMatches(cfg, ownership, localNets)
		if err != nil {
			return nil, err
		}
	}
	var shared *filter.Filter
	if shareStateWith != nil {
		shared = shareStateWith.filter
	}
	return &Policy{filter: filter.New(matches, nil, localNets, nil, shared, logger.Discard)}, nil
}

// Device filters packets read from and written to an underlying TUN. Its
// policy can be replaced atomically without replacing the TUN itself.
type Device struct {
	underlying tun.Device
	policy     atomic.Pointer[Policy]
}

// NewDevice wraps underlying with initial. Neither argument may be nil.
func NewDevice(underlying tun.Device, initial *Policy) (*Device, error) {
	if underlying == nil {
		return nil, fmt.Errorf("filtered TUN requires an underlying device")
	}
	if initial == nil || initial.filter == nil {
		return nil, fmt.Errorf("filtered TUN requires an initial policy")
	}
	d := &Device{underlying: underlying}
	d.policy.Store(initial)
	return d, nil
}

// Install atomically replaces the current policy. A nil policy is rejected so
// the device can never accidentally become allow-all.
func (d *Device) Install(policy *Policy) error {
	if policy == nil || policy.filter == nil {
		return fmt.Errorf("cannot install a nil packet filter")
	}
	d.policy.Store(policy)
	return nil
}

// Policy returns the currently installed policy.
func (d *Device) Policy() *Policy { return d.policy.Load() }

func (d *Device) File() *os.File { return d.underlying.File() }
func (d *Device) Close() error   { return d.underlying.Close() }
func (d *Device) MTU() (int, error) {
	return d.underlying.MTU()
}
func (d *Device) Name() (string, error) { return d.underlying.Name() }
func (d *Device) Events() <-chan tun.Event {
	return d.underlying.Events()
}
func (d *Device) BatchSize() int { return d.underlying.BatchSize() }

func (d *Device) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	for {
		n, err := d.underlying.Read(bufs, sizes, offset)
		accepted := 0
		for i := range n {
			policy := d.policy.Load()
			var parsed packet.Parsed
			parsed.Decode(bufs[i][offset : offset+sizes[i]])
			if response, _ := policy.filter.RunOut(&parsed, 0); response != filter.Accept {
				continue
			}
			if accepted != i {
				sizes[accepted] = copy(bufs[accepted][offset:], bufs[i][offset:offset+sizes[i]])
			}
			accepted++
		}
		if accepted > 0 || err != nil {
			return accepted, err
		}
	}
}

func (d *Device) Write(bufs [][]byte, offset int) (int, error) {
	accepted := 0
	for _, buf := range bufs {
		policy := d.policy.Load()
		var parsed packet.Parsed
		parsed.Decode(buf[offset:])
		if policy.filter.RunIn(&parsed, 0) == filter.Accept {
			bufs[accepted] = buf
			accepted++
		}
	}
	if accepted > 0 {
		if _, err := d.underlying.Write(bufs[:accepted], offset); err != nil {
			return 0, err
		}
	}
	return len(bufs), nil
}

type prefixOwner struct {
	peer  string
	kind  wireguardcfg.SelectorKind
	value netip.Prefix
}

type ownership struct {
	all       *netipx.IPSet
	peers     map[string]*netipx.IPSet
	routes    map[string]*netipx.IPSet
	allPeers  *netipx.IPSet
	allRoutes *netipx.IPSet
}

func buildOwnership(cfg wireguardcfg.Config, exitIP netip.Addr) (ownership, error) {
	var declared []prefixOwner
	selected := ""
	for _, peer := range cfg.Peers {
		for _, addr := range peer.Addresses {
			declared = append(declared, prefixOwner{peer: peer.Name, kind: wireguardcfg.SelectorPeer, value: hostPrefix(addr)})
		}
		for _, route := range peer.Routes {
			if route.Bits() != 0 {
				declared = append(declared, prefixOwner{peer: peer.Name, kind: wireguardcfg.SelectorRoutes, value: route.Masked()})
			}
		}
		if exitIP.IsValid() && peer.ExitNode && slices.Contains(peer.Addresses, exitIP) {
			selected = peer.Name
		}
	}
	if selected != "" {
		families := addressFamilies(cfg)
		if families.v4 {
			declared = append(declared, prefixOwner{peer: selected, kind: wireguardcfg.SelectorInternet, value: netip.MustParsePrefix("0.0.0.0/0")})
		}
		if families.v6 {
			declared = append(declared, prefixOwner{peer: selected, kind: wireguardcfg.SelectorInternet, value: netip.MustParsePrefix("::/0")})
		}
	}

	result := ownership{peers: map[string]*netipx.IPSet{}, routes: map[string]*netipx.IPSet{}}
	var allBuilder, peerBuilder, routeBuilder netipx.IPSetBuilder
	for _, peer := range cfg.Peers {
		var ownedBuilder, directBuilder, routesBuilder netipx.IPSetBuilder
		for _, item := range declared {
			if item.peer != peer.Name {
				continue
			}
			var effective netipx.IPSetBuilder
			effective.AddPrefix(item.value)
			for _, other := range declared {
				if other.peer == peer.Name || other.value.Addr().BitLen() != item.value.Addr().BitLen() || other.value.Bits() <= item.value.Bits() || !item.value.Contains(other.value.Addr()) {
					continue
				}
				effective.RemovePrefix(other.value)
			}
			if item.kind == wireguardcfg.SelectorRoutes {
				// Route selectors describe routed space, not direct peer addresses.
				for _, direct := range declared {
					if direct.kind == wireguardcfg.SelectorPeer {
						effective.RemovePrefix(direct.value)
					}
				}
			}
			set, err := effective.IPSet()
			if err != nil {
				return ownership{}, err
			}
			ownedBuilder.AddSet(set)
			switch item.kind {
			case wireguardcfg.SelectorPeer:
				directBuilder.AddSet(set)
			case wireguardcfg.SelectorRoutes:
				routesBuilder.AddSet(set)
			}
		}
		owned, err := ownedBuilder.IPSet()
		if err != nil {
			return ownership{}, err
		}
		direct, err := directBuilder.IPSet()
		if err != nil {
			return ownership{}, err
		}
		routes, err := routesBuilder.IPSet()
		if err != nil {
			return ownership{}, err
		}
		result.peers[peer.Name] = direct
		result.routes[peer.Name] = routes
		allBuilder.AddSet(owned)
		peerBuilder.AddSet(direct)
		routeBuilder.AddSet(routes)
	}
	var err error
	if result.all, err = allBuilder.IPSet(); err != nil {
		return ownership{}, err
	}
	if result.allPeers, err = peerBuilder.IPSet(); err != nil {
		return ownership{}, err
	}
	if result.allRoutes, err = routeBuilder.IPSet(); err != nil {
		return ownership{}, err
	}
	return result, nil
}

func compileMatches(cfg wireguardcfg.Config, owned ownership, local *netipx.IPSet) ([]filter.Match, error) {
	var matches []filter.Match
	for grantIndex, grant := range cfg.PacketFilter.Grants {
		sources, err := resolveSources(grant.Src, owned)
		if err != nil {
			return nil, fmt.Errorf("grants[%d]: %w", grantIndex, err)
		}
		destinations, err := resolveDestinations(grant.Dst, local)
		if err != nil {
			return nil, fmt.Errorf("grants[%d]: %w", grantIndex, err)
		}
		if len(destinations.Prefixes()) == 0 {
			continue
		}
		for _, permissionText := range grant.IP {
			permission, err := wireguardcfg.ParsePermission(permissionText)
			if err != nil {
				return nil, fmt.Errorf("grants[%d]: ip: %w", grantIndex, err)
			}
			protocols := permissionProtocols(permission)
			ports := filter.PortRange{First: 0, Last: 65535}
			if permission.HasPorts {
				ports = filter.PortRange{First: permission.FirstPort, Last: permission.LastPort}
			}
			match := filter.Match{IPProto: views.SliceOf(protocols), Srcs: sources.Prefixes()}
			for _, prefix := range destinations.Prefixes() {
				match.Dsts = append(match.Dsts, filter.NetPortRange{Net: prefix, Ports: ports})
			}
			matches = append(matches, match)
		}
	}
	return matches, nil
}

func resolveSources(values []string, owned ownership) (*netipx.IPSet, error) {
	var b netipx.IPSetBuilder
	for i, value := range values {
		selector, err := wireguardcfg.ParseSourceSelector(value)
		if err != nil {
			return nil, fmt.Errorf("src[%d]: %w", i, err)
		}
		switch selector.Kind {
		case wireguardcfg.SelectorAll:
			b.AddSet(owned.all)
		case wireguardcfg.SelectorPeerAll:
			b.AddSet(owned.allPeers)
		case wireguardcfg.SelectorPeer:
			b.AddSet(owned.peers[selector.Peer])
		case wireguardcfg.SelectorRoutesAll:
			b.AddSet(owned.allRoutes)
		case wireguardcfg.SelectorRoutes:
			b.AddSet(owned.routes[selector.Peer])
		case wireguardcfg.SelectorPrefix:
			var explicit netipx.IPSetBuilder
			explicit.AddPrefix(selector.Prefix)
			if _, err := explicit.IPSet(); err != nil {
				return nil, err
			}
			explicit.Intersect(owned.all)
			intersection, err := explicit.IPSet()
			if err != nil {
				return nil, err
			}
			b.AddSet(intersection)
		default:
			return nil, fmt.Errorf("src[%d]: unsupported source selector", i)
		}
	}
	return b.IPSet()
}

func resolveDestinations(values []string, local *netipx.IPSet) (*netipx.IPSet, error) {
	var b netipx.IPSetBuilder
	for i, value := range values {
		selector, err := wireguardcfg.ParseDestinationSelector(value)
		if err != nil {
			return nil, fmt.Errorf("dst[%d]: %w", i, err)
		}
		switch selector.Kind {
		case wireguardcfg.SelectorSelf, wireguardcfg.SelectorAll:
			b.AddSet(local)
		case wireguardcfg.SelectorPrefix:
			var explicit netipx.IPSetBuilder
			explicit.AddPrefix(selector.Prefix)
			explicit.Intersect(local)
			set, err := explicit.IPSet()
			if err != nil {
				return nil, err
			}
			b.AddSet(set)
		case wireguardcfg.SelectorPeerAll, wireguardcfg.SelectorPeer, wireguardcfg.SelectorRoutesAll, wireguardcfg.SelectorRoutes, wireguardcfg.SelectorInternet:
			// Valid desired transit policy remains inactive until forwarding is available.
		default:
			return nil, fmt.Errorf("dst[%d]: unsupported destination selector", i)
		}
	}
	return b.IPSet()
}

func permissionProtocols(permission wireguardcfg.Permission) []ipproto.Proto {
	if permission.AnyProtocol {
		protocols := make([]ipproto.Proto, 0, 254)
		for value := 1; value < 255; value++ {
			if value != int(ipproto.TSMP) {
				protocols = append(protocols, ipproto.Proto(value))
			}
		}
		return protocols
	}
	return []ipproto.Proto{ipproto.Proto(permission.Protocol)}
}

func selfSet(cfg wireguardcfg.Config) (*netipx.IPSet, error) {
	var b netipx.IPSetBuilder
	for _, addr := range cfg.Addresses {
		b.AddPrefix(hostPrefix(addr))
	}
	return b.IPSet()
}

func hostPrefix(addr netip.Addr) netip.Prefix {
	return netip.PrefixFrom(addr, addr.BitLen())
}

type families struct{ v4, v6 bool }

func addressFamilies(cfg wireguardcfg.Config) families {
	var result families
	for _, addr := range cfg.Addresses {
		if addr.Is4() {
			result.v4 = true
		} else if addr.Is6() {
			result.v6 = true
		}
	}
	return result
}
