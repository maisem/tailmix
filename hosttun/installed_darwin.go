//go:build darwin

package hosttun

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"syscall"

	netroute "golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

type darwinInstalledState struct {
	localAddrs     []netip.Prefix
	routes         []Route
	scopedDefaults []darwinScopedDefault
}

func (h *darwinHost) installedState(wantRoutes []Route) (darwinInstalledState, error) {
	if h.readState != nil {
		return h.readState(wantRoutes)
	}
	return darwinInstalledState{
		localAddrs:     slices.Clone(h.localAddrs),
		routes:         slices.Clone(h.routes),
		scopedDefaults: slices.Clone(h.scopedDefaults),
	}, nil
}

func (h *darwinHost) readInstalledState(wantRoutes []Route) (darwinInstalledState, error) {
	iface, err := net.InterfaceByName(h.name)
	if err != nil {
		return darwinInstalledState{}, fmt.Errorf("find Darwin TUN %s: %w", h.name, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return darwinInstalledState{}, fmt.Errorf("list Darwin TUN %s addresses: %w", h.name, err)
	}
	var state darwinInstalledState
	for _, addr := range addrs {
		prefix, err := netip.ParsePrefix(addr.String())
		if err != nil || !prefix.Addr().IsGlobalUnicast() {
			continue
		}
		state.localAddrs = append(state.localAddrs, prefix)
	}

	rib, err := netroute.FetchRIB(syscall.AF_UNSPEC, netroute.RIBTypeRoute, 0)
	if err != nil {
		return darwinInstalledState{}, fmt.Errorf("read Darwin routing table: %w", err)
	}
	messages, err := netroute.ParseRIB(netroute.RIBTypeRoute, rib)
	if err != nil {
		return darwinInstalledState{}, fmt.Errorf("parse Darwin routing table: %w", err)
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return darwinInstalledState{}, fmt.Errorf("list Darwin interfaces: %w", err)
	}
	interfaceNames := make(map[int]string, len(interfaces))
	for _, candidate := range interfaces {
		interfaceNames[candidate.Index] = candidate.Name
	}
	wantByDestination := make(map[netip.Prefix]Route, len(wantRoutes))
	for _, route := range wantRoutes {
		wantByDestination[route.Destination] = route
	}
	for _, message := range messages {
		rm, ok := message.(*netroute.RouteMessage)
		if !ok || rm.Flags&unix.RTF_STATIC == 0 || rm.Flags&unix.RTF_WASCLONED != 0 {
			continue
		}
		destination, ok := darwinRouteDestination(rm)
		if !ok {
			continue
		}
		if rm.Index == iface.Index {
			installed := Route{
				Destination: destination,
				Source:      darwinRouteAddr(rm.Addrs, unix.RTAX_IFA),
			}
			if want, ok := wantByDestination[destination]; ok {
				installed.Exit = want.Exit
				installed.Optional = want.Optional
			}
			state.routes = append(state.routes, installed)
			continue
		}
		if rm.Flags&unix.RTF_IFSCOPE == 0 || rm.Flags&unix.RTF_PROTO2 == 0 || destination.Bits() != 0 {
			continue
		}
		state.scopedDefaults = append(state.scopedDefaults, darwinScopedDefault{
			Destination: destination,
			Interface:   interfaceNames[rm.Index],
			Gateway:     darwinRouteAddr(rm.Addrs, unix.RTAX_GATEWAY),
		})
	}
	return state, nil
}

func darwinRouteDestination(message *netroute.RouteMessage) (netip.Prefix, bool) {
	addr := darwinRouteAddr(message.Addrs, unix.RTAX_DST)
	if !addr.IsValid() {
		return netip.Prefix{}, false
	}
	bits := addr.BitLen()
	if message.Flags&unix.RTF_HOST == 0 {
		mask := darwinRouteAddr(message.Addrs, unix.RTAX_NETMASK)
		if !mask.IsValid() || mask.Is6() != addr.Is6() {
			return netip.Prefix{}, false
		}
		ones, total := net.IPMask(mask.AsSlice()).Size()
		if total != bits || ones < 0 {
			return netip.Prefix{}, false
		}
		bits = ones
	}
	return netip.PrefixFrom(addr, bits).Masked(), true
}

func darwinRouteAddr(addrs []netroute.Addr, index int) netip.Addr {
	if index < 0 || index >= len(addrs) || addrs[index] == nil {
		return netip.Addr{}
	}
	switch addr := addrs[index].(type) {
	case *netroute.Inet4Addr:
		return netip.AddrFrom4(addr.IP)
	case *netroute.Inet6Addr:
		return netip.AddrFrom16(addr.IP)
	default:
		return netip.Addr{}
	}
}

func verifyDarwinScopedDefaults(want, got []darwinScopedDefault) error {
	wantSet := make(map[darwinScopedDefault]bool, len(want))
	for _, route := range want {
		wantSet[route] = true
	}
	gotSet := make(map[darwinScopedDefault]bool, len(got))
	var errs []error
	for _, route := range got {
		gotSet[route] = true
		if !wantSet[route] {
			errs = append(errs, fmt.Errorf("unexpected scoped underlay default %v via %v on %s", route.Destination, route.Gateway, route.Interface))
		}
	}
	for _, route := range want {
		if !gotSet[route] {
			errs = append(errs, fmt.Errorf("missing scoped underlay default %v via %v on %s", route.Destination, route.Gateway, route.Interface))
		}
	}
	return errors.Join(errs...)
}
