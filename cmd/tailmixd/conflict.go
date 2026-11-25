package main

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
)

// tailscaleULA is the IPv6 range Tailscale assigns to nodes. Tailscale's
// IPv4 addresses come from 100.64.0.0/10, which carriers also use for CGNAT
// uplinks, so IPv4 addresses only count as single-host (/32) addresses.
var (
	tailscaleULA   = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	tailscaleCGNAT = netip.MustParsePrefix("100.64.0.0/10")
)

type interfaceAddrs struct {
	Name  string
	Addrs []netip.Prefix
}

// systemInterfaces lists the host's interfaces and their addresses.
func systemInterfaces() ([]interfaceAddrs, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []interfaceAddrs
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		entry := interfaceAddrs{Name: iface.Name}
		for _, addr := range addrs {
			if prefix, err := netip.ParsePrefix(addr.String()); err == nil {
				entry.Addrs = append(entry.Addrs, prefix)
			}
		}
		out = append(out, entry)
	}
	return out, nil
}

// otherTailscaleInterfaces returns the interfaces, other than tailmix's own
// TUN, that hold a Tailscale node address. Such an interface means another
// Tailscale client (tailscaled or the Tailscale app) is connected and
// competing with tailmix for routes and DNS.
func otherTailscaleInterfaces(own string, ifaces []interfaceAddrs) []string {
	var names []string
	for _, iface := range ifaces {
		if iface.Name == own {
			continue
		}
		if slices.ContainsFunc(iface.Addrs, isTailscaleNodeAddr) {
			names = append(names, iface.Name)
		}
	}
	return names
}

func isTailscaleNodeAddr(prefix netip.Prefix) bool {
	addr := prefix.Addr().Unmap()
	if tailscaleULA.Contains(addr) {
		return true
	}
	return tailscaleCGNAT.Contains(addr) && prefix.Bits() == 32
}

// tailscaleConflictWarnings reports another connected Tailscale client. It
// names only the interface, never its addresses.
func tailscaleConflictWarnings(own string, list func() ([]interfaceAddrs, error)) []string {
	if list == nil {
		return nil
	}
	ifaces, err := list()
	if err != nil {
		return nil
	}
	var warnings []string
	for _, name := range otherTailscaleInterfaces(own, ifaces) {
		warnings = append(warnings, fmt.Sprintf(
			"another Tailscale client is connected on %s; it conflicts with tailmix's routes and DNS. Disconnect it (tailscale down, or quit the Tailscale app).", name))
	}
	return warnings
}
