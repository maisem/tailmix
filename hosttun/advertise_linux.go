//go:build linux

package hosttun

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Subnet-route forwarding for advertised prefixes.
//
// A profile engine that advertises routes receives tailnet packets for those
// destinations and injects them into the shared host TUN. The host kernel
// then forwards them to the LAN and back. That forwarding needs three things
// this file owns:
//
//   - FORWARD rules accepting tailnet-originated packets for advertised
//     prefixes, plus stateful replies toward the TUN.
//   - POSTROUTING MASQUERADE so LAN hosts reply to the router instead of
//     dropping tailnet sources as martians. Rules match only packets
//     arriving from the tailmix TUN, so locally-originated LAN traffic is
//     never NATed.
//   - IPv4/IPv6 forwarding sysctls while the matching family is advertised.
//
// All rules live in dedicated chains (TAILMIX-FWD, TAILMIX-MASQ) jumped to
// from FORWARD and POSTROUTING, mirroring the dedicated exit-route table
// approach. Every rule carries a "tailmix:<profile>" comment (or the
// "tailmix:established" marker) so reconciliation only ever touches rules it
// owns. Sysctls are enabled but never disabled again, matching tailscaled:
// other host software may depend on forwarding once it exists.
const (
	tailmixForwardChain = "TAILMIX-FWD"
	tailmixMasqChain    = "TAILMIX-MASQ"

	advertiseCommentPrefix = "tailmix:"
	establishedComment     = "tailmix:established"

	sysctlForwardV4 = "net/ipv4/ip_forward"
	sysctlForwardV6 = "net/ipv6/conf/all/forwarding"
)

// iptablesBin, ip6tablesBin, and sysctlRoot are variables so tests can point
// them at fakes and scratch directories.
var (
	iptablesBin  = "iptables"
	ip6tablesBin = "ip6tables"
	sysctlRoot   = "/proc/sys"
)

type forwardRule struct {
	binary string
	table  string
	chain  string
	spec   []string
}

func (r forwardRule) key() string {
	return r.binary + " " + r.table + " " + r.chain + " " + strings.Join(r.spec, " ")
}

// desiredForwardRules converts advertised prefixes into the exact owned rule
// set. Every rule is scoped to packets arriving from the tailmix TUN.
func desiredForwardRules(tun string, advertised []AdvertisedRoute) []forwardRule {
	var rules []forwardRule
	var haveV4, haveV6 bool
	for _, route := range advertised {
		binary := iptablesBin
		if route.Prefix.Addr().Is6() {
			binary = ip6tablesBin
			haveV6 = true
		} else {
			haveV4 = true
		}
		comment := advertiseCommentPrefix + route.ProfileID
		prefix := route.Prefix.String()
		rules = append(rules,
			forwardRule{binary: binary, chain: tailmixForwardChain, spec: []string{
				"-i", tun, "-d", prefix,
				"-m", "comment", "--comment", comment,
				"-j", "ACCEPT",
			}},
			forwardRule{binary: binary, table: "nat", chain: tailmixMasqChain, spec: []string{
				"-i", tun, "-d", prefix,
				"-m", "comment", "--comment", comment,
				"-j", "MASQUERADE",
			}},
		)
	}
	// Replies to accepted flows travel toward the TUN. Accepting only
	// established traffic keeps the rule independent of which LAN address a
	// reply comes from, including the default-route (exit-node) case where
	// the source range is the whole internet.
	if haveV4 {
		rules = append(rules, forwardRule{binary: iptablesBin, chain: tailmixForwardChain, spec: []string{
			"-o", tun, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
			"-m", "comment", "--comment", establishedComment,
			"-j", "ACCEPT",
		}})
	}
	if haveV6 {
		rules = append(rules, forwardRule{binary: ip6tablesBin, chain: tailmixForwardChain, spec: []string{
			"-o", tun, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
			"-m", "comment", "--comment", establishedComment,
			"-j", "ACCEPT",
		}})
	}
	slices.SortFunc(rules, func(a, b forwardRule) int { return strings.Compare(a.key(), b.key()) })
	return rules
}

// reconcileForwardingLocked converges firewall rules and forwarding sysctls
// to the desired advertised set. Callers must hold h.mu.
func (h *linuxHost) reconcileForwardingLocked(advertised []AdvertisedRoute) error {
	desired := desiredForwardRules(h.name, advertised)
	jumps, err := h.forwardJumpsPresent()
	if err != nil {
		return err
	}
	if len(desired) == 0 && !jumps {
		return nil
	}
	for _, chain := range []struct{ binary, table, name string }{
		{iptablesBin, "", tailmixForwardChain},
		{ip6tablesBin, "", tailmixForwardChain},
		{iptablesBin, "nat", tailmixMasqChain},
		{ip6tablesBin, "nat", tailmixMasqChain},
	} {
		if err := h.ensureForwardChain(chain.binary, chain.table, chain.name); err != nil {
			return err
		}
	}
	if err := h.ensureForwardJump(iptablesBin, "", "FORWARD", tailmixForwardChain); err != nil {
		return err
	}
	if err := h.ensureForwardJump(ip6tablesBin, "", "FORWARD", tailmixForwardChain); err != nil {
		return err
	}
	if err := h.ensureForwardJump(iptablesBin, "nat", "POSTROUTING", tailmixMasqChain); err != nil {
		return err
	}
	if err := h.ensureForwardJump(ip6tablesBin, "nat", "POSTROUTING", tailmixMasqChain); err != nil {
		return err
	}
	wantByKey := make(map[string]forwardRule, len(desired))
	for _, rule := range desired {
		wantByKey[rule.key()] = rule
	}
	seen := make(map[string]bool, len(desired))
	for _, chain := range []struct{ binary, table, name string }{
		{iptablesBin, "", tailmixForwardChain},
		{ip6tablesBin, "", tailmixForwardChain},
		{iptablesBin, "nat", tailmixMasqChain},
		{ip6tablesBin, "nat", tailmixMasqChain},
	} {
		owned, err := h.listOwnedForwardRules(chain.binary, chain.table, chain.name)
		if err != nil {
			return err
		}
		for _, rule := range owned {
			if _, ok := wantByKey[rule.key()]; ok {
				seen[rule.key()] = true
				continue
			}
			if err := h.deleteForwardRule(rule); err != nil {
				return err
			}
		}
	}
	for _, rule := range desired {
		if seen[rule.key()] {
			continue
		}
		if err := h.ensureForwardRule(rule); err != nil {
			return err
		}
	}
	return h.ensureForwardingSysctls(advertised)
}

// teardownForwardingLocked removes every owned forwarding rule, jump, and
// chain. Missing pieces are ignored so teardown converges after partial
// setup. Forwarding sysctls are intentionally left enabled. Callers must hold
// h.mu.
func (h *linuxHost) teardownForwardingLocked() error {
	var errs []error
	for _, chain := range []struct{ binary, table, name string }{
		{iptablesBin, "", tailmixForwardChain},
		{ip6tablesBin, "", tailmixForwardChain},
		{iptablesBin, "nat", tailmixMasqChain},
		{ip6tablesBin, "nat", tailmixMasqChain},
	} {
		if owned, err := h.listOwnedForwardRules(chain.binary, chain.table, chain.name); err != nil {
			errs = append(errs, err)
		} else {
			for _, rule := range owned {
				if err := h.deleteForwardRule(rule); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}
	for _, jump := range []struct{ binary, table, chain, target string }{
		{iptablesBin, "", "FORWARD", tailmixForwardChain},
		{ip6tablesBin, "", "FORWARD", tailmixForwardChain},
		{iptablesBin, "nat", "POSTROUTING", tailmixMasqChain},
		{ip6tablesBin, "nat", "POSTROUTING", tailmixMasqChain},
	} {
		if err := h.deleteForwardJump(jump.binary, jump.table, jump.chain, jump.target); err != nil {
			errs = append(errs, err)
		}
	}
	for _, chain := range []struct{ binary, table, name string }{
		{iptablesBin, "", tailmixForwardChain},
		{ip6tablesBin, "", tailmixForwardChain},
		{iptablesBin, "nat", tailmixMasqChain},
		{ip6tablesBin, "nat", tailmixMasqChain},
	} {
		if err := h.deleteForwardChain(chain.binary, chain.table, chain.name); err != nil {
			errs = append(errs, err)
		}
	}
	return joinForwardErrs(errs)
}

func joinForwardErrs(errs []error) error {
	var out []error
	for _, err := range errs {
		if err != nil {
			out = append(out, err)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return fmt.Errorf("remove subnet-route forwarding: %w", joinErrs(out))
}

func joinErrs(errs []error) error {
	if len(errs) == 1 {
		return errs[0]
	}
	msg := errs[0].Error()
	for _, err := range errs[1:] {
		msg += "; " + err.Error()
	}
	return errors.New(msg)
}

func (h *linuxHost) forwardJumpsPresent() (bool, error) {
	for _, jump := range []struct{ binary, table, chain, target string }{
		{iptablesBin, "", "FORWARD", tailmixForwardChain},
		{ip6tablesBin, "", "FORWARD", tailmixForwardChain},
		{iptablesBin, "nat", "POSTROUTING", tailmixMasqChain},
		{ip6tablesBin, "nat", "POSTROUTING", tailmixMasqChain},
	} {
		args := forwardArgs(jump.table, "-C", jump.chain, "-j", jump.target)
		if _, err := h.runCmd(jump.binary, args...); err == nil {
			return true, nil
		}
	}
	return false, nil
}

func (h *linuxHost) ensureForwardChain(binary, table, chain string) error {
	if _, err := h.runCmd(binary, forwardArgs(table, "-S", chain)...); err == nil {
		return nil
	} else if !isForwardMissingChain(err) {
		return fmt.Errorf("inspect firewall chain %s: %w", chain, err)
	}
	if out, err := h.runCmd(binary, forwardArgs(table, "-N", chain)...); err != nil {
		if isForwardExists(out) {
			return nil
		}
		return fmt.Errorf("create firewall chain %s: %w", chain, err)
	}
	return nil
}

func (h *linuxHost) ensureForwardJump(binary, table, chain, target string) error {
	if _, err := h.runCmd(binary, forwardArgs(table, "-C", chain, "-j", target)...); err == nil {
		return nil
	}
	if out, err := h.runCmd(binary, forwardArgs(table, "-I", chain, "1", "-j", target)...); err != nil {
		if isForwardExists(out) {
			return nil
		}
		return fmt.Errorf("add firewall jump %s to %s: %w", target, chain, err)
	}
	return nil
}

func (h *linuxHost) ensureForwardRule(rule forwardRule) error {
	if _, err := h.runCmd(rule.binary, forwardArgs(rule.table, append([]string{"-C", rule.chain}, rule.spec...)...)...); err == nil {
		return nil
	}
	args := forwardArgs(rule.table, append([]string{"-A", rule.chain}, rule.spec...)...)
	if out, err := h.runCmd(rule.binary, args...); err != nil {
		if isForwardExists(out) {
			return nil
		}
		return fmt.Errorf("add firewall forwarding rule in %s: %w", rule.chain, err)
	}
	return nil
}

func (h *linuxHost) deleteForwardRule(rule forwardRule) error {
	args := forwardArgs(rule.table, append([]string{"-D", rule.chain}, rule.spec...)...)
	if out, err := h.runCmd(rule.binary, args...); err != nil {
		if isForwardMissingRule(out) {
			return nil
		}
		return fmt.Errorf("remove firewall forwarding rule in %s: %w", rule.chain, err)
	}
	return nil
}

func (h *linuxHost) deleteForwardJump(binary, table, chain, target string) error {
	if out, err := h.runCmd(binary, forwardArgs(table, "-D", chain, "-j", target)...); err != nil {
		if isForwardMissingRule(out) {
			return nil
		}
		return fmt.Errorf("remove firewall jump %s from %s: %w", target, chain, err)
	}
	return nil
}

func (h *linuxHost) deleteForwardChain(binary, table, chain string) error {
	if _, err := h.runCmd(binary, forwardArgs(table, "-F", chain)...); err != nil {
		if !isForwardMissingChain(err) {
			return fmt.Errorf("flush firewall chain %s: %w", chain, err)
		}
		return nil
	}
	if out, err := h.runCmd(binary, forwardArgs(table, "-X", chain)...); err != nil {
		if isForwardMissingChain(err) || isForwardMissingRule(out) {
			return nil
		}
		return fmt.Errorf("delete firewall chain %s: %w", chain, err)
	}
	return nil
}

// listOwnedForwardRules returns the rules in chain that carry a tailmix
// ownership comment. Quoting differences in list output are normalized away
// by stripping double quotes before comparing.
func (h *linuxHost) listOwnedForwardRules(binary, table, chain string) ([]forwardRule, error) {
	out, err := h.runCmd(binary, forwardArgs(table, "-S", chain)...)
	if err != nil {
		if isForwardMissingChain(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list firewall chain %s: %w", chain, err)
	}
	var owned []forwardRule
	prefix := "-A " + chain + " "
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.ReplaceAll(strings.TrimSpace(line), "\"", "")
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		if !strings.Contains(line, "--comment "+advertiseCommentPrefix) {
			continue
		}
		owned = append(owned, forwardRule{
			binary: binary,
			table:  table,
			chain:  chain,
			spec:   strings.Fields(strings.TrimPrefix(line, prefix)),
		})
	}
	return owned, nil
}

func forwardArgs(table string, args ...string) []string {
	if table == "" {
		return args
	}
	return append([]string{"-t", table}, args...)
}

func isForwardMissingChain(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "No chain/target/match by that name")
}

func isForwardMissingRule(out []byte) bool {
	s := string(out)
	return strings.Contains(s, "Bad rule") ||
		strings.Contains(s, "does not exist") ||
		strings.Contains(s, "No chain/target/match by that name")
}

func isForwardExists(out []byte) bool {
	return strings.Contains(string(out), "already exists")
}

// ensureForwardingSysctls enables packet forwarding for each address family
// with advertised prefixes, then verifies the write landed. Families without
// advertisements are left untouched.
func (h *linuxHost) ensureForwardingSysctls(advertised []AdvertisedRoute) error {
	var needV4, needV6 bool
	for _, route := range advertised {
		if route.Prefix.Addr().Is6() {
			needV6 = true
		} else {
			needV4 = true
		}
	}
	if needV4 {
		if err := ensureSysctlForwarding(sysctlForwardV4, len(advertised)); err != nil {
			return err
		}
	}
	if needV6 {
		if err := ensureSysctlForwarding(sysctlForwardV6, len(advertised)); err != nil {
			return err
		}
	}
	return nil
}

func ensureSysctlForwarding(name string, count int) error {
	path := filepath.Join(sysctlRoot, filepath.FromSlash(name))
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read forwarding sysctl %s for %d advertised route(s): %w", name, count, err)
	}
	if strings.TrimSpace(string(raw)) == "1" {
		return nil
	}
	if err := os.WriteFile(path, []byte("1\n"), 0644); err != nil {
		return fmt.Errorf("enable forwarding sysctl %s for %d advertised route(s): %w", name, count, err)
	}
	raw, err = os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("verify forwarding sysctl %s for %d advertised route(s): %w", name, count, err)
	}
	if strings.TrimSpace(string(raw)) != "1" {
		family := "IPv4"
		if strings.Contains(name, "ipv6") {
			family = "IPv6"
		}
		return fmt.Errorf("%s forwarding is disabled; packet forwarding for advertised routes requires it", family)
	}
	return nil
}
