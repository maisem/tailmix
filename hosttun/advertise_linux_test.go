//go:build linux

package hosttun

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fakeFirewall models just enough iptables/ip6tables behavior to exercise the
// forwarding reconciler: chains, rules, jumps, and list output.
type fakeFirewall struct {
	chains map[string]bool
	rules  map[string][]string
}

func newFakeFirewall() *fakeFirewall {
	fw := &fakeFirewall{chains: map[string]bool{}, rules: map[string][]string{}}
	// Built-in chains always exist.
	for _, binary := range []string{"iptables", "ip6tables"} {
		for _, table := range []string{"", "nat"} {
			for _, chain := range []string{"FORWARD", "POSTROUTING"} {
				fw.chains[fw.chainKey(binary, table, chain)] = true
			}
		}
	}
	return fw
}

func (f *fakeFirewall) chainKey(binary, table, chain string) string {
	return binary + "\x00" + table + "\x00" + chain
}

func (f *fakeFirewall) run(name string, args ...string) ([]byte, error) {
	table := ""
	rest := args
	if len(rest) >= 2 && rest[0] == "-t" {
		table = rest[1]
		rest = rest[2:]
	}
	if len(rest) < 2 {
		return nil, fmt.Errorf("fake firewall: short command %v", args)
	}
	op, chain := rest[0], rest[1]
	spec := rest[2:]
	key := f.chainKey(name, table, chain)
	switch op {
	case "-S":
		if !f.chains[key] {
			return nil, errors.New("iptables: No chain/target/match by that name")
		}
		var out strings.Builder
		for _, rule := range f.rules[key] {
			out.WriteString("-A " + chain + " " + rule + "\n")
		}
		return []byte(out.String()), nil
	case "-N":
		if f.chains[key] {
			return []byte("iptables: Chain already exists."), errors.New("exit status 1")
		}
		f.chains[key] = true
		return nil, nil
	case "-F":
		if !f.chains[key] {
			return nil, errors.New("iptables: No chain/target/match by that name")
		}
		f.rules[key] = nil
		return nil, nil
	case "-X":
		if !f.chains[key] {
			return nil, errors.New("iptables: No chain/target/match by that name")
		}
		delete(f.chains, key)
		delete(f.rules, key)
		return nil, nil
	case "-C":
		for _, rule := range f.rules[key] {
			if rule == strings.Join(spec, " ") {
				return nil, nil
			}
		}
		return nil, errors.New("exit status 1")
	case "-A", "-I":
		if !f.chains[key] {
			return nil, errors.New("iptables: No chain/target/match by that name")
		}
		line := strings.Join(spec, " ")
		if op == "-I" {
			// Position arguments are insertion metadata, not rule
			// identity: a later -C/-D omits them.
			if fields := strings.Fields(line); len(fields) > 0 && fields[0] == "1" {
				line = strings.Join(fields[1:], " ")
			}
		}
		for _, rule := range f.rules[key] {
			if rule == line {
				return nil, nil
			}
		}
		if op == "-I" {
			f.rules[key] = append([]string{line}, f.rules[key]...)
		} else {
			f.rules[key] = append(f.rules[key], line)
		}
		return nil, nil
	case "-D":
		line := strings.Join(spec, " ")
		for i, rule := range f.rules[key] {
			if rule == line {
				f.rules[key] = append(f.rules[key][:i], f.rules[key][i+1:]...)
				return nil, nil
			}
		}
		return []byte("iptables: Bad rule (does a matching rule exist in that chain?)"), errors.New("exit status 1")
	default:
		return nil, fmt.Errorf("fake firewall: unsupported op %q", op)
	}
}

func (f *fakeFirewall) has(binary, table, chain, substr string) bool {
	for _, rule := range f.rules[f.chainKey(binary, table, chain)] {
		if strings.Contains(rule, substr) {
			return true
		}
	}
	return false
}

func (f *fakeFirewall) count(binary, table, chain string) int {
	return len(f.rules[f.chainKey(binary, table, chain)])
}

func testForwardSysctlRoot(t *testing.T) string {
	t.Helper()
	old := sysctlRoot
	root := t.TempDir()
	sysctlRoot = root
	t.Cleanup(func() { sysctlRoot = old })
	for _, family := range []string{"net/ipv4/ip_forward", "net/ipv6/conf/all/forwarding"} {
		path := filepath.Join(root, filepath.FromSlash(family))
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("0\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func readSysctl(t *testing.T, root, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(raw))
}

func TestNormalizeAdvertisedRoutes(t *testing.T) {
	routes, err := normalizeAdvertised([]AdvertisedRoute{
		{ProfileID: "work", Prefix: netip.MustParsePrefix("192.168.1.5/24")},
		{ProfileID: "work", Prefix: netip.MustParsePrefix("192.168.1.0/24")},
		{ProfileID: "lab", Prefix: netip.MustParsePrefix("0.0.0.0/0")},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []AdvertisedRoute{
		{ProfileID: "lab", Prefix: netip.MustParsePrefix("0.0.0.0/0")},
		{ProfileID: "work", Prefix: netip.MustParsePrefix("192.168.1.0/24")},
	}
	if !slices.Equal(routes, want) {
		t.Fatalf("normalized = %v, want %v", routes, want)
	}
	if _, err := normalizeAdvertised([]AdvertisedRoute{{Prefix: netip.MustParsePrefix("10.0.0.0/8")}}); err == nil {
		t.Fatal("profile-less advertisement was accepted")
	}
	if _, err := normalizeAdvertised([]AdvertisedRoute{{ProfileID: "work"}}); err == nil {
		t.Fatal("invalid prefix advertisement was accepted")
	}
}

func TestDesiredForwardRulesAreScopedToTUN(t *testing.T) {
	rules := desiredForwardRules("tailmix0", []AdvertisedRoute{
		{ProfileID: "work", Prefix: netip.MustParsePrefix("192.168.1.0/24")},
		{ProfileID: "work", Prefix: netip.MustParsePrefix("::/0")},
	})
	if len(rules) != 6 {
		t.Fatalf("rules = %v, want 6 (accept+masq per prefix, established per family)", rules)
	}
	for _, rule := range rules {
		if !slices.Contains(rule.spec, "tailmix0") {
			t.Fatalf("rule %v is not scoped to the tailmix TUN", rule.spec)
		}
		if !slices.Contains(rule.spec, "tailmix:work") && !slices.Contains(rule.spec, "tailmix:established") {
			t.Fatalf("rule %v carries no ownership comment", rule.spec)
		}
	}
	var masqV6 bool
	for _, rule := range rules {
		if rule.table == "nat" && rule.binary == ip6tablesBin {
			masqV6 = true
		}
	}
	if !masqV6 {
		t.Fatal("no IPv6 masquerade rule for the advertised default route")
	}
	if len(desiredForwardRules("tailmix0", nil)) != 0 {
		t.Fatal("empty advertisements produced forwarding rules")
	}
}

func TestForwardingConvergesAndTearsDown(t *testing.T) {
	fw := newFakeFirewall()
	h := testLinuxHost(linuxInstalledState{}, linuxInstalledState{}, linuxInstalledState{})
	h.runCmd = fw.run
	sysctlDir := testForwardSysctlRoot(t)

	advertised := []AdvertisedRoute{
		{ProfileID: "work", Prefix: netip.MustParsePrefix("192.168.1.0/24")},
		{ProfileID: "work", Prefix: netip.MustParsePrefix("0.0.0.0/0")},
	}
	if err := h.Configure(Config{Advertised: advertised}); err != nil {
		t.Fatal(err)
	}
	if !fw.has("iptables", "", "FORWARD", "-j "+tailmixForwardChain) {
		t.Fatal("FORWARD jump to the tailmix chain is missing")
	}
	if !fw.has("iptables", "nat", "POSTROUTING", "-j "+tailmixMasqChain) {
		t.Fatal("POSTROUTING jump to the tailmix chain is missing")
	}
	if !fw.has("iptables", "", tailmixForwardChain, "-d 192.168.1.0/24") {
		t.Fatal("FORWARD accept for the advertised subnet is missing")
	}
	if !fw.has("iptables", "nat", tailmixMasqChain, "-d 192.168.1.0/24") {
		t.Fatal("masquerade for the advertised subnet is missing")
	}
	if !fw.has("iptables", "nat", tailmixMasqChain, "-d 0.0.0.0/0") {
		t.Fatal("masquerade for the advertised exit default is missing")
	}
	if got := readSysctl(t, sysctlDir, "net/ipv4/ip_forward"); got != "1" {
		t.Fatalf("IPv4 forwarding = %q, want 1", got)
	}
	if got := readSysctl(t, sysctlDir, "net/ipv6/conf/all/forwarding"); got != "0" {
		t.Fatalf("IPv6 forwarding = %q, want untouched 0", got)
	}

	// Reconciling to empty removes every owned rule but leaves the host
	// forwarding sysctl enabled. The third state serves Close's cleanup read.
	h2 := testLinuxHost(linuxInstalledState{}, linuxInstalledState{}, linuxInstalledState{})
	h2.runCmd = fw.run
	if err := h2.Configure(Config{}); err != nil {
		t.Fatal(err)
	}
	if fw.count("iptables", "", tailmixForwardChain) != 0 || fw.count("iptables", "nat", tailmixMasqChain) != 0 {
		t.Fatal("owned forwarding rules survived the empty reconcile")
	}
	if got := readSysctl(t, sysctlDir, "net/ipv4/ip_forward"); got != "1" {
		t.Fatalf("IPv4 forwarding = %q, want permanently enabled 1", got)
	}

	if err := h2.Close(); err != nil {
		t.Fatal(err)
	}
	for _, chain := range [][3]string{
		{"iptables", "", "FORWARD"},
		{"iptables", "nat", "POSTROUTING"},
	} {
		if fw.has(chain[0], chain[1], chain[2], "-j TAILMIX-") {
			t.Fatalf("jump to a tailmix chain survived close in %v", chain)
		}
	}
	if fw.chains[fw.chainKey("iptables", "", tailmixForwardChain)] ||
		fw.chains[fw.chainKey("iptables", "nat", tailmixMasqChain)] {
		t.Fatal("tailmix chains survived close")
	}
}

func TestForwardingSkipsWorkWithoutAdvertisements(t *testing.T) {
	fw := newFakeFirewall()
	calls := 0
	h := testLinuxHost(linuxInstalledState{}, linuxInstalledState{})
	h.runCmd = func(name string, args ...string) ([]byte, error) {
		calls++
		return fw.run(name, args...)
	}
	if err := h.Configure(Config{}); err != nil {
		t.Fatal(err)
	}
	if calls != 4 {
		t.Fatalf("firewall calls = %d, want 4 jump probes and nothing else", calls)
	}
	for key := range fw.chains {
		if strings.Contains(key, "TAILMIX-") {
			t.Fatalf("tailmix chain %q created without advertisements", key)
		}
	}
}

func TestForwardingSysctlFailureFailsConfigure(t *testing.T) {
	fw := newFakeFirewall()
	h := testLinuxHost(linuxInstalledState{})
	h.runCmd = fw.run
	old := sysctlRoot
	sysctlRoot = t.TempDir()
	t.Cleanup(func() { sysctlRoot = old })
	err := h.Configure(Config{Advertised: []AdvertisedRoute{
		{ProfileID: "work", Prefix: netip.MustParsePrefix("192.168.1.0/24")},
	}})
	if err == nil || !strings.Contains(err.Error(), "forwarding") {
		t.Fatalf("Configure error = %v, want a forwarding sysctl error", err)
	}
}
