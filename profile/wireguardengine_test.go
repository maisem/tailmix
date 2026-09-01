package profile

import (
	"context"
	"errors"
	"math/rand"
	"net/netip"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/maisem/tailmix/tunmux"
	"github.com/maisem/tailmix/wireguardcfg"
	"github.com/tailscale/wireguard-go/conn/bindtest"
	"github.com/tailscale/wireguard-go/tun/tuntest"
	"tailscale.com/net/packet"
)

func TestWireGuardEngineAppliesLiveChanges(t *testing.T) {
	privateKey, err := wireguardcfg.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	peerPrivate, err := wireguardcfg.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	peerKey, err := peerPrivate.Public()
	if err != nil {
		t.Fatal(err)
	}

	cfg := testWGConfig(peerKey)
	tun := tuntest.NewChannelTUN()
	binds := bindtest.NewChannelBinds()
	e := NewWireGuardEngine(WireGuardEngineConfig{
		ProfileID: "wg-profile", Alias: "work", Config: cfg,
		Secrets: wireguardcfg.Secrets{PrivateKey: &privateKey}, Tun: tun.TUN(), Bind: binds[0],
	})
	if err := e.Start(t.Context()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { e.Close() })
	dev := e.dev

	status, err := e.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if status.BackendState != "Running" || status.SelfDNSName != "" || len(status.Peers) != 1 || status.Peers[0].DNSName != "server.example.test" {
		t.Fatalf("unexpected initial status: %+v", status)
	}

	cfg.Peers[0].Routes = append(cfg.Peers[0].Routes, netip.MustParsePrefix("10.20.0.0/16"))
	if err := e.Apply(t.Context(), cfg, wireguardcfg.Secrets{}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if e.dev != dev {
		t.Fatal("Apply replaced the WireGuard device")
	}
	uapi, err := e.dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(uapi, "allowed_ip=10.20.0.0/16") {
		t.Fatalf("updated route missing from device state:\n%s", redactWGKeys(uapi))
	}

	if err := e.SetExitNodeIP(t.Context(), cfg.Peers[0].Addresses[0]); err != nil {
		t.Fatalf("SetExitNodeIP: %v", err)
	}
	uapi, err = e.dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(uapi, "allowed_ip=0.0.0.0/0") || !strings.Contains(uapi, "allowed_ip=::/0") {
		t.Fatalf("exit routes missing from device state:\n%s", redactWGKeys(uapi))
	}
	status, err = e.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if status.ExitNodeID != "server" || !status.Peers[0].ExitNode {
		t.Fatalf("exit selection missing from status: %+v", status)
	}

	cfg.Peers = nil
	if err := e.Apply(t.Context(), cfg, wireguardcfg.Secrets{}); err != nil {
		t.Fatalf("remove peer: %v", err)
	}
	uapi, err = e.dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(uapi, "public_key=") {
		t.Fatalf("removed peer remains in device state:\n%s", redactWGKeys(uapi))
	}
}

func TestWireGuardEngineWatchUpdates(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := NewWireGuardEngine(WireGuardEngineConfig{})
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		calls := 0
		done := make(chan error, 1)
		go func() { done <- e.WatchUpdates(ctx, func() { calls++ }) }()
		synctest.Wait()

		e.mu.Lock()
		e.notifyLocked()
		e.mu.Unlock()
		synctest.Wait()
		if calls != 1 {
			t.Fatalf("callback calls = %d, want 1", calls)
		}

		cancel()
		synctest.Wait()
		if err := <-done; err != nil {
			t.Fatalf("WatchUpdates: %v", err)
		}
	})
}

func TestWireGuardConfigDiffRotationAndAddressFamilies(t *testing.T) {
	oldPrivate, err := wireguardcfg.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	oldPublic, err := oldPrivate.Public()
	if err != nil {
		t.Fatal(err)
	}
	newPrivate, err := wireguardcfg.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	newPublic, err := newPrivate.Public()
	if err != nil {
		t.Fatal(err)
	}
	oldCfg := wireguardcfg.Config{
		Addresses: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
		Peers:     []wireguardcfg.Peer{{Name: "peer", PublicKey: oldPublic, Addresses: []netip.Addr{netip.MustParseAddr("100.64.0.2")}, ExitNode: true}},
	}
	newCfg := cloneWGConfig(oldCfg)
	newCfg.Peers[0].PublicKey = newPublic
	ip := netip.MustParseAddr("100.64.0.2")
	uapi := diffWGConfig(oldCfg, wireguardcfg.Secrets{}, ip, newCfg, wireguardcfg.Secrets{}, ip)
	addAt := strings.Index(uapi, "public_key="+newPublic.UAPIHex())
	removeAt := strings.Index(uapi, "public_key="+oldPublic.UAPIHex())
	if addAt < 0 || removeAt < 0 || addAt > removeAt {
		t.Fatalf("key rotation did not add before remove:\n%s", redactWGKeys(uapi))
	}
	if !strings.Contains(uapi, "allowed_ip=0.0.0.0/0") {
		t.Fatal("IPv4 exit default missing")
	}
	if strings.Contains(uapi, "allowed_ip=::/0") {
		t.Fatal("IPv6 exit default configured for IPv4-only profile")
	}
}

func TestWireGuardEngineRejectsIneligibleExitNode(t *testing.T) {
	key, err := wireguardcfg.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	peerPrivate, err := wireguardcfg.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	peerKey, err := peerPrivate.Public()
	if err != nil {
		t.Fatal(err)
	}
	cfg := testWGConfig(peerKey)
	cfg.Peers[0].ExitNode = false
	binds := bindtest.NewChannelBinds()
	e := NewWireGuardEngine(WireGuardEngineConfig{Config: cfg, Secrets: wireguardcfg.Secrets{PrivateKey: &key}, Tun: tuntest.NewChannelTUN().TUN(), Bind: binds[0]})
	if err := e.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	if err := e.SetExitNodeIP(t.Context(), cfg.Peers[0].Addresses[0]); err == nil {
		t.Fatal("SetExitNodeIP succeeded for ineligible peer")
	}
}

func TestWireGuardEngineLivePeerChurn(t *testing.T) {
	privateKey, err := wireguardcfg.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	const peerCount = 8
	peers := make([]wireguardcfg.Peer, peerCount)
	for i := range peers {
		peerPrivate, err := wireguardcfg.GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		public, err := peerPrivate.Public()
		if err != nil {
			t.Fatal(err)
		}
		peers[i] = wireguardcfg.Peer{
			Name:      "peer-" + string(rune('a'+i)),
			PublicKey: public,
			Addresses: []netip.Addr{netip.AddrFrom4([4]byte{100, 64, 0, byte(i + 2)})},
			Routes:    []netip.Prefix{netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i), 0, 0}), 16)},
		}
	}
	cfg := wireguardcfg.Config{
		Version: wireguardcfg.Version, Name: "churn", DNSSuffix: "example.test",
		Addresses: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
	}
	binds := bindtest.NewChannelBinds()
	e := NewWireGuardEngine(WireGuardEngineConfig{Config: cfg, Secrets: wireguardcfg.Secrets{PrivateKey: &privateKey}, Tun: tuntest.NewChannelTUN().TUN(), Bind: binds[0]})
	if err := e.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	dev := e.dev
	rng := rand.New(rand.NewSource(1))
	present := make([]bool, peerCount)
	for step := range 100 {
		i := rng.Intn(peerCount)
		present[i] = !present[i]
		cfg.Peers = cfg.Peers[:0]
		want := map[string]bool{}
		for j, included := range present {
			if included {
				cfg.Peers = append(cfg.Peers, peers[j])
				want[peers[j].PublicKey.UAPIHex()] = true
			}
		}
		if err := e.Apply(t.Context(), cfg, wireguardcfg.Secrets{}); err != nil {
			t.Fatalf("step %d: Apply: %v", step, err)
		}
		if e.dev != dev {
			t.Fatalf("step %d: Apply replaced device", step)
		}
		uapi, err := e.dev.IpcGet()
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		for _, line := range strings.Split(uapi, "\n") {
			if key, ok := strings.CutPrefix(line, "public_key="); ok {
				got[key] = true
			}
		}
		if len(got) != len(want) {
			t.Fatalf("step %d: got %d peers, want %d", step, len(got), len(want))
		}
		for key := range want {
			if !got[key] {
				t.Fatalf("step %d: expected peer missing", step)
			}
		}
	}
}

func TestWireGuardEngineRestrictedStartWaitsForCommit(t *testing.T) {
	e, raw, _ := newFilteredWireGuardEngineWithStart(t, []string{"udp:53"}, false, true)
	inbound := packet.Generate(packet.UDP4Header{
		IP4Header: packet.IP4Header{Src: netip.MustParseAddr("100.100.0.2"), Dst: netip.MustParseAddr("100.100.0.1")},
		SrcPort:   40000, DstPort: 53,
	}, nil)
	assertFilteredWrite(t, e, raw, inbound, false)
	if !e.ApplyDegraded() {
		t.Fatal("restricted start did not retain transition state")
	}
	if err := e.CommitStartPolicy(); err != nil {
		t.Fatal(err)
	}
	if e.ApplyDegraded() {
		t.Fatal("start policy commit did not clear transition state")
	}
	assertFilteredWrite(t, e, raw, inbound, true)
}

func TestWireGuardEngineStagesPolicyUntilCommit(t *testing.T) {
	e, raw, private := newFilteredWireGuardEngine(t, []string{"udp:53"}, false)
	oldAllowed := packet.Generate(packet.UDP4Header{
		IP4Header: packet.IP4Header{Src: netip.MustParseAddr("100.100.0.2"), Dst: netip.MustParseAddr("100.100.0.1")},
		SrcPort:   40000, DstPort: 53,
	}, nil)
	newAllowed := packet.Generate(packet.UDP4Header{
		IP4Header: packet.IP4Header{Src: netip.MustParseAddr("100.100.0.2"), Dst: netip.MustParseAddr("100.100.0.1")},
		SrcPort:   40000, DstPort: 54,
	}, nil)
	assertFilteredWrite(t, e, raw, oldAllowed, true)

	cfg := e.config.Clone()
	cfg.PacketFilter.Grants[0].IP = []string{"udp:54"}
	apply, err := e.PrepareApply(t.Context(), cfg, wireguardcfg.Secrets{PrivateKey: &private})
	if err != nil {
		t.Fatal(err)
	}
	if err := apply.Apply(); err != nil {
		t.Fatal(err)
	}
	assertFilteredWrite(t, e, raw, oldAllowed, false)
	assertFilteredWrite(t, e, raw, newAllowed, false)
	if err := apply.Commit(); err != nil {
		t.Fatal(err)
	}
	assertFilteredWrite(t, e, raw, oldAllowed, false)
	assertFilteredWrite(t, e, raw, newAllowed, true)
}

func TestWireGuardEngineApplyFailureDoesNotIssueInverseUpdate(t *testing.T) {
	e, raw, private := newFilteredWireGuardEngine(t, []string{"udp:53"}, false)
	oldAllowed := packet.Generate(packet.UDP4Header{
		IP4Header: packet.IP4Header{Src: netip.MustParseAddr("100.100.0.2"), Dst: netip.MustParseAddr("100.100.0.1")},
		SrcPort:   40000, DstPort: 53,
	}, nil)
	assertFilteredWrite(t, e, raw, oldAllowed, true)

	cfg := e.config.Clone()
	cfg.ListenPort++
	cfg.PacketFilter.Grants[0].IP = []string{"udp:54"}
	applyErr := errors.New("uapi apply failed")
	calls := 0
	e.mu.Lock()
	setConfig := e.setConfig
	e.setConfig = func(string) error {
		calls++
		return applyErr
	}
	e.mu.Unlock()

	err := e.Apply(t.Context(), cfg, wireguardcfg.Secrets{PrivateKey: &private})
	if !errors.Is(err, applyErr) {
		t.Fatalf("Apply error = %v, want %v", err, applyErr)
	}
	if calls != 1 {
		t.Fatalf("UAPI calls = %d, want one forward apply and no inverse update", calls)
	}
	assertFilteredWrite(t, e, raw, oldAllowed, false)
	degraded := e.ApplyDegraded()
	e.mu.Lock()
	e.setConfig = setConfig
	e.mu.Unlock()
	if !degraded {
		t.Fatal("failed apply did not retain degraded transition state")
	}

	if err := e.Apply(t.Context(), cfg, wireguardcfg.Secrets{PrivateKey: &private}); err != nil {
		t.Fatalf("explicit retry: %v", err)
	}
	if e.ApplyDegraded() {
		t.Fatal("successful retry did not clear degraded transition state")
	}
}

func TestWireGuardEngineShieldsUpPersistenceOrdering(t *testing.T) {
	e, raw, _ := newFilteredWireGuardEngine(t, []string{"udp:53"}, false)
	inbound := packet.Generate(packet.UDP4Header{
		IP4Header: packet.IP4Header{Src: netip.MustParseAddr("100.100.0.2"), Dst: netip.MustParseAddr("100.100.0.1")},
		SrcPort:   40000, DstPort: 53,
	}, nil)
	assertFilteredWrite(t, e, raw, inbound, true)

	enable, err := e.PrepareShieldsUp(true)
	if err != nil {
		t.Fatal(err)
	}
	if err := enable.ApplyBeforeSave(); err != nil {
		t.Fatal(err)
	}
	assertFilteredWrite(t, e, raw, inbound, false)
	if err := enable.Rollback(); err != nil {
		t.Fatal(err)
	}
	assertFilteredWrite(t, e, raw, inbound, true)

	enable, err = e.PrepareShieldsUp(true)
	if err != nil {
		t.Fatal(err)
	}
	if err := enable.ApplyBeforeSave(); err != nil {
		t.Fatal(err)
	}
	if err := enable.Commit(); err != nil {
		t.Fatal(err)
	}
	if status, err := e.Status(t.Context()); err != nil || !status.ShieldsUp {
		t.Fatalf("status after enable = %+v, %v", status, err)
	}
	assertFilteredWrite(t, e, raw, inbound, false)

	disable, err := e.PrepareShieldsUp(false)
	if err != nil {
		t.Fatal(err)
	}
	if err := disable.ApplyBeforeSave(); err != nil {
		t.Fatal(err)
	}
	assertFilteredWrite(t, e, raw, inbound, false)
	if err := disable.Commit(); err != nil {
		t.Fatal(err)
	}
	if status, err := e.Status(t.Context()); err != nil || status.ShieldsUp {
		t.Fatalf("status after disable = %+v, %v", status, err)
	}
	assertFilteredWrite(t, e, raw, inbound, true)
}

func newFilteredWireGuardEngine(t *testing.T, permissions []string, shieldsUp bool) (*WireGuardEngine, *tunmux.ChanTUN, wireguardcfg.Key) {
	return newFilteredWireGuardEngineWithStart(t, permissions, shieldsUp, false)
}

func newFilteredWireGuardEngineWithStart(t *testing.T, permissions []string, shieldsUp, startRestricted bool) (*WireGuardEngine, *tunmux.ChanTUN, wireguardcfg.Key) {
	t.Helper()
	private, err := wireguardcfg.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	peerPrivate, err := wireguardcfg.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	peerKey, err := peerPrivate.Public()
	if err != nil {
		t.Fatal(err)
	}
	cfg := testWGConfig(peerKey)
	cfg.PacketFilter = wireguardcfg.PacketFilter{Grants: []wireguardcfg.Grant{{
		Src: []string{"peer:server"}, Dst: []string{"self"}, IP: permissions,
	}}}
	raw := tunmux.NewChanTUN("filter-test")
	binds := bindtest.NewChannelBinds()
	e := NewWireGuardEngine(WireGuardEngineConfig{
		ProfileID: "wg-profile", Config: cfg, Secrets: wireguardcfg.Secrets{PrivateKey: &private},
		Tun: raw, Bind: binds[0], ShieldsUp: shieldsUp, StartRestricted: startRestricted,
	})
	if err := e.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return e, raw, private
}

func assertFilteredWrite(t *testing.T, e *WireGuardEngine, raw *tunmux.ChanTUN, pkt []byte, want bool) {
	t.Helper()
	if n, err := e.filteredTun.Write([][]byte{pkt}, 0); err != nil || n != 1 {
		t.Fatalf("filtered Write() = (%d, %v)", n, err)
	}
	select {
	case got := <-raw.Inbound:
		if !want {
			t.Fatalf("packet unexpectedly accepted: %v", got)
		}
	default:
		if want {
			t.Fatal("packet unexpectedly dropped")
		}
	}
}

func testWGConfig(peerKey wireguardcfg.Key) wireguardcfg.Config {
	return wireguardcfg.Config{
		Version: wireguardcfg.Version, Name: "laptop", DNSSuffix: "example.test",
		Addresses: []netip.Addr{netip.MustParseAddr("100.100.0.1"), netip.MustParseAddr("fd00::1")},
		Peers: []wireguardcfg.Peer{{
			Name: "server", PublicKey: peerKey,
			Addresses: []netip.Addr{netip.MustParseAddr("100.100.0.2"), netip.MustParseAddr("fd00::2")},
			Routes:    []netip.Prefix{netip.MustParsePrefix("10.10.0.0/16")},
			Keepalive: 25 * time.Second, ExitNode: true,
		}},
	}
}

func redactWGKeys(uapi string) string {
	var result []string
	for _, line := range strings.Split(uapi, "\n") {
		if strings.Contains(line, "key=") {
			continue
		}
		result = append(result, line)
	}
	return strings.Join(result, "\n")
}
