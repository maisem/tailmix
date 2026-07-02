# Multi-Tailnet Implementation Plan

> **For agentic workers:** Create botd tickets from this plan using the `botd-ticketing` skill. Steps use checkbox (`- [ ]`) syntax for tracking and should be copied into the corresponding task ticket body.

**Goal:** Build the first working multi-tailnet daemon slice: multiple independent tsnet-backed profiles, stable effective IPs, explicit DNS/status surfaces, and a shared packet mux that can route node traffic without switching.

**Architecture:** Import Tailscale upstream as the fork base, keep `module tailscale.com` initially to avoid import churn, and add `mnet/...` packages plus `cmd/mnet` and `cmd/mnetd`. Use one tsnet profile engine per tailnet and one daemon-owned packet mux; upstream already has `tsnet.Server.Tun`, so the first implementation characterizes that boundary before adding any fork-only tsnet API.

**Tech Stack:** Go 1.26.4, upstream `tailscale/tailscale` at `fad8b9b8a957c3d4d81d1d9f61c09090dd8d0ba3`, `github.com/tailscale/wireguard-go/tun`, Tailscale `net/packet`, `net/packet/checksum`, `tstest/integration/testcontrol`, and standard-library JSON persistence.

---

## File Structure

- `docs/superpowers/specs/2026-06-30-multi-tailnet-design.md`: approved semantic design.
- `docs/superpowers/plans/2026-06-30-multi-tailnet-implementation.md`: this implementation plan.
- `mnet/effectiveip/effectiveip.go`: pure allocator for stable canonical-to-effective address leases.
- `mnet/effectiveip/effectiveip_test.go`: allocator contract tests.
- `mnet/state/state.go`: persistent daemon state schema.
- `mnet/state/jsonstore.go`: atomic JSON load/save for daemon state.
- `mnet/state/jsonstore_test.go`: restart and corruption contract tests.
- `mnet/packetmap/packetmap.go`: packet decode, effective-address lookup, and checksum-correct address translation.
- `mnet/packetmap/packetmap_test.go`: packet translation tests using Tailscale packet helpers.
- `mnet/profile/profile.go`: profile engine interface and profile status types.
- `mnet/profile/manager.go`: profile lifecycle manager over engine instances.
- `mnet/profile/manager_test.go`: fake-engine profile isolation tests.
- `mnet/profile/tsnetengine.go`: adapter that starts one `tsnet.Server` with one profile state directory and one provided `tun.Device`.
- `mnet/profile/tsnetengine_test.go`: characterization tests around `tsnet.Server.Tun`.
- `mnet/tunmux/chantun.go`: in-memory `tun.Device` used by tests and profile engines.
- `mnet/tunmux/mux.go`: shared TUN multiplexer that maps packets to profile TUNs.
- `mnet/tunmux/mux_test.go`: two-profile routing tests without live control plane.
- `mnet/dns/resolver.go`: explicit-only node-name resolver returning effective IPs.
- `mnet/dns/resolver_test.go`: DNS ambiguity and no-short-name tests.
- `mnet/status/status.go`: structured status model for CLI/API.
- `mnet/status/status_test.go`: status projection tests.
- `cmd/mnetd/main.go`: daemon entrypoint.
- `cmd/mnet/main.go`: CLI entrypoint.
- `cmd/mnet/main_test.go`: CLI output contract tests.

## Dependency Graph

Task 1 has no dependencies. Task 2 depends on Task 1. Task 3 depends on Task 2. Task 4 depends on Task 2. Task 5 depends on Task 1. Task 6 depends on Tasks 3, 4, and 5. Task 7 depends on Tasks 2 and 6. Task 8 depends on Tasks 2, 3, 6, and 7. Task 9 depends on Task 8. Task 10 depends on Tasks 7, 8, and 9.

## Scope Check

The approved spec covers the full product semantics, including live control-plane behavior, OS route installation, DNS integration, per-profile shields-up, and exit-node selection. This plan intentionally implements the first testable foundation only: upstream fork import, stable effective IP state, packet translation, profile engine boundaries, explicit DNS/status models, CLI skeleton, and a local contract test. The final section lists the remaining production slices that should receive separate plans after this foundation lands.

## Task 1: Import Upstream Tailscale Fork Base

**Files:**
- Create/modify: upstream Tailscale tree at repository root.
- Preserve: `docs/superpowers/specs/2026-06-30-multi-tailnet-design.md`
- Preserve: `docs/superpowers/plans/2026-06-30-multi-tailnet-implementation.md`

- [ ] **Step 1: Add upstream remote and fetch the approved base**

Run:

```bash
git remote add upstream https://github.com/tailscale/tailscale.git
git fetch --depth=1 upstream fad8b9b8a957c3d4d81d1d9f61c09090dd8d0ba3
```

Expected: `FETCH_HEAD` points at `fad8b9b8a957c3d4d81d1d9f61c09090dd8d0ba3`.

- [ ] **Step 2: Merge upstream into this repo without losing the spec**

Run:

```bash
git merge --allow-unrelated-histories --no-ff --no-commit FETCH_HEAD
git status --short
```

Expected: many upstream files are staged or modified, and both `docs/superpowers/specs/2026-06-30-multi-tailnet-design.md` and this plan file are still present.

- [ ] **Step 3: Verify baseline Go toolchain and focused upstream tests**

Run:

```bash
go version
go test ./tsnet -run 'TestListenPacket|TestListenTCP|TestDialTCP|TestDialUDP' -count=1
go test ./net/packet/... -count=1
```

Expected:

```text
go version go1.26.4 linux/amd64
ok  	tailscale.com/tsnet
ok  	tailscale.com/net/packet
```

- [ ] **Step 4: Commit upstream import**

Run:

```bash
git add -A
git commit -m "upstream: import tailscale base"
```

Expected: one commit containing the upstream tree plus the existing design and plan docs.

## Task 2: Effective IP Allocator

**Files:**
- Create: `mnet/effectiveip/effectiveip.go`
- Create: `mnet/effectiveip/effectiveip_test.go`

- [ ] **Step 1: Write failing allocator tests**

Create `mnet/effectiveip/effectiveip_test.go`:

```go
package effectiveip

import (
	"net/netip"
	"testing"
)

func TestAllocatorKeepsCanonicalForUniqueAndSynthesizesConflicts(t *testing.T) {
	pool := netip.MustParsePrefix("100.127.0.0/30")
	a := NewAllocator(pool, nil)
	nodes := []Node{
		{ProfileID: "work", NodeID: "node-a", CanonicalIP: netip.MustParseAddr("100.64.0.1")},
		{ProfileID: "home", NodeID: "node-b", CanonicalIP: netip.MustParseAddr("100.64.0.1")},
		{ProfileID: "lab", NodeID: "node-c", CanonicalIP: netip.MustParseAddr("100.64.0.2")},
	}
	plan, err := a.Assign(nodes)
	if err != nil {
		t.Fatal(err)
	}
	gotA := plan.MustEffective(NodeKey{ProfileID: "work", NodeID: "node-a", CanonicalIP: nodes[0].CanonicalIP})
	gotB := plan.MustEffective(NodeKey{ProfileID: "home", NodeID: "node-b", CanonicalIP: nodes[1].CanonicalIP})
	gotC := plan.MustEffective(NodeKey{ProfileID: "lab", NodeID: "node-c", CanonicalIP: nodes[2].CanonicalIP})
	if gotA == gotB {
		t.Fatalf("conflicting canonical IPs received same effective IP: %v", gotA)
	}
	if gotC != nodes[2].CanonicalIP {
		t.Fatalf("unique canonical IP remapped: got %v want %v", gotC, nodes[2].CanonicalIP)
	}
	if !pool.Contains(gotA) && !pool.Contains(gotB) {
		t.Fatalf("neither conflicting node used the synthetic pool: %v %v", gotA, gotB)
	}
}

func TestAllocatorPreservesExistingLeases(t *testing.T) {
	canonical := netip.MustParseAddr("100.64.0.1")
	effective := netip.MustParseAddr("100.127.0.1")
	key := NodeKey{ProfileID: "work", NodeID: "node-a", CanonicalIP: canonical}
	a := NewAllocator(netip.MustParsePrefix("100.127.0.0/30"), []Lease{{NodeKey: key, EffectiveIP: effective}})
	plan, err := a.Assign([]Node{{ProfileID: key.ProfileID, NodeID: key.NodeID, CanonicalIP: canonical}})
	if err != nil {
		t.Fatal(err)
	}
	if got := plan.MustEffective(key); got != effective {
		t.Fatalf("effective IP changed across restart: got %v want %v", got, effective)
	}
}

func TestAllocatorReportsPoolExhaustion(t *testing.T) {
	a := NewAllocator(netip.MustParsePrefix("100.127.0.0/32"), nil)
	_, err := a.Assign([]Node{
		{ProfileID: "a", NodeID: "n1", CanonicalIP: netip.MustParseAddr("100.64.0.1")},
		{ProfileID: "b", NodeID: "n2", CanonicalIP: netip.MustParseAddr("100.64.0.1")},
		{ProfileID: "c", NodeID: "n3", CanonicalIP: netip.MustParseAddr("100.64.0.1")},
	})
	if err == nil {
		t.Fatal("expected pool exhaustion error")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
go test ./mnet/effectiveip -count=1
```

Expected: FAIL because `NewAllocator`, `Node`, `NodeKey`, and `Lease` are undefined.

- [ ] **Step 3: Implement allocator**

Create `mnet/effectiveip/effectiveip.go`:

```go
package effectiveip

import (
	"fmt"
	"net/netip"
	"sort"
)

type Node struct {
	ProfileID   string
	NodeID      string
	CanonicalIP netip.Addr
}

type NodeKey struct {
	ProfileID   string
	NodeID      string
	CanonicalIP netip.Addr
}

type Lease struct {
	NodeKey     NodeKey
	EffectiveIP netip.Addr
}

type Allocator struct {
	pool   netip.Prefix
	leases map[NodeKey]netip.Addr
	used   map[netip.Addr]NodeKey
}

type Plan struct {
	Leases []Lease
	byKey  map[NodeKey]netip.Addr
}

func NewAllocator(pool netip.Prefix, existing []Lease) *Allocator {
	a := &Allocator{
		pool:   pool,
		leases: map[NodeKey]netip.Addr{},
		used:   map[netip.Addr]NodeKey{},
	}
	for _, l := range existing {
		if !l.NodeKey.CanonicalIP.IsValid() || !l.EffectiveIP.IsValid() {
			continue
		}
		a.leases[l.NodeKey] = l.EffectiveIP
		a.used[l.EffectiveIP] = l.NodeKey
	}
	return a
}

func (a *Allocator) Assign(nodes []Node) (*Plan, error) {
	canonicalCount := map[netip.Addr]int{}
	for _, n := range nodes {
		canonicalCount[n.CanonicalIP]++
	}
	out := &Plan{byKey: map[NodeKey]netip.Addr{}}
	for _, n := range nodes {
		key := NodeKey{ProfileID: n.ProfileID, NodeID: n.NodeID, CanonicalIP: n.CanonicalIP}
		if existing, ok := a.leases[key]; ok {
			out.add(key, existing)
			continue
		}
		effective := n.CanonicalIP
		if canonicalCount[n.CanonicalIP] > 1 || a.claimedByOther(key, effective) {
			var err error
			effective, err = a.nextSynthetic(key)
			if err != nil {
				return nil, err
			}
		}
		a.leases[key] = effective
		a.used[effective] = key
		out.add(key, effective)
	}
	sort.Slice(out.Leases, func(i, j int) bool {
		a, b := out.Leases[i], out.Leases[j]
		if a.NodeKey.ProfileID != b.NodeKey.ProfileID {
			return a.NodeKey.ProfileID < b.NodeKey.ProfileID
		}
		return a.NodeKey.NodeID < b.NodeKey.NodeID
	})
	return out, nil
}

func (a *Allocator) claimedByOther(key NodeKey, ip netip.Addr) bool {
	owner, ok := a.used[ip]
	return ok && owner != key
}

func (a *Allocator) nextSynthetic(key NodeKey) (netip.Addr, error) {
	for ip := a.pool.Addr(); a.pool.Contains(ip); ip = ip.Next() {
		if !ip.IsValid() {
			break
		}
		if owner, used := a.used[ip]; !used || owner == key {
			return ip, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("effective IP pool %v exhausted for profile=%q node=%q canonical=%v", a.pool, key.ProfileID, key.NodeID, key.CanonicalIP)
}

func (p *Plan) add(key NodeKey, effective netip.Addr) {
	p.byKey[key] = effective
	p.Leases = append(p.Leases, Lease{NodeKey: key, EffectiveIP: effective})
}

func (p *Plan) MustEffective(key NodeKey) netip.Addr {
	ip, ok := p.byKey[key]
	if !ok {
		panic(fmt.Sprintf("missing effective IP for %+v", key))
	}
	return ip
}
```

- [ ] **Step 4: Run allocator tests**

Run:

```bash
go test ./mnet/effectiveip -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit allocator**

Run:

```bash
git add mnet/effectiveip
git commit -m "mnet/effectiveip: add stable effective IP allocator"
```

Expected: one focused allocator commit.

## Task 3: Persistent Daemon State

**Files:**
- Create: `mnet/state/state.go`
- Create: `mnet/state/jsonstore.go`
- Create: `mnet/state/jsonstore_test.go`

- [ ] **Step 1: Write failing state tests**

Create `mnet/state/jsonstore_test.go`:

```go
package state

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestStoreRoundTripPreservesEffectiveLeases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store := NewJSONStore(path)
	want := State{
		SyntheticPool: "100.127.0.0/24",
		Profiles: []Profile{{ID: "work", Alias: "work", StateDir: "profiles/work"}},
		Leases: []EffectiveLease{{
			ProfileID:   "work",
			NodeID:      "node-a",
			CanonicalIP: netip.MustParseAddr("100.64.0.1"),
			EffectiveIP: netip.MustParseAddr("100.127.0.1"),
		}},
	}
	if err := store.Save(want); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.Leases[0].EffectiveIP != want.Leases[0].EffectiveIP {
		t.Fatalf("effective IP did not round trip: got %v want %v", got.Leases[0].EffectiveIP, want.Leases[0].EffectiveIP)
	}
}

func TestStoreMissingFileReturnsEmptyState(t *testing.T) {
	got, err := NewJSONStore(filepath.Join(t.TempDir(), "missing.json")).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Profiles) != 0 || len(got.Leases) != 0 {
		t.Fatalf("missing file returned non-empty state: %+v", got)
	}
}

func TestStoreCorruptFileFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewJSONStore(path).Load(); err == nil {
		t.Fatal("expected corrupt state to fail")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
go test ./mnet/state -count=1
```

Expected: FAIL because the state package is not implemented.

- [ ] **Step 3: Implement state schema and JSON store**

Create `mnet/state/state.go`:

```go
package state

import "net/netip"

type State struct {
	SyntheticPool string           `json:"syntheticPool"`
	Profiles      []Profile        `json:"profiles"`
	Leases        []EffectiveLease `json:"leases"`
	ExitNode      *ExitNode        `json:"exitNode,omitempty"`
}

type Profile struct {
	ID       string `json:"id"`
	Alias    string `json:"alias"`
	StateDir string `json:"stateDir"`
}

type EffectiveLease struct {
	ProfileID   string     `json:"profileId"`
	NodeID      string     `json:"nodeId"`
	CanonicalIP netip.Addr `json:"canonicalIp"`
	EffectiveIP netip.Addr `json:"effectiveIp"`
}

type ExitNode struct {
	ProfileID string     `json:"profileId"`
	NodeID    string     `json:"nodeId"`
	PeerIP    netip.Addr `json:"peerIp"`
}
```

Create `mnet/state/jsonstore.go`:

```go
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type JSONStore struct {
	path string
}

func NewJSONStore(path string) *JSONStore {
	return &JSONStore{path: path}
}

func (s *JSONStore) Load() (State, error) {
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return State{}, nil
	}
	if err != nil {
		return State{}, err
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return State{}, fmt.Errorf("load mnet state %s: %w", s.path, err)
	}
	return st, nil
}

func (s *JSONStore) Save(st State) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
```

- [ ] **Step 4: Run state tests**

Run:

```bash
go test ./mnet/state -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit state store**

Run:

```bash
git add mnet/state
git commit -m "mnet/state: persist profile and effective IP state"
```

Expected: one focused state commit.

## Task 4: Packet Address Mapping

**Files:**
- Create: `mnet/packetmap/packetmap.go`
- Create: `mnet/packetmap/packetmap_test.go`

- [ ] **Step 1: Write failing packet translation tests**

Create `mnet/packetmap/packetmap_test.go`:

```go
package packetmap

import (
	"net/netip"
	"testing"

	"tailscale.com/net/packet"
)

func udp4(src, dst netip.Addr, sport, dport uint16) []byte {
	return packet.Generate(packet.UDP4Header{
		IP4Header: packet.IP4Header{Src: src, Dst: dst},
		SrcPort:   sport,
		DstPort:   dport,
	}, []byte("hello"))
}

func TestOutboundMapsEffectiveDestinationToCanonicalProfile(t *testing.T) {
	effectiveDst := netip.MustParseAddr("100.127.0.1")
	canonicalDst := netip.MustParseAddr("100.64.0.1")
	effectiveSrc := netip.MustParseAddr("100.127.0.10")
	canonicalSrc := netip.MustParseAddr("100.65.0.10")
	mapper := New(Table{
		Destinations: map[netip.Addr]Destination{
			effectiveDst: {ProfileID: "work", CanonicalIP: canonicalDst},
		},
		Sources: map[string]Source{
			"work": {EffectiveIP: effectiveSrc, CanonicalIP: canonicalSrc},
		},
	})
	translated, route, err := mapper.Outbound(udp4(effectiveSrc, effectiveDst, 1111, 2222))
	if err != nil {
		t.Fatal(err)
	}
	if route.ProfileID != "work" {
		t.Fatalf("route profile = %q, want work", route.ProfileID)
	}
	var p packet.Parsed
	p.Decode(translated)
	if p.Src.Addr() != canonicalSrc || p.Dst.Addr() != canonicalDst {
		t.Fatalf("translated packet = %v > %v, want %v > %v", p.Src.Addr(), p.Dst.Addr(), canonicalSrc, canonicalDst)
	}
}

func TestInboundMapsCanonicalAddressesToEffective(t *testing.T) {
	effectivePeer := netip.MustParseAddr("100.127.0.1")
	canonicalPeer := netip.MustParseAddr("100.64.0.1")
	effectiveSelf := netip.MustParseAddr("100.127.0.10")
	canonicalSelf := netip.MustParseAddr("100.65.0.10")
	mapper := New(Table{
		InboundPeers: map[InboundKey]netip.Addr{{ProfileID: "work", CanonicalIP: canonicalPeer}: effectivePeer},
		Sources:      map[string]Source{"work": {EffectiveIP: effectiveSelf, CanonicalIP: canonicalSelf}},
	})
	translated, err := mapper.Inbound("work", udp4(canonicalPeer, canonicalSelf, 2222, 1111))
	if err != nil {
		t.Fatal(err)
	}
	var p packet.Parsed
	p.Decode(translated)
	if p.Src.Addr() != effectivePeer || p.Dst.Addr() != effectiveSelf {
		t.Fatalf("translated packet = %v > %v, want %v > %v", p.Src.Addr(), p.Dst.Addr(), effectivePeer, effectiveSelf)
	}
}

func TestOutboundUnknownEffectiveDestinationIsRejected(t *testing.T) {
	mapper := New(Table{})
	_, _, err := mapper.Outbound(udp4(netip.MustParseAddr("100.127.0.10"), netip.MustParseAddr("100.127.0.99"), 1, 2))
	if err == nil {
		t.Fatal("expected unknown destination error")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
go test ./mnet/packetmap -count=1
```

Expected: FAIL because the package is not implemented.

- [ ] **Step 3: Implement checksum-correct translation**

Create `mnet/packetmap/packetmap.go`:

```go
package packetmap

import (
	"fmt"
	"net/netip"
	"slices"

	"tailscale.com/net/packet"
	"tailscale.com/net/packet/checksum"
)

type Destination struct {
	ProfileID   string
	CanonicalIP netip.Addr
}

type Source struct {
	EffectiveIP netip.Addr
	CanonicalIP netip.Addr
}

type InboundKey struct {
	ProfileID   string
	CanonicalIP netip.Addr
}

type Table struct {
	Destinations map[netip.Addr]Destination
	Sources      map[string]Source
	InboundPeers map[InboundKey]netip.Addr
}

type Route struct {
	ProfileID   string
	CanonicalIP netip.Addr
}

type Mapper struct {
	table Table
}

func New(table Table) *Mapper {
	return &Mapper{table: table}
}

func (m *Mapper) Outbound(pkt []byte) ([]byte, Route, error) {
	var p packet.Parsed
	out := slices.Clone(pkt)
	p.Decode(out)
	if p.IPVersion == 0 {
		return nil, Route{}, fmt.Errorf("unsupported packet")
	}
	dst, ok := m.table.Destinations[p.Dst.Addr()]
	if !ok {
		return nil, Route{}, fmt.Errorf("no profile route for effective destination %v", p.Dst.Addr())
	}
	src, ok := m.table.Sources[dst.ProfileID]
	if !ok {
		return nil, Route{}, fmt.Errorf("no source mapping for profile %q", dst.ProfileID)
	}
	checksum.UpdateSrcAddr(&p, src.CanonicalIP)
	checksum.UpdateDstAddr(&p, dst.CanonicalIP)
	return out, Route{ProfileID: dst.ProfileID, CanonicalIP: dst.CanonicalIP}, nil
}

func (m *Mapper) Inbound(profileID string, pkt []byte) ([]byte, error) {
	var p packet.Parsed
	out := slices.Clone(pkt)
	p.Decode(out)
	if p.IPVersion == 0 {
		return nil, fmt.Errorf("unsupported packet")
	}
	effectivePeer, ok := m.table.InboundPeers[InboundKey{ProfileID: profileID, CanonicalIP: p.Src.Addr()}]
	if !ok {
		return nil, fmt.Errorf("no inbound peer mapping for profile=%q canonical=%v", profileID, p.Src.Addr())
	}
	src, ok := m.table.Sources[profileID]
	if !ok {
		return nil, fmt.Errorf("no source mapping for profile %q", profileID)
	}
	checksum.UpdateSrcAddr(&p, effectivePeer)
	checksum.UpdateDstAddr(&p, src.EffectiveIP)
	return out, nil
}
```

- [ ] **Step 4: Run packet mapping tests**

Run:

```bash
go test ./mnet/packetmap -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit packet mapper**

Run:

```bash
git add mnet/packetmap
git commit -m "mnet/packetmap: translate effective and canonical packet addresses"
```

Expected: one focused packet mapping commit.

## Task 5: Profile Engine Boundary

**Files:**
- Create: `mnet/tunmux/chantun.go`
- Create: `mnet/profile/profile.go`
- Create: `mnet/profile/manager.go`
- Create: `mnet/profile/manager_test.go`
- Create: `mnet/profile/tsnetengine.go`
- Create: `mnet/profile/tsnetengine_test.go`

- [ ] **Step 1: Create reusable channel TUN**

Create `mnet/tunmux/chantun.go`:

```go
package tunmux

import (
	"errors"
	"io"
	"os"
	"slices"

	"github.com/tailscale/wireguard-go/tun"
)

type ChanTUN struct {
	Inbound  chan []byte
	Outbound chan []byte
	events   chan tun.Event
	closed   chan struct{}
	name     string
	mtu      int
}

func NewChanTUN(name string) *ChanTUN {
	t := &ChanTUN{
		Inbound:  make(chan []byte, 1024),
		Outbound: make(chan []byte, 1024),
		events:   make(chan tun.Event, 1),
		closed:   make(chan struct{}),
		name:     name,
		mtu:      1280,
	}
	t.events <- tun.EventUp
	return t
}

func (t *ChanTUN) File() *os.File { return nil }

func (t *ChanTUN) Close() error {
	select {
	case <-t.closed:
	default:
		close(t.closed)
		close(t.Inbound)
	}
	return nil
}

func (t *ChanTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-t.closed:
		return 0, io.EOF
	case pkt := <-t.Outbound:
		sizes[0] = copy(bufs[0][offset:], pkt)
		return 1, nil
	}
}

func (t *ChanTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		pkt := buf[offset:]
		if len(pkt) == 0 {
			continue
		}
		select {
		case <-t.closed:
			return 0, errors.New("tun closed")
		case t.Inbound <- slices.Clone(pkt):
		}
	}
	return len(bufs), nil
}

func (t *ChanTUN) MTU() (int, error)        { return t.mtu, nil }
func (t *ChanTUN) Name() (string, error)    { return t.name, nil }
func (t *ChanTUN) Events() <-chan tun.Event { return t.events }
func (t *ChanTUN) BatchSize() int           { return 1 }
```

- [ ] **Step 2: Write failing manager tests**

Create `mnet/profile/manager_test.go`:

```go
package profile

import (
	"context"
	"net/netip"
	"testing"
)

type fakeEngine struct {
	id      string
	started bool
	status  Status
}

func (f *fakeEngine) Start(context.Context) error {
	f.started = true
	return nil
}

func (f *fakeEngine) Close() error {
	f.started = false
	return nil
}

func (f *fakeEngine) Status(context.Context) (Status, error) {
	return f.status, nil
}

func TestManagerStartsProfilesIndependently(t *testing.T) {
	work := &fakeEngine{id: "work", status: Status{ProfileID: "work", SelfNodeID: "work-self", SelfIPs: []netip.Addr{netip.MustParseAddr("100.64.0.10")}}}
	home := &fakeEngine{id: "home", status: Status{ProfileID: "home", SelfNodeID: "home-self", SelfIPs: []netip.Addr{netip.MustParseAddr("100.64.0.10")}}}
	m := NewManager()
	m.Add("work", work)
	m.Add("home", home)
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !work.started || !home.started {
		t.Fatalf("profiles not started independently: work=%v home=%v", work.started, home.started)
	}
	st, err := m.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(st) != 2 {
		t.Fatalf("status count = %d, want 2", len(st))
	}
}
```

- [ ] **Step 3: Implement profile interfaces and manager**

Create `mnet/profile/profile.go`:

```go
package profile

import (
	"context"
	"net/netip"
)

type Engine interface {
	Start(context.Context) error
	Close() error
	Status(context.Context) (Status, error)
}

type Status struct {
	ProfileID  string
	Alias      string
	SelfNodeID string
	SelfIPs    []netip.Addr
	PeerCount  int
	ShieldsUp  bool
}
```

Create `mnet/profile/manager.go`:

```go
package profile

import (
	"context"
	"fmt"
	"sort"
)

type Manager struct {
	engines map[string]Engine
}

func NewManager() *Manager {
	return &Manager{engines: map[string]Engine{}}
}

func (m *Manager) Add(profileID string, engine Engine) {
	m.engines[profileID] = engine
}

func (m *Manager) Start(ctx context.Context) error {
	for id, engine := range m.engines {
		if err := engine.Start(ctx); err != nil {
			return fmt.Errorf("start profile %q: %w", id, err)
		}
	}
	return nil
}

func (m *Manager) Close() error {
	var first error
	for id, engine := range m.engines {
		if err := engine.Close(); err != nil && first == nil {
			first = fmt.Errorf("close profile %q: %w", id, err)
		}
	}
	return first
}

func (m *Manager) Status(ctx context.Context) ([]Status, error) {
	var out []Status
	for id, engine := range m.engines {
		st, err := engine.Status(ctx)
		if err != nil {
			return nil, fmt.Errorf("status profile %q: %w", id, err)
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ProfileID < out[j].ProfileID })
	return out, nil
}
```

- [ ] **Step 4: Add tsnet engine adapter**

Create `mnet/profile/tsnetengine.go`:

```go
package profile

import (
	"context"
	"net/netip"

	"github.com/tailscale/wireguard-go/tun"

	"tailscale.com/tsnet"
)

type TSNetConfig struct {
	ProfileID  string
	Alias      string
	Dir        string
	Hostname   string
	AuthKey    string
	ControlURL string
	Tun        tun.Device
}

type TSNetEngine struct {
	cfg    TSNetConfig
	server *tsnet.Server
}

func NewTSNetEngine(cfg TSNetConfig) *TSNetEngine {
	return &TSNetEngine{cfg: cfg}
}

func (e *TSNetEngine) Start(ctx context.Context) error {
	s := &tsnet.Server{
		Dir:        e.cfg.Dir,
		Hostname:   e.cfg.Hostname,
		AuthKey:    e.cfg.AuthKey,
		ControlURL: e.cfg.ControlURL,
		Tun:        e.cfg.Tun,
	}
	if _, err := s.Up(ctx); err != nil {
		return err
	}
	e.server = s
	return nil
}

func (e *TSNetEngine) Close() error {
	if e.server == nil {
		return nil
	}
	return e.server.Close()
}

func (e *TSNetEngine) Status(ctx context.Context) (Status, error) {
	if e.server == nil {
		return Status{ProfileID: e.cfg.ProfileID, Alias: e.cfg.Alias}, nil
	}
	st, err := e.server.Up(ctx)
	if err != nil {
		return Status{}, err
	}
	var ips []netip.Addr
	for _, ip := range st.TailscaleIPs {
		ips = append(ips, ip)
	}
	return Status{
		ProfileID: e.cfg.ProfileID,
		Alias:     e.cfg.Alias,
		SelfIPs:   ips,
		PeerCount: len(st.Peer),
	}, nil
}
```

- [ ] **Step 5: Add tsnet TUN characterization test**

Create `mnet/profile/tsnetengine_test.go`:

```go
package profile

import (
	"testing"

	"tailscale.com/mnet/tunmux"
)

func TestTSNetEngineAcceptsProvidedTunBeforeStart(t *testing.T) {
	tun := tunmux.NewChanTUN("profile-work")
	engine := NewTSNetEngine(TSNetConfig{
		ProfileID: "work",
		Alias:     "work",
		Dir:       t.TempDir(),
		Hostname:  "mnet-work",
		Tun:       tun,
	})
	if engine == nil {
		t.Fatal("engine is nil")
	}
}
```

- [ ] **Step 6: Run profile tests**

Run:

```bash
go test ./mnet/tunmux ./mnet/profile -count=1
```

Expected: PASS.

- [ ] **Step 7: Commit profile boundary**

Run:

```bash
git add mnet/tunmux/chantun.go mnet/profile
git commit -m "mnet/profile: add tsnet-backed profile engine boundary"
```

Expected: one focused profile-boundary commit.

## Task 6: Shared TUN Multiplexer

**Files:**
- Create: `mnet/tunmux/mux.go`
- Create: `mnet/tunmux/mux_test.go`

- [ ] **Step 1: Write failing mux tests**

Create `mnet/tunmux/mux_test.go`:

```go
package tunmux

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/mnet/packetmap"
	"tailscale.com/net/packet"
)

func testUDP(src, dst netip.Addr) []byte {
	return packet.Generate(packet.UDP4Header{
		IP4Header: packet.IP4Header{Src: src, Dst: dst},
		SrcPort:   1000,
		DstPort:   2000,
	}, []byte("mux"))
}

func TestMuxRoutesOutboundPacketToSelectedProfileTun(t *testing.T) {
	host := NewChanTUN("host")
	work := NewChanTUN("work")
	effectiveSelf := netip.MustParseAddr("100.127.0.10")
	effectivePeer := netip.MustParseAddr("100.127.0.1")
	canonicalSelf := netip.MustParseAddr("100.65.0.10")
	canonicalPeer := netip.MustParseAddr("100.64.0.1")
	mux := NewMux(host, map[string]*ChanTUN{"work": work}, packetmap.New(packetmap.Table{
		Destinations: map[netip.Addr]packetmap.Destination{
			effectivePeer: {ProfileID: "work", CanonicalIP: canonicalPeer},
		},
		Sources: map[string]packetmap.Source{
			"work": {EffectiveIP: effectiveSelf, CanonicalIP: canonicalSelf},
		},
	}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go mux.Run(ctx)
	host.Outbound <- testUDP(effectiveSelf, effectivePeer)
	select {
	case got := <-work.Outbound:
		var p packet.Parsed
		p.Decode(got)
		if p.Dst.Addr() != canonicalPeer {
			t.Fatalf("profile packet destination = %v, want %v", p.Dst.Addr(), canonicalPeer)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for routed packet")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
go test ./mnet/tunmux -run TestMuxRoutesOutboundPacketToSelectedProfileTun -count=1
```

Expected: FAIL because `NewMux` and `Mux.Run` are undefined.

- [ ] **Step 3: Implement mux**

Create `mnet/tunmux/mux.go`:

```go
package tunmux

import (
	"context"
	"log"

	"tailscale.com/mnet/packetmap"
)

type Mux struct {
	host     *ChanTUN
	profiles map[string]*ChanTUN
	mapper   *packetmap.Mapper
}

func NewMux(host *ChanTUN, profiles map[string]*ChanTUN, mapper *packetmap.Mapper) *Mux {
	return &Mux{host: host, profiles: profiles, mapper: mapper}
}

func (m *Mux) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case pkt := <-m.host.Outbound:
			translated, route, err := m.mapper.Outbound(pkt)
			if err != nil {
				log.Printf("mnet mux outbound: %v", err)
				continue
			}
			profileTun := m.profiles[route.ProfileID]
			if profileTun == nil {
				log.Printf("mnet mux outbound: missing profile tun %q", route.ProfileID)
				continue
			}
			profileTun.Outbound <- translated
		}
	}
}
```

- [ ] **Step 4: Run mux tests**

Run:

```bash
go test ./mnet/tunmux -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit mux**

Run:

```bash
git add mnet/tunmux
git commit -m "mnet/tunmux: route effective IP packets to profile TUNs"
```

Expected: one focused mux commit.

## Task 7: Explicit DNS Resolver

**Files:**
- Create: `mnet/dns/resolver.go`
- Create: `mnet/dns/resolver_test.go`

- [ ] **Step 1: Write failing DNS tests**

Create `mnet/dns/resolver_test.go`:

```go
package dns

import (
	"net/netip"
	"testing"
)

func TestResolverRejectsUnqualifiedNames(t *testing.T) {
	r := NewResolver([]Record{{ProfileAlias: "work", Name: "db.work.ts.net", EffectiveIP: netip.MustParseAddr("100.127.0.1")}})
	if _, err := r.Resolve("db"); err == nil {
		t.Fatal("expected unqualified name to fail")
	}
}

func TestResolverReturnsEffectiveIPForQualifiedName(t *testing.T) {
	want := netip.MustParseAddr("100.127.0.1")
	r := NewResolver([]Record{{ProfileAlias: "work", Name: "db.work.ts.net", EffectiveIP: want}})
	got, err := r.Resolve("db.work.ts.net")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("Resolve returned %v, want %v", got, want)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
go test ./mnet/dns -count=1
```

Expected: FAIL because resolver types are undefined.

- [ ] **Step 3: Implement explicit resolver**

Create `mnet/dns/resolver.go`:

```go
package dns

import (
	"fmt"
	"net/netip"
	"strings"
)

type Record struct {
	ProfileAlias string
	Name         string
	EffectiveIP  netip.Addr
}

type Resolver struct {
	records map[string]netip.Addr
}

func NewResolver(records []Record) *Resolver {
	r := &Resolver{records: map[string]netip.Addr{}}
	for _, rec := range records {
		r.records[strings.TrimSuffix(strings.ToLower(rec.Name), ".")] = rec.EffectiveIP
	}
	return r
}

func (r *Resolver) Resolve(name string) (netip.Addr, error) {
	key := strings.TrimSuffix(strings.ToLower(name), ".")
	if !strings.Contains(key, ".") {
		return netip.Addr{}, fmt.Errorf("unqualified MagicDNS names are disabled in multi-tailnet mode: %q", name)
	}
	ip, ok := r.records[key]
	if !ok {
		return netip.Addr{}, fmt.Errorf("no explicit mnet DNS record for %q", name)
	}
	return ip, nil
}
```

- [ ] **Step 4: Run DNS tests**

Run:

```bash
go test ./mnet/dns -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit DNS resolver**

Run:

```bash
git add mnet/dns
git commit -m "mnet/dns: require explicit multi-tailnet names"
```

Expected: one focused DNS commit.

## Task 8: Status Projection

**Files:**
- Create: `mnet/status/status.go`
- Create: `mnet/status/status_test.go`

- [ ] **Step 1: Write failing status tests**

Create `mnet/status/status_test.go`:

```go
package status

import (
	"net/netip"
	"testing"

	"tailscale.com/mnet/effectiveip"
	"tailscale.com/mnet/profile"
)

func TestProjectShowsCanonicalAndEffectiveIPs(t *testing.T) {
	st := Project([]profile.Status{{ProfileID: "work", Alias: "work", SelfNodeID: "self", SelfIPs: []netip.Addr{netip.MustParseAddr("100.64.0.10")}}}, []effectiveip.Lease{{
		NodeKey:     effectiveip.NodeKey{ProfileID: "work", NodeID: "self", CanonicalIP: netip.MustParseAddr("100.64.0.10")},
		EffectiveIP: netip.MustParseAddr("100.127.0.10"),
	}})
	if len(st.Profiles) != 1 {
		t.Fatalf("profile count = %d, want 1", len(st.Profiles))
	}
	got := st.Profiles[0].SelfIPs[0]
	if got.Canonical != "100.64.0.10" || got.Effective != "100.127.0.10" {
		t.Fatalf("self IP projection = %+v", got)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
go test ./mnet/status -count=1
```

Expected: FAIL because status projection is undefined.

- [ ] **Step 3: Implement status model**

Create `mnet/status/status.go`:

```go
package status

import (
	"net/netip"

	"tailscale.com/mnet/effectiveip"
	"tailscale.com/mnet/profile"
)

type Status struct {
	Profiles []Profile `json:"profiles"`
}

type Profile struct {
	ID       string   `json:"id"`
	Alias    string   `json:"alias"`
	SelfNode string   `json:"selfNode"`
	SelfIPs  []IPPair `json:"selfIps"`
	PeerCount int     `json:"peerCount"`
	ShieldsUp bool    `json:"shieldsUp"`
}

type IPPair struct {
	Canonical string `json:"canonical"`
	Effective string `json:"effective"`
}

func Project(profiles []profile.Status, leases []effectiveip.Lease) Status {
	byKey := map[effectiveip.NodeKey]netip.Addr{}
	for _, lease := range leases {
		byKey[lease.NodeKey] = lease.EffectiveIP
	}
	out := Status{}
	for _, p := range profiles {
		proj := Profile{
			ID:        p.ProfileID,
			Alias:     p.Alias,
			SelfNode:  p.SelfNodeID,
			PeerCount: p.PeerCount,
			ShieldsUp: p.ShieldsUp,
		}
		for _, canonical := range p.SelfIPs {
			effective := canonical
			key := effectiveip.NodeKey{ProfileID: p.ProfileID, NodeID: p.SelfNodeID, CanonicalIP: canonical}
			if leased, ok := byKey[key]; ok {
				effective = leased
			}
			proj.SelfIPs = append(proj.SelfIPs, IPPair{Canonical: canonical.String(), Effective: effective.String()})
		}
		out.Profiles = append(out.Profiles, proj)
	}
	return out
}
```

- [ ] **Step 4: Run status tests**

Run:

```bash
go test ./mnet/status -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit status projection**

Run:

```bash
git add mnet/status
git commit -m "mnet/status: expose canonical and effective addresses"
```

Expected: one focused status commit.

## Task 9: CLI And Daemon Skeleton

**Files:**
- Create: `cmd/mnetd/main.go`
- Create: `cmd/mnet/main.go`
- Create: `cmd/mnet/main_test.go`

- [ ] **Step 1: Write failing CLI contract test**

Create `cmd/mnet/main_test.go`:

```go
package main

import (
	"bytes"
	"testing"
)

func TestStatusRequiresJSONFlagForMachineReadableOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"status", "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d stderr=%s", code, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte(`"profiles"`)) {
		t.Fatalf("status JSON missing profiles: %s", stdout.String())
	}
}

func TestShortDNSLookupIsRejected(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"resolve", "db"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected short-name resolve to fail")
	}
	if !bytes.Contains(stderr.Bytes(), []byte("unqualified")) {
		t.Fatalf("stderr = %s", stderr.String())
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
go test ./cmd/mnet -count=1
```

Expected: FAIL because `cmd/mnet` is not implemented.

- [ ] **Step 3: Implement CLI skeleton**

Create `cmd/mnet/main.go`:

```go
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	mnetdns "tailscale.com/mnet/dns"
	mnetstatus "tailscale.com/mnet/status"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: mnet status --json | mnet resolve <name>")
		return 2
	}
	switch args[0] {
	case "status":
		if len(args) != 2 || args[1] != "--json" {
			fmt.Fprintln(stderr, "usage: mnet status --json")
			return 2
		}
		b, err := json.MarshalIndent(mnetstatus.Status{Profiles: []mnetstatus.Profile{}}, "", "  ")
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintln(stdout, string(b))
		return 0
	case "resolve":
		if len(args) != 2 {
			fmt.Fprintln(stderr, "usage: mnet resolve <explicit-name>")
			return 2
		}
		_, err := mnetdns.NewResolver(nil).Resolve(args[1])
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		return 2
	}
}
```

- [ ] **Step 4: Implement daemon skeleton**

Create `cmd/mnetd/main.go`:

```go
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	statePath := flag.String("state", "/var/lib/mnet/state.json", "path to mnet daemon state")
	flag.Parse()
	if *statePath == "" {
		fmt.Fprintln(os.Stderr, "state path is required")
		os.Exit(2)
	}
	fmt.Printf("mnetd state=%s\n", *statePath)
}
```

- [ ] **Step 5: Run CLI and daemon tests**

Run:

```bash
go test ./cmd/mnet -count=1
go test ./cmd/mnetd -count=1
go run ./cmd/mnet status --json
go run ./cmd/mnetd --state "$(mktemp -d)/state.json"
```

Expected:

```text
ok  	tailscale.com/cmd/mnet
?   	tailscale.com/cmd/mnetd
{
  "profiles": []
}
mnetd state=/tmp/.../state.json
```

- [ ] **Step 6: Commit CLI and daemon skeleton**

Run:

```bash
git add cmd/mnet cmd/mnetd
git commit -m "cmd/mnet: add multi-tailnet CLI skeleton"
```

Expected: one focused CLI commit.

## Task 10: First End-To-End Contract Test

**Files:**
- Create: `mnet/integration/multitailnet_test.go`

- [ ] **Step 1: Write failing contract test with fake profile engines**

Create `mnet/integration/multitailnet_test.go`:

```go
package integration

import (
	"net/netip"
	"testing"

	"tailscale.com/mnet/effectiveip"
)

func TestTwoTailnetsWithCollidingCanonicalIPsReceiveStableEffectiveIPs(t *testing.T) {
	canonical := netip.MustParseAddr("100.64.0.1")
	selfA := effectiveip.Node{ProfileID: "tailnet-a", NodeID: "self-a", CanonicalIP: canonical}
	selfB := effectiveip.Node{ProfileID: "tailnet-b", NodeID: "self-b", CanonicalIP: canonical}
	alloc := effectiveip.NewAllocator(netip.MustParsePrefix("100.127.0.0/24"), nil)
	first, err := alloc.Assign([]effectiveip.Node{selfA, selfB})
	if err != nil {
		t.Fatal(err)
	}
	second, err := effectiveip.NewAllocator(netip.MustParsePrefix("100.127.0.0/24"), first.Leases).Assign([]effectiveip.Node{selfA, selfB})
	if err != nil {
		t.Fatal(err)
	}
	keyA := effectiveip.NodeKey{ProfileID: selfA.ProfileID, NodeID: selfA.NodeID, CanonicalIP: canonical}
	keyB := effectiveip.NodeKey{ProfileID: selfB.ProfileID, NodeID: selfB.NodeID, CanonicalIP: canonical}
	if first.MustEffective(keyA) == first.MustEffective(keyB) {
		t.Fatal("colliding tailnets received same effective self IP")
	}
	if first.MustEffective(keyA) != second.MustEffective(keyA) || first.MustEffective(keyB) != second.MustEffective(keyB) {
		t.Fatal("effective IPs changed after restart")
	}
}
```

- [ ] **Step 2: Run the contract test**

Run:

```bash
go test ./mnet/integration -count=1
```

Expected: PASS after Tasks 1 through 9 are complete.

- [ ] **Step 3: Run focused multi-tailnet package suite**

Run:

```bash
go test ./mnet/... ./cmd/mnet ./cmd/mnetd -count=1
```

Expected: PASS.

- [ ] **Step 4: Commit first contract test**

Run:

```bash
git add mnet/integration
git commit -m "mnet/integration: cover stable colliding tailnet identities"
```

Expected: one focused integration-test commit.

## Acceptance Criteria

- Repository contains the imported upstream Tailscale base at `fad8b9b8a957c3d4d81d1d9f61c09090dd8d0ba3`.
- `go test ./mnet/... ./cmd/mnet ./cmd/mnetd -count=1` passes.
- Effective IP leases are stable across allocator restarts.
- Same canonical node IPs in different profiles receive distinct effective IPs.
- Packet translation rewrites effective addresses to canonical profile addresses on outbound and back to effective addresses on inbound.
- Profile engines are represented as independent profile objects.
- `tsnet.Server.Tun` is characterized as the initial packet boundary.
- DNS resolver rejects unqualified names.
- Status projection exposes canonical and effective addresses.
- CLI skeleton has no upstream compatibility assumptions.

## Follow-Up Plan Boundary

This plan got the fork to a tested local multi-profile/mux foundation. The next implementation slice is userspace networking with one aggregate SOCKS5 listener before TUN mode. That slice should start `tsnet` profile engines without a provided TUN, learn each profile's MagicDNS suffix after login, and route aggregate SOCKS TCP CONNECT requests by MagicDNS FQDN or synthetic effective IP. It should reject canonical IP literals, unqualified names, and UDP ASSOCIATE for now.

A later plan should cover live two-tailnet control-plane tests, OS TUN creation, route installation, daemon LocalAPI, per-profile shields-up wiring, exit-node selection, and a real forked-tsnet API if `tsnet.Server.Tun` proves insufficient under live packet tests.
