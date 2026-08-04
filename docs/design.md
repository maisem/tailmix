# Multi-Tailnet Design

Date: 2026-06-30

## Goal

Build a standalone daemon, using the upstream Tailscale Go modules, that can log into multiple tailnets at the same time and make node devices in every active tailnet reachable concurrently from one host.

The core contract is that there is no active-tailnet switch. If three tailnets are active, local processes can reach node devices in all three at the same time.

## Non-Goals For V1

- Do not accept advertised subnet routes or split-DNS routes without explicit
  daemon policy.
- Do not infer application or app-connector routes from DNS answers.
- Do not install OS search domains implicitly from the active profile set.
- Do not expose an unqualified, ambiguous single-tailnet CLI target.
- Do not install anti-bridging firewall rules.
- Do not build a Tailscale-managed cross-tailnet router feature.

Host administrators can still forward, NAT, bridge, or proxy traffic with normal OS tooling. V1 does not add special support for that and does not try to prevent it.

## Architecture

The system is one daemon with a shared host-facing TUN and one locally forked `tsnet` profile engine per active tailnet.

The first runnable milestone uses userspace networking instead of a host TUN. In that mode, the daemon runs one `tsnet` profile engine per active tailnet and exposes one aggregate local SOCKS5 listener for outbound TCP. The aggregate SOCKS listener chooses a profile per request and then dials through that profile's `tsnet.Server.Dial`. This validates simultaneous multi-profile login and outbound reachability before OS route installation, shared TUN injection, and packet-level effective-IP translation are enabled.

The daemon uses `tsnet.Server.Tun` to provide the packet/TUN interface for each profile engine. The local fork also exposes `LocalBackend` so the daemon can attach Tailscale's native `ipnserver` to a per-profile Unix socket. This keeps `tsnet` responsible for tailnet identity, control-plane state, peer crypto, DERP/magicsock behavior, and netmap handling, while the daemon owns the host-wide multi-tailnet policy.

The daemon owns:

- Shared host-facing TUN.
- Profile orchestration.
- Effective IP allocation and persistence.
- Effective-IP-to-profile packet routing.
- Explicit IP route acceptance and profile pinning.
- Explicit DNS query routing and search-domain behavior.
- Profile selection and per-profile LocalAPI socket orchestration.
- Exit-node/default-route selection.

Each `tsnet` profile engine owns:

- One tailnet login.
- One machine key.
- One node key.
- One control-plane auth/session.
- One netmap and peer set.
- Profile-local Tailscale preferences and policy inputs.
- Tailnet transport behavior for that profile.
- Native LocalAPI behavior, credentials, and operator permissions.

Outbound packet flow supports direct peers, Tailscale Services, and accepted
subnets:

1. A local process sends traffic to an effective peer or Service IP, or an
   explicitly accepted subnet destination.
2. The OS routes that traffic to the shared daemon-owned TUN using the shared
   host NAT address as its source.
3. A BART longest-prefix-match table maps the destination to a profile and
   route kind.
4. The daemon SNATs the shared host NAT address to that profile's canonical
   self address. It translates a direct target's effective destination to its
   canonical address, but preserves a subnet destination.
5. The packet enters the selected `tsnet` engine's packet path.
6. The selected profile engine sends the packet through its normal Tailscale transport.

Inbound packet flow:

1. A profile engine receives canonical tailnet traffic for its local profile identity.
2. A per-profile BART table maps a canonical peer or Service source to its
   stable effective address. An accepted subnet source remains unchanged and
   is admitted only if longest-prefix match pins it to the receiving profile.
   The daemon DNATs the canonical self destination to the shared host NAT
   address.
3. The packet is injected toward the host through the shared TUN/listener path.
4. Local OS firewall and listener behavior apply normally.

This is a packet-level architecture. It is not a public-`tsnet` TCP/UDP flow proxy.

## Identity And Lifecycle

The physical machine appears as a separate device in each tailnet.

Each profile has independent:

- Machine key.
- Node key.
- Control-plane auth session.
- Device approval state.
- Key expiry state.
- Tags.
- Tailnet Lock state.
- Tailscale SSH policy.
- Audit/log identity.

The local daemon may group profiles as identities on the same host, but no tailnet receives a merged identity. Tailnet A cannot observe that the same local daemon is also logged into tailnet B unless the user creates that visibility through ordinary host networking or application behavior.

Login, logout, removal, reauth, expiry, and approval are profile operations. Removing one profile destroys or retires only that profile's identity state and does not affect other active profiles.

## Addressing

Each node keeps its canonical Tailscale IPs exactly as assigned by its own tailnet. The multi-tailnet daemon adds a local-only effective IP layer.

Every visible peer across all active profiles gets a locally unique effective IP
from the configured pool. Canonical CGNAT and Tailscale ULA addresses are never
used as host dial targets, even when they are unique across profiles. The shared
TUN has one separately reserved host NAT address per active address family.

Effective IPs are:

- Local dial targets.
- Stable daemon state.
- Never advertised into any tailnet.
- Never serialized as peer identity in WireGuard traffic.
- Never used as ACL subjects.

Effective IPv4 and IPv6 addresses and the host NAT addresses come from
daemon-configurable pools. The prefix base remains unassigned. Pool selection
is persisted alongside the leases. Changing a pool retires the old leases and
host NAT address for that family and allocates replacements.

Effective IPs map to canonical tailnet identity:

```text
(tailnet stable ID, node stable ID, canonical Tailscale IP) -> effective IP
```

The mapping applies to remote peers. Each profile's canonical self address is a
NAT translation target, not an address assigned to the host TUN. All profiles
DNAT inbound traffic to the shared host NAT address, allowing the host OS to
manage one ordinary local address rather than selecting among per-profile
sources.

Persistence rules:

- Effective IP assignments survive daemon/process restarts.
- Assignments survive temporary profile disconnects.
- Assignments survive peer offline transitions.
- Removing a peer does not immediately free its lease.
- Reappearing peers receive their prior effective IP when their stable identity matches.
- Cleanup is explicit or retention-based.
- If effective-IP state is missing or corrupt, the daemon fails closed or requires explicit recovery instead of silently remapping everything.

Allocation failures are reported per peer/profile. A peer whose effective IP cannot be allocated is marked unreachable with a specific allocation error. Other profiles and peers continue operating.

## Policy Semantics

Tailscale policy is evaluated on the inbound path by the receiving node/profile.

Effective IPs do not create a new authorization namespace. They only select
which profile and canonical peer or Service a local packet should use. Before a
packet enters a profile engine, the daemon maps the effective local addresses
to the canonical addresses expected in that tailnet. The receiving node
evaluates policy against canonical tailnet identity and profile-local policy
state.

Consequences:

- Dialing a remapped effective IP cannot bypass ACLs.
- Effective IPs must not leak into netmap, peer identity, audit identity, or ACL-visible packet metadata.
- Status and diagnostics should show both canonical and effective addresses so denials remain debuggable.

## DNS And Names

Multi-tailnet mode installs no OS search domains by default. The administrator
may configure an explicit ordered list at runtime. DNS query routing is a
separate suffix-to-profile policy.

Rules:

- Unqualified MagicDNS names like `db` fail while the search-domain list is
  empty.
- A DNS route binding maps a normalized suffix to one stable profile ID.
- The root suffix `.` may bind a profile's default resolver route; it is not a
  valid OS search domain.
- Exact suffixes have one binding; overlapping suffixes use longest-suffix
  match, so a subtree can be pinned to another profile.
- A profile-wide DNS accept-all flag continuously imports that profile's
  MagicDNS, split-DNS, and default/fallback resolver behavior, including routes
  advertised later. It never imports search domains.
- A binding is installed only while the selected profile reports an equal or
  covering MagicDNS or split-DNS route. Otherwise it remains desired and no
  other profile is substituted.
- Selection uses longest-suffix match across all routes. Desired exact
  bindings, accept-all imports, then automatic routes break ties for the same
  suffix. A waiting exact binding fails closed for that suffix rather than
  falling through.
- Identical imports from several profiles fail closed until an exact binding
  selects one.
- An otherwise unbound and unimported MagicDNS suffix is installed
  automatically only when exactly one active profile is authoritative for it.
  Split-DNS and default resolver routes are not imported automatically.
- An active exit node contributes an automatic root route through that
  profile's effective Tailscale DNS configuration. An explicit or imported root
  route retains precedence at the same suffix, so an explicitly configured
  root route is not replaced or withdrawn with the exit node. More-specific
  routes, including MagicDNS zones, remain active.
- Split-DNS queries use a profile-scoped forwarder. Resolver addresses cannot
  be installed through a shared dialer because private resolver IPs may overlap
  across tailnets.
- Unique short names do not cause tailmix to infer or install a search domain.
- A configured search domain is installed only when it is equal to or below
  an effective DNS route.
- Search-domain order is explicit administrator policy. Short-name expansion
  and collisions follow the host resolver's normal search-list behavior;
  tailmix does not pick a profile by priority.
- Configured domains without a current DNS route remain desired but
  are not installed.
- DNS answers for node and Tailscale Service names return effective IPs.
- Addresses returned by split DNS follow ordinary host IP routing. A
  destination that must traverse a tailnet needs a separate IP route policy;
  DNS bindings do not create application or app-connector routes.

Expected DNS-shaped names include upstream-style fully qualified names:

```text
host.tailnet-name.ts.net
```

The CLI/API may also expose non-DNS selectors such as:

```text
host@profile-name
```

Those selectors are CLI/API conveniences, not OS search-domain behavior.

In the userspace SOCKS milestone, SOCKS destinations are intentionally stricter:

- MagicDNS FQDNs are allowed when the effective DNS plan selects one profile.
- Synthetic effective IP literals are allowed when they appear in the local effective-IP lease table.
- IP literals covered by installed exact or accept-all subnet policy select its
  profile.
- Canonical Tailscale IP literals are rejected, even when a canonical IP is unique.
- Unqualified names are rejected.
- UDP ASSOCIATE is out of scope for the first SOCKS milestone.

## Routing And Exit Nodes

The daemon installs routes for effective node IPs and for explicitly accepted
subnet prefixes. An IP route binding maps a destination prefix to one stable
profile ID.

Rules:

- All active tailnet node peers and visible Tailscale Services are reachable
  concurrently through effective IPs.
- Route lookup maps each effective IP to exactly one profile and canonical
  node or Service.
- A subnet binding is installed only while the selected profile reports an
  approved primary advertised route equal to or covering the requested prefix.
  A narrower binding can accept only part of an advertisement.
- A profile-wide route accept-all flag continuously imports every approved
  non-default subnet route from that profile, including later advertisements.
- Exact prefixes have one binding. Overlapping bindings are allowed and use
  longest-prefix match, so `10.0.0.0/8` and `10.20.0.0/16` may be pinned to
  different profiles.
- Lookup first uses longest-prefix match among desired exact bindings, then
  among accept-all imports. A waiting exact binding fails closed rather than
  falling through. Identical imports from several profiles fail closed until an
  exact binding selects one.
- The binding selects a tailnet profile, not a subnet-router peer. The selected
  tailnet's control plane chooses and may fail over its primary router.
- A withdrawn route or unavailable profile withdraws the host route but leaves
  the desired binding waiting. No other profile is selected automatically.
- The profile engine may accept a covering route internally, but the host sees
  only exact-bound prefixes and routes imported by accept-all policy.
- Default routes are excluded from subnet bindings and remain governed by the
  exit-node policy below.
- The daemon does not install anti-bridging rules.
- The daemon does not automatically forward packets between tailnets.
- Host-admin forwarding, NAT, and proxying are ordinary host networking outside v1 semantics.

Exit/default route behavior:

- Only one exit node/default route can be active for the host at a time.
- Exit node selection is explicit by profile and peer identity.
- There is no automatic failover across profiles.
- Disabling or removing the selected profile disables its exit-node route.

## Inbound Behavior

A local service listening on this host is reachable through all active tailnet identities by default, subject to normal tailnet policy.

Rules:

- Inbound node traffic can arrive through any active profile.
- Each profile presents its own device identity to its tailnet.
- Policy enforcement remains inbound on the receiving side.
- Shields-up is respected per profile.
- Enabling shields-up for one profile blocks inbound from that profile only.
- Shields-up for one profile does not block inbound from another profile.
- Local OS firewall rules still apply normally.

Higher-level features such as Tailscale SSH, Serve, and Funnel are configured per profile, not globally. Their policy, audit, and identity surfaces belong to a specific tailnet.

## CLI And API Surface

The proposed live lifecycle commands and daemon control protocol are specified
in [profile-management.md](profile-management.md).

Profile-scoped commands use:

```text
tailmix tailscale --profile <name> <tailscale-subcommand> [arguments]
tailmix ts --profile <name> <tailscale-subcommand> [arguments]
```

Every `--profile` option also accepts `-p`.

`tailmix` selects that profile's LocalAPI socket and delegates the remaining
arguments to `tailscale.com/cmd/tailscale/cli`. Command behavior and output are
therefore upstream Tailscale behavior. `ts` is an exact shortcut for the
`tailscale` command namespace. The explicit command namespace and profile
option keep CLI command names and local profile names in separate naming
domains. The daemon serves each socket through `ipnserver`, so peer credentials
and `OperatorUser` permissions are evaluated in the same request path as
`tailscaled`.

Aggregate lifecycle commands use `tailmix profiles ...`; IP route bindings use
`tailmix routes ...`; and DNS bindings and search policy use
`tailmix dns routes ...` and `tailmix dns search ...`. All use a separate
multi-profile API and must not silently pick one profile.

Profile-wide imports are explicit live policy:

```text
tailmix routes set --profile <name> --accept-all=<true|false>
tailmix dns routes set --profile <name> --accept-all=<true|false>
```

Disabling accept-all withdraws imported routes without removing exact
prefix/suffix bindings.

Core objects:

- Profile: one local login/device identity for one tailnet.
- Peer: one visible node inside one profile's netmap.
- Effective IP: local dial address assigned to a visible peer.
- Canonical IP: tailnet-assigned node address.
- IP route binding: accepted destination prefix pinned to a stable profile ID.
- DNS route binding: query suffix pinned to a stable profile ID.
- Search domain: ordered OS short-name expansion suffix, independent of DNS
  route bindings.
- Profile ID: stable daemon-generated key for runtime state, identity storage,
  and effective-IP leases; it is not a CLI selector.
- Profile name: local user-friendly handle for selecting a profile; it is
  distinct from the tailnet hostname and DNS suffix.
- Host identity group: optional local grouping showing that several profiles live in one daemon.

Required behavior:

- Commands that act on one tailnet require a profile selector.
- Future commands that show global state return structured multi-profile output.
- Future aggregate status shows profile state, peer canonical IPs, effective IPs, DNS names, shields-up state, and conflicts.
- Login, logout, add, remove, and reauth are profile operations.
- Exit-node selection requires a profile and peer selector.
- Effective-IP mapping and cleanup are explicit inspectable operations.
- Available subnet and DNS routes are observable without accepting them.
- IP and DNS route bindings require an explicit profile selector and survive
  profile renames.
- Accept-all policy follows future profile advertisements and remains separate
  for IP routes, DNS routes, and OS search domains.

## Persistent State

The daemon persists multi-tailnet state as first-class data, while each `tsnet` profile engine keeps its own tailnet identity state.

Persistent daemon state includes:

- Profile definitions and local profile names.
- Effective-IP leases and allocator metadata.
- Desired IP route bindings keyed by stable profile ID.
- Desired DNS route bindings keyed by stable profile ID.
- Per-profile IP and DNS accept-all flags, both defaulting to false.
- Ordered desired OS search domains.
- Exit-node/default-route selection.
- Multi-tailnet-layer preferences.

Persistent profile-engine state includes:

- Machine key.
- Node key.
- Control-plane auth/session material.
- Netmap/control-plane cache as appropriate.
- Profile-local Tailscale preferences.

Failure behavior:

- Daemon restart preserves profile identities and effective IPs.
- Daemon restart and profile rename preserve IP and DNS route bindings and
  accept-all flags.
- A failed profile engine does not stop other profile engines.
- Auth expiry, device approval, or Tailnet Lock problems are reported per profile.
- If the shared TUN fails, node reachability fails globally, but profile state remains inspectable where possible.
- If one profile cannot allocate a unique effective IP for a peer, that peer is marked unreachable and other peers continue operating.
- Removing one profile does not garbage-collect another profile's effective-IP leases.
- Removing or disabling a profile withdraws its installed bindings without
  assigning them to another profile; retained bindings can resume if the same
  stable profile returns.

## Testing And Validation

Tests should validate contracts, not implementation details.

Core contract tests:

- Two profile engines can be active simultaneously with independent machine keys and node keys.
- Devices in both tailnets are reachable at the same time without switching.
- Every peer receives a stable address from the configured effective pool.
- Same canonical node IPs in different tailnets receive stable, distinct effective IPs.
- Same canonical Service VIPs in different tailnets receive stable, distinct effective IPs.
- Effective IPs survive daemon restart.
- Effective IPs do not leak into profile engine identity, peer identity, netmap, or ACL-visible packet metadata.
- Inbound policy remains evaluated by the receiving profile/tailnet.
- Shields-up blocks inbound for one profile without blocking another.
- Explicit subnet bindings install only when the pinned profile has an approved
  covering route.
- IP accept-all follows current and future non-default routes from one profile;
  disabling it retains exact bindings.
- Overlapping subnet bindings select profiles by longest prefix, including when
  canonical private address space overlaps between tailnets.
- Exact bindings override accept-all imports, and identical imports from
  multiple profiles fail closed.
- Route withdrawal removes only the affected host route while preserving its
  desired binding.
- Nested DNS bindings select profiles by longest suffix.
- DNS accept-all follows MagicDNS, split, and default/fallback resolution from
  one profile without importing its search domains.
- Ambiguous MagicDNS suffixes and all split-DNS routes require an exact binding
  or profile-wide accept-all policy.
- Private DNS resolver queries use the selected profile even when resolver
  addresses overlap.
- DNS answers do not implicitly install IP or app-connector routes.
- Unqualified MagicDNS names fail when no search domains are configured.
- Explicitly configured, actively routed search domains are installed in the
  requested order and allow normal OS short-name expansion.
- Search domains without an effective DNS route are not installed.
- Tailnet-qualified names resolve to effective IPs.
- Removing or restarting one profile does not disrupt the others.
- One explicitly selected exit node/default route is active at a time.

Manual/system tests:

- Create two test tailnets with intentionally colliding node IPs.
- Restart the daemon and confirm effective-IP stability.
- Verify ordinary local tools can reach nodes in both tailnets concurrently.
- Verify an inbound local listener is reachable from both tailnets.
- Enable shields-up on one profile and verify inbound is blocked only there.
- Verify OS DNS has no tailnet search domains by default.
- Configure and clear selected search domains without restarting the daemon,
  and verify OS DNS tracks only the installed subset.
- Pin overlapping subnet routes to different profiles and verify longest-prefix
  selection.
- Pin a split-DNS suffix to one of two profiles with the same resolver IP and
  verify queries traverse only the selected profile.
- Verify host-admin forwarding/NAT is not blocked by the daemon.

## Open Implementation Risks

The design carries small forks of `tailscale.com/tsnet` and
`tailscale.com/net/netns` pinned to the module version in `go.mod`. The `tsnet`
fork retains the packet-facing `Server.Tun` hook, exposes
`Server.LocalBackend` for `ipnserver`, and makes remote log upload opt-in with
a replaceable endpoint. The `netns` fork adds Darwin underlay publication
without vendoring the rest of Tailscale. Updating Tailscale requires a clean
upstream import followed by separate reconciliation commits for both forks.

The effective-IP allocator must choose an address space that avoids collisions
with canonical Tailscale addresses, host routes, and ordinary LAN routes. One
address in each pool is reserved for host-side SNAT/DNAT and cannot be leased to
a peer.
