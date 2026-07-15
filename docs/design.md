# Multi-Tailnet Design

Date: 2026-06-30

## Goal

Build a standalone daemon, using the upstream Tailscale Go modules, that can log into multiple tailnets at the same time and make node devices in every active tailnet reachable concurrently from one host.

The core contract is that there is no active-tailnet switch. If three tailnets are active, local processes can reach node devices in all three at the same time.

## Non-Goals For V1

- Do not support overlapping advertised subnet route remapping.
- Do not define app connector route conflict semantics unless they reduce to direct node reachability.
- Do not add tailnets as OS search domains.
- Do not preserve upstream single-tailnet CLI compatibility.
- Do not install anti-bridging firewall rules.
- Do not build a Tailscale-managed cross-tailnet router feature.

Host administrators can still forward, NAT, bridge, or proxy traffic with normal OS tooling. V1 does not add special support for that and does not try to prevent it.

## Architecture

The system is one daemon with a shared host-facing TUN and one upstream `tsnet` profile engine per active tailnet.

The first runnable milestone uses userspace networking instead of a host TUN. In that mode, the daemon runs one `tsnet` profile engine per active tailnet and exposes one aggregate local SOCKS5 listener for outbound TCP. The aggregate SOCKS listener chooses a profile per request and then dials through that profile's `tsnet.Server.Dial`. This validates simultaneous multi-profile login and outbound reachability before OS route installation, shared TUN injection, and packet-level effective-IP translation are enabled.

The daemon uses the upstream `tsnet.Server.Tun` hook to provide the packet/TUN interface for each profile engine. This keeps `tsnet` responsible for tailnet identity, control-plane state, peer crypto, DERP/magicsock behavior, and netmap handling, while the daemon owns the host-wide multi-tailnet policy.

The daemon owns:

- Shared host-facing TUN.
- Profile orchestration.
- Effective IP allocation and persistence.
- Effective-IP-to-profile packet routing.
- Explicit DNS resolution behavior.
- New multi-tailnet-native CLI/API.
- Exit-node/default-route selection.

Each `tsnet` profile engine owns:

- One tailnet login.
- One machine key.
- One node key.
- One control-plane auth/session.
- One netmap and peer set.
- Profile-local Tailscale preferences and policy inputs.
- Tailnet transport behavior for that profile.

Outbound packet flow:

1. A local process sends traffic to an effective IP.
2. The OS routes that traffic to the shared daemon-owned TUN.
3. The daemon maps the effective destination IP to one `(profile, canonical peer IP)`.
4. The daemon translates the local effective source/destination addresses to the canonical addresses expected by that profile engine.
5. The packet enters the selected `tsnet` engine's packet path.
6. The selected profile engine sends the packet through its normal Tailscale transport.

Inbound packet flow:

1. A profile engine receives canonical tailnet traffic for its local profile identity.
2. The daemon maps canonical source/destination addresses to stable local effective addresses for that profile.
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

Every local profile identity and every visible peer across all active profiles gets a locally unique effective IP. If a canonical IP has no conflict, the effective IP may equal the canonical IP. If two identities from different profiles share a canonical IP, one or both get synthetic effective IPs.

Effective IPs are:

- Local dial targets.
- Stable daemon state.
- Never advertised into any tailnet.
- Never serialized as peer identity in WireGuard traffic.
- Never used as ACL subjects.

Effective IPs map to canonical tailnet identity:

```text
(tailnet stable ID, node stable ID, canonical Tailscale IP) -> effective IP
```

The mapping applies to remote peers and to this host's local profile identities. The self mapping is required so local processes have stable per-profile local addresses and inbound packets can be delivered without collapsing separate tailnet identities into one address.

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

Effective IPs do not create a new authorization namespace. They only select which profile and canonical peer a local packet should use. Before a packet enters a profile engine, the daemon maps the effective local addresses to the canonical addresses expected in that tailnet. The receiving node evaluates policy against canonical tailnet identity and profile-local policy state.

Consequences:

- Dialing a remapped effective IP cannot bypass ACLs.
- Effective IPs must not leak into netmap, peer identity, audit identity, or ACL-visible packet metadata.
- Status and diagnostics should show both canonical and effective addresses so denials remain debuggable.

## DNS And Names

Multi-tailnet mode does not add tailnet DNS suffixes to OS search domains.

Rules:

- Unqualified MagicDNS names like `db` are disabled.
- Names must identify the target tailnet explicitly.
- Unique short names do not resolve implicitly.
- Ambiguous short names do not pick a profile by priority.
- DNS answers for node names return effective IPs.
- DNS answers must be specific enough to map to exactly one profile.

Expected DNS-shaped names include upstream-style fully qualified names:

```text
host.tailnet-name.ts.net
```

The CLI/API may also expose non-DNS selectors such as:

```text
host@tailnet-alias
```

Those selectors are CLI/API conveniences, not OS search-domain behavior.

In the userspace SOCKS milestone, SOCKS destinations are intentionally stricter:

- MagicDNS FQDNs are allowed and select the profile whose running tailnet reports that MagicDNS suffix.
- Synthetic effective IP literals are allowed when they appear in the local effective-IP lease table.
- Canonical Tailscale IP literals are rejected, even when a canonical IP is unique.
- Unqualified names are rejected.
- UDP ASSOCIATE is out of scope for the first SOCKS milestone.

## Routing And Exit Nodes

The daemon installs enough local routing for effective node IPs from all active profiles to be reachable at the same time.

Rules:

- All active tailnet node peers are reachable concurrently through effective IPs.
- Route lookup maps each effective IP to exactly one profile and canonical node.
- The daemon does not install anti-bridging rules.
- The daemon does not automatically forward packets between tailnets.
- Host-admin forwarding, NAT, and proxying are ordinary host networking outside v1 semantics.
- Advertised subnet routes are out of scope.
- Overlapping subnet route handling is out of scope.

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

There is no CLI compatibility mode. The daemon exposes a multi-tailnet-native CLI/API instead of preserving upstream single-tailnet command semantics.

Core objects:

- Profile: one local login/device identity for one tailnet.
- Peer: one visible node inside one profile's netmap.
- Effective IP: local address assigned to a profile identity or peer.
- Canonical IP: tailnet-assigned node address.
- Tailnet alias: local user-friendly name for selecting a profile.
- Host identity group: optional local grouping showing that several profiles live in one daemon.

Required behavior:

- Commands that act on one tailnet require a profile selector.
- Commands that show global state return structured multi-profile output.
- Status shows profile state, peer canonical IPs, effective IPs, DNS names, shields-up state, and conflicts.
- Login, logout, add, remove, and reauth are profile operations.
- Exit-node selection requires a profile and peer selector.
- Effective-IP mapping and cleanup are explicit inspectable operations.
- Output does not mimic upstream `tailscale status`.

## Persistent State

The daemon persists multi-tailnet state as first-class data, while each `tsnet` profile engine keeps its own tailnet identity state.

Persistent daemon state includes:

- Profile list and tailnet aliases.
- Effective-IP leases and allocator metadata.
- DNS/profile metadata for explicit resolution.
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
- A failed profile engine does not stop other profile engines.
- Auth expiry, device approval, or Tailnet Lock problems are reported per profile.
- If the shared TUN fails, node reachability fails globally, but profile state remains inspectable where possible.
- If one profile cannot allocate a unique effective IP for a peer, that peer is marked unreachable and other peers continue operating.
- Removing one profile does not garbage-collect another profile's effective-IP leases.

## Testing And Validation

Tests should validate contracts, not implementation details.

Core contract tests:

- Two profile engines can be active simultaneously with independent machine keys and node keys.
- Devices in both tailnets are reachable at the same time without switching.
- Same canonical node IPs in different tailnets receive stable, distinct effective IPs.
- Effective IPs survive daemon restart.
- Effective IPs do not leak into profile engine identity, peer identity, netmap, or ACL-visible packet metadata.
- Inbound policy remains evaluated by the receiving profile/tailnet.
- Shields-up blocks inbound for one profile without blocking another.
- Unqualified MagicDNS names fail in multi-tailnet mode.
- Tailnet-qualified names resolve to effective IPs.
- Removing or restarting one profile does not disrupt the others.
- One explicitly selected exit node/default route is active at a time.
- Subnet route conflicts are out of scope and are not silently remapped.

Manual/system tests:

- Create two test tailnets with intentionally colliding node IPs.
- Restart the daemon and confirm effective-IP stability.
- Verify ordinary local tools can reach nodes in both tailnets concurrently.
- Verify an inbound local listener is reachable from both tailnets.
- Enable shields-up on one profile and verify inbound is blocked only there.
- Verify OS DNS has no tailnet search domains.
- Verify host-admin forwarding/NAT is not blocked by the daemon.

## Open Implementation Risks

The design depends on the upstream `tsnet.Server.Tun` packet-facing hook. The pinned Tailscale module version must continue to expose that boundary so the daemon can provide the shared TUN/multiplexer while keeping each profile engine's control-plane and transport responsibilities intact.

The synthetic effective-IP allocator must choose an address space that avoids collisions with canonical Tailscale addresses, host routes, and ordinary LAN routes. That allocator policy is part of implementation planning, not this semantic spec.

Inbound delivery through one shared TUN may require careful source/destination translation for local self effective IPs so host applications see stable per-profile addresses while profile engines still see canonical tailnet addresses.
