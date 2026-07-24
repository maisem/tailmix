# Live Profile Management

Status: Implemented

Date: 2026-07-23

## Summary

tailmix should manage its configured profile set through a daemon-owned local
control API. The `tailmix` CLI should use that API for profile lifecycle
commands while continuing to send profile-local Tailscale commands to the
selected profile's existing LocalAPI socket.

The proposed command shape is:

```text
tailmix profiles list
tailmix profiles show <name>
tailmix profiles add <name> [options]
tailmix profiles rename <name> <new-name>
tailmix profiles set <name> [options]
tailmix profiles enable <name>
tailmix profiles disable <name>
tailmix profiles restart <name>
tailmix profiles remove <name> [--purge --yes]

tailmix routes list [--available]
tailmix routes bind --profile <name> <prefix>...
tailmix routes unbind <prefix>...
tailmix routes set --profile <name> --accept-all=<true|false>

tailmix dns routes list [--available]
tailmix dns routes bind --profile <name> <domain>...
tailmix dns routes unbind <domain>...
tailmix dns routes set --profile <name> --accept-all=<true|false>

tailmix dns search list
tailmix dns search set <domain>...
tailmix dns search add <domain>...
tailmix dns search remove <domain>...
tailmix dns search clear
```

Profile-local Tailscale commands have their own explicit namespace and select a
profile by option:

```text
tailmix tailscale --profile work status
tailmix ts --profile home ping peer.home.example
```

`ts` is an exact shortcut for `tailscale`; neither form changes the delegated
arguments or behavior.

Profile changes are persisted and applied to the running daemon. Restarting one
profile is allowed when its engine configuration changes, but adding, changing,
or removing a profile must not restart the daemon or disrupt other profiles.

## Goals

- Add and remove profiles without restarting `tailmixd`.
- Start, stop, and restart one profile without affecting the others.
- Persist every successful requested configuration change.
- Give tailmix commands, local profile names, advertised hostnames, and
  tailnet-provided DNS names distinct naming domains.
- Accept selected advertised IP routes and pin each destination prefix to one
  profile.
- Pin selected DNS suffixes to one profile's MagicDNS or split-DNS route.
- Optionally follow every current and future IP or DNS route advertised by a
  selected profile.
- Change the ordered OS search-domain policy without restarting the daemon.
- Report profiles that are disabled, starting, awaiting login, running, or
  failed without blocking on them.
- Isolate profile startup, authentication, and watcher failures.
- Apply live changes in both TUN and SOCKS modes.
- Keep auth keys out of daemon state, command-line arguments, and logs.
- Allow the daemon to run with zero configured or enabled profiles.

## Non-goals

- Replace Tailscale's profile-local LocalAPI or CLI.
- Merge Tailscale login profiles inside one `tsnet.Server`.
- Automatically delete a removed profile's identity or effective-IP leases.
- Provide remote profile administration.
- Make global address-pool changes live in the first version.
- Infer application or app-connector routes from DNS answers. A DNS route
  binding selects where DNS queries go; returned traffic still follows the IP
  route table.
- Guarantee uninterrupted flows through the profile being stopped or
  restarted. Other profiles must remain uninterrupted.

## CLI

### Command namespaces

The first positional token always names a command namespace, never a profile:

```text
tailmix status [--json]
tailmix profiles <lifecycle-command> [arguments]
tailmix routes <policy-command> [arguments]
tailmix dns routes <policy-command> [arguments]
tailmix dns search <policy-command> [arguments]
tailmix {tailscale|ts} --profile <name> <tailscale-subcommand> [arguments]
```

`status` is the concise active-profile overview, equivalent to `profiles list`.
`profiles` owns tailmix lifecycle operations. `tailscale` delegates to the
selected profile's upstream Tailscale CLI, and `ts` is its exact alias. A
profile name appears only as an operand or the value of `--profile`. `routes`
owns daemon-wide IP route policy. `dns routes` owns DNS query routing, while
`dns search` owns the ordered OS search list. Prefixes and DNS domains therefore
occupy only resource positions and cannot collide with profile or command
names.

The current `tailmix work status` form is intentionally not part of the target
grammar. A release may recognize it solely to print a deprecation error with
the exact replacement, but new functionality must not extend that ambiguous
grammar:

```text
tailmix work status
# error: use "tailmix ts --profile work status"
```

Global CLI options precede the namespace; command-specific options follow their
command:

```text
tailmix --socket-dir /var/run/tailmix profiles list
tailmix --socket-dir /var/run/tailmix profiles show work --json
```

`TAILMIX_SOCKET_DIR` remains supported. `--socket-dir` takes precedence and
selects both the daemon control socket and per-profile LocalAPI sockets.

### Naming domains

The CLI and API use five deliberately separate names:

- **Profile ID** is an opaque, stable value generated by the daemon. It keys
  runtime state, leases, identity storage, and LocalAPI sockets. It is returned
  in JSON for correlation but is not normally typed by a user.
- **Profile name** is the locally unique operator-chosen handle, such as
  `work`. It is the only CLI selector and is never sent to a tailnet.
- **Device hostname** is the name advertised by that profile's Tailscale
  engine. It is configured with `--hostname` and is never a profile selector.
- **Tailnet DNS suffix** and **node DNS names** are observed from the profile's
  control-plane state. They are read-only status and routing data.
- **Command names** belong only to the CLI grammar.

There is no alias in the new model. The profile name is the one user-facing
local name and may be changed without changing the profile ID, identity,
leases, state directory, or socket. Existing state keeps its `Profile.ID` as
the stable ID and initializes the new name from that ID. An old `Alias` is
retained only for backwards-compatible decoding and is not a selector.

Profile names use a local CLI/storage grammar, not a DNS grammar. New names
match `[A-Za-z0-9][A-Za-z0-9._-]{0,63}` and are compared exactly. They are not
DNS-normalized, appended to a tailnet suffix, or used to derive the advertised
hostname. Default state directories and socket paths derive from the opaque
profile ID, so a filesystem name is not another implicit user-facing identity.

### IP route bindings

An IP route binding says both which advertised subnet route to accept and which
profile must carry it. There is no daemon-wide `accept-routes` boolean:

```text
tailmix routes list [--available] [--json]
tailmix routes bind --profile <name> <prefix>... [--replace] [--json]
tailmix routes unbind <prefix>... [--profile <name>] [--json]
tailmix routes set --profile <name> --accept-all=<true|false> [--json]
```

`bind` atomically records every normalized prefix against the selected
profile's stable ID. Repeating the same binding is a successful no-op. Binding
an already-bound prefix to another profile returns a conflict unless
`--replace` is present, making a re-pin intentional. `unbind` is idempotent;
its optional profile is a precondition that prevents removing a binding that
has since been re-pinned.

`set --accept-all=true` adds a persistent profile-wide import policy. It
accepts every current approved primary subnet route from that profile and
automatically follows routes added later. Setting it to `false` stops following
the profile without removing any exact bindings. Direct peer reachability is
unchanged, and exit-node default routes remain separate.

`list` reports desired and observed state. With `--available`, it instead shows
the approved, primary subnet routes currently observed in each profile's
netmap, including routes that have not been bound:

```text
PREFIX          PROFILE  ADVERTISED BY  STATE                          MATCHED ROUTE
10.20.0.0/16    work     router-a       ✓                              10.20.0.0/16
10.30.0.0/16    lab                     waiting:route_not_advertised
10.40.0.0/16    work     router-b       ✓                              10.40.0.0/16
```

A binding becomes enabled only while the selected profile is active and its
netmap has an approved primary subnet route that contains the requested
prefix. Allowing a more-specific prefix lets an operator accept only part of an
advertised route. Default routes are excluded because exit-node selection is a
separate policy. Prefixes that overlap tailmix's effective-IP pools, host NAT
addresses, or other daemon-reserved ranges are rejected.

`ADVERTISED BY` uses the subnet router's readable Tailscale node name rather
than its opaque stable node ID. The `PROFILE` column identifies the tailnet
profile where that advertiser was observed. `STATE` combines the active marker
and exceptional runtime status in one column. `MATCHED ROUTE` shows the
approved advertised prefix that covers a configured binding.

An exact prefix has only one binding, but different bindings may overlap.
Longest-prefix match is deterministic, so `10.0.0.0/8` may use `work` while
`10.20.0.0/16` uses `lab`. Within the selected profile, the Tailscale control
plane still chooses the primary subnet-router peer and may fail over between
eligible routers. The binding pins a tailnet profile, not an individual peer.

Exact bindings are authoritative overrides of profile-wide imports. Lookup
first uses longest-prefix match among desired exact bindings. If that binding
is waiting, the destination fails closed; only when no exact binding matches
does lookup use longest-prefix match among imported routes. Imported routes
from multiple accept-all profiles may overlap, but an identical prefix from
more than one profile is left uninstalled as `ambiguous-route` until an exact
binding selects one.

If the route is withdrawn or the profile becomes unavailable, tailmix removes
the host route and packet mapping but retains the desired binding as
`waiting-for-route`. It is restored automatically when the same stable profile
can serve it again. A binding implies acceptance: tailmix ensures the profile
engine accepts the covering route while it is needed. That internal preference
is only a transport mechanism and does not expose any unbound route to the
host.

### DNS route bindings

A DNS route binding sends queries for a suffix through one selected profile:

```text
tailmix dns routes list [--available] [--json]
tailmix dns routes bind --profile <name> <domain>... [--replace] [--json]
tailmix dns routes unbind <domain>... [--profile <name>] [--json]
tailmix dns routes set --profile <name> --accept-all=<true|false> [--json]
```

The mutation and precondition behavior matches IP route bindings. Domains are
normalized to lowercase suffixes without a trailing dot. An exact suffix has
one binding, nested suffixes may bind different profiles, and DNS
longest-suffix match selects the most-specific binding.
The root suffix `.` is a valid DNS route binding for a profile's default
resolver route, but it is not a valid search domain.
Validation and containment use Tailscale's `util/dnsname` parser and `FQDN`
semantics, so DNS labels are not incorrectly restricted to hostname syntax.

`set --accept-all=true` follows the profile's complete current and future DNS
route configuration: its MagicDNS suffix, split-DNS routes, and Tailscale's
configured default/fallback resolver behavior. It does not import the profile's
search domains; `tailmix dns search` remains the only way to change the OS
search list. Setting the flag to `false` removes only the profile-wide import
policy and retains exact suffix bindings.

Each active profile contributes observed DNS capabilities from its netmap:

- Its MagicDNS suffix, which tailmix can answer from that profile's node data.
- Its split-DNS routes and resolver descriptors, which tailmix can forward
  through that profile.

A binding is installed only when the selected profile currently has an equal
or covering DNS route. A more-specific binding can therefore select a subtree
of an advertised split-DNS suffix. If the capability disappears, the binding
remains desired with `waiting-for-route` state and no other profile is chosen.

Human-readable status distinguishes policy, source, and realization:

```text
DOMAIN                PROFILE  SOURCE     POLICY     STATE
work.example.ts.net   work     magicdns   automatic  installed
corp.example.com      work     split-dns  bound      installed
internal.example.com  work     split-dns  accept-all installed
lab.example.com       lab                  bound      waiting-for-route
```

DNS selection uses three policy tiers. It first uses longest-suffix match among
desired exact bindings; a waiting result fails closed. Only with no matching
exact binding does it consider routes imported from accept-all profiles, then
automatic MagicDNS routes. Identical imported suffixes from multiple profiles
are `ambiguous-route` and are not installed until an exact binding selects one.

For compatibility, an otherwise unbound and unimported MagicDNS suffix is
routed automatically only when exactly one active profile is authoritative for
it. Ambiguous MagicDNS suffixes require an exact binding or one unambiguous
accept-all import. Split-DNS and default resolver routes are never imported
automatically.

Forwarding must use a profile-scoped DNS path. Installing a private resolver IP
directly in a shared host resolver is insufficient because identical resolver
addresses may be reachable in several tailnets. The aggregate DNS service
therefore selects the binding by suffix and invokes a resolver/forwarder whose
dials enter the selected profile engine. It must preserve upstream UDP, TCP,
and DNS-over-HTTPS behavior rather than assuming every resolver is a plain UDP
address.

This policy routes DNS queries, not arbitrary application connections by
hostname. MagicDNS node answers contain effective IPs. Addresses returned by
split DNS follow the host's IP routing policy; reaching one through a tailnet
requires a corresponding installed IP route binding or accept-all import.

### DNS search domains

Search domains are daemon-wide ordered policy, not profile names or aliases.
The default list is empty, preserving fully qualified MagicDNS behavior.

```text
tailmix dns search list [--json]
tailmix dns search set <domain>... [--json]
tailmix dns search add <domain>... [--json]
tailmix dns search remove <domain>... [--json]
tailmix dns search clear [--json]
```

`set` atomically replaces the desired list in the given order. `add` appends
domains that are not already present, `remove` is an idempotent removal, and
`clear` restores the empty default. DNS names are case-insensitive; input is
normalized to lowercase fully qualified suffixes stored without a trailing
dot. Duplicates are removed while preserving the first occurrence.

A desired search domain is installed only while it is equal to or below one
effective DNS route, whether that route is an explicit binding or an
unambiguous automatic MagicDNS route. This matters because on systems such as
Linux with `systemd-resolved`, a search domain also routes matching queries to
tailmix's DNS service. tailmix must not capture an arbitrary suffix without a
known query path.

Desired domains that are not currently covered remain persisted but have
`waiting-for-route` state. They are installed automatically if a profile later
provides the required route and withdrawn if that profile is disabled,
removed, or loses its usable netmap. Profile lifecycle changes do not silently
edit the desired search-domain list.

Human-readable status distinguishes desired policy from observed installation:

```text
ORDER  DOMAIN               PROFILE  STATE
1      work.example.ts.net  work     installed
2      lab.example.ts.net            waiting-for-route
```

The configured order is passed to the OS unchanged after filtering unavailable
domains. Short-name expansion and collision behavior then follow the host
resolver's normal search-list semantics. tailmix does not inspect a short name
and choose a profile itself.

### `profiles list`

```text
tailmix profiles list [--all] [--json]
```

The human-readable output is stable enough for people, not scripts:

```text
PROFILE  ENABLED  RUNTIME      TAILNET          PEERS  ERROR
home     yes      running      home.ts.net      14
lab      no       disabled
work     yes      needs-login                  0
```

JSON is the scripting interface. Profiles are sorted by name in both formats.
Listing is a non-blocking snapshot and never waits for a profile to become
online. Removed profile tombstones are included only with `--all`.

### `profiles show`

```text
tailmix profiles show <name> [--json]
```

The result includes:

- Persisted configuration: stable profile ID, profile name, state directory,
  hostname, control URL, and enabled state.
- Runtime state and last lifecycle error.
- Tailscale backend state, login URL, tailnet suffix, self DNS name and
  addresses, peer count, and shields-up state when available.
- Approved primary subnet routes and observed DNS routes, plus the IP and DNS
  bindings pinned to the profile.
- The profile LocalAPI socket path when the engine is running.

An auth key is never returned.

### `profiles add`

```text
tailmix profiles add <name> \
  [--hostname <hostname>] \
  [--state-dir <directory>] \
  [--auth-key-env <name> | --auth-key-file <path|->] \
  [--disabled] \
  [--json]
```

Defaults are:

- The daemon generates a stable opaque profile ID.
- State directory defaults to a persisted path under
  `<daemon-state-dir>/profiles` derived from that ID.
- Hostname defaults to an independently generated, persisted DNS hostname. It
  is not derived from the profile name.
- The profile is enabled unless `--disabled` is supplied.

The CLI, not the daemon, resolves `--auth-key-env`. `--auth-key-file -` reads
the key from standard input. The resolved key is sent in the one local API
request, used for the initial engine start, and then discarded. It is not
persisted or echoed. There should be no raw `--auth-key` option because process
arguments and shell history are poor secret transports.

Adding an enabled profile returns after its engine, watcher, packet path, and
profile LocalAPI listener have either been attached or have failed. It does not
wait indefinitely for interactive login. If login is required, output points
the user at the normal profile-local command:

```text
Profile "work" added; login required.
Run: tailmix ts --profile work up
```

Alternative coordination servers are selected by the profile-local upstream
command and persisted in native Tailscale state:

```text
tailmix ts --profile work login \
  --login-server=https://headscale.example.com
```

`add` fails with a conflict if the name is already active or disabled.
Re-adding a previously removed name resurrects its retained profile definition,
stable ID, state directory, and effective-IP leases unless it was purged.

### `profiles rename` and `set`

```text
tailmix profiles rename <name> <new-name>

tailmix profiles set <name> \
  --hostname <hostname> \
  [--json]
```

State directory is immutable after creation. Moving identity state is a
separate, offline administrative operation and should not be hidden inside a
live update.

`rename` updates only the local control-plane index; the stable ID and running
engine do not change. `set` changes the Tailmix-owned hostname. Changing it
restarts only the selected profile after persisting the new desired
configuration. The command reports that brief profile-local disruption before
applying it. Native Tailscale settings, including the login server, remain in
the profile's Tailscale state and are preserved by that restart.

### `profiles enable`, `disable`, and `restart`

```text
tailmix profiles enable <name>
tailmix profiles disable <name>
tailmix profiles restart <name>
```

`enable` persists the enabled state and starts the profile. `disable` persists
the disabled state, withdraws its routes and DNS records, closes its LocalAPI
socket and engine, and retains its identity directory and leases. Disabled
profiles remain visible in `list` and are not started after daemon restart.

`restart` replaces only the selected enabled profile's runtime. It is useful
for recovery and for explicitly reloading profile engine state. It does not
change whether the profile is enabled.

Repeated `enable` and `disable` requests are successful no-ops. `restart` on a
disabled profile returns a conflict and suggests `enable`.

### `profiles remove`

```text
tailmix profiles remove <name>
tailmix profiles remove <name> --purge --yes
```

The default operation is deliberately reversible:

1. Mark the persisted profile definition as removed.
2. Withdraw its live routes and DNS records.
3. Stop its API listener, watcher, packet path, and engine.
4. Retain its stable ID, name, identity state directory, and effective-IP
   leases.

Removed definitions are omitted from `profiles list` unless `--all` is used.
`profiles add` with the same name resurrects a removed definition rather than
creating a new identity.

If the profile is the selected exit-node profile, removal also clears that
selection. IP route bindings, DNS route bindings, and the profile's accept-all
flags retain the stable profile ID and become `waiting-for-profile`, so
resurrecting the profile restores its policy without a rename-sensitive
rewrite.

`--purge` additionally deletes only that profile's resolved state directory and
effective-IP leases. It requires an interactive confirmation, or `--yes` for
non-interactive use. The daemon must reject purge while any IP or DNS route
binding refers to the profile; the operator must unbind those resources first.
It must also reject purge if the state directory is empty, is a parent of the
daemon state file, is shared by another profile, or does not resolve beneath an
explicitly allowed profile-state root. Partial purge failure leaves the profile
removed but reports which retained data could not be deleted.

## Exit status and errors

The CLI uses:

- `0`: requested state is applied, including idempotent no-ops.
- `1`: daemon or profile operation failed.
- `2`: CLI usage error.

API errors have stable machine-readable codes:

```json
{
  "code": "profile_exists",
  "message": "profile \"work\" already exists",
  "profileId": "p_01k2x7vq3c8m",
  "profileName": "work"
}
```

Initial codes should include `invalid_request`, `profile_exists`,
`profile_not_found`, `profile_disabled`, `transition_in_progress`,
`invalid_prefix`, `route_binding_conflict`, `invalid_dns_name`,
`dns_route_binding_conflict`, `binding_profile_mismatch`,
`profile_has_bindings`, `permission_denied`, `runtime_start_failed`,
`dns_configuration_failed`, `reconcile_failed`, and `purge_failed`.

## Daemon control API

### Transport and authorization

The daemon serves HTTP/JSON over a dedicated Unix socket:

```text
<socket-dir>/tailmixd.sock
```

This socket is separate from each profile's hashed LocalAPI socket. The CLI
must never edit the state JSON directly.

For the first version, local read requests may use the normal local socket
access policy, while mutations require the connecting UID to be root. Peer
credentials must be checked by the server; filesystem mode alone is not an
authorization check. A future daemon-wide operator setting can widen mutation
access without changing the API.

### Endpoints

```text
GET    /v1/profiles
POST   /v1/profiles
GET    /v1/profiles/by-name/{escaped-profile-name}
PATCH  /v1/profiles/by-name/{escaped-profile-name}
POST   /v1/profiles/by-name/{escaped-profile-name}/enable
POST   /v1/profiles/by-name/{escaped-profile-name}/disable
POST   /v1/profiles/by-name/{escaped-profile-name}/restart
DELETE /v1/profiles/by-name/{escaped-profile-name}?purge=false

GET    /v1/routes
PUT    /v1/routes
PATCH  /v1/routes
DELETE /v1/routes
GET    /v1/routes/available

GET    /v1/dns/routes
PUT    /v1/dns/routes
PATCH  /v1/dns/routes
DELETE /v1/dns/routes
GET    /v1/dns/routes/available

GET    /v1/dns/search-domains
PUT    /v1/dns/search-domains
PATCH  /v1/dns/search-domains
DELETE /v1/dns/search-domains
```

Mutations are serialized by the daemon lifecycle loop. A response is sent only
after the desired state has been persisted and the corresponding live
transition has completed or failed.

The profile resource separates desired state from observed state:

```json
{
  "id": "p_01k2x7vq3c8m",
  "name": "work",
  "stateDir": "/var/db/tailmix/profiles/p_01k2x7vq3c8m",
  "hostname": "tailmix-a2c123",
  "enabled": true,
  "removed": false,
  "acceptAllRoutes": true,
  "acceptAllDnsRoutes": true,
  "runtimeState": "running",
  "backendState": "Running",
  "magicDnsSuffix": "example.ts.net",
  "selfDnsName": "tailmix-a2c123.example.ts.net",
  "selfIps": ["100.64.0.10", "fd7a:115c:a1e0::10"],
  "peerCount": 12,
  "shieldsUp": false,
  "authUrl": "",
  "localApiSocket": "/var/run/tailmix/p_01k2x7vq3c8m.sock",
  "lastError": ""
}
```

`runtimeState` is one of `disabled`, `starting`, `needs-login`, `running`,
`stopping`, or `error`. It is tailmix lifecycle state; `backendState` is the
profile's upstream Tailscale state.

IP and DNS route resources report the persisted binding and its current
realization together:

```json
{
  "acceptAllProfiles": [{
    "profileId": "p_01k2x7vq3c8m",
    "profileName": "work",
    "state": "installed"
  }],
  "bindings": [{
    "prefix": "10.20.0.0/16",
    "profileId": "p_01k2x7vq3c8m",
    "profileName": "work",
    "state": "installed",
    "coveringRoute": "10.20.0.0/16",
    "primaryRouter": "router-a"
  }]
}
```

```json
{
  "acceptAllProfiles": [{
    "profileId": "p_01k2x7vq3c8m",
    "profileName": "work",
    "state": "installed"
  }],
  "bindings": [{
    "domain": "corp.example.com",
    "profileId": "p_01k2x7vq3c8m",
    "profileName": "work",
    "state": "installed",
    "coveringRoute": "corp.example.com",
    "source": "split-dns"
  }]
}
```

Waiting bindings use `state: "waiting"` and a stable `reason`, including
`profile_unavailable`, `route_not_advertised`, `dns_route_not_advertised`, or
`host_route_conflict`. The `available` resources are observational snapshots
grouped by profile and do not mutate policy.

An accept-all or automatic row shadowed completely by a higher policy tier uses
`state: "overridden"` and reports `overriddenBy`, `overrideProfileId`, and
`overrideProfileName`. A partially shadowed row remains installed and reports
`reason: "partially_overridden"`. Identical accept-all imports from different
profiles remain waiting with `reason: "ambiguous_route"`. Route and search
resources also expose `reconcileError` when persisted desired state could not
be fully applied to the live aggregate.

For both binding resources, `PUT` atomically replaces the complete desired
binding table and accept-all profile set. `PATCH` accepts atomic `bind` and
`unbind` arrays, an explicit `replace` flag, and an `acceptAll` map from profile
name to boolean. `DELETE` clears exact bindings and accept-all policy. Mutation
entries use a profile name; the daemon resolves it under the lifecycle lock and
persists the stable profile ID. Profile renames therefore change display only.

The search-domain resource reports desired and observed state separately:

```json
{
  "desired": ["work.example.ts.net", "lab.example.ts.net"],
  "installed": [{
    "domain": "work.example.ts.net",
    "profileId": "p_01k2x7vq3c8m",
    "profileName": "work"
  }],
  "waiting": [{
    "domain": "lab.example.ts.net",
    "reason": "no_active_route"
  }]
}
```

For search domains, `PUT` atomically replaces `desired`. `PATCH` accepts `add`
and `remove` arrays and applies them atomically to the current list. `DELETE`
clears the list. Every routing-policy mutation persists desired state and
completes aggregate route and DNS reconciliation before returning.

## Runtime design

### One lifecycle owner

Introduce a daemon supervisor that is the sole owner of:

- Persisted desired profile configuration.
- The map of runtime profiles.
- Profile engine, watcher, TUN, and LocalAPI listener lifetimes.
- TUN or SOCKS aggregate reconciliation.
- Lifecycle command serialization and response delivery.

HTTP handlers validate and enqueue commands. Engine watcher goroutines enqueue
observations. They do not mutate daemon state directly. A single lifecycle loop
processes both, avoiding concurrent state-file updates and cross-component
lock ordering.

Each runtime profile contains at least:

```text
persisted profile configuration
runtime state and last error
engine
per-profile lifecycle context/cancel
update watcher
LocalAPI server/listener
ChanTUN (TUN mode)
```

### Passive status

The current `TSNetEngine.Status` calls `tsnet.Server.Up`, which waits for the
backend to reach `Running`. Live management requires a passive status method
that uses `LocalClient.Status` and current backend notifications without
bringing the profile up or blocking.

Aggregate status must return a result per profile, including a per-profile
error, instead of failing the entire snapshot when one profile is unhealthy.
Capability readiness is evaluated separately: direct peer and subnet routing
need a usable netmap and self address, MagicDNS needs node data and a suffix,
and split DNS needs a usable netmap DNS configuration. A profile without one
capability can still contribute the others. A profile in `needs-login` or
`error` remains inspectable and does not take down healthy profiles.

The passive snapshot must include approved primary subnet routes and the
netmap's DNS route map and resolver descriptors. These observations are not
persisted as policy; they are inputs used to decide whether desired bindings
can currently be installed.

Zero profiles is a valid steady state. The daemon control socket and selected
networking mode remain available after the last profile is removed, with an
empty aggregate peer route and DNS configuration. Startup no longer requires
at least one `--profile`.

### Permanent update stream

The current manager builds `WatchUpdates` from a fixed engine map. Replace it
with one permanent supervisor update channel. Starting a profile starts its
watcher with a profile-scoped context; stopping it cancels that watcher.
Watcher termination updates only that profile's error state.

### Dynamic LocalAPI servers

The current profile API group is a fixed slice. Store servers by stable
profile ID, and support `Start(profile)` and `Stop(profile)`. Stopping closes
the listener, waits for the serving goroutine, and removes the stale socket
path. Failure of one profile LocalAPI server marks that profile failed rather
than terminating the daemon.

### Dynamic DNS policy

The supervisor owns exact DNS route bindings, profile-wide accept-all flags,
and the desired search-domain list. It builds a tiered longest-suffix-match DNS
plan from exact bindings, routes imported from accept-all profiles, and
unambiguous automatic MagicDNS routes. The most-specific desired exact binding
acts as either an installed route or a fail-closed waiting barrier. A lower
tier is considered only when no exact binding matches.

MagicDNS routes terminate in tailmix's aggregate authoritative resolver.
Split-DNS and accepted default/fallback resolution terminate in profile-scoped
forwarders that reuse Tailscale's resolver behavior with dials bound to the
selected engine. A single shared dialer cannot be used because resolver IPs can
overlap between profiles.

The installed search-domain subset is derived from that effective DNS plan.
No covering DNS route produces `no_active_route`; an unresolved automatic
MagicDNS conflict produces `ambiguous_route`.

The DNS service configuration carries domains, records, and search domains
together. Its live `Configure` operation validates the complete next
configuration before calling the Tailscale DNS manager, so a failed search
policy update cannot partially replace routes or records. Installed domains
retain desired-list order even though authoritative route tables are otherwise
sorted for determinism.

### Dynamic IP route policy

The supervisor expands each active accept-all profile into its current approved
primary subnet routes, then validates exact IP bindings against each selected
profile's routes. It excludes direct Tailscale addresses and `/0` exit routes.
An exact requested prefix is usable when it is equal to or more specific than
an observed route. Expansion happens on every relevant netmap update, so future
advertisements are followed without changing persisted state.

The installed prefix table records a policy tier and route kind:

```text
effective peer address -> profile + canonical peer address
accepted subnet prefix -> profile, destination preserved
```

Lookup uses longest-prefix match over desired exact bindings before considering
the imported tier. A waiting exact binding is a fail-closed barrier. An exact
duplicate imported from multiple profiles is omitted as ambiguous rather than
relying on profile iteration order.

For a subnet packet, the outbound mapper selects the profile, translates the
shared host source to that profile's self address, and preserves the
destination for the profile engine. On return, it preserves the subnet source
and translates the profile self destination back to the shared host address.
Inbound subnet packets are admitted only when longest-prefix match pins their
source to the profile on which they arrived.

The selected profile engine may internally accept a covering route, but the
host receives only exact-bound prefixes and routes materialized by accept-all
policy. Those daemon policies remain authoritative even if the delegated
profile-local CLI changes its broad `accept-routes` preference.

### Dynamic TUN membership

The current TUN mux receives a fixed profile map and starts one inbound worker
per entry. It needs:

```text
AddProfile(profileID, tun)
RemoveProfile(profileID)
SetMapper(mapper)
```

Host-to-profile lookup should use an atomically replaced immutable profile map,
matching the existing immutable packet mapper approach. Each inbound worker has
a profile-scoped cancellation function. Removing a profile first withdraws its
aggregate routes and mapper entries, then removes it from the mux and cancels
the worker.

Worker errors are reported with both stable profile ID and current profile name
and isolated where possible. Host TUN failure remains global.

### Dynamic SOCKS routing

The current SOCKS router is immutable. The SOCKS server should hold an atomic
pointer to a newly validated router snapshot. New connections use the latest
snapshot; established connections continue through their selected engine until
they close or that profile is stopped. IP destinations consult the same
effective-peer and bound-prefix table as TUN mode. Domain destinations use the
DNS plan for resolution, then the resolved address must still select an
effective peer, installed IP binding, or accept-all import; a DNS binding alone
does not authorize an application route.

### Aggregate reconciliation

Every profile lifecycle change or relevant netmap update rebuilds one complete,
immutable aggregate plan from:

```text
persisted desired state + passive healthy profile snapshots + retained leases
```

The plan includes effective-IP leases, direct-peer and bound-subnet packet
mappings, host routes, DNS bindings and profile forwarders, records, installed
search domains, and the SOCKS routing snapshot. It is fully validated before
any live component changes.

Removing or disabling a profile follows this order:

1. Persist the new desired state.
2. Rebuild and apply an aggregate plan that excludes the profile.
3. Detach its aggregate packet or SOCKS path.
4. Stop its LocalAPI server, watcher, TUN, and engine.

Adding or enabling follows this order:

1. Validate and persist the new desired state.
2. Create the runtime and start the engine.
3. Attach its watcher, LocalAPI server, and TUN or SOCKS runtime.
4. Reconcile it into the aggregate plan once passive status is usable.

The desired state is written first so a daemon crash converges correctly after
restart. If startup fails, the enabled profile remains configured with
`runtimeState: error`; healthy profiles continue and a later `restart` or daemon
restart retries it. Removing a profile is similarly durable even if teardown
reports an error.

Live plan application may briefly drop packets during route changes, but it
must never send a packet through the wrong profile.

## Persistent state

Persist the stable identity, local name, lifecycle flags, and existing engine
configuration:

```go
type State struct {
    // Existing fields...
    IPRouteBindings []IPRouteBinding `json:"ipRouteBindings,omitempty"`
    DNSRouteBindings []DNSRouteBinding `json:"dnsRouteBindings,omitempty"`
    SearchDomains []string `json:"searchDomains,omitempty"`
}

type IPRouteBinding struct {
    Prefix string `json:"prefix"`
    ProfileID string `json:"profileId"`
}

type DNSRouteBinding struct {
    Domain string `json:"domain"`
    ProfileID string `json:"profileId"`
}

type Profile struct {
    ID string `json:"id"`
    Name string `json:"name"`
    Disabled bool `json:"disabled,omitempty"`
    Removed bool `json:"removed,omitempty"`
    AcceptAllRoutes bool `json:"acceptAllRoutes,omitempty"`
    AcceptAllDNSRoutes bool `json:"acceptAllDnsRoutes,omitempty"`
    // Existing engine configuration fields...
}
```

On migration, an existing profile keeps its `ID`, gets `Name = ID`, and ignores
the legacy `Alias` for selection. New profiles receive daemon-generated opaque
IDs. Using `Disabled` rather than `Enabled` makes existing stored profiles
enabled after upgrade. A removed profile remains as a tombstone until purge so
its ID, state directory, and leases can be recovered. Runtime state and errors
are observational and are not persisted.

Route binding slices are normalized desired policy keyed by stable profile ID;
profile names are never persisted in a binding. Exact prefixes and domains are
unique, and slices are serialized in canonical order for stable diffs.
Accept-all flags live on the stable profile definition and survive rename,
disable, reversible removal, resurrection, and daemon restart. They default to
false during migration, so an upgrade never begins importing subnet or
split-DNS routes.
`SearchDomains` is the normalized desired order. Installed, available, and
waiting state is derived from desired policy plus live profile observations, so
those observations are not persisted.

The daemon remains the only state writer after startup. Startup `--profile`
flags can remain as a compatibility bootstrap, but should be documented as
deprecated once `profiles add` is available. A flag-supplied `id` maps to the
legacy profile ID during migration and is merged into desired state before the
supervisor starts. The legacy `alias` field is not carried into the new CLI.

Auth key material is never added to `state.State`.

## Implementation slices

### Slice 1: management reads and lifecycle foundation

- Add control socket client/server packages.
- Add `tailmix profiles list` and `show`.
- Add passive per-profile status and per-profile errors.
- Introduce the supervisor and permanent update stream while preserving static
  startup behavior.

### Slice 2: live membership

- Make LocalAPI servers, TUN mux membership, and SOCKS router snapshots dynamic.
- Add `profiles add`, `enable`, `disable`, `restart`, and non-purging `remove`.
- Reconcile incomplete and failed profiles without global failure.

### Slice 3: live routing policy

- Expose approved primary subnet routes and netmap DNS routes in passive profile
  snapshots.
- Add IP route binding commands, resources, longest-prefix matching, and
  dynamic host-route installation.
- Add DNS route binding commands, resources, longest-suffix matching, and
  profile-scoped DNS forwarding.
- Add profile-wide accept-all flags that continuously import current and future
  IP or DNS routes without importing search domains.
- Add `dns search` commands and control endpoints, deriving installation from
  the effective DNS route plan.
- Carry all three policies through TUN, SOCKS, and DNS aggregate
  reconciliation without restarting a profile.

### Slice 4: configuration and destructive cleanup

- Add `profiles rename` and `set`.
- Add guarded `remove --purge`.
- Deprecate routine use of startup `--profile` flags.
- Add a daemon-wide operator policy if non-root mutation is required.

## Validation

Unit tests should cover:

- Strict separation of command namespaces from profile-name operands.
- Exact argument and behavior parity between `tailscale` and its `ts` alias.
- Deprecation errors for the old ambiguous delegation grammar.
- Profile-name changes preserving stable ID, leases, state path, and socket.
- Profile names never being DNS-normalized or used as device hostnames.
- Human and JSON output from the same API resource.
- IP prefix normalization, atomic bind/unbind, intentional re-pinning, and
  optional-profile unbind preconditions.
- Enabling and disabling accept-all without removing exact bindings, including
  automatic import and withdrawal after netmap updates.
- Binding persistence by stable profile ID across profile rename, disable,
  removal, resurrection, and daemon restart.
- Installation only when a selected profile has an approved covering primary
  subnet route; withdrawn routes remain desired and fail closed.
- Longest-prefix selection for overlapping bindings to different profiles,
  including inbound source/profile validation.
- Exclusion of default routes and daemon-reserved address ranges.
- No unbound subnet route becoming host-reachable when a profile engine
  internally enables accept-routes.
- Exact IP bindings overriding accept-all imports, with identical imports from
  multiple profiles failing as ambiguous.
- DNS suffix normalization, atomic bind/unbind, and longest-suffix selection
  for nested bindings to different profiles.
- Automatic routing only for unambiguous MagicDNS suffixes, with ambiguous
  suffixes waiting for an explicit binding.
- Split-DNS routes requiring an exact binding or accept-all policy and
  forwarding UDP, TCP, and DoH through the selected profile even when resolver
  IPs overlap.
- DNS accept-all importing MagicDNS, split, and default/fallback resolution but
  never the profile's search-domain list.
- Exact DNS bindings overriding accept-all imports, with identical imports from
  multiple profiles failing as ambiguous.
- DNS bindings not creating application routes for returned IP addresses.
- Search-domain normalization, stable ordering, deduplication, and atomic
  set/add/remove/clear operations.
- Search-domain installation only when covered by an effective DNS route.
- Automatic withdrawal and restoration as the covering profile stops and
  starts, without changing desired policy.
- OS DNS configuration receiving search and match domains as separate fields.
- Auth key environment/file resolution without secret output or persistence.
- State migration from legacy ID/alias fields and an absent `disabled` field.
- Idempotent enable and disable transitions.
- Add conflict, missing profile, and invalid transition error codes.
- Per-profile startup, watcher, status, and shutdown failure isolation.
- Dynamic LocalAPI socket creation and removal.
- Dynamic TUN add/remove under concurrent packet lookup, including race tests.
- Atomic SOCKS router replacement.
- Lease retention on remove and deletion only on confirmed purge.
- Removed-profile resurrection preserving the prior stable ID and leases.
- Exit-node selection clearing when its profile is removed.
- Purge path containment and shared-directory rejection.

Integration tests should start two fake profile engines and prove:

1. A third profile can be added and becomes routable without restarting the
   daemon.
2. Removing that profile withdraws only its routes and DNS records.
3. Existing traffic and status for the original profiles remain available.
4. A profile that needs login or fails startup does not prevent reconciliation.
5. Restarting the daemon reproduces the last requested enabled/disabled set.
6. Updating search domains changes OS DNS configuration without restarting the
   daemon or any profile.
7. Binding overlapping private prefixes to different profiles routes each
   destination by longest prefix and withdraws only the affected binding when
   an advertisement disappears.
8. Binding the same split-DNS suffix to one of two tailnets with overlapping
   resolver addresses sends queries only through the selected profile.
9. Renaming a profile leaves its IP and DNS bindings installed under the new
   display name.
10. Enabling accept-all on one profile follows newly advertised subnet and DNS
    routes live; disabling it withdraws only imported routes and keeps exact
    bindings.

The final validation target is:

```text
go test -race ./...
```
