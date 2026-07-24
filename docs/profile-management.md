# Live Profile Management

Status: Proposed

Date: 2026-07-23

## Summary

tailmix should manage its configured profile set through a daemon-owned local
control API. The `tailmix` CLI should use that API for profile lifecycle
commands while continuing to send profile-local Tailscale commands to the
selected profile's existing LocalAPI socket.

The proposed command shape is:

```text
tailmix profile list
tailmix profile show <profile>
tailmix profile add <profile> [options]
tailmix profile set <profile> [options]
tailmix profile enable <profile>
tailmix profile disable <profile>
tailmix profile restart <profile>
tailmix profile remove <profile> [--purge --yes]
```

Existing commands remain compatible:

```text
tailmix work status
tailmix home ping peer.home.example
```

The explicit equivalent is available when a profile ID or future top-level
command would otherwise be ambiguous:

```text
tailmix tailscale work status
```

Profile changes are persisted and applied to the running daemon. Restarting one
profile is allowed when its engine configuration changes, but adding, changing,
or removing a profile must not restart the daemon or disrupt other profiles.

## Goals

- Add and remove profiles without restarting `tailmixd`.
- Start, stop, and restart one profile without affecting the others.
- Persist every successful requested configuration change.
- Keep the existing profile-prefixed Tailscale CLI behavior.
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
- Guarantee uninterrupted flows through the profile being stopped or
  restarted. Other profiles must remain uninterrupted.

## CLI

### Command namespaces

`profile` is the tailmix management namespace. All other first positional
arguments continue to be treated as profile IDs for compatibility:

```text
tailmix profile list
tailmix <profile> <tailscale-subcommand> [arguments]
```

`tailscale` is an explicit delegation namespace:

```text
tailmix tailscale <profile> <tailscale-subcommand> [arguments]
```

This provides an escape hatch for an existing profile whose ID is `profile`,
`tailscale`, or the name of another future top-level command. The shorthand
remains the documented form for ordinary profile IDs.

Global CLI options must precede the namespace; command-specific options follow
their command:

```text
tailmix --socket-dir /var/run/tailmix profile list
tailmix --socket-dir /var/run/tailmix profile show work --json
```

`TAILMIX_SOCKET_DIR` remains supported. `--socket-dir` takes precedence and
selects both the daemon control socket and per-profile LocalAPI sockets.

Profile operands select the immutable profile ID. Aliases remain mutable
display metadata in the first version; they are not alternate selectors. This
keeps delegation possible from the profile ID and deterministic socket path
alone.

### `profile list`

```text
tailmix profile list [--json]
```

The human-readable output is stable enough for people, not scripts:

```text
PROFILE  ENABLED  RUNTIME      TAILNET          PEERS  ERROR
home     yes      running      home.ts.net      14
lab      no       disabled
work     yes      needs-login                  0
```

JSON is the scripting interface. Profiles are sorted by ID in both formats.
Listing is a non-blocking snapshot and never waits for a profile to become
online.

### `profile show`

```text
tailmix profile show <profile> [--json]
```

The result includes:

- Persisted configuration: ID, alias, state directory, hostname, control URL,
  and enabled state.
- Runtime state and last lifecycle error.
- Tailscale backend state, login URL, tailnet suffix, self DNS name and
  addresses, peer count, and shields-up state when available.
- The profile LocalAPI socket path when the engine is running.

An auth key is never returned.

### `profile add`

```text
tailmix profile add <profile> \
  [--alias <alias>] \
  [--hostname <hostname>] \
  [--state-dir <directory>] \
  [--control-url <url>] \
  [--auth-key-env <name> | --auth-key-file <path|->] \
  [--disabled] \
  [--json]
```

Defaults match current daemon startup behavior:

- Alias defaults to the profile ID.
- State directory defaults to `<daemon-state-dir>/profiles/<profile>`.
- Hostname defaults to `tailmix-<dns-safe-profile-id>`.
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
Run: tailmix work up
```

`add` fails with a conflict if the ID is already configured. Re-adding a
previously removed ID reuses its default state directory and retained
effective-IP leases unless that profile was purged.

### `profile set`

```text
tailmix profile set <profile> \
  [--alias <alias>] \
  [--hostname <hostname>] \
  [--control-url <url>] \
  [--json]
```

ID and state directory are immutable after creation. Moving identity state is a
separate, offline administrative operation and should not be hidden inside a
live update.

An alias-only change is applied by aggregate metadata reconciliation. Changing
hostname or control URL restarts only the selected profile after persisting the
new desired configuration. The command reports that brief profile-local
disruption before applying it.

### `profile enable`, `disable`, and `restart`

```text
tailmix profile enable <profile>
tailmix profile disable <profile>
tailmix profile restart <profile>
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

### `profile remove`

```text
tailmix profile remove <profile>
tailmix profile remove <profile> --purge --yes
```

The default operation is deliberately reversible:

1. Remove the profile from persisted configuration.
2. Withdraw its live routes and DNS records.
3. Stop its API listener, watcher, packet path, and engine.
4. Retain its identity state directory and effective-IP leases.

If the profile is the selected exit-node profile, removal also clears that
selection.

`--purge` additionally deletes only that profile's resolved state directory and
effective-IP leases. It requires an interactive confirmation, or `--yes` for
non-interactive use. The daemon must reject purge if the state directory is
empty, is a parent of the daemon state file, is shared by another profile, or
does not resolve beneath an explicitly allowed profile-state root. Partial
purge failure leaves the profile removed but reports which retained data could
not be deleted.

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
  "profileId": "work"
}
```

Initial codes should include `invalid_request`, `profile_exists`,
`profile_not_found`, `profile_disabled`, `transition_in_progress`,
`permission_denied`, `runtime_start_failed`, `reconcile_failed`, and
`purge_failed`.

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
GET    /v1/profiles/{escaped-profile-id}
PATCH  /v1/profiles/{escaped-profile-id}
POST   /v1/profiles/{escaped-profile-id}/enable
POST   /v1/profiles/{escaped-profile-id}/disable
POST   /v1/profiles/{escaped-profile-id}/restart
DELETE /v1/profiles/{escaped-profile-id}?purge=false
```

Mutations are serialized by the daemon lifecycle loop. A response is sent only
after the desired state has been persisted and the corresponding live
transition has completed or failed.

The profile resource separates desired state from observed state:

```json
{
  "id": "work",
  "alias": "work",
  "stateDir": "/var/db/tailmix/profiles/work",
  "hostname": "tailmix-work",
  "controlUrl": "",
  "enabled": true,
  "runtimeState": "running",
  "backendState": "Running",
  "magicDnsSuffix": "example.ts.net",
  "selfDnsName": "tailmix-work.example.ts.net",
  "selfIps": ["100.64.0.10", "fd7a:115c:a1e0::10"],
  "peerCount": 12,
  "shieldsUp": false,
  "authUrl": "",
  "localApiSocket": "/var/run/tailmix/work-abc123.sock",
  "lastError": ""
}
```

`runtimeState` is one of `disabled`, `starting`, `needs-login`, `running`,
`stopping`, or `error`. It is tailmix lifecycle state; `backendState` is the
profile's upstream Tailscale state.

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
Only enabled profiles with a usable netmap, self address, and MagicDNS suffix
participate in the aggregate route and DNS plan. A profile in `needs-login` or
`error` remains inspectable and does not take down healthy profiles.

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

The current profile API group is a fixed slice. Store servers by profile ID and
support `Start(profile)` and `Stop(profile)`. Stopping closes the listener,
waits for the serving goroutine, and removes the stale socket path. Failure of
one profile LocalAPI server marks that profile failed rather than terminating
the daemon.

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

Worker errors are reported with the profile ID and isolated where possible.
Host TUN failure remains global.

### Dynamic SOCKS routing

The current SOCKS router is immutable. The SOCKS server should hold an atomic
pointer to a newly validated router snapshot. New connections use the latest
snapshot; established connections continue through their selected engine until
they close or that profile is stopped.

### Aggregate reconciliation

Every profile lifecycle change or relevant netmap update rebuilds one complete,
immutable aggregate plan from:

```text
persisted desired state + passive healthy profile snapshots + retained leases
```

The plan includes effective-IP leases, packet mappings, host routes, DNS
domains and records, and the SOCKS routing snapshot. It is fully validated
before any live component changes.

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

Add a backwards-compatible disabled marker:

```go
type Profile struct {
    // Existing fields...
    Disabled bool `json:"disabled,omitempty"`
}
```

Using `Disabled` rather than `Enabled` makes existing stored profiles enabled
after upgrade. Runtime state and errors are observational and are not
persisted.

The daemon remains the only state writer after startup. Startup `--profile`
flags can remain as a compatibility bootstrap, but should be documented as
deprecated once `profile add` is available. A flag-supplied profile is merged
into desired state before the supervisor starts, as it is today.

Auth key material is never added to `state.State`.

## Implementation slices

### Slice 1: management reads and lifecycle foundation

- Add control socket client/server packages.
- Add `tailmix profile list` and `show`.
- Add passive per-profile status and per-profile errors.
- Introduce the supervisor and permanent update stream while preserving static
  startup behavior.

### Slice 2: live membership

- Make LocalAPI servers, TUN mux membership, and SOCKS router snapshots dynamic.
- Add `profile add`, `enable`, `disable`, `restart`, and non-purging `remove`.
- Reconcile incomplete and failed profiles without global failure.

### Slice 3: configuration and destructive cleanup

- Add `profile set`.
- Add guarded `remove --purge`.
- Deprecate routine use of startup `--profile` flags.
- Add a daemon-wide operator policy if non-root mutation is required.

## Validation

Unit tests should cover:

- CLI management parsing, explicit delegation, and shorthand compatibility.
- Human and JSON output from the same API resource.
- Auth key environment/file resolution without secret output or persistence.
- State migration where an absent `disabled` field means enabled.
- Idempotent enable and disable transitions.
- Add conflict, missing profile, and invalid transition error codes.
- Per-profile startup, watcher, status, and shutdown failure isolation.
- Dynamic LocalAPI socket creation and removal.
- Dynamic TUN add/remove under concurrent packet lookup, including race tests.
- Atomic SOCKS router replacement.
- Lease retention on remove and deletion only on confirmed purge.
- Exit-node selection clearing when its profile is removed.
- Purge path containment and shared-directory rejection.

Integration tests should start two fake profile engines and prove:

1. A third profile can be added and becomes routable without restarting the
   daemon.
2. Removing that profile withdraws only its routes and DNS records.
3. Existing traffic and status for the original profiles remain available.
4. A profile that needs login or fails startup does not prevent reconciliation.
5. Restarting the daemon reproduces the last requested enabled/disabled set.

The final validation target is:

```text
go test -race ./...
```
