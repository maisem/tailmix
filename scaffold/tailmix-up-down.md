# `tailmix up` and `tailmix down`

## Goal

Add daemon-wide pause and resume commands. `tailmix down` must disconnect every profile without changing per-profile desired enablement. `tailmix up` must restore exactly the profiles whose persisted configuration is enabled. The down state must survive daemon and host restarts until explicitly cleared by `tailmix up`.

## CLI contract

- Add root commands `tailmix down` and `tailmix up`.
- Both commands are idempotent, accept no operands or options, and support the existing help spellings.
- Successful human output is `tailmix is down.` or `tailmix is up.`.
- Add both commands to root help and shell completion.
- `tailmix status` prints `STATE\tup|down` before the profile table; JSON status includes a top-level `state` field with the same value.
- While globally down, enabled profiles report runtime state `down`; explicitly disabled and removed profiles continue to report `disabled` and `removed`.
- Delegated `tailmix tailscale`/`tailmix ts` commands fail before socket access with `tailmix is down; run "tailmix up" first`.

## State and daemon behavior

- Persist a daemon-wide `down` boolean in `state.State` with `omitempty`. Existing state files therefore default to up.
- On daemon startup while down, start the aggregate control infrastructure but no profile runtimes. Reconcile an empty data plane so host routes, DNS configuration, exit-node routing, and packet mappings are withdrawn.
- `down` persists the fail-closed state, stops every Tailscale and WireGuard runtime, and reconciles the empty data plane. It does not alter profile `Disabled` flags, retained identities, bindings, or policy.
- `up` persists the active state, starts every non-disabled, non-removed profile using the existing startup path, and reconciles aggregate policy. Existing per-profile startup failures remain visible through profile status and do not prevent other profiles from starting.
- Repeating either action is a successful no-op that still returns the current daemon state.
- Once `down` has been persisted, a partial teardown error must leave the daemon logically down and return the error; a restart must not reconnect profiles unexpectedly.

## Mutation behavior while down

Reject these requests with control-API code `daemon_down` and message `tailmix is down; run "tailmix up" first`:

- `profiles add`, `rename`, `set`, `enable`, `disable`, `restart`, and `remove`
- `wireguard apply`

Profile reads remain available. Other management surfaces keep their existing behavior because policy and update configuration are not part of the profile restore set. Operations that require live profile observations continue to return their existing validation errors while down.

## Control API

- Add `controlapi.DaemonState` with `state: "up" | "down"`.
- Add root-only `POST /v1/up` and `POST /v1/down` mutation endpoints, following the existing action-endpoint style. Each returns `DaemonState`.
- Add a top-level `state` field to the aggregate status response.
- Extend the core backend, client, and CLI management interfaces with this single daemon lifecycle operation; do not introduce a parallel lifecycle model.

## Documentation

Update the README command examples/reference to explain that daemon-wide down preserves per-profile enablement and persists until up. Keep per-profile `profiles enable/disable` documented as the way to change the restore set.

## Verification

Cover:

- state JSON compatibility and round trips;
- control API routing, responses, and mutation authorization;
- startup in persisted down state;
- down stopping all profile kinds and withdrawing aggregate policy;
- up restoring only enabled, non-removed profiles;
- idempotent transitions and partial teardown/start failures;
- rejection of profile mutations while down;
- profile/status projections while down;
- CLI parsing, output, help, errors, and completion;
- full `make check`.
