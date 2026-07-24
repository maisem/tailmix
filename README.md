# tailmix

tailmix connects one host to multiple Tailscale tailnets at the same time.

It runs one independent `tsnet.Server` per profile and exposes them through a
shared host TUN. tailmix assigns every visible peer a stable local effective
address and translates packets at the profile boundary. MagicDNS is served at
`100.100.100.100` inside the shared TUN using Tailscale's DNS manager and
resolver.

Most Tailscale functionality comes directly from the published
[`tailscale.com`](https://pkg.go.dev/tailscale.com) Go module. The repository
contains a focused [tsnet fork](tsnet/README.md) so tailmix can attach Tailscale's
native `ipnserver` to each embedded profile.

## Status

The TUN implementation supports macOS and Linux. Direct node routes, IPv4/IPv6
effective addresses, interactive login, auth-key login, shared-node FQDNs, and
MagicDNS are implemented. Profiles, selected subnet routes, split-DNS routes,
and OS search domains can be changed through the local control API without
restarting the daemon. Exact route bindings are explicit, fail-closed
overrides of profile-wide accept-all imports. tailmix watches every profile
for netmap updates and reconciles host routes, packet mappings, and DNS state
when peers or advertised routes change. Exit nodes are not yet supported.

## Build

Go 1.26.4 or newer is required.

```sh
go build -o /tmp/tailmixd ./cmd/tailmixd
go build -o /tmp/tailmix ./cmd/tailmix
```

## Run on macOS

Disconnect the regular Tailscale client first, then run tailmix as root. Zero
profiles is a valid starting state:

```sh
unset TS_AUTHKEY TS_AUTH_KEY

sudo /tmp/tailmixd \
  -state /var/db/tailmix/state.json \
  -synthetic-pool 10.250.0.0/16
```

Add profiles through the live CLI, then use the profile-local Tailscale
namespace for interactive login:

```sh
sudo /tmp/tailmix profiles add work
sudo /tmp/tailmix profiles add home
sudo /tmp/tailmix ts --profile work up
sudo /tmp/tailmix ts --profile home up
```

Existing profiles reuse their persisted login state. For unattended login,
pass `--auth-key-env` or `--auth-key-file` to `profiles add`; the resolved key
is used once and is not persisted.

Each profile also gets a credential-authenticated LocalAPI socket. The `tailmix`
CLI selects one and delegates the remaining arguments to Tailscale's upstream
CLI implementation:

```sh
sudo /tmp/tailmix ts --profile work status
sudo /tmp/tailmix ts --profile home ping peer.home.example
sudo /tmp/tailmix ts --profile work set --shields-up
```

Route policy is managed separately from profile names and delegated Tailscale
commands:

```sh
sudo /tmp/tailmix routes bind --profile work 10.20.0.0/16
sudo /tmp/tailmix routes set --profile home --accept-all=true
sudo /tmp/tailmix dns routes bind --profile work corp.example.com
sudo /tmp/tailmix dns search set corp.example.com
```

Use `tailmix help` for the complete subcommand space. Route listings mark
enabled entries with `✓` and retain details for waiting, ambiguous, and
overridden state.

Use `sudo /tmp/tailmix status` for one aggregate view of profile health, IP
routes, DNS routes, and OS search-domain state. Add `--json` for structured
output.

The sockets default to `/var/run/tailmix`. If `tailmixd` uses `-socket-dir`, set
`TAILMIX_SOCKET_DIR` to the same directory when invoking `tailmix`. Access uses
Tailscale's normal peer-credential and operator permission checks.

`-synthetic-pool` selects the IPv4 CIDR used for every peer's effective address
and the shared host-side NAT address. Choose a range that does not overlap local
routes. The value is persisted in daemon state, so it only needs to be supplied
when setting or changing the pool. `-synthetic-pool-v6` provides the equivalent
IPv6 setting. Changing either pool retires that family's leases and NAT address.
MagicDNS remains at `100.100.100.100`.

Remote logtail upload is disabled by default in tailmix's tsnet fork. Pass
`-log-upload` to opt in. `-log-upload-url URL` replaces the default upload base
URL and requires `-log-upload`; local user and verbose logging are unaffected.

See [docs/darwin-testing.md](docs/darwin-testing.md) for verification steps,
[docs/architecture.html](docs/architecture.html) for the implementation
architecture, [docs/design.md](docs/design.md) for the design semantics, and
[docs/profile-management.md](docs/profile-management.md) for the live profile
lifecycle CLI and daemon control API.

## Run on Linux

Build and invoke tailmixd with the same flags shown above. The default interface
name is `tailmix0`; creating it and installing routes requires root or
`CAP_NET_ADMIN`. MagicDNS uses Tailscale's native Linux DNS configurator, which
selects the host's systemd-resolved, NetworkManager, resolvconf, or direct
`resolv.conf` integration. Disconnect a regular Tailscale client first if its
routes would overlap tailmix's.

## License

tailmix's original code is available under the BSD 3-Clause License. See
[LICENSE](LICENSE). The copied tsnet source retains Tailscale's copyright and
license in [tsnet/LICENSE](tsnet/LICENSE). The linked Go dependency license
report is generated with `go-licenses`; see [licenses/tailmix.md](licenses/tailmix.md)
and [licenses/README.md](licenses/README.md).
