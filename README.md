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

## How it works

`tailmixd` runs one independent embedded Tailscale node for each profile. Every
profile has its own identity, login state, preferences, netmap, and
credential-authenticated LocalAPI socket.

- A shared host TUN presents all selected peers and subnet routes to the
  operating system at once.
- Stable effective addresses prevent overlapping Tailscale CGNAT and ULA
  addresses from colliding across profiles. Packets are translated to and from
  each profile's canonical addresses at its boundary.
- Explicit route and DNS bindings choose a profile. Profile-wide accept-all
  settings import everything else advertised by that profile, while explicit
  bindings remain overrides.
- The DNS service merges the selected split-DNS routes and search domains, then
  forwards each query through the profile chosen for that suffix.
- `tailmix` updates desired profile and routing policy through a local control
  socket. The daemon reconciles those changes and live netmap updates without
  restarting unrelated profiles.

## Install

### Homebrew

Disconnect the regular Tailscale client before starting the service so its
routes and DNS configuration do not overlap Tailmix.

Until the first versioned release, install the current `main` branch and start
`tailmixd` automatically at system startup with:

```sh
brew tap maisem/tailmix git@github.com:maisem/tailmix.git
brew install --HEAD maisem/tailmix/tailmix && \
  sudo brew services start maisem/tailmix/tailmix
```

The repository is currently private, so this requires GitHub access and a
working SSH key. This installs both `tailmix` and `tailmixd`; the explicit
`sudo` authorizes Homebrew to register the root LaunchDaemon. Future updates are
installed with:

```sh
brew upgrade --fetch-HEAD maisem/tailmix/tailmix
```

The service stores daemon state under `$(brew --prefix)/var/lib/tailmix`, writes
logs to `$(brew --prefix)/var/log/tailmixd.log`, and uses the default
`/var/run/tailmix` socket directory. Root is required for the host TUN, routes,
DNS configuration, and system-startup service. Manage it with:

```sh
sudo brew services info maisem/tailmix/tailmix
sudo brew services restart maisem/tailmix/tailmix
sudo brew services stop maisem/tailmix/tailmix
```

For source builds and local installation, see [DEVELOPMENT.md](DEVELOPMENT.md).

## Run on macOS

The daemon can run with zero profiles. Add profiles through the live CLI, then
use the profile-local Tailscale namespace for interactive login:

```sh
sudo tailmix profiles add work
sudo tailmix profiles add home
sudo tailmix ts --profile work up
sudo tailmix ts --profile home up
```

For a non-default coordination server, use Tailscale's native login option:

```sh
sudo tailmix ts --profile work login \
  --login-server=https://headscale.example.com
```

The selected server and other native Tailscale preferences are stored in that
profile's Tailscale state and survive profile and daemon restarts.

Existing profiles reuse their persisted login state. For unattended login,
pass `--auth-key-env` or `--auth-key-file` to `profiles add`; the resolved key
is used once and is not persisted.

Each profile also gets a credential-authenticated LocalAPI socket. The `tailmix`
CLI selects one and delegates the remaining arguments to Tailscale's upstream
CLI implementation:

```sh
sudo tailmix ts --profile work status
sudo tailmix ts --profile home ping peer.home.example
sudo tailmix ts --profile work set --shields-up
```

Route policy is managed separately from profile names and delegated Tailscale
commands:

```sh
sudo tailmix routes bind --profile work 10.20.0.0/16
sudo tailmix routes set --profile home --accept-all=true
sudo tailmix dns routes bind --profile work corp.example.com
sudo tailmix dns search set corp.example.com
```

Use `tailmix help` for the complete subcommand space. Route listings use one
state column: `✓` marks enabled entries, while waiting, ambiguous, and
overridden entries retain diagnostic details.

Use `sudo tailmix status` for a concise list of active profiles and their
runtime health. Add `--json` for structured output.

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

Run `tailmixd` as root or with `CAP_NET_ADMIN`. The default interface name is
`tailmix0`; creating it and installing routes requires those privileges.
MagicDNS uses Tailscale's native Linux DNS configurator, which
selects the host's systemd-resolved, NetworkManager, resolvconf, or direct
`resolv.conf` integration. Disconnect a regular Tailscale client first if its
routes would overlap tailmix's.

## License

tailmix's original code is available under the BSD 3-Clause License. See
[LICENSE](LICENSE). The copied tsnet source retains Tailscale's copyright and
license in [tsnet/LICENSE](tsnet/LICENSE). The linked Go dependency license
report is generated with `go-licenses`; see [licenses/tailmix.md](licenses/tailmix.md)
and [licenses/README.md](licenses/README.md).
