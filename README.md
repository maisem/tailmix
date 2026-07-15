# tailmix

tailmix connects one host to multiple Tailscale tailnets at the same time.

It runs one independent `tsnet.Server` per profile and exposes them through a
shared host TUN. tailmix assigns every visible peer a stable local effective
address and translates packets at the profile boundary. MagicDNS is served at
`100.100.100.100` inside the shared TUN using Tailscale's DNS manager and
resolver.

The repository contains only tailmix code. It depends directly on the published
[`tailscale.com`](https://pkg.go.dev/tailscale.com) Go module; it does not vendor
or patch the Tailscale repository.

## Status

The TUN implementation supports macOS and Linux. Direct node routes, IPv4/IPv6
effective addresses, interactive login, auth-key login, shared-node FQDNs, and
MagicDNS are implemented. tailmix watches every profile for netmap updates and
reconciles host routes, packet mappings, and DNS records when peers appear,
change, or disappear. Subnet routes and exit nodes are not yet supported.

## Build

Go 1.26.4 or newer is required.

```sh
go build -o /tmp/tailmixd ./cmd/tailmixd
```

## Run on macOS

Disconnect the regular Tailscale client first, then run tailmix as root with a
separate state directory for each profile:

```sh
unset TS_AUTHKEY TS_AUTH_KEY

sudo /tmp/tailmixd \
  -state /var/db/tailmix/state.json \
  -synthetic-pool 10.250.0.0/16 \
  -profile id=work \
  -profile id=home
```

Open each interactive login URL as it appears. Existing profiles reuse their
persisted login state. For unattended login, configure a distinct
`auth-key-env` for each profile.

`-synthetic-pool` selects the IPv4 CIDR used for every peer's effective address
and the shared host-side NAT address. Choose a range that does not overlap local
routes. The value is persisted in daemon state, so it only needs to be supplied
when setting or changing the pool. `-synthetic-pool-v6` provides the equivalent
IPv6 setting. Changing either pool retires that family's leases and NAT address.
MagicDNS remains at `100.100.100.100`.

See [docs/darwin-testing.md](docs/darwin-testing.md) for verification steps,
[docs/architecture.html](docs/architecture.html) for the implementation
architecture, and [docs/design.md](docs/design.md) for the design semantics.

## Run on Linux

Build and invoke tailmixd with the same flags shown above. The default interface
name is `tailmix0`; creating it and installing routes requires root or
`CAP_NET_ADMIN`. MagicDNS uses Tailscale's native Linux DNS configurator, which
selects the host's systemd-resolved, NetworkManager, resolvconf, or direct
`resolv.conf` integration. Disconnect a regular Tailscale client first if its
routes would overlap tailmix's.

## License

tailmix is available under the BSD 3-Clause License. See [LICENSE](LICENSE).
Notices for third-party modules linked into distributed binaries are collected
in [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).
