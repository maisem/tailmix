# tailmix

tailmix connects one host to multiple Tailscale tailnets at the same time.

It runs one independent `tsnet.Server` per profile and exposes them through a
shared host TUN. When tailnets reuse the same canonical Tailscale address, tailmix
assigns stable local effective addresses and translates packets at the profile
boundary. MagicDNS is served at `100.100.100.100` inside the shared TUN using
Tailscale's DNS manager and resolver.

The repository contains only tailmix code. It depends directly on the published
[`tailscale.com`](https://pkg.go.dev/tailscale.com) Go module; it does not vendor
or patch the Tailscale repository.

## Status

The current TUN implementation targets macOS. Direct node routes, IPv4/IPv6
effective addresses, interactive login, auth-key login, shared-node FQDNs, and
MagicDNS are implemented. The route and DNS tables are startup snapshots;
restart tailmix after the visible peer set changes. Subnet routes and exit nodes
are not yet supported.

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
  -profile id=work \
  -profile id=home
```

Open each interactive login URL as it appears. Existing profiles reuse their
persisted login state. For unattended login, configure a distinct
`auth-key-env` for each profile.

See [docs/darwin-testing.md](docs/darwin-testing.md) for verification steps and
[docs/design.md](docs/design.md) for the architecture and semantics.

## License

tailmix is available under the BSD 3-Clause License. See [LICENSE](LICENSE).
Notices for third-party modules linked into distributed binaries are collected
in [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).
