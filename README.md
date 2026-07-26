# tailmix

tailmix connects one host to multiple Tailscale tailnets at the same time.

tailmix is an independent project and is not affiliated with, sponsored by, or
endorsed by Tailscale Inc. Tailscale is a registered trademark of Tailscale
Inc.

## Start here

You only need to install it, connect one profile, and check that it works.

Before starting, disconnect the regular Tailscale client. It can otherwise
compete with tailmix for routes and DNS.

### 1. Install and start tailmix

Choose your operating system.

**macOS**

```sh
brew tap maisem/tailmix https://github.com/maisem/tailmix.git
brew install --HEAD tailmix
sudo brew services start tailmix
```

**Linux with systemd**

From this repository checkout:

```sh
sudo make install-systemd
```

For Linux prerequisites and troubleshooting, see the
[systemd guide](docs/linux-install.md).

### 2. Connect your first tailnet

Pick a short profile name such as `work`:

```sh
sudo tailmix profiles add work
sudo tailmix ts --profile work up
```

Open the login link printed by the second command.

### 3. Check it

```sh
sudo tailmix status
sudo tailmix ts --profile work status
```

If `work` is listed and the second command shows the tailnet, you are done.

To connect another tailnet, repeat step 2 with a different profile name.

## Common next steps

List everything before changing policy:

```sh
sudo tailmix routes list
sudo tailmix exit-node list
sudo tailmix dns routes list
sudo tailmix dns search list
```

Accept every advertised subnet route and DNS route from one profile:

```sh
sudo tailmix routes set --profile work --accept-all=true
sudo tailmix dns routes set --profile work --accept-all=true
```

Pin one subnet to a profile:

```sh
sudo tailmix routes bind --profile work 10.20.0.0/16
```

Send default traffic through one exit node:

```sh
sudo tailmix exit-node set --profile work gateway
```

`gateway` may be the node's short hostname, full DNS name, stable node ID, or
Tailscale IP. Run `sudo tailmix exit-node clear` to return to the host's normal
default route.

Route a DNS suffix through a profile, then make it a search domain so short
names such as `printer` can expand to `printer.corp.example.com`:

```sh
sudo tailmix dns routes bind --profile work corp.example.com
sudo tailmix dns search add corp.example.com
```

Explicit bindings override profile-wide accept-all settings. Changes apply
without restarting `tailmixd`.

Run `tailmix help` for every command.

## How it works

`tailmixd` runs one embedded Tailscale node per profile and connects them to one
host TUN. It gives overlapping tailnet addresses stable local addresses, then
uses your route and DNS bindings to choose the right profile. `tailmix` changes
that policy through a local socket, so adding profiles or changing bindings
does not restart unrelated profiles.

One exit node can be selected across all profiles. Direct peer and accepted
subnet routes remain profile-specific and take precedence over that default.

## More information

- [Linux service setup and troubleshooting](docs/linux-install.md)
- [Profile, route, exit-node, and DNS command reference](docs/profile-management.md)
- [Architecture](docs/architecture.md)
- [Development workflows](DEVELOPMENT.md)

## License

Except for the forked source under `tsnet/`, the contents of this repository
are available under the BSD 3-Clause License. See [LICENSE](LICENSE). The
`tsnet` fork retains Tailscale's copyright and license in
[tsnet/LICENSE](tsnet/LICENSE). The linked Go dependency license report is
generated with `go-licenses`; see [licenses/tailmix.md](licenses/tailmix.md) and
[licenses/README.md](licenses/README.md).
