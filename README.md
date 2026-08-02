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
tailmix version
tailmixd --version
tailmix status
tailmix ts --profile work status
```

If the version prints, `work` is listed, and the final command shows the
tailnet, you are done.

To connect another tailnet, repeat step 2 with a different profile name.

## Common next steps

List everything before changing policy:

```sh
tailmix routes list
tailmix exit-node list
tailmix dns routes list
tailmix dns search list
```

`tailmix status` summarizes the policy currently selected from every active
profile. It includes accepted IP routes, the selected exit node, effective DNS
routes, and configured DNS search domains without listing every available
choice.

Like Tailscale's CLI, `tailmix exit-node list` collapses located nodes to the
highest-priority node per city and adds an **Any** row for countries with
multiple cities. Use `tailmix exit-node list --filter Canada` to show every
node in one country.

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

Enable Tailscale SSH on one profile:

```sh
sudo tailmix ts --profile work set --ssh
```

The tailnet must also have Tailscale SSH enabled and grant access to the node in
its access-control policy.

Route a DNS suffix through a profile, then make it a search domain so short
names such as `printer` can expand to `printer.corp.example.com`:

```sh
sudo tailmix dns routes bind --profile work corp.example.com
sudo tailmix dns search add corp.example.com
```

Explicit bindings override profile-wide accept-all settings. Changes apply
without restarting `tailmixd`.

Run `tailmix help` for every command. `-p` is shorthand for `--profile`
everywhere. Status and other read-only commands work as a regular local user;
commands that change daemon-managed state require root.

## How it works

`tailmixd` runs one embedded Tailscale node per profile and connects them to one
host TUN. It gives overlapping tailnet addresses stable local addresses, then
uses your route and DNS bindings to choose the right profile. `tailmix` changes
that policy through a local socket, so adding profiles or changing bindings
does not restart unrelated profiles.

One exit node can be selected across all profiles. Direct peer and accepted
subnet routes remain profile-specific and take precedence over that default.
The selected exit-node profile also supplies DNS for otherwise-unmatched names.
More-specific DNS routes, including automatic MagicDNS zones, keep precedence.
An explicitly bound root (`.`) replaces the exit-node DNS default and remains
configured when the exit node is changed or cleared.

## More information

- [Linux service setup and troubleshooting](docs/linux-install.md)
- [Profile, route, exit-node, and DNS command reference](docs/profile-management.md)
- [Architecture](docs/architecture.md)
- [Development workflows](DEVELOPMENT.md)

## License

Except for the forked source under `tsnet/` and `netns/`, the contents of this
repository are available under the BSD 3-Clause License. See
[LICENSE](LICENSE). The [`tsnet` fork](tsnet/README.md) and
[`netns` fork](netns/README.md) record their exact upstream sources and why
tailmix carries them. They retain Tailscale's copyright and licenses in
[tsnet/LICENSE](tsnet/LICENSE) and [netns/LICENSE](netns/LICENSE). The linked
Go dependency license report is generated with `go-licenses`; see
[licenses/tailmix.md](licenses/tailmix.md) and
[licenses/README.md](licenses/README.md).
