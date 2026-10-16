# tailmix

tailmix connects one Mac or Linux machine to multiple Tailscale tailnets at the
same time. Each tailnet gets its own profile, and you choose which routes, exit
node, and DNS each one provides.

Website: <https://tailmix.net>

tailmix is an independent project and is not affiliated with, sponsored by, or
endorsed by Tailscale Inc. Tailscale is a registered trademark of Tailscale
Inc.

## Install

Disconnect the regular Tailscale client first; it competes with tailmix for
routes and DNS.

1. Install and start tailmix (macOS, or Linux with systemd):

   ```sh
   curl -fsSL https://tailmix.net/install.sh | sudo sh
   ```

   This serves `install.sh` from the latest GitHub release. To read it first,
   run `curl -fLO https://tailmix.net/install.sh`, then `sudo sh install.sh`.

2. Log in to your first tailnet and open the link it prints:

   ```sh
   sudo tailmix ts login
   ```

   tailmix creates a profile named `default` for it.

3. Check it:

   ```sh
   tailmix status
   ```

   You are done when `default` is listed as running.

For Linux prerequisites and troubleshooting, see the
[Linux guide](docs/linux-install.md).

## Add another tailnet

```sh
sudo tailmix profiles add work
sudo tailmix ts -p work login
```

`tailmix ts` uses the only profile when there is one; with several, choose one
with `-p`. Rename the first profile with
`sudo tailmix profiles rename default home`.

## Routes and exit nodes

For each destination, tailmix uses the first match:

1. **Peers** are reached through the tailnet they belong to.
2. **Subnet routes** you accepted; the most specific one wins.
3. **The exit node**, if you selected one.
4. Otherwise, your normal network.

No subnet routes are accepted until you ask:

```sh
tailmix routes list --available                         # what each tailnet advertises
sudo tailmix routes set -p work --accept-all=true       # accept all of work's routes
sudo tailmix routes bind -p lab 10.20.0.0/16            # pin one prefix to lab
```

A pinned prefix overrides accept-all. If two tailnets advertise the same prefix
under accept-all, neither is used until you pin one.

Select one exit node from any tailnet:

```sh
tailmix exit-node list                                  # or: --filter Canada
sudo tailmix exit-node set -p home gateway
sudo tailmix exit-node clear
```

`gateway` may be a short hostname, full DNS name, stable node ID, or Tailscale
IP.

## DNS

Each tailnet's MagicDNS names work automatically. The exit node's tailnet
answers names no other route covers.

Use short names such as `ssh mybox` by adding a tailnet's MagicDNS suffix as a
search domain. `tailmix dns search list` shows each profile's suffix:

```sh
sudo tailmix dns search add example.ts.net
```

Add one suffix per tailnet; earlier entries win when a short name exists in
more than one.

Send another DNS suffix to a tailnet, optionally as a search domain too:

```sh
sudo tailmix dns routes bind -p work corp.example.com
sudo tailmix dns search add corp.example.com
sudo tailmix dns routes set -p work --accept-all=true   # or accept all of work's DNS routes
```

## Overlapping addresses

Two tailnets can use the same `100.x` address. tailmix gives every node and
Tailscale Service a stable local address from `100.127.0.0/16` (and
`fd6d:6e65:7400::/56` for IPv6), and rewrites packets as they enter and leave
each tailnet. MagicDNS names resolve to these local addresses, so connect by
name. Inside each tailnet, your machine still uses its own Tailscale address,
so ACLs work as usual.

## Everyday commands

```sh
tailmix status                     # what is running and selected
tailmix ts -p work ping printer    # any Tailscale CLI command, per profile
sudo tailmix ts -p work set --ssh  # enable Tailscale SSH for one profile
sudo tailmix down                  # pause every profile; survives reboots
sudo tailmix up                    # resume them
tailmix help                       # every command
```

Read-only commands work without `sudo`. Policy changes apply immediately
without restarting other profiles.

## Updates

Installs from `install.sh` update themselves: they check stable GitHub releases
daily, verify release checksums, and restart the daemon.

```sh
tailmix update status
sudo tailmix update apply
sudo tailmix update disable           # or: enable
```

Homebrew installs from source are updated by Homebrew instead.

## Shell completion

Homebrew installs completions automatically. Otherwise, load them in your shell:

```sh
source <(tailmix completion bash)     # Bash
source <(tailmix completion zsh)      # Zsh
tailmix completion fish | source      # fish
```

For PowerShell, run
`tailmix completion powershell | Out-String | Invoke-Expression`.

## Documentation

- [Linux guide](docs/linux-install.md)
- [Command reference: profiles, routes, exit nodes, DNS](docs/profile-management.md)
- [Raw WireGuard profiles](docs/wireguard.md)
- [Architecture](docs/architecture.md)
- [Development](DEVELOPMENT.md)

## License

BSD 3-Clause; see [LICENSE](LICENSE). The forks under [`tsnet/`](tsnet/README.md)
and [`netns/`](netns/README.md) keep Tailscale's copyright and licenses. The Go
dependency license report is in [licenses/](licenses/README.md).
