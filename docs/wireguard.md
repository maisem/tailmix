# Raw WireGuard profiles

tailmix can run a userspace WireGuard interface as a profile alongside its
Tailscale profiles. Raw WireGuard profiles are available in TUN mode. They do
not provide Tailscale coordination, DERP, or control-plane ACL distribution,
but they can enforce a local per-profile packet filter at the userspace TUN
boundary.

Each profile is one versioned YAML file. Packet filters remain part of
`version: 1`:

```yaml
version: 1
name: lab
dnsSuffix: lab.example
addresses:
  - 10.80.0.1
  - fd80::1
# listenPort: 51820
# privateKeyFile: ./lab.key
packetFilter:
  grants:
    - src: [peer:gateway, 10.90.0.0/16]
      dst: [self]
      ip: [tcp:22, udp:53, "icmp:*"]
peers:
  - name: gateway
    publicKey: AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
    # presharedKeyFile: ./gateway.psk
    endpoint: gateway.example.net:51820
    keepalive: 25s
    addresses:
      - 10.80.0.2
      - fd80::2
    routes:
      - 10.90.0.0/16
    exitNode: true
```

Replace the example public key and generate optional preshared keys with your
usual WireGuard tools. `name` is both the stable peer identity in the profile
and its DNS label, so this peer is published as `gateway.lab.example`. Peer
addresses receive tailmix effective addresses when necessary, just like
addresses from Tailscale profiles.

Apply and inspect the profile with:

```sh
sudo tailmix wireguard apply --file ./lab.yaml
tailmix wireguard show lab
tailmix wireguard show lab --json
```

Relative key paths are resolved from the YAML file's directory. If
`privateKeyFile` is omitted, tailmix generates and persists a managed private
key. Reapplying the file reconciles peers, keys, endpoints, keepalives,
addresses, routes, and packet policy on the running WireGuard device without
recreating its TUN. Removing `presharedKeyFile` from a peer clears that peer's
preshared key.

Apply validates and resolves the complete request, compiles its packet policy,
and saves the new desired configuration and secrets before live mutation. The
runtime then installs an outbound-only transition and applies changes forward.
If WireGuard UAPI or aggregate host reconciliation fails after mutation starts,
tailmix returns that failure and leaves the profile fail-closed; it does not
issue inverse UAPI or reconstruct the previous mapper, routes, or filter. Status
reports that runtime may differ from saved desired state. Reapply the manifest
or restart the daemon to retry device convergence; normal reconciliation
retries aggregate host networking. A newly started profile also remains on the
restrictive transition until its first aggregate reconciliation succeeds.

## Packet-filter behavior

Packet filters are unordered, additive allow grants for new inbound traffic.
Outbound traffic is always permitted. Replies to locally initiated UDP and
SCTP flows, TCP continuation packets, and ICMP responses follow the same
stateful behavior as Tailscale's userspace filter.

An omitted or null `packetFilter`, and an omitted, null, or empty `grants`
array, all normalize to:

```yaml
packetFilter:
  grants: []
```

That empty policy is outbound-only: it rejects new inbound connections. This is
an intentional security tightening for raw profiles created before packet
filters existed. Review and add explicit grants before upgrading a host that
must continue accepting inbound traffic. Older tailmix binaries reject a
manifest containing `packetFilter`; they do not silently ignore it.

Every grant requires non-empty `src`, `dst`, and `ip` arrays. Unknown fields,
selectors, peer names, protocols, or malformed ports reject the complete apply
before runtime or persisted state changes.

### Source selectors

| Selector | Meaning |
| --- | --- |
| `*` | Any source currently authenticated by this profile's WireGuard AllowedIPs |
| `peer:*` | Direct addresses of every peer |
| `peer:<name>` | Direct addresses of one peer |
| `routes:*` | Non-default routes declared by every peer |
| `routes:<name>` | Non-default routes declared by one peer |
| IP or CIDR | Address-based policy intersected with authenticated source ownership |

WireGuard's longest-prefix AllowedIPs ownership applies. When peer routes
overlap, a named route selector only includes the portions still owned by that
peer after more-specific routes are subtracted. Equal-prefix ownership by two
peers is invalid. Literal `/0` source selectors are invalid; use `*`.

### Destination selectors

| Selector | Meaning |
| --- | --- |
| `self` | This profile's canonical local addresses |
| `*` | Every destination class available to the profile |
| `peer:*`, `peer:<name>` | Peer-address transit destinations |
| `routes:*`, `routes:<name>` | Routed transit destinations |
| `internet` | Default-path transit destinations |
| IP or CIDR | An explicit destination range |

Only `self` delivery is currently available. Other valid destination selectors
remain in normalized desired state but compile no allow match until forwarding
exists. `tailmix wireguard show` reports each destination selector as `active`,
`partial`, or `inactive`; unavailable transit uses the stable reason
`forwarding_unavailable`. `*` and a CIDR that includes both self and non-self
space are therefore partial today. Literal destination `/0` selectors are
invalid; use `*` or `internet`.

### IP permissions

Permissions use these forms:

```text
*
<protocol>:*
<port-protocol>:<port>
<port-protocol>:<start>-<end>
<port>
<start>-<end>
```

Bare ports and ranges expand to both TCP and UDP. TCP, UDP, and SCTP accept
ports. DCCP, ICMP, IPv6 ICMP, IGMP, GRE, ESP, AH, EGP, IGP, and IPv4-in-IPv4 are
portless and require `:*`. Numeric protocol IDs 1 through 254 are accepted
except Tailscale's reserved protocol 99; numeric TCP, UDP, and SCTP may carry
ports. Ports are decimal 0 through 65535 and ranges must ascend. Names and
keywords are lowercase.

## Shields-up override

Shields-up persistently suppresses all configured grants without changing the
YAML:

```sh
sudo tailmix wireguard shields-up lab on
sudo tailmix wireguard shields-up lab off
```

It remains mutable while the profile is disabled, stopped, failed, or while the
daemon is globally down. It survives restarts, disable/enable cycles, global
down/up, and later YAML applies. Removing the profile clears it. Enabling it
still permits outbound traffic and replies to locally initiated traffic.

The daemon publishes an enabling restrictive filter before persisting the
setting. It persists a disable before publishing the restored grant filter, so
a failed state write remains fail-closed. `tailmix status` and
`tailmix wireguard show` report the current override.

## Routes and exit nodes

`routes` only declares what a peer can route. Select those routes through the
normal tailmix policy commands:

```sh
sudo tailmix routes bind --profile lab 10.90.0.0/16
sudo tailmix routes set --profile lab --accept-all=true
```

Likewise, `exitNode: true` declares eligibility but does not select the peer:

```sh
sudo tailmix exit-node set --profile lab gateway
sudo tailmix exit-node clear
```

Default routes are not accepted in `routes`; use `exitNode` and the tailmix
exit-node policy instead. Raw profile endpoint traffic bypasses a selected
full-tunnel route so the WireGuard transport does not recursively enter itself.
