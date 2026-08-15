# Raw WireGuard profiles

tailmix can run a userspace WireGuard interface as a profile alongside its
Tailscale profiles. Raw WireGuard profiles are available in TUN mode. They do
not provide Tailscale coordination, ACLs, grants, DERP, or a profile LocalAPI.

Each profile is one versioned YAML file:

```yaml
version: 1
name: lab
dnsSuffix: lab.example
addresses:
  - 10.80.0.1
  - fd80::1
# listenPort: 51820
# privateKeyFile: ./lab.key
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
addresses, and routes on the running WireGuard device without recreating its
TUN. Removing `presharedKeyFile` from a peer clears that peer's preshared key.

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
