# Testing tailmix TUN mode on Darwin

TUN mode is the default. It creates one shared `utun`, assigns each profile's
effective self addresses to it, installs one source-selected host route per
peer, and forwards packets through the selected profile engine. It also uses
Tailscale's DNS manager and resolver to serve every profile's MagicDNS zone at
`100.100.100.100`, with macOS split-DNS entries for each tailnet suffix. DNS
packets are terminated inside the shared TUN; tailmix does not open a kernel DNS
listener.

## Before starting

- Disconnect the regular Tailscale client so its CGNAT and ULA routes do not
  conflict with tailmix's routes.
- Use a distinct state directory for every profile.
- TUN creation and route changes require root.
- Unset `TS_AUTHKEY` and `TS_AUTH_KEY`; interactive login is supported, and a
  global key could accidentally enroll every profile into the same tailnet.

## Build and run

```sh
go build -o /tmp/tailmixd ./cmd/tailmixd

unset TS_AUTHKEY TS_AUTH_KEY

sudo /tmp/tailmixd \
  -state "$HOME/Library/Application Support/tailmix/state.json" \
  -synthetic-pool 10.250.0.0/16 \
  -profile id=work \
  -profile id=home
```

Open each login URL as it is printed. For unattended enrollment, set distinct
environment variables and add `auth-key-env=WORK_AUTHKEY` (and the equivalent
for every other profile); preserve those variables through `sudo`. Persisted
profiles do not need their auth key again after initial enrollment. Pass
`-verbose` to include the per-profile tsnet logs. Use `-mode socks` to run the
previous userspace SOCKS milestone instead.

The synthetic IPv4 pool is persisted in daemon state; omit the flag on later
runs to reuse it. Choose a CIDR that does not overlap LAN, VPN, or other host
routes. Changing the flag retires old synthetic IPv4 leases and allocates new
ones. The corresponding IPv6 flag is `-synthetic-pool-v6`. These flags do not
change MagicDNS's Tailscale-defined service address, `100.100.100.100`.

At startup, tailmixd prints the allocated interface and every active peer route:

```text
TUN utun7 configured with 4 local address(es) and 12 peer route(s)
MagicDNS serving 100.100.100.100:53 inside the TUN for home.ts.net, work.ts.net
route profile=home name=db.example.ts.net effective=10.250.0.3 canonical=100.64.0.1
```

Use each peer's fully-qualified MagicDNS name or the effective address shown in
this output. MagicDNS returns effective addresses, including synthetic ones for
addresses that collide between profiles. A canonical address is also an
effective address when it is unique across all profiles. Shared-in nodes retain
their source tailnet FQDN; tailmix installs an exact-name DNS route for each one
without taking over the source tailnet's entire DNS suffix.

## First checks

```sh
route -n get 10.250.0.3
scutil --dns | grep -A8 'home.ts.net'
dig @100.100.100.100 db.home.ts.net
dscacheutil -q host -a name db.home.ts.net
ping 10.250.0.3
nc -vz 10.250.0.3 22
```

`route -n get` should show the tailmix `utun` and the effective self address for
the peer's profile. Test one peer in each tailnet without restarting or
switching profiles. Use fully-qualified names: tailmix intentionally does not add
tailnet search domains because a short name can be ambiguous across profiles.
Then stop tailmixd with Ctrl-C and confirm its `utun`, host routes, and tailmix-created
files under `/etc/resolver` disappear.

The current route table is a startup snapshot. Restart tailmixd after adding or
removing peers. Subnet routes and exit nodes are not part of this Darwin TUN
test.
