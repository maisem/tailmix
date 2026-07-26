# Testing tailmix TUN mode on Darwin

TUN mode is the default. It creates one shared `utun`, assigns one host NAT
address per active address family, installs ordinary interface routes for peer
effective addresses, and forwards packets through the selected profile engine.
tailmix performs SNAT to the selected profile's canonical self address on outbound
packets and DNAT back to the host NAT address on inbound packets; host routes do
select the shared host NAT address, never a profile-specific source address. It
also uses Tailscale's DNS manager and resolver to serve every profile's MagicDNS
zone at `100.100.100.100`, with macOS split-DNS entries for each tailnet suffix.
DNS packets are terminated inside the shared TUN; tailmix does not open a
kernel DNS listener.

## Before starting

- Disconnect the regular Tailscale client so its CGNAT and ULA routes do not
  conflict with tailmix's routes.
- Use a distinct state directory for every profile.
- TUN creation and route changes require root.

## Build and run

```sh
go install ./cmd/tailmixd ./cmd/tailmix

sudo tailmixd \
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

Remote logtail upload is separate from `-verbose` and is disabled by default.
Pass `-log-upload` to opt in, optionally with `-log-upload-url URL` to replace
the upload endpoint.

The effective IPv4 pool is persisted in daemon state; omit the flag on later
runs to reuse it. Every peer and the host NAT receive an address from this
pool, while the prefix base remains unassigned. Choose a CIDR that does not
overlap LAN, VPN, or other host routes.
Changing the flag retires old IPv4 leases and allocates new ones. The
corresponding IPv6 flag is `-synthetic-pool-v6`. These flags do not change
MagicDNS's Tailscale-defined service address, `100.100.100.100`.

At startup, tailmixd prints the allocated interface and every active peer route:

```text
TUN utun7 configured with 2 local address(es) and 12 peer route(s)
MagicDNS serving 100.100.100.100:53 inside the TUN for home.ts.net, work.ts.net
route profile=home name=db.example.ts.net effective=10.250.0.3 canonical=100.64.0.1
```

Use each peer's fully-qualified MagicDNS name or the effective address shown in
this output. MagicDNS always returns addresses from the configured effective
pool and never exposes canonical CGNAT or Tailscale ULA addresses. Shared-in
nodes retain their source tailnet FQDN; tailmix installs an exact-name DNS route
for each one without taking over the source tailnet's entire DNS suffix.

## First checks

```sh
tailmix ts --profile work status
tailmix ts --profile home status
route -n get 10.250.0.3
scutil --dns | grep -A8 'home.ts.net'
dig @100.100.100.100 db.home.ts.net
dscacheutil -q host -a name db.home.ts.net
ping 10.250.0.3
nc -vz 10.250.0.3 22
```

The profile commands use Tailscale's upstream CLI against the selected
profile's `ipnserver` socket. The socket applies normal Unix peer credentials
and Tailscale operator permissions; use `sudo tailmix ...` for write commands
unless your user is a local administrator or the profile's configured operator.

`route -n get` should show the tailmix `utun` and the shared host NAT address as
its preferred source; it must not contain a profile-specific source. Test one
peer in each tailnet without restarting or switching profiles. Use
fully-qualified names: tailmix intentionally does not add tailnet search domains
because a short name can be ambiguous across profiles. Then stop tailmixd with
Ctrl-C and confirm its `utun`, host routes, and tailmix-created files under
`/etc/resolver` disappear.

tailmixd watches all profile netmaps. After adding or removing a peer, wait for a
`profile ... updated` line and repeat the route and DNS checks without
restarting the daemon. The route, packet translation, and MagicDNS tables
should all reflect the new peer set.

## Exit-node checks

When an exit node is selected, tailmix installs global `0.0.0.0/1` and
`128.0.0.0/1` routes on its aggregate `utun`. Darwin `netns` keeps tsnet
control, DERP, and direct WireGuard sockets on the physical underlay with
`IP_BOUND_IF`. The local tsnet fork publishes the interface owning the
underlying `/0` route through tailmix's `netns` fork into netmon's OS-provided
default, independently of the effective split default. The host router also
installs one interface-scoped `/0` on that physical interface. This gives bound
sockets a route in their interface scope without duplicating the aggregate
`/1`s.

With `-verbose`, verify the aggregate routes and continued underlay
connectivity:

```sh
route -n get 1.1.1.1
route -n get -ifscope en0 1.1.1.1
netstat -rn -f inet | grep -E '(^default|^0/1|^128\.0/1)'
ping 1.1.1.1
```

The ordinary lookup should use tailmix's `utun`, while the scoped lookup should
use the physical gateway. There should be one tailmix-created scoped `/0`, not
scoped copies of both `/1`s. The verbose log should continue to report
successful DERP or direct peer connectivity while the exit node is active.
