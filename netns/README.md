# tailmix netns fork

This package was forked from
[`tailscale/tailscale@fad8b9b8a957c3d4d81d1d9f61c09090dd8d0ba3`](https://github.com/tailscale/tailscale/commit/fad8b9b8a957c3d4d81d1d9f61c09090dd8d0ba3),
published as `tailscale.com v1.101.0-pre.0.20260630140925-fad8b9b8a957`,
from the `net/netns` source path. The machine-readable source record is in
[UPSTREAM](UPSTREAM).

tailmix carries the fork to expose `SetUnderlayInterfaceIndex` on Darwin. The
local [`tsnet` fork](../tsnet/README.md) refreshes that setting from the
physical `/0` route before tailmix installs aggregate exit-node routes.

Go modules cannot replace `tailscale.com/net/netns` independently while the
parent `tailscale.com` module also provides that package. tailmix therefore
imports this focused fork directly for the added underlay publisher. The
publisher updates Tailscale netmon's shared OS-default state, which the
published `netns` package already prioritizes for control, DERP, magicsock,
port mapping, and DNS fallback sockets. The standard socket constructors
remain supplied by the published Tailscale module.

The copied files are otherwise unchanged, retain their upstream copyright
headers, and are distributed under the accompanying BSD 3-Clause license.
