# tailmix tsnet fork

This package was forked from
[`tailscale/tailscale@fad8b9b8a957c3d4d81d1d9f61c09090dd8d0ba3`](https://github.com/tailscale/tailscale/commit/fad8b9b8a957c3d4d81d1d9f61c09090dd8d0ba3),
published as `tailscale.com v1.101.0-pre.0.20260630140925-fad8b9b8a957`.
The machine-readable source record is in [UPSTREAM](UPSTREAM).

tailmix carries the fork to expose the embedded `LocalBackend` to Tailscale's
`ipnserver`. This lets each profile provide the native LocalAPI, including the
same peer-credential authentication and read/write permission checks as
`tailscaled`.

The fork also changes remote logging behavior:

- logtail upload is disabled by default;
- `Server.LogUpload` explicitly enables it; and
- `Server.LogUploadURL` can replace the default upload base URL.

OAuth-secret and workload-identity auth-key minting are omitted because their
registration hooks live in an internal Tailscale package that cannot be
imported by this module. Device auth keys and interactive login remain
supported.

The copied files retain their upstream copyright headers and are distributed
under the accompanying BSD 3-Clause license.
