# Developing tailmix

## Prerequisites

Go 1.26.4 or newer is required. Runtime testing of TUN, route, and DNS changes
also requires root privileges on macOS or `CAP_NET_ADMIN` on Linux.

## Build

Compile the repository:

```sh
go build ./...
```

Install development binaries into the Go binary directory on your `PATH`:

```sh
make install BINDIR="$(go env GOPATH)/bin"
```

The Make target installs both binaries under `/usr/local/bin` by default:

```sh
sudo make install
```

On a systemd-based Linux host, install the binaries and service, enable it at
boot, and start or restart it with:

```sh
sudo make install-systemd
```

For an unprivileged or staged installation, set `PREFIX`, `BINDIR`, or
`DESTDIR`:

```sh
make install PREFIX="$HOME/.local"
make install DESTDIR="$PWD/package-root"
make install-systemd DESTDIR="$PWD/package-root" PREFIX=/usr
```

A staged systemd installation does not contact `systemctl`. Set
`SYSTEMD_UNIT_DIR` to override the unit destination or `SYSTEMCTL` to use a
different systemctl command. See
[docs/linux-install.md](docs/linux-install.md) for the runtime workflow.

## Versioning

The development version lives in `version/VERSION.txt` as a semantic version
without a leading `v` and with an explicit prerelease channel, such as
`0.2.0-dev`. It identifies untagged builds; it does not need to change for each
release.

Packaged builds append the number of commits since `VERSION.txt` last changed.
The target commit reports `v0.1.0-dev`, seven later commits report
`v0.1.0-dev.7`, and the long form also includes the source revision, such as
`v0.1.0-dev.7-t012345678`.

An exact clean semantic-version Git tag is authoritative. For example, a clean
commit tagged `v0.1.4` reports `v0.1.4`, regardless of the development version.
This keeps ordinary releases from requiring version-bump commits.

The Make and Homebrew builds inject the derived short version, long version,
and Git commit. A plain `go build` cannot calculate the commit count inside the
resulting binary, so it appends the commit date to the explicit channel, such
as `v0.1.0-dev.20260727`, instead.

Before publishing a release tag, validate the full package build locally. The
target runs the consolidated checks and a snapshot release using the same
pinned GoReleaser version as the release workflow:

```sh
make release-check
```

If it succeeds, create and publish the tag that should become the release:

```sh
git tag -a v0.1.5 -m v0.1.5
git push origin v0.1.5
```

The tag push starts the release workflow. No version-file change or release
commit is needed.

## Validate

Run the same consolidated validation used by CI:

```sh
make check
```

See [docs/darwin-testing.md](docs/darwin-testing.md) for the privileged macOS
TUN integration workflow.

## Dependency licenses

Check that dependency licenses are accepted and the generated report is
current:

```sh
make licenses-check
```

After an intentional dependency change, regenerate the report and review its
diff:

```sh
make licenses
git diff -- licenses/tailmix.md
```

See [licenses/README.md](licenses/README.md) for the classifier exception and
copied-source provenance details.
