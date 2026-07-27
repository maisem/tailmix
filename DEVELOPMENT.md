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

The target version lives in `version/VERSION.txt` as a semantic version without
a leading `v` and with an explicit prerelease channel. Main development uses a
`-dev` target such as `0.2.0-dev`; release branches use the next patch target
with `-rc`, such as `0.1.1-rc`.

Packaged builds append the number of commits since `VERSION.txt` last changed.
The target commit reports `v0.1.0-dev`, seven later commits report
`v0.1.0-dev.7`, and the long form also includes the source revision, such as
`v0.1.0-dev.7-t012345678`.

An exact clean Git tag matching the target's release version is authoritative:
a commit containing `0.1.0-dev` or `0.1.0-rc` and tagged `v0.1.0` reports
`v0.1.0`. After a release, update main to the next `-dev` target and the release
branch to the next patch's `-rc` target so subsequent builds remain ordered
after the release.

The Make and Homebrew builds inject the derived short version, long version,
and Git commit. A plain `go build` cannot calculate the commit count inside the
resulting binary, so it appends the commit date to the explicit channel, such
as `v0.1.0-dev.20260727`, instead.

## Validate

Run the normal test, race, and static-analysis suites:

```sh
go test ./...
go test -race ./...
go vet ./...
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
