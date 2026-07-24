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
go install ./cmd/tailmix ./cmd/tailmixd
```

The Make target installs both binaries under `/usr/local/bin` by default:

```sh
sudo make install
```

For an unprivileged or staged installation, set `PREFIX`, `BINDIR`, or
`DESTDIR`:

```sh
make install PREFIX="$HOME/.local"
make install DESTDIR="$PWD/package-root"
```

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
