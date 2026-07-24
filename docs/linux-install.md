# Install tailmix with systemd

The repository includes a systemd unit and a Make target that installs both
binaries, enables `tailmixd` at boot, and starts it immediately.

## Prerequisites

- A Linux distribution using systemd
- Go 1.26.4 or newer
- Root access for installing and running the service

Disconnect the regular Tailscale client before starting Tailmix so the two
services do not install overlapping routes or DNS configuration. On a machine
dedicated to Tailmix, disable it at boot as well:

```sh
sudo systemctl disable --now tailscaled
```

The Tailmix unit deliberately does not stop or disable `tailscaled`
automatically.

## Install and start

From the repository checkout, run:

```sh
sudo make install-systemd
```

This command:

- installs `tailmix` and `tailmixd` under `/usr/local/bin`;
- installs `tailmixd.service` under `/usr/local/lib/systemd/system`;
- stores persistent daemon and profile state under `/var/lib/tailmix`;
- creates the runtime socket directory at `/run/tailmix`;
- enables the service at boot and starts or restarts it immediately.

The daemon can start with no profiles. Add one and complete its Tailscale login
after installation:

```sh
sudo tailmix profiles add work
sudo tailmix ts --profile work up
sudo tailmix status
```

## Service management and logs

Use the normal systemd commands:

```sh
sudo systemctl status tailmixd
sudo systemctl restart tailmixd
sudo systemctl stop tailmixd
sudo journalctl -u tailmixd -f
```

Run `sudo systemctl enable --now tailmixd` to start the service again and keep
it enabled at boot.

## Configure daemon flags

The service accepts additional `tailmixd` options through `TAILMIXD_FLAGS`.
Create a systemd drop-in:

```sh
sudo systemctl edit tailmixd
```

For example:

```ini
[Service]
Environment="TAILMIXD_FLAGS=-synthetic-pool=10.250.0.0/16 -verbose"
```

Apply the change with:

```sh
sudo systemctl restart tailmixd
```

The service already fixes `-state` to `/var/lib/tailmix/state.json` and
`-socket-dir` to `/var/run/tailmix`. Avoid overriding those flags unless the
unit's `StateDirectory` and `RuntimeDirectory` settings are changed to match.

## Update

After updating the checkout, run the install target again. It rebuilds both
binaries, refreshes the unit, reloads systemd, and restarts the service:

```sh
git pull
sudo make install-systemd
```

For distribution packaging, set `DESTDIR` and optionally `PREFIX`. A staged
install writes the binaries and rendered unit without contacting systemd:

```sh
make install-systemd DESTDIR="$PWD/package-root" PREFIX=/usr
```
