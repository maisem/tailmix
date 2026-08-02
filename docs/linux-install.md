# Install tailmix on Linux

You need systemd, `curl`, and root access.

## Do this

1. Stop the regular Tailscale service so it does not compete for routes and
   DNS:

   ```sh
   sudo systemctl disable --now tailscaled
   ```

2. Download the stable-release installer, inspect it, then install and start
   the service:

   ```sh
   curl -fLO https://github.com/maisem/tailmix/releases/latest/download/install.sh
   sudo sh install.sh
   ```

3. Add a profile and log in:

   ```sh
   sudo tailmix profiles add work
   sudo tailmix ts --profile work up
   ```

   Open the login link printed by the second command.

4. Check it:

   ```sh
   tailmix status
   tailmix ts --profile work status
   ```

If `work` is listed and the second command shows the tailnet, you are done.

The installer enables `tailmixd` at boot and starts it immediately. It keeps
state in `/var/lib/tailmix` and runtime sockets in `/run/tailmix`.

## If something goes wrong

Check the service, then follow its logs:

```sh
sudo systemctl status tailmixd
sudo journalctl -u tailmixd -f
```

Restart it after fixing the problem:

```sh
sudo systemctl restart tailmixd
```

## Updates

```sh
tailmix update status
sudo tailmix update check
sudo tailmix update apply
```

Automatic stable-release updates are enabled by default. The daemon checks
after a randomized startup delay and then daily, verifies the release checksum,
switches `tailmix` and `tailmixd` together, and restarts itself. No systemd timer
is installed. Use `sudo tailmix update disable` to opt out and
`sudo tailmix update enable` to turn automatic updates back on.

## Change daemon flags

Most users can skip this section. Run:

```sh
sudo systemctl edit tailmixd
```

Add a drop-in such as:

```ini
[Service]
Environment="TAILMIXD_FLAGS=-synthetic-pool=10.250.0.0/16 -verbose"
```

Then apply it:

```sh
sudo systemctl restart tailmixd
```

The service already sets the state path and socket directory. Development and
packaging options are documented in [DEVELOPMENT.md](../DEVELOPMENT.md).
