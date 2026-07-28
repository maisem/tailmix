# Install tailmix on Linux

You need systemd, Go 1.26.4 or newer, and root access.

## Do this

1. Stop the regular Tailscale service so it does not compete for routes and
   DNS:

   ```sh
   sudo systemctl disable --now tailscaled
   ```

2. From the tailmix repository checkout, install and start the service:

   ```sh
   sudo make install-systemd
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

## Update

```sh
git pull
sudo make install-systemd
```

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
