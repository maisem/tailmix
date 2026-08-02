#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
stage=$(mktemp -d "${TMPDIR:-/tmp}/tailmix-install-test.XXXXXX")
trap 'rm -rf "$stage"' EXIT HUP INT TERM
mkdir -p "$stage/archive/service" "$stage/root"
printf '#!/bin/sh\n' > "$stage/archive/tailmix"
printf '#!/bin/sh\n' > "$stage/archive/tailmixd"
cp "$repo_root/systemd/tailmixd.service.in" "$stage/archive/service/"
cp "$repo_root/launchd/io.github.maisem.tailmixd.plist.in" "$stage/archive/service/"
tar -czf "$stage/tailmix_linux_amd64.tar.gz" -C "$stage/archive" \
	tailmix tailmixd service/tailmixd.service.in \
	service/io.github.maisem.tailmixd.plist.in

DESTDIR="$stage/root" "$repo_root/scripts/install.sh" \
	--archive "$stage/tailmix_linux_amd64.tar.gz" --version v1.2.3

test "$(readlink "$stage/root/usr/local/lib/tailmix/current")" = versions/v1.2.3
test "$(readlink "$stage/root/usr/local/bin/tailmix")" = /usr/local/lib/tailmix/current/tailmix
test -x "$stage/root/usr/local/lib/tailmix/versions/v1.2.3/tailmixd"
grep -q 'ExecStart=/usr/local/lib/tailmix/current/tailmixd' \
	"$stage/root/etc/systemd/system/tailmixd.service"

DESTDIR="$stage/root" "$repo_root/scripts/install.sh" \
	--archive "$stage/tailmix_linux_amd64.tar.gz" --version v1.2.4
test "$(readlink "$stage/root/usr/local/lib/tailmix/current")" = versions/v1.2.4
test -x "$stage/root/usr/local/lib/tailmix/versions/v1.2.3/tailmixd"

printf 'different\n' > "$stage/root/usr/local/lib/tailmix/versions/v1.2.4/tailmix"
if DESTDIR="$stage/root" "$repo_root/scripts/install.sh" \
	--archive "$stage/tailmix_linux_amd64.tar.gz" --version v1.2.4 \
	>"$stage/reinstall.out" 2>&1; then
	echo "installer accepted a conflicting existing version" >&2
	exit 1
fi
