#!/usr/bin/env bash
# Measure TCP goodput through two complete Tailmix WireGuard stacks in isolated
# Linux network namespaces. Results describe this machine and are not portable
# performance assertions.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/tailmix-wireguard-benchmark.XXXXXX")
run_id=$$
ns_a="tmwgba${run_id}"
ns_b="tmwgbb${run_id}"
veth_a="tmwbva${run_id}"
veth_b="tmwbvb${run_id}"
background_pids=()
concurrencies=(1 4 8)
iperf3_bin=

cleanup() {
	local rc=$?
	trap - EXIT INT TERM
	set +e
	for pid in "${background_pids[@]}"; do
		sudo kill "$pid" 2>/dev/null || true
	done
	for ns in "$ns_a" "$ns_b"; do
		mapfile -t pids < <(sudo ip netns pids "$ns" 2>/dev/null)
		if ((${#pids[@]})); then
			sudo kill "${pids[@]}" 2>/dev/null || true
		fi
		sudo ip netns del "$ns" 2>/dev/null || true
	done
	sudo rm -rf "$work_dir"
	exit "$rc"
}
trap cleanup EXIT INT TERM

fail() {
	printf 'FAIL: %s\n' "$*" >&2
	exit 1
}

require_command() {
	command -v "$1" >/dev/null 2>&1 || fail "required command is unavailable: $1"
}

for command in awk date getconf git go grep head ip iperf3 mktemp python3 seq ss sudo timeout uname; do
	require_command "$command"
done
[[ $(uname -s) == Linux ]] || fail "Linux is required"
sudo -n true 2>/dev/null || fail "passwordless sudo is required"
[[ -c /dev/net/tun ]] || fail "/dev/net/tun is unavailable"
iperf3_bin=$(command -v iperf3)
[[ $iperf3_bin == /* ]] || fail "iperf3 did not resolve to an absolute path"

mkdir -p "$work_dir/bin" "$work_dir/a/run" "$work_dir/b/run" "$work_dir/results"
(
	cd "$repo_root"
	go build -o "$work_dir/bin/tailmixd" ./cmd/tailmixd
	go build -o "$work_dir/bin/tailmix" ./cmd/tailmix
)

cat >"$work_dir/keygen.go" <<'GO'
package main

import (
	"fmt"

	"github.com/maisem/tailmix/wireguardcfg"
)

func main() {
	for range 2 {
		private, err := wireguardcfg.GeneratePrivateKey()
		if err != nil {
			panic(err)
		}
		public, err := private.Public()
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s %s\n", private.String(), public.String())
	}
}
GO
mapfile -t key_pairs < <(cd "$repo_root" && go run "$work_dir/keygen.go")
((${#key_pairs[@]} == 2)) || fail "key generation returned an unexpected result"
read -r private_a public_a <<<"${key_pairs[0]}"
read -r private_b public_b <<<"${key_pairs[1]}"
printf '%s\n' "$private_a" >"$work_dir/a.key"
printf '%s\n' "$private_b" >"$work_dir/b.key"
chmod 0600 "$work_dir/a.key" "$work_dir/b.key"

sudo ip netns add "$ns_a"
sudo ip netns add "$ns_b"
sudo ip link add "$veth_a" type veth peer name "$veth_b"
sudo ip link set "$veth_a" netns "$ns_a"
sudo ip link set "$veth_b" netns "$ns_b"
sudo ip -n "$ns_a" link set lo up
sudo ip -n "$ns_b" link set lo up
sudo ip -n "$ns_a" link set "$veth_a" name underlay0
sudo ip -n "$ns_b" link set "$veth_b" name underlay0
sudo ip -n "$ns_a" address add 192.0.2.1/30 dev underlay0
sudo ip -n "$ns_b" address add 192.0.2.2/30 dev underlay0
sudo ip -n "$ns_a" link set underlay0 up
sudo ip -n "$ns_b" link set underlay0 up

sudo ip netns exec "$ns_a" "$work_dir/bin/tailmixd" \
	-auto-update=false \
	-state "$work_dir/a/state.json" \
	-socket-dir "$work_dir/a/run" \
	-tun-name tailmix0 >"$work_dir/a-daemon.log" 2>&1 &
background_pids+=("$!")
sudo ip netns exec "$ns_b" "$work_dir/bin/tailmixd" \
	-auto-update=false \
	-state "$work_dir/b/state.json" \
	-socket-dir "$work_dir/b/run" \
	-tun-name tailmix0 >"$work_dir/b-daemon.log" 2>&1 &
background_pids+=("$!")

wait_for_file() {
	local path=$1
	for _ in $(seq 1 150); do
		[[ -e $path ]] && return 0
		sleep 0.1
	done
	return 1
}

wait_for_file "$work_dir/a/run/tailmixd.sock" || fail "first daemon did not create its control socket"
wait_for_file "$work_dir/b/run/tailmixd.sock" || fail "second daemon did not create its control socket"

write_manifest() {
	local side=$1 name self_address peer_name peer_address peer_public endpoint private_file
	if [[ $side == a ]]; then
		name=alpha
		self_address=10.77.0.1
		peer_name=beta
		peer_address=10.77.0.2
		peer_public=$public_b
		endpoint=192.0.2.2:51820
		private_file=$work_dir/a.key
	else
		name=beta
		self_address=10.77.0.2
		peer_name=alpha
		peer_address=10.77.0.1
		peer_public=$public_a
		endpoint=192.0.2.1:51820
		private_file=$work_dir/b.key
	fi
	cat >"$work_dir/$side.yaml" <<YAML
version: 1
name: $name
dnsSuffix: $name.test
addresses: [$self_address]
listenPort: 51820
privateKeyFile: $private_file
packetFilter:
  grants:
    - src: [peer:$peer_name]
      dst: [self]
      ip: [tcp:5201]
peers:
  - name: $peer_name
    publicKey: $peer_public
    endpoint: $endpoint
    keepalive: 1s
    addresses: [$peer_address]
YAML
}

apply_profile() {
	local side=$1
	write_manifest "$side"
	sudo env TAILMIX_SOCKET_DIR="$work_dir/$side/run" \
		"$work_dir/bin/tailmix" wireguard apply --file "$work_dir/$side.yaml" --json \
		>"$work_dir/$side-profile.json"
}

apply_profile a
apply_profile b

effective_b=$(python3 - "$work_dir/a-profile.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    profile = json.load(source)
print(profile["peers"][0]["effectiveAddresses"][0])
PY
)
[[ -n $effective_b ]] || fail "first profile did not report an effective peer address"

sudo ip netns exec "$ns_b" "$iperf3_bin" -s >"$work_dir/iperf3-server.log" 2>&1 &
background_pids+=("$!")

server_ready=0
for _ in $(seq 1 100); do
	if sudo ip netns exec "$ns_b" ss -ltn | grep -F ':5201 ' >/dev/null; then
		server_ready=1
		break
	fi
	sleep 0.1
done
((server_ready == 1)) || fail "iperf3 server did not listen"

# Establish the WireGuard session and validate the complete data path before
# starting the measured repetitions. The output is intentionally discarded.
sudo ip netns exec "$ns_a" timeout --signal=TERM --kill-after=5s 15s "$iperf3_bin" \
	-c "$effective_b" -P 1 -t 1 -J >"$work_dir/iperf3-warmup.json"

run_iperf() {
	local concurrency=$1 direction=$2 run=$3
	local -a command=(timeout --signal=TERM --kill-after=5s 30s "$iperf3_bin" -c "$effective_b" -P "$concurrency" -t 12 -O 2 -J)
	if [[ $direction == reverse ]]; then
		command+=(-R)
	fi
	sudo ip netns exec "$ns_a" "${command[@]}" >"$work_dir/results/p$concurrency-$direction-$run.json"
}

for concurrency in "${concurrencies[@]}"; do
	for direction in normal reverse; do
		for run in 1 2 3; do
			run_iperf "$concurrency" "$direction" "$run"
		done
	done
done

commit=$(git -C "$repo_root" rev-parse HEAD)
if [[ -n $(git -C "$repo_root" status --porcelain) ]]; then
	worktree_state=dirty
else
	worktree_state=clean
fi
cpu_model=$(awk -F: '/model name/ {sub(/^[ \t]+/, "", $2); print $2; exit}' /proc/cpuinfo)
logical_cpus=$(getconf _NPROCESSORS_ONLN)

printf 'Tailmix WireGuard end-to-end benchmark\n'
printf 'date_utc: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
printf 'commit: %s (%s)\n' "$commit" "$worktree_state"
printf 'go: %s\n' "$(go version)"
printf 'iperf3: %s [%s]\n' "$($iperf3_bin --version 2>&1 | head -1)" "$iperf3_bin"
printf 'kernel: %s\n' "$(uname -r)"
printf 'cpu: %s\n' "$cpu_model"
printf 'logical_cpus: %s\n' "$logical_cpus"
printf 'parameters: TCP, P1/P4/P8 through one tunnel, normal+reverse, 3 repetitions/concurrency/direction, 12s/run, omit first 2s, 30s hard timeout/run\n'

python3 - "$work_dir/results" <<'PY'
import json
import pathlib
import statistics
import sys

results_dir = pathlib.Path(sys.argv[1])
for concurrency in (1, 4, 8):
    for direction in ("normal", "reverse"):
        throughputs = []
        print(f"P{concurrency} {direction} runs:")
        for run in range(1, 4):
            path = results_dir / f"p{concurrency}-{direction}-{run}.json"
            with path.open(encoding="utf-8") as source:
                result = json.load(source)
            error = result.get("error")
            if error:
                raise SystemExit(
                    f"iperf3 P{concurrency} {direction} run {run} failed: {error}"
                )
            end = result["end"]
            bits_per_second = float(end["sum_received"]["bits_per_second"])
            retransmits = int(end.get("sum_sent", {}).get("retransmits", 0))
            throughputs.append(bits_per_second)
            print(
                f"  run {run}: {bits_per_second / 1_000_000_000:.3f} Gbit/s, "
                f"retransmits={retransmits}"
            )
        minimum = min(throughputs)
        maximum = max(throughputs)
        median = statistics.median(throughputs)
        unstable = maximum - minimum > 0.10 * median
        print(
            f"  summary: median={median / 1_000_000_000:.3f} Gbit/s "
            f"min={minimum / 1_000_000_000:.3f} Gbit/s "
            f"max={maximum / 1_000_000_000:.3f} Gbit/s "
            f"unstable={'yes' if unstable else 'no'}"
        )
PY
