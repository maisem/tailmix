#!/usr/bin/env bash
# Run a privileged, two-network-namespace end-to-end exercise of raw WireGuard
# packet filters. The test builds the current checkout and leaves the host
# unchanged unless TAILMIX_E2E_KEEP=1 is set for diagnosis.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/tailmix-wireguard-e2e.XXXXXX")
run_id=$$
ns_a="tmwga${run_id}"
ns_b="tmwgb${run_id}"
veth_a="tmva${run_id}"
veth_b="tmvb${run_id}"
background_pids=()

cleanup() {
	local rc=$?
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
	if [[ ${TAILMIX_E2E_KEEP:-0} == 1 ]]; then
		printf 'diagnostics retained at %s\n' "$work_dir" >&2
	else
		sudo rm -rf "$work_dir"
	fi
	exit "$rc"
}
trap cleanup EXIT INT TERM

fail() {
	printf 'FAIL: %s\n' "$*" >&2
	exit 1
}

pass() {
	printf 'PASS: %s\n' "$*"
}

require_command() {
	command -v "$1" >/dev/null 2>&1 || fail "required command is unavailable: $1"
}

for command in go ip jq ping python3 sudo; do
	require_command "$command"
done
[[ $(uname -s) == Linux ]] || fail "Linux is required"
sudo -n true 2>/dev/null || fail "passwordless sudo is required"
[[ -c /dev/net/tun ]] || fail "/dev/net/tun is unavailable"

mkdir -p "$work_dir/bin" "$work_dir/a/run" "$work_dir/b/run"
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

cat >"$work_dir/socket_tool.py" <<'PY'
import pathlib
import socket
import sys
import time

mode = sys.argv[1]


def ready(path):
    pathlib.Path(path).write_text("ready\n")


def tcp_server():
    port = int(sys.argv[2])
    ready_path = sys.argv[3]
    count = int(sys.argv[4])
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", port))
        listener.listen()
        listener.settimeout(15)
        ready(ready_path)
        for _ in range(count):
            conn, _ = listener.accept()
            with conn:
                conn.settimeout(5)
                data = conn.recv(4096)
                conn.sendall(b"reply:" + data)


def tcp_client():
    address, port, payload = sys.argv[2], int(sys.argv[3]), sys.argv[4].encode()
    try:
        with socket.create_connection((address, port), timeout=2) as conn:
            conn.settimeout(2)
            conn.sendall(payload)
            conn.shutdown(socket.SHUT_WR)
            response = conn.recv(4096)
    except TimeoutError:
        raise SystemExit(20)
    except ConnectionRefusedError:
        raise SystemExit(21)
    except OSError:
        raise SystemExit(22)
    sys.stdout.buffer.write(response)


def hold_server():
    port = int(sys.argv[2])
    ready_path = sys.argv[3]
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", port))
        listener.listen(1)
        listener.settimeout(15)
        ready(ready_path)
        conn, _ = listener.accept()
        with conn:
            conn.settimeout(10)
            stream = conn.makefile("rwb", buffering=0)
            for _ in range(2):
                line = stream.readline()
                if not line:
                    raise SystemExit(30)
                stream.write(b"reply:" + line)


def hold_client():
    address, port = sys.argv[2], int(sys.argv[3])
    first_path, continue_path, result_path = map(pathlib.Path, sys.argv[4:7])
    with socket.create_connection((address, port), timeout=3) as conn:
        conn.settimeout(10)
        stream = conn.makefile("rwb", buffering=0)
        stream.write(b"one\n")
        first = stream.readline()
        first_path.write_bytes(first)
        deadline = time.monotonic() + 10
        while not continue_path.exists():
            if time.monotonic() >= deadline:
                raise SystemExit(31)
            time.sleep(0.05)
        stream.write(b"two\n")
        second = stream.readline()
        result_path.write_bytes(first + second)


def udp_server():
    port = int(sys.argv[2])
    ready_path = sys.argv[3]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("0.0.0.0", port))
        server.settimeout(15)
        ready(ready_path)
        data, address = server.recvfrom(4096)
        server.sendto(b"reply:" + data, address)


def udp_client():
    address, port, payload = sys.argv[2], int(sys.argv[3]), sys.argv[4].encode()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(2)
        client.sendto(payload, (address, port))
        try:
            response, _ = client.recvfrom(4096)
        except TimeoutError:
            raise SystemExit(20)
    sys.stdout.buffer.write(response)


{
    "tcp-server": tcp_server,
    "tcp-client": tcp_client,
    "hold-server": hold_server,
    "hold-client": hold_client,
    "udp-server": udp_server,
    "udp-client": udp_client,
}[mode]()
PY

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
	local side=$1 permission=$2
	local name self_address peer_name peer_address peer_public endpoint private_file
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
YAML
	if [[ $permission != default ]]; then
		cat >>"$work_dir/$side.yaml" <<YAML
packetFilter:
  grants:
    - src: [peer:$peer_name]
      dst: [self]
      ip: [$permission]
YAML
	fi
	cat >>"$work_dir/$side.yaml" <<YAML
peers:
  - name: $peer_name
    publicKey: $peer_public
    endpoint: $endpoint
    keepalive: 1s
    addresses: [$peer_address]
YAML
}

apply_profile() {
	local side=$1 permission=$2
	write_manifest "$side" "$permission"
	sudo env TAILMIX_SOCKET_DIR="$work_dir/$side/run" \
		"$work_dir/bin/tailmix" wireguard apply --file "$work_dir/$side.yaml" --json \
		>"$work_dir/$side-profile.json"
}

set_shields() {
	local side=$1 state=$2 profile
	[[ $side == a ]] && profile=alpha || profile=beta
	sudo env TAILMIX_SOCKET_DIR="$work_dir/$side/run" \
		"$work_dir/bin/tailmix" wireguard shields-up "$profile" "$state" --json \
		>"$work_dir/$side-shields.json"
}

namespace_for() {
	[[ $1 == a ]] && printf '%s' "$ns_a" || printf '%s' "$ns_b"
}

start_tool() {
	local side=$1 mode=$2 port=$3 ready_path=$4
	shift 4
	local ns
	ns=$(namespace_for "$side")
	rm -f "$ready_path"
	sudo ip netns exec "$ns" python3 "$work_dir/socket_tool.py" "$mode" "$port" "$ready_path" "$@" \
		>"$ready_path.stdout" 2>"$ready_path.stderr" &
	LAST_TOOL_PID=$!
	background_pids+=("$LAST_TOOL_PID")
	wait_for_file "$ready_path" || fail "$mode did not become ready"
}

expect_tcp_allowed() {
	local source=$1 destination=$2 port=$3 payload=$4 target ns response
	[[ $destination == a ]] && target=$effective_a || target=$effective_b
	ns=$(namespace_for "$source")
	start_tool "$destination" tcp-server "$port" "$work_dir/server-ready" 1
	if ! response=$(sudo ip netns exec "$ns" python3 "$work_dir/socket_tool.py" tcp-client "$target" "$port" "$payload"); then
		fail "expected TCP flow was not accepted"
	fi
	[[ $response == "reply:$payload" ]] || fail "allowed TCP flow returned an unexpected payload"
	wait "$LAST_TOOL_PID" || fail "TCP server failed after an allowed flow"
}

expect_tcp_blocked() {
	local source=$1 destination=$2 port=$3 target ns rc
	[[ $destination == a ]] && target=$effective_a || target=$effective_b
	ns=$(namespace_for "$source")
	start_tool "$destination" tcp-server "$port" "$work_dir/server-ready" 1
	set +e
	sudo ip netns exec "$ns" python3 "$work_dir/socket_tool.py" tcp-client "$target" "$port" blocked \
		>"$work_dir/blocked.stdout" 2>"$work_dir/blocked.stderr"
	rc=$?
	set -e
	sudo kill "$LAST_TOOL_PID" 2>/dev/null || true
	[[ $rc == 20 ]] || fail "blocked TCP flow failed for a reason other than packet timeout (status $rc)"
}

expect_ping_blocked() {
	local source=$1 destination=$2 target ns
	[[ $destination == a ]] && target=$effective_a || target=$effective_b
	ns=$(namespace_for "$source")
	if sudo ip netns exec "$ns" ping -n -c 1 -W 1 "$target" >/dev/null 2>&1; then
		fail "non-granted ICMP flow was accepted"
	fi
}

expect_udp_allowed() {
	local source=$1 destination=$2 port=$3 payload=$4 target ns response
	[[ $destination == a ]] && target=$effective_a || target=$effective_b
	ns=$(namespace_for "$source")
	start_tool "$destination" udp-server "$port" "$work_dir/server-ready"
	if ! response=$(sudo ip netns exec "$ns" python3 "$work_dir/socket_tool.py" udp-client "$target" "$port" "$payload"); then
		fail "expected UDP flow was not accepted"
	fi
	[[ $response == "reply:$payload" ]] || fail "allowed UDP flow returned an unexpected payload"
	wait "$LAST_TOOL_PID" || fail "UDP server failed after an allowed flow"
}

# Establish both profiles once, then discover each namespace-local effective
# address. Equal values are expected because the namespaces have independent
# aggregate address spaces.
apply_profile a default
apply_profile b tcp:18080
effective_b=$(jq -er '.peers[0].effectiveAddresses[0]' "$work_dir/a-profile.json")
effective_a=$(jq -er '.peers[0].effectiveAddresses[0]' "$work_dir/b-profile.json")

# A default policy permits A's outbound flow and its reply state because B has
# the matching inbound grant. The reverse initiation is rejected at A. Repeat
# with the roles reversed so each default policy is exercised.
expect_tcp_allowed a b 18080 default-a-outbound
expect_tcp_blocked b a 18081
apply_profile a tcp:18081
apply_profile b default
expect_tcp_allowed b a 18081 default-b-outbound
expect_tcp_blocked a b 18080
pass "default policy is outbound-and-replies only in both directions"

# A single named-peer TCP grant admits its exact port and rejects both another
# TCP port and a different protocol.
apply_profile a tcp:18082
apply_profile b default
expect_tcp_allowed b a 18082 exact-grant
expect_tcp_blocked b a 18083
expect_ping_blocked b a
pass "named-peer TCP grant permits only its selected port and protocol"

# Keep a TCP connection open while removing the destination grant. Continuation
# packets on that established flow must keep working through the policy swap.
apply_profile a default
apply_profile b tcp:18084
rm -f "$work_dir/hold-server-ready" "$work_dir/hold-first" "$work_dir/hold-continue" "$work_dir/hold-result"
start_tool b hold-server 18084 "$work_dir/hold-server-ready"
hold_server_pid=$LAST_TOOL_PID
sudo ip netns exec "$ns_a" python3 "$work_dir/socket_tool.py" hold-client \
	"$effective_b" 18084 "$work_dir/hold-first" "$work_dir/hold-continue" "$work_dir/hold-result" \
	>"$work_dir/hold-client.stdout" 2>"$work_dir/hold-client.stderr" &
hold_client_pid=$!
background_pids+=("$hold_client_pid")
wait_for_file "$work_dir/hold-first" || fail "established TCP flow did not receive its first reply"
[[ $(cat "$work_dir/hold-first") == reply:one ]] || fail "established TCP flow returned an unexpected first reply"
apply_profile b default
touch "$work_dir/hold-continue"
wait "$hold_client_pid" || fail "established TCP flow failed after policy replacement"
wait "$hold_server_pid" || fail "established TCP server failed after policy replacement"
[[ $(cat "$work_dir/hold-result") == $'reply:one\nreply:two' ]] || fail "established TCP continuation returned unexpected replies"
pass "established TCP continuation and replies survive grant removal"

# Shields-up suppresses B's grant for new inbound traffic. B can still initiate
# an outbound flow to an A grant and receive its reply. Disabling shields-up
# republishes B's grant.
apply_profile a default
apply_profile b tcp:18085
expect_tcp_allowed a b 18085 before-shields
set_shields b on
expect_tcp_blocked a b 18085
apply_profile a tcp:18086
expect_tcp_allowed b a 18086 shields-outbound
set_shields b off
expect_tcp_allowed a b 18085 after-shields
pass "shields-up blocks new inbound, preserves outbound replies, and restores grants"

# Exercise the UDP state path independently of TCP.
apply_profile a udp:18087
apply_profile b default
expect_udp_allowed b a 18087 udp-grant
pass "named-peer UDP grant admits datagrams and reply traffic"

printf 'All raw WireGuard packet-filter end-to-end scenarios passed.\n'
