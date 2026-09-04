#!/usr/bin/env python3
"""Run a benchmark command in its own process group with a hard timeout."""

import os
import signal
import subprocess
import sys


def run_bounded(seconds: float, command: list[str]) -> int:
    process = subprocess.Popen(command, start_new_session=True)
    try:
        return process.wait(timeout=seconds)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGQUIT)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        print(f"benchmark timed out after {seconds:g}s", file=sys.stderr)
        return 124


def main() -> int:
    if len(sys.argv) < 3:
        raise SystemExit(f"usage: {sys.argv[0]} SECONDS COMMAND [ARG ...]")
    seconds = float(sys.argv[1])
    command = sys.argv[2:]
    if command[0] == "--":
        command = command[1:]
    if not command:
        raise SystemExit("missing command")
    return run_bounded(seconds, command)


if __name__ == "__main__":
    raise SystemExit(main())
