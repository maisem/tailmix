#!/usr/bin/env python3
"""Dispatch the published, committed HEAD to GitHub Actions, without SSH."""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import uuid
from urllib.parse import urlsplit


WORKFLOW = "checks.yml"
FIELDS = "databaseId,displayTitle,url,headSha,status,conclusion"


class CIError(Exception):
    pass


class LocalTimeout(Exception):
    pass


def origin_repository(remote):
    """Extract a GitHub hostname and owner/repo without exposing URL credentials."""
    if "://" in remote:
        try:
            parsed = urlsplit(remote)
            if parsed.scheme not in ("https", "ssh") or parsed.port:
                raise ValueError()
            host, path = parsed.hostname, parsed.path.lstrip("/")
        except ValueError:
            raise CIError("origin must be an HTTPS or SSH GitHub repository URL") from None
    else:
        match = re.fullmatch(r"(?:[^/@:\s]+@)?([A-Za-z0-9.-]+):(.+)", remote)
        if not match:
            raise CIError("origin must be an HTTPS or SSH GitHub repository URL")
        host, path = match.groups()
    path = path.removesuffix(".git")
    parts = path.split("/")
    if (
        not host
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", host)
        or len(parts) != 2
        or any(not re.fullmatch(r"[A-Za-z0-9_.-]+", p) or p in (".", "..") for p in parts)
    ):
        raise CIError("origin must identify a GitHub hostname and owner/repository")
    return host.lower(), path


class Client:
    def __init__(self, timeout):
        self.deadline = time.monotonic() + timeout
        self.env = os.environ.copy()
        self.repo = None
        self.host = None

    def remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise LocalTimeout()
        return remaining

    def command(self, *args, input_text=None):
        try:
            result = subprocess.run(
                args, env=self.env, text=True, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=self.remaining(), check=False, input=input_text,
            )
        except FileNotFoundError:
            raise CIError(f"{args[0]} is required but was not found") from None
        except subprocess.TimeoutExpired:
            raise LocalTimeout() from None
        except OSError:
            raise CIError(f"could not execute {args[0]}") from None
        if result.returncode:
            hint = (
                "check gh auth status and repository Actions permissions"
                if args[0] == "gh" else "check the repository and origin access"
            )
            # Never echo subprocess output: remote URLs may contain credentials.
            raise CIError(f"{args[0]} command failed; {hint}")
        return result.stdout.strip()

    def gh(self, *args):
        return self.command("gh", *args, "--repo", self.repo)

    def run_json(self, *args):
        try:
            result = json.loads(self.gh(*args, "--json", FIELDS))
        except ValueError:
            raise CIError("gh returned invalid JSON") from None
        if args[:2] == ("run", "list"):
            valid = isinstance(result, list) and all(isinstance(run, dict) for run in result)
        else:
            valid = isinstance(result, dict)
        if not valid:
            raise CIError("gh returned an unexpected JSON structure")
        return result

    def pause(self):
        time.sleep(min(2, self.remaining()))


def preflight(client, args):
    if client.command("git", "status", "--porcelain", "--untracked-files=all", "--ignore-submodules=none"):
        raise CIError("worktree is dirty (including untracked files); commit or remove changes first")
    revision = client.command("git", "rev-parse", "--verify", "HEAD^{commit}")
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise CIError("HEAD must be a full GitHub commit SHA")
    host, client.repo = origin_repository(client.command("git", "remote", "get-url", "origin"))
    client.env.setdefault("GH_HOST", host)
    client.host = client.env["GH_HOST"]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", client.host):
        raise CIError("GH_HOST must be a GitHub hostname")
    # symbolic-ref exits nonzero on detached HEAD; branch --show-current returns empty.
    branch = client.command("git", "branch", "--show-current")
    if not branch and not args.ref:
        raise CIError("detached HEAD requires --ref naming a published branch or tag at HEAD")
    if args.push and (args.ref or not branch):
        raise CIError("--push requires the current named branch and cannot be combined with --ref")
    ref = args.ref or branch
    # Validate without interpolating a ref into a shell command.
    client.command("git", "check-ref-format", "refs/heads/" + ref)
    head_ref, tag_ref = "refs/heads/" + ref, "refs/tags/" + ref

    def published():
        patterns = [head_ref] if not args.ref else [head_ref, tag_ref, tag_ref + "^{}"]
        output = client.command("git", "ls-remote", "origin", *patterns)
        refs = {}
        for line in output.splitlines():
            fields = line.split()
            if len(fields) != 2 or not re.fullmatch(r"[0-9a-f]{40}", fields[0]):
                raise CIError("git returned invalid remote ref metadata")
            sha, name = fields
            refs[name] = sha
        if args.ref and head_ref in refs and tag_ref in refs:
            raise CIError("--ref is ambiguous: both a branch and tag have this name")
        return refs.get(head_ref) or refs.get(tag_ref + "^{}") or refs.get(tag_ref)

    remote_sha = published()
    if remote_sha != revision and args.push:
        print("Publishing the current branch with a non-force push…", file=sys.stderr)
        client.command("git", "push", "origin", "HEAD:" + head_ref)
        remote_sha = published()
    if remote_sha != revision:
        raise CIError(
            "origin ref does not point to committed HEAD; publish it first"
            + (" (or use --push for the current branch)" if not args.ref else "")
        )
    return revision, ref


def observe(client, state, title, args):
    previous = None
    while True:
        client.remaining()
        if state["run_id"] is None:
            runs = client.run_json(
                "run", "list", "--workflow", WORKFLOW, "--event", "workflow_dispatch",
                "--limit", "100",
            )
            matches = [run for run in runs if run.get("displayTitle") == title]
            if len(matches) > 1:
                raise CIError("multiple runs matched the unique request ID; refusing to guess")
            run = matches[0] if matches else None
        else:
            run = client.run_json("run", "view", str(state["run_id"]))
        if run is not None:
            if (
                type(run.get("databaseId")) is not int or run["databaseId"] <= 0
                or not isinstance(run.get("url"), str)
                or not run["url"]
                or not isinstance(run.get("status"), str)
            ):
                raise CIError("gh returned incomplete run metadata")
            if run.get("displayTitle") != title or (
                state["run_id"] is not None and run["databaseId"] != state["run_id"]
            ):
                raise CIError("run metadata does not match this request")
            state.update(run_id=run["databaseId"], url=run["url"])
            if run.get("headSha") != state["revision"]:
                raise CIError("run metadata does not match committed HEAD")
            state.update(
                status=run["status"], conclusion=run.get("conclusion") or None,
            )
            if state["status"] != previous:
                print(f"CI {state['status']}: {state['url']}", file=sys.stderr)
                previous = state["status"]
            if state["status"] == "completed":
                return 0 if state["conclusion"] == "success" else 1
            if args.no_wait:
                return 0
        client.pause()


def positive_seconds(value):
    try:
        value = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("timeout must be a positive number") from None
    if not 0 < value < float("inf"):
        raise argparse.ArgumentTypeError("timeout must be a finite positive number")
    return value


def parser():
    result = argparse.ArgumentParser(
        description="Run GitHub CI for clean, committed HEAD on origin; never pushes implicitly.",
        epilog=(
            "Requires git and authenticated gh. The workflow must already be published at the "
            "selected ref, which must point exactly to HEAD (also with --ref). "
            "Exit codes: 0 success/accepted --no-wait, 1 completed nonsuccess, "
            "2 preflight/CLI error, 124 local timeout, 130 interrupted. "
            "Timeout and Ctrl-C never cancel the remote run. "
            'Examples: make ci; make ci CI_ARGS="--push --suite linux-network"; '
            'make ci CI_ARGS="--json --no-wait".'
        ),
    )
    result.add_argument("--suite", choices=("all", "check", "linux-network"), default="all")
    result.add_argument("--push", action="store_true", help="publish current branch if needed (never force)")
    result.add_argument("--ref", help="published branch/tag at HEAD; required for detached HEAD")
    result.add_argument("--no-wait", action="store_true", help="return once the exact dispatched run is identified")
    result.add_argument("--json", action="store_true", help="emit one JSON object on stdout; progress goes to stderr")
    result.add_argument("--timeout", type=positive_seconds, default=1800, metavar="SECONDS",
                        help="overall local deadline including dispatch/discovery (default: 1800)")
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    client = Client(args.timeout)
    state = dict(run_id=None, url=None, revision=None, suite=args.suite,
                 status="preflight", conclusion=None, request_id=str(uuid.uuid4()))
    try:
        state["revision"], ref = preflight(client, args)
        # Record correlation before calling gh: interruption during dispatch is ambiguous.
        state["status"] = "dispatching"
        # Direct REST avoids gh workflow run's unrelated /meta capability probe,
        # which restricted GitHub API proxies need not expose.
        client.command(
            "gh", "api", "--method", "POST",
            f"repos/{client.repo}/actions/workflows/{WORKFLOW}/dispatches", "--input", "-",
            input_text=json.dumps(dict(ref=ref, inputs=dict(
                suite=args.suite, revision=state["revision"], request_id=state["request_id"],
            ))),
        )
        state["status"] = "dispatched"
        code = observe(client, state, "checks / " + state["request_id"], args)
    except CIError as error:
        state["error"] = str(error)
        print(f"CI: {error}", file=sys.stderr)
        code = 2
    except LocalTimeout:
        state["error"] = "local timeout; the remote run was not cancelled"
        print(f"CI: {state['error']}", file=sys.stderr)
        code = 124
    except KeyboardInterrupt:
        state["error"] = "interrupted; the remote run was not cancelled"
        print(f"\nCI: {state['error']}", file=sys.stderr)
        code = 130
    if state["run_id"] and code:
        print(f"Inspect: gh run view {state['run_id']} --repo {client.host}/{client.repo}", file=sys.stderr)
    elif state["status"] in ("dispatching", "dispatched"):
        print(
            f"Find request title: checks / {state['request_id']}\n"
            f"  gh run list --repo {client.host}/{client.repo} --workflow {WORKFLOW} --event workflow_dispatch",
            file=sys.stderr,
        )
    if args.json:
        print(json.dumps(state, sort_keys=True))
    elif state["run_id"]:
        print(f"{state['url']} ({state['conclusion'] or state['status']})")
    return code


if __name__ == "__main__":
    sys.exit(main())
