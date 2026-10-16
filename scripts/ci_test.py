#!/usr/bin/env python3
"""Unit tests for CI CLI orchestration, not substitutes for application tests."""

import contextlib
import io
import json
import os
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
import ci


SHA = "a" * 40
OTHER_SHA = "b" * 40
REQUEST = "unique-request"


def run_record(**changes):
    result = dict(databaseId=42, displayTitle="checks / " + REQUEST,
                  url="https://github.example/owner/repo/actions/runs/42",
                  headSha=SHA, status="completed", conclusion="success")
    result.update(changes)
    return result


class Tools:
    """Fake only the git/gh process boundary; run the actual CLI orchestration."""

    def __init__(self):
        self.calls = []
        self.dirty = ""
        self.branch = "feature/ci"
        self.origin = "https://github.example/owner/repo.git"
        self.refs = {"refs/heads/feature/ci": SHA}
        self.runs = [run_record(databaseId=99, displayTitle="checks / another-request"),
                     run_record()]
        self.views = [run_record()]
        self.fail = None
        self.interrupt = False

    def __call__(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if self.fail and args[:len(self.fail)] == self.fail:
            return subprocess.CompletedProcess(args, 1, "", "secret credential diagnostics")
        if args[:2] == ("git", "status"):
            output = self.dirty
        elif args[:2] == ("git", "rev-parse"):
            output = SHA
        elif args[:2] == ("git", "remote"):
            output = self.origin
        elif args[:2] == ("git", "branch"):
            output = self.branch
        elif args[:2] == ("git", "check-ref-format"):
            output = ""
        elif args[:2] == ("git", "ls-remote"):
            output = "\n".join(f"{sha}\t{ref}" for ref, sha in self.refs.items()
                               if ref in args[3:])
        elif args[:2] == ("git", "push"):
            self.refs["refs/heads/" + self.branch] = SHA
            output = ""
        elif args[:2] == ("gh", "api"):
            if self.interrupt:
                raise KeyboardInterrupt()
            # Deliberately return an unrelated URL; don't trust dispatch output or latest run.
            output = "https://github.example/owner/repo/actions/runs/99"
        elif args[:3] == ("gh", "run", "list"):
            output = json.dumps(self.runs)
        elif args[:3] == ("gh", "run", "view"):
            output = json.dumps(self.views.pop(0) if len(self.views) > 1 else self.views[0])
        else:
            raise AssertionError(f"unexpected command: {args}")
        return subprocess.CompletedProcess(args, 0, output, "")

    def commands(self):
        return [args for args, _ in self.calls]


class CITest(unittest.TestCase):
    def invoke(self, tools, *args, pause=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("ci.subprocess.run", side_effect=tools),
            patch("ci.uuid.uuid4", return_value=REQUEST),
            patch("ci.Client.pause", side_effect=pause),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            code = ci.main(list(args))
        return code, stdout.getvalue(), stderr.getvalue()

    def test_defaults_pin_sha_and_correlate_not_latest_run(self):
        tools = Tools()
        code, output, _ = self.invoke(tools, "--json")
        result = json.loads(output)
        self.assertEqual(code, 0)
        self.assertEqual(result["run_id"], 42)
        self.assertEqual(result["revision"], SHA)
        self.assertEqual(result["suite"], "all")
        self.assertEqual(result["conclusion"], "success")
        dispatch, kwargs = next((c, k) for c, k in tools.calls if c[:2] == ("gh", "api"))
        self.assertEqual(
            dispatch,
            ("gh", "api", "--method", "POST",
             "repos/owner/repo/actions/workflows/checks.yml/dispatches", "--input", "-"),
        )
        self.assertEqual(json.loads(kwargs["input"]), {
            "ref": "feature/ci",
            "inputs": {"suite": "all", "revision": SHA, "request_id": REQUEST},
        })
        self.assertFalse(any(c[:2] == ("git", "push") for c in tools.commands()))
        for command, kwargs in tools.calls:
            if command[0] == "gh":
                self.assertEqual(kwargs["env"]["GH_HOST"], "github.example")
                self.assertGreater(kwargs["timeout"], 0)

    def test_normal_github_and_existing_host_override(self):
        tools = Tools()
        tools.origin = "git@github.com:owner/repo.git"
        with patch.dict(os.environ, {"GH_HOST": "configured.example"}, clear=True):
            client = ci.Client(10)
            with patch("ci.subprocess.run", side_effect=tools):
                ci.preflight(client, ci.parser().parse_args([]))
            self.assertEqual(client.env["GH_HOST"], "configured.example")

    def test_dirty_tracked_or_untracked_never_dispatch_or_push(self):
        for dirty in (" M file.go", "?? private-key"):
            with self.subTest(dirty=dirty):
                tools = Tools()
                tools.dirty = dirty
                code, output, _ = self.invoke(tools, "--json", "--push")
                self.assertEqual(code, 2)
                self.assertIn("dirty", json.loads(output)["error"])
                self.assertEqual(len(tools.calls), 1)

    def test_unpublished_or_wrong_remote_head_requires_explicit_push(self):
        for refs in ({}, {"refs/heads/feature/ci": OTHER_SHA}):
            with self.subTest(refs=refs):
                tools = Tools()
                tools.refs = refs
                code, _, _ = self.invoke(tools)
                self.assertEqual(code, 2)
                self.assertFalse(any(c[0] == "gh" or c[:2] == ("git", "push")
                                     for c in tools.commands()))

    def test_explicit_push_is_nonforce_current_branch_only(self):
        tools = Tools()
        tools.refs = {}
        code, _, _ = self.invoke(tools, "--push", "--suite", "linux-network")
        self.assertEqual(code, 0)
        self.assertIn(("git", "push", "origin", "HEAD:refs/heads/feature/ci"), tools.commands())
        _, kwargs = next((c, k) for c, k in tools.calls if c[:2] == ("gh", "api"))
        self.assertEqual(json.loads(kwargs["input"])["inputs"]["suite"], "linux-network")

    def test_push_failure_stops_dispatch_and_hides_diagnostics(self):
        tools = Tools()
        tools.refs = {}
        tools.fail = ("git", "push")
        code, output, errors = self.invoke(tools, "--push", "--json")
        self.assertEqual(code, 2)
        self.assertNotIn("secret", output + errors)
        self.assertFalse(any(c[0] == "gh" for c in tools.commands()))

    def test_detached_head_requires_published_ref_at_same_sha(self):
        tools = Tools()
        tools.branch = ""
        code, _, errors = self.invoke(tools)
        self.assertEqual(code, 2)
        self.assertIn("--ref", errors)
        tools.refs = {"refs/tags/v1": OTHER_SHA, "refs/tags/v1^{}": SHA}
        code, _, _ = self.invoke(tools, "--ref", "v1")
        self.assertEqual(code, 0)
        tools.refs["refs/tags/v1^{}"] = OTHER_SHA
        code, _, _ = self.invoke(tools, "--ref", "v1")
        self.assertEqual(code, 2)

    def test_ambiguous_ref_and_push_ref_combination_rejected(self):
        tools = Tools()
        tools.refs["refs/tags/feature/ci"] = SHA
        for args in (("--ref", "feature/ci"), ("--ref", "feature/ci", "--push")):
            with self.subTest(args=args):
                code, _, _ = self.invoke(tools, *args)
                self.assertEqual(code, 2)
                self.assertFalse(any(c[0] == "gh" for c in tools.commands()))

    def test_completed_conclusions(self):
        for conclusion in ("success", "failure", "cancelled", "timed_out", "skipped", "neutral"):
            with self.subTest(conclusion=conclusion):
                tools = Tools()
                tools.runs = [run_record(conclusion=conclusion)]
                code, output, errors = self.invoke(tools, "--json")
                self.assertEqual(code, 0 if conclusion == "success" else 1)
                self.assertEqual(json.loads(output)["conclusion"], conclusion)
                if code:
                    self.assertIn("gh run view 42", errors)
                    self.assertIn("--repo github.example/owner/repo", errors)

    def test_waits_for_only_identified_run(self):
        tools = Tools()
        tools.runs = [run_record(status="queued", conclusion="")]
        tools.views = [run_record(status="in_progress", conclusion=""), run_record()]
        code, output, errors = self.invoke(tools, "--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)["status"], "completed")
        views = [c for c in tools.commands() if c[:3] == ("gh", "run", "view")]
        self.assertEqual(len(views), 2)
        self.assertTrue(all(c[3] == "42" for c in views))
        self.assertIn("queued", errors)
        self.assertIn("in_progress", errors)

    def test_no_wait_still_identifies_own_run(self):
        tools = Tools()
        tools.runs = [run_record(status="queued", conclusion="")]
        code, output, _ = self.invoke(tools, "--no-wait", "--json", "--suite", "check")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)["run_id"], 42)
        self.assertFalse(any(c[:3] == ("gh", "run", "view") for c in tools.commands()))

    def test_wrong_sha_retains_identity_for_inspection(self):
        tools = Tools()
        tools.runs = [run_record(headSha=OTHER_SHA)]
        code, output, errors = self.invoke(tools, "--json")
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output)["run_id"], 42)
        self.assertIn("gh run view 42", errors)

    def test_duplicate_correlation_is_not_accepted(self):
        tools = Tools()
        tools.runs = [run_record(), run_record(databaseId=43)]
        code, output, _ = self.invoke(tools, "--json")
        self.assertEqual(code, 2)
        self.assertIsNone(json.loads(output)["run_id"])

    def test_invalid_run_id_is_sanitized_error(self):
        for value in (None, "42", -1, True):
            tools = Tools()
            tools.runs = [run_record(databaseId=value)]
            code, output, _ = self.invoke(tools, "--json")
            self.assertEqual(code, 2)
            self.assertIn("metadata", json.loads(output)["error"])

    def test_malformed_git_remote_metadata_is_sanitized_error(self):
        client = ci.Client(10)
        args = ci.parser().parse_args([])
        with patch.object(client, "command", side_effect=[
            "", SHA, "https://github.example/owner/repo.git", "feature/ci", "", "secret",
        ]):
            with self.assertRaisesRegex(ci.CIError, "invalid remote ref metadata") as raised:
                ci.preflight(client, args)
        self.assertNotIn("secret", str(raised.exception))

    def test_discovery_timeout_reports_request_without_cancelling(self):
        tools = Tools()
        tools.runs = []
        code, output, errors = self.invoke(tools, "--json", pause=ci.LocalTimeout())
        self.assertEqual(code, 124)
        self.assertEqual(json.loads(output)["request_id"], REQUEST)
        self.assertIn("Find request title: checks / " + REQUEST, errors)
        self.assertFalse(any("cancel" in c for c in tools.commands()))

    def test_known_run_timeout_keeps_run_identity(self):
        tools = Tools()
        tools.runs = [run_record(status="queued", conclusion="")]
        code, output, errors = self.invoke(tools, "--json", pause=ci.LocalTimeout())
        self.assertEqual(code, 124)
        self.assertEqual(json.loads(output)["run_id"], 42)
        self.assertIn("gh run view 42", errors)

    def test_interrupt_during_dispatch_does_not_cancel(self):
        tools = Tools()
        tools.interrupt = True
        code, output, errors = self.invoke(tools, "--json")
        self.assertEqual(code, 130)
        self.assertEqual(json.loads(output)["request_id"], REQUEST)
        self.assertIn("not cancelled", errors)
        self.assertIn("Find request title", errors)

    def test_gh_failure_is_json_and_sanitized(self):
        tools = Tools()
        tools.fail = ("gh", "api")
        code, output, errors = self.invoke(tools, "--json")
        self.assertEqual(code, 2)
        self.assertIn("auth", json.loads(output)["error"])
        self.assertNotIn("secret", output + errors)

    def test_subprocess_deadline_and_missing_binary(self):
        client = ci.Client(10)
        with patch("ci.subprocess.run", side_effect=subprocess.TimeoutExpired("git", 10)):
            with self.assertRaises(ci.LocalTimeout):
                client.command("git", "status")
        with patch("ci.subprocess.run", side_effect=FileNotFoundError()):
            with self.assertRaisesRegex(ci.CIError, "required"):
                client.command("gh", "version")
        client.deadline = 0
        with self.assertRaises(ci.LocalTimeout):
            client.remaining()

    def test_malformed_gh_json_is_controlled_error(self):
        client = ci.Client(10)
        for output in ("not-json", "null", "[1]"):
            with self.subTest(output=output), patch.object(client, "gh", return_value=output):
                with self.assertRaises(ci.CIError):
                    client.run_json("run", "list")

    def test_origin_urls_and_credentials(self):
        for url in ("https://user:secret@github.example/owner/repo.git",
                    "ssh://git@github.example/owner/repo.git",
                    "git@github.example:owner/repo.git"):
            self.assertEqual(ci.origin_repository(url), ("github.example", "owner/repo"))
        for url in ("file:///tmp/repo", "http://github.example/owner/repo",
                    "https://secret@github.example/owner/repo/extra",
                    "https://github.example/../repo", "/tmp/repo",
                    "https://github.example:bad/owner/repo"):
            with self.subTest(url=url):
                with self.assertRaises(ci.CIError) as raised:
                    ci.origin_repository(url)
                self.assertNotIn("secret", str(raised.exception))

    def test_timeout_validation(self):
        for value in ("0", "-1", "nan", "inf", "nope"):
            with self.subTest(value=value), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    ci.parser().parse_args(["--timeout", value])
                self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
