#!/usr/bin/env python3

import subprocess
import unittest
from unittest import mock

import run_bounded_benchmark


class RunBoundedBenchmarkTest(unittest.TestCase):
    def test_process_group_exit_at_deadline_returns_timeout(self) -> None:
        process = mock.Mock(pid=1234)
        process.wait.side_effect = [
            subprocess.TimeoutExpired(["benchmark"], 1),
            0,
            0,
        ]
        with (
            mock.patch.object(run_bounded_benchmark.subprocess, "Popen", return_value=process) as popen,
            mock.patch.object(run_bounded_benchmark.os, "killpg", side_effect=ProcessLookupError) as killpg,
        ):
            status = run_bounded_benchmark.run_bounded(1, ["benchmark"])

        self.assertEqual(status, 124)
        popen.assert_called_once_with(["benchmark"], start_new_session=True)
        self.assertEqual(
            process.wait.call_args_list,
            [mock.call(timeout=1), mock.call(timeout=5), mock.call()],
        )
        self.assertEqual(killpg.call_count, 2)


if __name__ == "__main__":
    unittest.main()
