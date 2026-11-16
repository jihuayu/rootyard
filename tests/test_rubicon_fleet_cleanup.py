"""Regression tests for partial Rubicon serve-blob fleet launch cleanup (Refs #164)."""

from __future__ import annotations

import builtins
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
from typing import Any
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from rubicon_workload.runner import _start_fleet  # noqa: E402

_CHILD_CODE = "import time; time.sleep(30)"


class RubiconFleetCleanupTests(unittest.TestCase):
    def _run_partial_launch_failure(self, failure: BaseException, fail_on: str, expected_logs: int) -> None:
        real_open = builtins.open
        real_popen = subprocess.Popen
        opened_logs: list[Any] = []
        child_proc: subprocess.Popen[bytes] | None = None
        child_alive_at_failure = False

        def tracking_open(file: object, *args: object, **kwargs: object) -> Any:
            nonlocal child_alive_at_failure
            try:
                name = Path(file).name  # type: ignore[arg-type]
            except TypeError:
                name = ""
            if fail_on == "open" and name == "serve-blob-1.log":
                if child_proc is not None:
                    child_alive_at_failure = child_proc.poll() is None
                raise failure
            handle = real_open(file, *args, **kwargs)  # type: ignore[arg-type]
            if name.startswith("serve-blob-") and name.endswith(".log"):
                opened_logs.append(handle)
            return handle

        def flaky_popen(args: list[str], **kwargs: object) -> subprocess.Popen[bytes]:
            nonlocal child_proc, child_alive_at_failure
            if child_proc is None:
                child_proc = real_popen(
                    [sys.executable, "-c", _CHILD_CODE],
                    stdout=kwargs.get("stdout"),
                    stderr=kwargs.get("stderr"),
                    start_new_session=True,
                    env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
                )
                return child_proc
            if fail_on == "popen":
                child_alive_at_failure = child_proc.poll() is None
                raise failure
            raise AssertionError("second Popen must not be reached in this failure injection")

        with tempfile.TemporaryDirectory() as td:
            scratch = Path(td)
            try:
                with mock.patch("builtins.open", side_effect=tracking_open), \
                     mock.patch("rubicon_workload.runner.subprocess.Popen", side_effect=flaky_popen):
                    with self.assertRaises(BaseException) as caught:
                        _start_fleet(
                            2,
                            "/unused/rootyard",
                            {},
                            "/usr/bin/git",
                            "postgresql://u@127.0.0.1/db",
                            "http://127.0.0.1:9",
                            scratch,
                        )

                self.assertIs(caught.exception, failure)
                self.assertIsNotNone(child_proc)
                self.assertTrue(child_alive_at_failure)
                try:
                    child_proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.fail("partially started fleet child was not reaped")
                self.assertIsNotNone(child_proc.poll())
                with self.assertRaises(ProcessLookupError):
                    os.killpg(child_proc.pid, 0)
                self.assertEqual(len(opened_logs), expected_logs)
                for handle in opened_logs:
                    self.assertTrue(handle.closed)
            finally:
                if child_proc is not None and child_proc.poll() is None:
                    try:
                        os.killpg(child_proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        child_proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        pass
                for handle in opened_logs:
                    if not handle.closed:
                        handle.close()

    def test_later_popen_oserror_reaps_partial_fleet_and_closes_owned_logs(self) -> None:
        injected = OSError("injected later Popen failure")
        self._run_partial_launch_failure(injected, "popen", expected_logs=2)

    def test_later_log_open_oserror_reaps_partial_fleet_and_closes_owned_logs(self) -> None:
        injected = OSError("injected later log open failure")
        self._run_partial_launch_failure(injected, "open", expected_logs=1)

    def test_keyboard_interrupt_after_first_worker_reaps_partial_fleet(self) -> None:
        self._run_partial_launch_failure(KeyboardInterrupt(), "popen", expected_logs=2)


if __name__ == "__main__":
    unittest.main()
