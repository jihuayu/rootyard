#!/usr/bin/env python3
"""Pure and instrumented tests for the failure-only S4 Git exit observer.

These tests never need GDB, PostgreSQL, S3, a network listener or a service.
The instrumented cases use a fake GDB executable to prove the bounded process
plumbing, the strict result grammar, exit-code preservation and fail-closed
behavior. One preflight case reads the real source tree and verifies every
closed caller locator against its physical file and line.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from tests import s4_git_exit_debugger as debugger

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "target"


FAKE_GDB = r"""#!/usr/bin/env python3
import os
import subprocess
import sys
import time

mode = os.environ.get("FAKE_GDB_MODE", "classified")
if "--args" not in sys.argv:
    if mode == "bad_preflight":
        raise SystemExit(1)
    if "--se" not in sys.argv:
        raise SystemExit(2)
    print('s4-gdb-python-ok')
    print('Line 359 of "src/namespace_service/s4_git_proc.rs" starts at address 0x0.')
    raise SystemExit(0)

if mode == "timeout":
    time.sleep(10)

path = os.environ["S4_GIT_RESULT_PATH"]
nonce = os.environ["S4_GIT_NONCE"]
if mode in ("interrupt", "interrupt_result"):
    if mode == "interrupt_result":
        with open(path, "x", encoding="utf-8") as handle:
            handle.write("\n".join([
                "s4git-result 1 " + nonce,
                "breakpoint resolved src/namespace_service/s4_git_proc.rs 359",
                "failure 1",
                "frame src/namespace_service/s4_git_view_reverse.rs 170",
                "exit 101",
                "signal 0",
            ]) + "\n")
    child = subprocess.Popen([
        sys.executable,
        "-c",
        "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)",
    ])
    pidfile = os.environ.get("FAKE_GDB_PIDFILE")
    if pidfile:
        with open(pidfile, "w", encoding="utf-8") as handle:
            handle.write(str(child.pid))
    time.sleep(30)
    raise SystemExit(0)
if mode in ("missing", "no_result"):
    raise SystemExit(0)

lines = ["s4git-result 1 " + nonce]
if mode == "breakpoint_unresolved":
    lines += [
        "breakpoint unresolved src/namespace_service/s4_git_proc.rs 359",
        "error breakpoint_unresolved",
    ]
elif mode == "invalid":
    lines = ["bogus"]
else:
    lines.append("breakpoint resolved src/namespace_service/s4_git_proc.rs 359")
    failure = "0" if mode in ("no_failure", "no_marker_failure") else "1"
    lines.append("failure " + failure)
    if failure == "1":
        frame = {
            "classified": "frame src/namespace_service/s4_git_view_reverse.rs 170",
            "unresolved_frame": "frame src/namespace_service/s4_git_view_reverse.rs 99999",
            "signaled": "frame src/namespace_service/s4_git_view_reverse.rs 170",
            "no_marker_failure": "",
            "marker_zero": "frame src/namespace_service/s4_git_view_reverse.rs 170",
            "bad_path": "frame /etc/passwd 1",
        }[mode]
        if frame:
            lines.append(frame)
    exit_code = "0"
    if mode == "marker_zero":
        exit_code = "0"
    elif mode == "signaled":
        exit_code = "-1"
    elif mode == "no_marker_failure":
        exit_code = "101"
    elif failure == "1":
        exit_code = "101"
    lines.append("exit " + exit_code)
    lines.append("signal " + ("9" if mode == "signaled" else "0"))

with open(path, "x", encoding="utf-8") as handle:
    handle.write("\n".join(lines) + "\n")
"""


def _wait_for_path(path: Path, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.02)
    raise AssertionError("fake GDB did not publish its child pid")


def _pid_gone(pid: int, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        completed = subprocess.run(
            ["ps", "-o", "stat=", "-p", str(pid)],
            check=False,
            capture_output=True,
            text=True,
        )
        status = completed.stdout.strip()
        if completed.returncode != 0 or not status or status.startswith("Z"):
            return True
        time.sleep(0.05)
    return False


LEADER_SCRIPT = """import os
import signal
import subprocess
import sys
import time

pidfile = sys.argv[1]
child = subprocess.Popen([
    sys.executable,
    "-c",
    "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)",
])
with open(pidfile, "w", encoding="utf-8") as handle:
    handle.write(str(child.pid))
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
time.sleep(30)
"""


class ObserverFixture(unittest.TestCase):
    def setUp(self) -> None:
        TARGET.mkdir(exist_ok=True)
        self._temporary = tempfile.TemporaryDirectory(dir=TARGET, prefix="s4-exit-test-")
        self.base = Path(self._temporary.name)
        self.binary = self.base / "test-binary"
        self.binary.write_bytes(b"#!/bin/sh\nexit 0\n")
        self.binary.chmod(0o700)
        self.gdb = self.base / "fake-gdb"
        self.gdb.write_text(FAKE_GDB, encoding="utf-8")
        self.gdb.chmod(0o700)
        self.report_path = self.base / "report.json"
        self.work = self.base / "work"

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def run_sidecar(self, mode: str, extra: list[str] | None = None) -> int:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.dict(os.environ, {"FAKE_GDB_MODE": mode}):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                return debugger.main(
                    [
                        "--binary",
                        str(self.binary),
                        "--report",
                        str(self.report_path),
                        "--work-dir",
                        str(self.work),
                        "--source-root",
                        str(ROOT),
                        "--gdb",
                        str(self.gdb),
                        "--git",
                        "/usr/bin/git",
                        "--timeout-seconds",
                        "30",
                        *(extra or []),
                    ]
                )

    def report(self) -> dict[str, object]:
        return json.loads(self.report_path.read_text(encoding="utf-8"))


class ClosedMapperTests(unittest.TestCase):
    def test_every_physical_caller_location_matches_the_closed_table(self) -> None:
        debugger.verify_sites(ROOT)

    def test_target_case_is_unique_sha1_reverse_case(self) -> None:
        self.assertEqual(debugger.target_case(ROOT), debugger.TARGET_CASE)
        self.assertEqual(debugger.TARGET_OBJECT_FORMAT, "sha1")
        body = debugger.read_source(ROOT, debugger.TEST_FILE)
        self.assertEqual(body.count("async fn " + debugger.TARGET_CASE + "("), 1)

    def test_innermost_verified_frame_wins(self) -> None:
        frames = [
            debugger.Frame("src/namespace_service/s4_git_proc.rs", 359),
            debugger.Frame("src/namespace_service/s4_git_proc_reverse.rs", 190),
            debugger.Frame("src/namespace_service/s4_git_view_reverse.rs", 202),
        ]
        operation, frame = debugger.classify_frames(frames)
        self.assertIs(operation, debugger.Operation.ROOT_MKTREE)
        self.assertEqual(frame, frames[1])
    def test_missing_or_ambiguous_target_case_is_rejected(self) -> None:
        with mock.patch.object(debugger, "TARGET_CASE", "missing_case"):
            with self.assertRaises(debugger.PreflightError):
                debugger.target_case(ROOT)
        pattern = mock.Mock()
        pattern.findall.return_value = [debugger.TARGET_CASE, debugger.TARGET_CASE]
        with mock.patch.object(debugger, "CASE_PATTERN", pattern):
            with self.assertRaises(debugger.PreflightError):
                debugger.target_case(ROOT)
class ResultGrammarTests(unittest.TestCase):
    NONCE = "0123456789abcdef0123456789abcdef"

    def result(self, *lines: str) -> str:
        return "\n".join((("s4git-result 1 " + self.NONCE), *lines)) + "\n"

    def test_accepts_the_fixed_result_shape(self) -> None:
        parsed = debugger.parse_result(
            self.result(
                "breakpoint resolved src/namespace_service/s4_git_proc.rs 359",
                "failure 1",
                "frame src/namespace_service/s4_git_view_reverse.rs 170",
                "exit 101",
                "signal 0",
            ),
            self.NONCE,
        )
        self.assertTrue(parsed.failure)
        self.assertEqual(parsed.frames, (debugger.Frame("src/namespace_service/s4_git_view_reverse.rs", 170),))
        self.assertEqual(parsed.exit_code, 101)

    def test_rejects_malformed_or_injected_results(self) -> None:
        cases = {
            "nonce": self.result("breakpoint resolved src/namespace_service/s4_git_proc.rs 359", "failure 0", "exit 0", "signal 0"),
            "wrong-breakpoint": self.result(
                "breakpoint resolved src/namespace_service/s4_git_proc.rs 358", "failure 0", "exit 0", "signal 0"
            ),
            "absolute-frame": self.result(
                "breakpoint resolved src/namespace_service/s4_git_proc.rs 359",
                "failure 1", "frame /etc/passwd 1", "exit 1", "signal 0",
            ),
            "unknown-record": self.result(
                "breakpoint resolved src/namespace_service/s4_git_proc.rs 359",
                "failure 1", "marker injected", "exit 1", "signal 0",
            ),
            "duplicate-exit": self.result(
                "breakpoint resolved src/namespace_service/s4_git_proc.rs 359",
                "failure 1", "exit 1", "exit 1", "signal 0",
            ),
            "unresolved-with-target": self.result(
                "breakpoint unresolved src/namespace_service/s4_git_proc.rs 359",
                "failure 0", "exit 1", "signal 0", "error breakpoint_unresolved",
            ),
            "too-many-frames": self.result(
                "breakpoint resolved src/namespace_service/s4_git_proc.rs 359",
                "failure 1",
                *(f"frame src/namespace_service/s4_git_view_reverse.rs {line}" for line in range(1, 20)),
                "exit 1", "signal 0",
            ),
        }
        for name, text in cases.items():
            with self.subTest(name=name):
                with self.assertRaises(debugger.ResultError):
                    debugger.parse_result(text, "f" * 32 if name == "nonce" else self.NONCE)

    def test_git_version_is_numeric_only(self) -> None:
        self.assertEqual(debugger.parse_git_version("git version 2.43.0\n"), (2, 43, 0))
        self.assertEqual(debugger.parse_git_version("git version 2.50.1 (Apple Git-155)"), (2, 50, 1))
        with self.assertRaises(debugger.PreflightError):
            debugger.parse_git_version("git version unknown")


class FixedDebuggerCommandTests(unittest.TestCase):
    def test_run_argv_is_fixed_and_failure_scoped(self) -> None:
        argv = debugger.build_gdb_argv(ROOT, "gdb", ROOT / "target" / "test-binary")
        self.assertEqual(argv[0], "gdb")
        self.assertIn("--batch", argv)
        self.assertIn("--nx", argv)
        self.assertIn("-x", argv)
        self.assertIn("--args", argv)
        self.assertEqual(
            argv[-5:],
            [
                str(ROOT / "target" / "test-binary"),
                "--ignored",
                "--exact",
                debugger.TARGET_CASE,
                "--test-threads=1",
            ],
        )
        self.assertEqual(argv.count(debugger.TARGET_CASE), 1)
        self.assertNotIn("attach", argv)
        self.assertNotIn("-ex", argv)
        self.assertEqual(argv.count("-x"), 1)
    def test_preflight_argv_binds_the_verified_binary_before_the_script(self) -> None:
        binary = ROOT / "target" / "test-binary"
        argv = debugger.build_preflight_argv(ROOT, "gdb", binary)
        self.assertIn("--se", argv)
        self.assertEqual(argv[argv.index("--se") + 1], str(binary))
        self.assertLess(argv.index("--se"), argv.index("-x"))
        self.assertNotIn("--args", argv)
        self.assertNotIn("-ex", argv)

    def test_gdb_extension_has_one_breakpoint_and_no_target_calls(self) -> None:
        body = debugger.GDB_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("gdb.Breakpoint", body)
        self.assertIn("newest_frame", body)
        self.assertIn("unset environment", body)
        self.assertIn('gdb.execute("run")', body)
        self.assertIn("_REVERSE_PHASE_FILES", body)
        self.assertIn("s4_git_view_reverse.rs", body)
        self.assertNotIn("gdb.execute(\"attach", body)
        self.assertNotIn("gdb.execute(\"call", body)
        self.assertNotIn("parse_and_eval", body)


class InstrumentedObserverTests(ObserverFixture):
    def test_classified_failure_preserves_exit_code_and_bounded_report(self) -> None:
        self.assertEqual(self.run_sidecar("classified"), 101)
        report = self.report()
        debugger.validate_report(report)
        self.assertEqual(report["status"], "classified_failure")
        self.assertEqual(report["operation"], "proposal_fetch")
        self.assertEqual(report["failure_kind"], "unknown")
        self.assertEqual(report["test_exit"], 101)
        self.assertTrue(report["failure_observed"])
        self.assertEqual(report["caller"], {"file": "src/namespace_service/s4_git_view_reverse.rs", "line": 170})
        self.assertEqual(report["binary_sha256"], debugger.hash_file(self.binary))
        self.assertEqual(report["source"]["harness_sha256"], debugger.hash_file(ROOT / debugger.HARNESS_FILE))
        self.assertTrue(report["rebuilt_executable_may_differ_by_build_path"])

    def test_no_failure_marker_is_not_called_a_diagnostic_pass(self) -> None:
        self.assertEqual(self.run_sidecar("no_failure"), 0)
        report = self.report()
        self.assertEqual(report["status"], "no_failure_observed")
        self.assertFalse(report["failure_observed"])
        self.assertIsNone(report["operation"])

    def test_failure_without_marker_is_unresolved_and_preserved(self) -> None:
        self.assertEqual(self.run_sidecar("no_marker_failure"), 101)
        report = self.report()
        self.assertEqual(report["status"], "unresolved_failure")
        self.assertEqual(report["reason"], "no_failure_marker")
        self.assertIsNone(report["operation"])

    def test_unknown_frame_is_unresolved_and_preserved(self) -> None:
        self.assertEqual(self.run_sidecar("unresolved_frame"), 101)
        report = self.report()
        self.assertEqual(report["status"], "unresolved_failure")
        self.assertEqual(report["reason"], "no_known_caller_frame")
        self.assertIsNone(report["operation"])
    def test_child_failure_with_zero_exit_reports_mismatch_and_passes_zero(self) -> None:
        self.assertEqual(self.run_sidecar("marker_zero"), 0)
        report = self.report()
        debugger.validate_report(report)
        self.assertEqual(report["status"], "observer_mismatch")
        self.assertEqual(report["test_exit"], 0)
        self.assertTrue(report["failure_observed"])
        self.assertEqual(report["operation"], "proposal_fetch")
        self.assertEqual(report["test_suite"], "passed")
        self.assertEqual(report["run_phase"], "completed")
    def test_missing_result_reports_started_without_result(self) -> None:
        self.assertEqual(self.run_sidecar("no_result"), 2)
        report = self.report()
        debugger.validate_report(report)
        self.assertEqual(report["status"], "unsupported")
        self.assertEqual(report["reason"], "result_missing")
        self.assertEqual(report["run_phase"], "run_started_no_result")
        self.assertEqual(report["test_suite"], "started_unknown")

    def test_started_timeout_is_not_reported_as_never_started(self) -> None:
        self.assertEqual(self.run_sidecar("timeout", ["--timeout-seconds", "1"]), 2)
        report = self.report()
        debugger.validate_report(report)
        self.assertEqual(report["status"], "unsupported")
        self.assertEqual(report["reason"], "run_timed_out")
        self.assertEqual(report["run_phase"], "run_started_timed_out")
        self.assertEqual(report["test_suite"], "started_unknown")
        self.assertIsNone(report["test_exit"])

    def test_invalid_result_reports_started_with_invalid_result(self) -> None:
        self.assertEqual(self.run_sidecar("invalid"), 2)
        report = self.report()
        debugger.validate_report(report)
        self.assertEqual(report["status"], "unsupported")
        self.assertEqual(report["reason"], "result_invalid")
        self.assertEqual(report["run_phase"], "run_started_invalid_result")
        self.assertEqual(report["test_suite"], "started_unknown")
    def test_unresolved_breakpoint_reports_target_not_run(self) -> None:
        self.assertEqual(self.run_sidecar("breakpoint_unresolved"), 2)
        report = self.report()
        debugger.validate_report(report)
        self.assertEqual(report["status"], "unsupported")
        self.assertEqual(report["reason"], "breakpoint_unresolved")
        self.assertEqual(report["run_phase"], "run_started_target_not_run")
        self.assertEqual(report["test_suite"], "not_run")

    def test_preflight_failure_is_reported_as_preflight_not_run(self) -> None:
        self.assertEqual(self.run_sidecar("bad_preflight"), 2)
        report = self.report()
        debugger.validate_report(report)
        self.assertEqual(report["status"], "unsupported")
        self.assertEqual(report["reason"], "breakpoint_unresolved")
        self.assertEqual(report["run_phase"], "preflight_not_run")
        self.assertEqual(report["test_suite"], "not_run")
        self.assertIsNone(report["test_exit"])

    def test_source_preflight_failure_writes_a_bounded_unsupported_report(self) -> None:
        with mock.patch.object(debugger, "verify_sites", side_effect=debugger.PreflightError("stale")):
            self.assertEqual(self.run_sidecar("classified"), 2)
        report = self.report()
        debugger.validate_report(report)
        self.assertEqual(report["status"], "unsupported")
        self.assertEqual(report["reason"], "source_preflight_failed")
        self.assertEqual(report["run_phase"], "preflight_not_run")
        self.assertEqual(report["case"], debugger.TARGET_CASE)
        self.assertEqual(report["test_suite"], "not_run")
    def test_report_has_no_absolute_paths(self) -> None:
        self.assertEqual(self.run_sidecar("classified"), 101)
        payload = self.report_path.read_text(encoding="utf-8")
        self.assertNotIn(str(ROOT), payload)
        self.assertNotIn("/Users/", payload)
        self.assertNotIn("/tmp/", payload)

    def test_started_interrupt_cleans_the_owned_group_and_preserves_a_known_exit(self) -> None:
        cases = (
            ("interrupt", None, "started_unknown"),
            ("interrupt_result", 101, "failed"),
        )
        for mode, expected_exit, expected_suite in cases:
            with self.subTest(mode=mode):
                pidfile = self.base / (mode + ".pid")
                report_path = self.base / (mode + ".json")
                work = self.base / ("work-" + mode)
                environment = dict(os.environ, FAKE_GDB_MODE=mode, FAKE_GDB_PIDFILE=str(pidfile))
                process = subprocess.Popen(
                    [
                        sys.executable,
                        str(ROOT / "tests" / "s4_git_exit_debugger.py"),
                        "--binary",
                        str(self.binary),
                        "--report",
                        str(report_path),
                        "--work-dir",
                        str(work),
                        "--source-root",
                        str(ROOT),
                        "--gdb",
                        str(self.gdb),
                        "--git",
                        "/usr/bin/git",
                        "--timeout-seconds",
                        "30",
                    ],
                    cwd=ROOT,
                    env=environment,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                child_pid = None
                try:
                    _wait_for_path(pidfile)
                    child_pid = int(pidfile.read_text(encoding="utf-8").strip())
                    process.send_signal(signal.SIGINT)
                    self.assertEqual(process.wait(timeout=10), 2)
                    report = json.loads(report_path.read_text(encoding="utf-8"))
                    debugger.validate_report(report)
                    self.assertEqual(report["status"], "unsupported")
                    self.assertEqual(report["reason"], "run_interrupted")
                    self.assertEqual(report["run_phase"], "run_started_interrupted")
                    self.assertEqual(report["test_exit"], expected_exit)
                    self.assertEqual(report["test_suite"], expected_suite)
                    self.assertIsNone(report["operation"])
                    self.assertTrue(_pid_gone(child_pid))
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait()
                    if child_pid is not None and not _pid_gone(child_pid):
                        try:
                            os.kill(child_pid, signal.SIGKILL)
                        except OSError:
                            pass

    def test_stop_process_group_kills_term_resistant_descendant_after_leader_exit(self) -> None:
        leader_script = self.base / "leader.py"
        leader_script.write_text(LEADER_SCRIPT, encoding="utf-8")
        pidfile = self.base / "descendant.pid"
        leader = subprocess.Popen(
            [sys.executable, str(leader_script), str(pidfile)],
            start_new_session=True,
        )
        descendant_pid = None
        try:
            _wait_for_path(pidfile)
            descendant_pid = int(pidfile.read_text(encoding="utf-8").strip())
            debugger._stop_process_group(leader)
            self.assertIsNotNone(leader.poll())
            self.assertTrue(_pid_gone(descendant_pid))
        finally:
            try:
                os.killpg(leader.pid, signal.SIGKILL)
            except OSError:
                pass
            if leader.poll() is None:
                leader.kill()
                leader.wait()
            if descendant_pid is not None and not _pid_gone(descendant_pid):
                try:
                    os.kill(descendant_pid, signal.SIGKILL)
                except OSError:
                    pass


class ReportShapeTests(unittest.TestCase):
    def sample(self) -> dict[str, object]:
        return debugger.make_report(
            status=debugger.Status.NO_FAILURE_OBSERVED,
            reason=debugger.Reason.NONE,
            run_phase=debugger.RunPhase.COMPLETED,
            test_exit=0,
            failure_observed=False,
            operation=None,
            caller=None,
            debug_resolution="resolved",
            git_version=(2, 43, 0),
            binary_sha256="a" * 64,
            source={
                "runner_sha256": "b" * 64,
                "reverse_sha256": "c" * 64,
                "test_sha256": "d" * 64,
                "harness_sha256": "e" * 64,
            },
            base_commit="1" * 40,
            base_tree="2" * 40,
            base_parents=["3" * 40, "4" * 40],
        )
class ReportValidationTests(unittest.TestCase):
    def sample(self) -> dict[str, object]:
        return debugger.make_report(
            status=debugger.Status.NO_FAILURE_OBSERVED,
            reason=debugger.Reason.NONE,
            run_phase=debugger.RunPhase.COMPLETED,
            test_exit=0,
            failure_observed=False,
            operation=None,
            caller=None,
            debug_resolution="resolved",
            git_version=(2, 43, 0),
            binary_sha256="a" * 64,
            source={
                "runner_sha256": "b" * 64,
                "reverse_sha256": "c" * 64,
                "test_sha256": "d" * 64,
                "harness_sha256": "e" * 64,
            },
            base_commit="1" * 40,
            base_tree="2" * 40,
            base_parents=["3" * 40, "4" * 40],
        )

    def test_malformed_provenance_and_limits_are_rejected(self) -> None:
        debugger.validate_report(self.sample())
        cases = {
            "schema": ("schema", "other"),
            "git-short": ("git_version", [2, 43]),
            "git-string": ("git_version", ["2", 43, 0]),
            "source-missing": ("source", {"runner_sha256": "b" * 64}),
            "source-bad": ("source", {
                "runner_sha256": "b" * 64,
                "reverse_sha256": "not-a-hash",
                "test_sha256": "d" * 64,
                "harness_sha256": "e" * 64,
            }),
            "binary": ("binary_sha256", "not-a-hash"),
            "parents-short": ("base_parents", ["3" * 40]),
            "parent-bad": ("base_parents", ["3" * 40, "not-a-hash"]),
            "base-incomplete": ("base_tree", None),
            "limitations": ("limitations", ["other"]),
        }
        for name, (key, value) in cases.items():
            with self.subTest(name=name):
                report = self.sample()
                report[key] = value
                with self.assertRaises(ValueError):
                    debugger.validate_report(report)


if __name__ == "__main__":
    unittest.main()
