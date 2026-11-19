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
import tempfile
import unittest
from unittest import mock

from tests import s4_git_exit_debugger as debugger

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "target"


FAKE_GDB = """#!/usr/bin/env python3
import os
import sys

mode = os.environ.get("FAKE_GDB_MODE", "classified")
if "--args" not in sys.argv:
    if mode == "bad_preflight":
        raise SystemExit(1)
    print('s4-gdb-python-ok')
    print('Line 359 of "src/namespace_service/s4_git_proc.rs"')
    raise SystemExit(0)

path = os.environ["S4_GIT_RESULT_PATH"]
nonce = os.environ["S4_GIT_NONCE"]
if mode == "missing":
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
    handle.write("\\n".join(lines) + "\\n")
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
    def test_operation_enum_is_closed(self) -> None:
        self.assertEqual(
            {operation.value for operation in debugger.Operation},
            {
                "proposal_fetch",
                "proposal_bundle_verify",
                "proposal_merge_base",
                "proposal_fsck",
                "source_projection",
                "source_fetch",
                "source_tree_listing",
                "root_mktree",
                "commit_synthesis",
                "pack_index",
            },
        )

    def test_every_physical_caller_location_matches_the_closed_table(self) -> None:
        debugger.verify_sites(ROOT)

    def test_the_six_exact_cases_are_in_source_order(self) -> None:
        self.assertEqual(debugger.test_cases(ROOT), debugger.EXPECTED_CASES)
        self.assertEqual(len(debugger.EXPECTED_CASES), 6)

    def test_innermost_verified_frame_wins(self) -> None:
        frames = [
            debugger.Frame("src/namespace_service/s4_git_proc.rs", 359),
            debugger.Frame("src/namespace_service/s4_git_proc_reverse.rs", 190),
            debugger.Frame("src/namespace_service/s4_git_view_reverse.rs", 202),
        ]
        classification = debugger.classify_frames(frames)
        self.assertIs(classification.operation, debugger.Operation.ROOT_MKTREE)
        self.assertEqual(classification.frame, frames[1])

    def test_unknown_frame_is_unresolved(self) -> None:
        classification = debugger.classify_frames(
            [
                debugger.Frame("src/namespace_service/s4_git_proc.rs", 359),
                debugger.Frame("src/namespace_service/s4_git_view_reverse.rs", 99999),
            ]
        )
        self.assertIsNone(classification.operation)
        self.assertIs(classification.reason, debugger.Reason.NO_KNOWN_CALLER_FRAME)

    def test_outside_or_traversal_frames_are_ignored(self) -> None:
        for relative in ("/etc/passwd", "../escape.rs", ".git/config", "src/../x.rs"):
            with self.subTest(relative=relative):
                classification = debugger.classify_frames([debugger.Frame(relative, 1)])
                self.assertIsNone(classification.operation)

    def test_duplicate_caller_location_is_rejected(self) -> None:
        first = debugger.Site("src/namespace_service/s4_git_proc.rs", 1, debugger.Operation.PACK_INDEX, "x")
        second = debugger.Site("src/namespace_service/s4_git_proc.rs", 1, debugger.Operation.ROOT_MKTREE, "x")
        with self.assertRaises(debugger.MappingError):
            debugger.verify_sites(ROOT, (first, second))

    def test_stale_needle_is_rejected(self) -> None:
        stale = (
            debugger.Site(
                "src/namespace_service/s4_git_view_reverse.rs",
                170,
                debugger.Operation.PROPOSAL_FETCH,
                "not-the-physical-line",
            ),
        )
        with self.assertRaises(debugger.MappingError):
            debugger.verify_sites(ROOT, stale)

    def test_changed_case_order_is_rejected(self) -> None:
        with mock.patch.object(debugger, "EXPECTED_CASES", tuple(reversed(debugger.EXPECTED_CASES))):
            with self.assertRaises(debugger.PreflightError):
                debugger.test_cases(ROOT)

    def test_symlinked_source_is_rejected(self) -> None:
        TARGET.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=TARGET, prefix="s4-exit-link-") as directory:
            base = Path(directory)
            (base / "link.rs").symlink_to("/etc/passwd")
            with self.assertRaises(debugger.PreflightError):
                debugger.safe_repo_path(base, "link.rs")


class ResultGrammarTests(unittest.TestCase):
    NONCE = "0123456789abcdef0123456789abcdef"

    def result(self, *lines: str) -> str:
        return "\n".join(( "s4git-result 1 " + self.NONCE, *lines)) + "\n"

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

    def test_rejects_nonce_mismatch(self) -> None:
        with self.assertRaises(debugger.ResultError):
            debugger.parse_result(self.result("breakpoint resolved x 1"), "f" * 32)

    def test_rejects_a_breakpoint_at_another_line(self) -> None:
        with self.assertRaises(debugger.ResultError):
            debugger.parse_result(
                self.result(
                    "breakpoint resolved src/namespace_service/s4_git_proc.rs 358",
                    "failure 0",
                    "exit 0",
                    "signal 0",
                ),
                self.NONCE,
            )

    def test_rejects_unknown_record_and_absolute_frame(self) -> None:
        with self.assertRaises(debugger.ResultError):
            debugger.parse_result(
                self.result(
                    "breakpoint resolved src/namespace_service/s4_git_proc.rs 359",
                    "failure 1",
                    "frame /etc/passwd 1",
                    "exit 1",
                    "signal 0",
                    "marker injected",
                ),
                self.NONCE,
            )

    def test_rejects_duplicate_and_unbounded_records(self) -> None:
        with self.assertRaises(debugger.ResultError):
            debugger.parse_result(
                self.result(
                    "breakpoint resolved src/namespace_service/s4_git_proc.rs 359",
                    "failure 1",
                    "exit 1",
                    "exit 1",
                    "signal 0",
                ),
                self.NONCE,
            )
        with self.assertRaises(debugger.ResultError):
            debugger.parse_result(
                self.result(
                    "breakpoint resolved src/namespace_service/s4_git_proc.rs 359",
                    "failure 1",
                    *(f"frame src/namespace_service/s4_git_view_reverse.rs {line}" for line in range(1, 20)),
                    "exit 1",
                    "signal 0",
                ),
                self.NONCE,
            )

    def test_rejects_target_data_on_unresolved_breakpoint(self) -> None:
        with self.assertRaises(debugger.ResultError):
            debugger.parse_result(
                self.result(
                    "breakpoint unresolved src/namespace_service/s4_git_proc.rs 359",
                    "failure 0",
                    "exit 1",
                    "signal 0",
                    "error breakpoint_unresolved",
                ),
                self.NONCE,
            )

    def test_failure_kind_is_unknown_without_positive_evidence(self) -> None:
        self.assertIs(debugger.failure_kind(), debugger.FailureKind.UNKNOWN)
        self.assertIs(debugger.failure_kind(positively_nonzero=True), debugger.FailureKind.NONZERO_EXIT)
        self.assertIs(debugger.failure_kind(positively_signaled=True), debugger.FailureKind.SIGNALED)

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
        self.assertEqual(argv[-3:], [str(ROOT / "target" / "test-binary"), "--ignored", "--test-threads=1"])
        self.assertNotIn("attach", argv)
        self.assertNotIn("-ex", argv)
        self.assertEqual(argv.count("-x"), 1)

    def test_preflight_script_has_no_run_break_attach_or_target_code(self) -> None:
        body = debugger.GDB_PREFLIGHT.read_text(encoding="utf-8")
        self.assertIn("info line src/namespace_service/s4_git_proc.rs:359", body)
        self.assertIn("s4-gdb-python-ok", body)
        self.assertNotIn("run", body)
        self.assertNotIn("break ", body)
        self.assertNotIn("attach", body)
        self.assertNotIn("call ", body)

    def test_gdb_extension_has_one_breakpoint_and_no_target_calls(self) -> None:
        body = debugger.GDB_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("gdb.Breakpoint", body)
        self.assertIn("newest_frame", body)
        self.assertIn("unset environment", body)
        self.assertIn('gdb.execute("run")', body)
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

    def test_signaled_exit_is_preserved(self) -> None:
        self.assertEqual(self.run_sidecar("signaled"), 137)
        report = self.report()
        self.assertEqual(report["test_exit"], 137)
        self.assertEqual(report["status"], "classified_failure")

    def test_marker_with_success_exit_is_inconsistent(self) -> None:
        self.assertEqual(self.run_sidecar("marker_zero"), 3)
        report = self.report()
        self.assertEqual(report["status"], "inconsistent")

    def test_missing_result_fails_closed(self) -> None:
        self.assertEqual(self.run_sidecar("missing"), 2)
        report = self.report()
        self.assertEqual(report["status"], "unsupported")
        self.assertEqual(report["reason"], "result_missing")

    def test_invalid_result_fails_closed(self) -> None:
        self.assertEqual(self.run_sidecar("invalid"), 2)
        report = self.report()
        self.assertEqual(report["status"], "unsupported")
        self.assertEqual(report["reason"], "result_invalid")

    def test_absolute_frame_path_fails_closed(self) -> None:
        self.assertEqual(self.run_sidecar("bad_path"), 2)
        report = self.report()
        self.assertEqual(report["status"], "unsupported")
        self.assertEqual(report["reason"], "result_invalid")

    def test_unresolved_breakpoint_fails_closed(self) -> None:
        self.assertEqual(self.run_sidecar("breakpoint_unresolved"), 2)
        report = self.report()
        self.assertEqual(report["status"], "unsupported")
        self.assertEqual(report["reason"], "breakpoint_unresolved")

    def test_preflight_failure_does_not_run_the_suite(self) -> None:
        self.assertEqual(self.run_sidecar("bad_preflight"), 2)
        report = self.report()
        self.assertEqual(report["status"], "unsupported")
        self.assertEqual(report["reason"], "breakpoint_unresolved")
        self.assertIsNone(report["test_exit"])

    def test_source_preflight_failure_writes_a_bounded_unsupported_report(self) -> None:
        with mock.patch.object(debugger, "verify_sites", side_effect=debugger.PreflightError("stale")):
            self.assertEqual(self.run_sidecar("classified"), 2)
        report = self.report()
        self.assertEqual(report["status"], "unsupported")
        self.assertEqual(report["reason"], "source_preflight_failed")
        self.assertEqual(report["cases"], [])

    def test_git_version_preflight_failure_is_reported_separately(self) -> None:
        with mock.patch.object(debugger, "probe_git_version", side_effect=debugger.PreflightError("missing")):
            self.assertEqual(self.run_sidecar("classified"), 2)
        report = self.report()
        self.assertEqual(report["status"], "unsupported")
        self.assertEqual(report["reason"], "git_version_unavailable")

    def test_report_has_no_absolute_paths(self) -> None:
        self.assertEqual(self.run_sidecar("classified"), 101)
        payload = self.report_path.read_text(encoding="utf-8")
        self.assertNotIn(str(ROOT), payload)
        self.assertNotIn("/Users/", payload)
        self.assertNotIn("/tmp/", payload)


class ReportShapeTests(unittest.TestCase):
    def sample(self) -> dict[str, object]:
        return debugger.make_report(
            status=debugger.Status.NO_FAILURE_OBSERVED,
            reason=debugger.Reason.NONE,
            test_exit=0,
            failure_observed=False,
            operation=None,
            caller=None,
            debug_resolution="resolved",
            git_version=(2, 43, 0),
            cases=debugger.EXPECTED_CASES,
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

    def test_fixed_report_shape_is_valid(self) -> None:
        debugger.validate_report(self.sample())

    def test_classified_caller_must_be_a_verified_site(self) -> None:
        report = self.sample()
        report["status"] = "classified_failure"
        report["reason"] = "classified"
        report["test_exit"] = 101
        report["test_suite"] = "failed"
        report["failure_observed"] = True
        report["operation"] = "proposal_fetch"
        report["caller"] = {"file": "src/namespace_service/s4_git_view_reverse.rs", "line": 170}
        debugger.validate_report(report)
        report["caller"] = {"file": "src/namespace_service/s4_git_view_reverse.rs", "line": 1}
        with self.assertRaises(ValueError):
            debugger.validate_report(report)

    def test_unsupported_preflight_report_may_have_no_case_list(self) -> None:
        report = self.sample()
        report["status"] = "unsupported"
        report["reason"] = "source_preflight_failed"
        report["test_exit"] = None
        report["test_suite"] = "not_run"
        report["debug_resolution"] = "not_run"
        report["git_version"] = None
        report["cases"] = []
        report["binary_sha256"] = None
        report["source"] = {}
        debugger.validate_report(report)

    def test_absolute_path_is_rejected(self) -> None:
        report = self.sample()
        report["caller"] = {"file": "/etc/passwd", "line": 1}
        with self.assertRaises(ValueError):
            debugger.validate_report(report)

    def test_report_is_bounded(self) -> None:
        report = self.sample()
        report["limitations"] = ["x" * debugger.MAX_REPORT_BYTES]
        with self.assertRaises(ValueError):
            debugger.validate_report(report)


if __name__ == "__main__":
    unittest.main()
