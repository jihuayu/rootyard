"""Pure contract tests for the workspace FUSE failure diagnostics projection.

These tests use only local fake exceptions and tracebacks. They do not start the
service, a FUSE mount, a child process, PostgreSQL, Git, or the network.
"""
import io
import json
from pathlib import Path
import subprocess
import types
import unittest
import urllib.error

from workspace_fuse_service_acceptance import (
    DIAGNOSTIC_FAILURE_TYPES,
    FAILURE_PHASES,
    MAX_DIAGNOSTIC_LINE,
    REQUIRED_CASES,
    ROOT,
    SOURCE_PATHS,
    WorkspaceFuseDiagnosticResult,
    _bounded_int,
    _child_exit,
    _diagnostic_record,
    _errno,
    _exception_kind,
    _failure_phase,
    _http_status,
    _report_payload,
    _source_location,
    _unknown_diagnostic,
)

SECRET = "SECRET-must-never-appear"


class _HiddenError(Exception):
    """Unknown exception whose text/repr expose a secret and count calls."""

    def __init__(self):
        self.text_calls = 0

    def __str__(self):
        self.text_calls += 1
        return SECRET

    def __repr__(self):
        self.text_calls += 1
        return SECRET


def _traceback_at(filename, source):
    try:
        exec(compile(source, filename, "exec"), {})
    except BaseException as error:
        return error.__traceback__
    raise AssertionError("synthetic source did not raise")


def _case(test_id):
    return types.SimpleNamespace(id=lambda: test_id)


class _ResultShape:
    def __init__(self, failures=(), errors=(), skipped=(), tests_run=3):
        self.failures = list(failures)
        self.errors = list(errors)
        self.skipped = list(skipped)
        self.expectedFailures = []
        self.unexpectedSuccesses = []
        self.testsRun = tests_run


class WorkspaceFuseDiagnosticsContractTest(unittest.TestCase):
    def test_secret_message_is_never_rendered(self):
        error = _HiddenError()
        tb = _traceback_at(
            str(ROOT / "tests/test_workspace_fuse_service.py"),
            "raise ValueError('synthetic')\n",
        )
        test = _case(REQUIRED_CASES[2])
        test._rootyard_diagnostic_primary_phase = "signal"
        record = _diagnostic_record(test, error, tb)

        self.assertEqual(error.text_calls, 0)
        self.assertNotIn(SECRET, json.dumps(record))
        self.assertEqual(record["exception"], "unknown")
        self.assertEqual(record["phase"], "signal")
        self.assertEqual(record["source"], {"path": "tests/test_workspace_fuse_service.py", "line": 1})

    def test_unknown_exception_and_phase_remain_unknown(self):
        self.assertEqual(_exception_kind(_HiddenError()), "unknown")
        self.assertEqual(_exception_kind(AssertionError("synthetic")), "AssertionError")
        self.assertIn("CalledProcessError", DIAGNOSTIC_FAILURE_TYPES)
        for phase in FAILURE_PHASES:
            self.assertEqual(_failure_phase(types.SimpleNamespace(
                _rootyard_diagnostic_primary_phase=phase)), phase)
        self.assertIsNone(_failure_phase(types.SimpleNamespace(
            _rootyard_diagnostic_primary_phase="not-a-phase")))

    def test_non_numeric_bool_and_overflow_scalars_are_rejected(self):
        self.assertEqual(_bounded_int(503, 100, 599), 503)
        for value in (True, False, "503", 99, 600, 10 ** 9, 503.0):
            self.assertIsNone(_bounded_int(value, 100, 599))

        status_error = urllib.error.HTTPError("http://invalid", 503, "", None, None)
        try:
            self.assertEqual(_http_status(status_error), 503)
        finally:
            status_error.close()
        bool_error = urllib.error.HTTPError("http://invalid", True, "", None, None)
        try:
            self.assertIsNone(_http_status(bool_error))
        finally:
            bool_error.close()

        self.assertEqual(_errno(OSError(5, SECRET)), 5)
        class _BoolErrno(OSError):
            errno = True
        self.assertIsNone(_errno(_BoolErrno()))
        class _BigErrno(OSError):
            errno = 10 ** 9
        self.assertIsNone(_errno(_BigErrno()))

        self.assertEqual(_child_exit(
            subprocess.CalledProcessError(3, ["secret-argv"], output=b"secret")), 3)
        self.assertIsNone(_child_exit(
            subprocess.CalledProcessError(True, ["secret-argv"])))
        self.assertIsNone(_child_exit(
            subprocess.CalledProcessError(10 ** 6, ["secret-argv"])))

    def test_source_location_allows_only_known_paths_and_valid_lines(self):
        allowed = _source_location(_traceback_at(
            str(ROOT / "tests/test_workspace_fuse_service.py"),
            "raise ValueError('synthetic')\n"))
        self.assertEqual(allowed, {"path": "tests/test_workspace_fuse_service.py", "line": 1})
        self.assertIn(allowed["path"], SOURCE_PATHS)

        foreign = _source_location(_traceback_at(
            str(ROOT / "tests/test_workspace_fuse_service_acceptance_diagnostics.py"),
            "raise ValueError('synthetic')\n"))
        self.assertIsNone(foreign)

        overflowing = _source_location(_traceback_at(
            str(ROOT / "tests/test_workspace_fuse_service.py"),
            "\n" * (MAX_DIAGNOSTIC_LINE - 1) + "raise ValueError('synthetic')\n"))
        self.assertIsNone(overflowing)

    def test_primary_phase_wins_over_cleanup_and_missing_record_is_null(self):
        test = _case(REQUIRED_CASES[2])
        test._rootyard_diagnostic_primary_phase = "signal"
        test._rootyard_diagnostic_phase = "cleanup"
        self.assertEqual(_failure_phase(test), "signal")

        self.assertEqual(_failure_phase(types.SimpleNamespace(
            _rootyard_diagnostic_phase="cleanup")), "cleanup")
        self.assertIsNone(_failure_phase(types.SimpleNamespace()))

        unknown = _unknown_diagnostic()
        self.assertEqual(unknown["exception"], "unknown")
        self.assertIsNone(unknown["phase"])
        self.assertIsNone(unknown["source"])
        self.assertIsNone(unknown["http_status"])
        self.assertIsNone(unknown["errno"])
        self.assertIsNone(unknown["child_exit"])

    def test_result_captures_before_unittest_formats_the_exception(self):
        result = WorkspaceFuseDiagnosticResult(io.StringIO(), False, 0)
        seen = {}
        error = _HiddenError()
        tb = _traceback_at(
            str(ROOT / "tests/test_workspace_fuse_service.py"),
            "raise ValueError('synthetic')\n",
        )

        def _formatted(err, test):
            seen["captured"] = test.id() in result.diagnostics
            return SECRET

        result._exc_info_to_string = _formatted
        test = _case(REQUIRED_CASES[2])
        test._rootyard_diagnostic_primary_phase = "signal"
        result.addError(test, (_HiddenError, error, tb))

        self.assertTrue(seen["captured"])
        self.assertEqual(result.diagnostics[REQUIRED_CASES[2]]["phase"], "signal")
        self.assertEqual(result.diagnostics[REQUIRED_CASES[2]]["exception"], "unknown")
        self.assertNotIn(SECRET, json.dumps(result.diagnostics))

    def test_passed_skipped_error_counts_are_unchanged(self):
        error_id = REQUIRED_CASES[2]
        skipped_id = REQUIRED_CASES[1]
        result = _ResultShape(
            errors=[(_case(error_id), "raw error detail " + SECRET)],
            skipped=[(_case(skipped_id), "raw skip reason " + SECRET)],
        )
        diagnostics = {error_id: {
            "phase": "signal", "exception": "AssertionError", "source": None,
            "http_status": None, "errno": None, "child_exit": None,
        }}
        report = _report_payload(
            scheduled=REQUIRED_CASES, result=result, imported=True,
            diagnostics=diagnostics)

        self.assertFalse(report["passed"])
        self.assertEqual(report["counts"], {
            "success": 1, "failure": 0, "error": 1, "skipped": 1,
            "expected_failure": 0, "unexpected_success": 0,
        })
        by_name = {case["name"]: case for case in report["cases"]}
        self.assertEqual(by_name[error_id]["status"], "error")
        self.assertEqual(by_name[error_id]["diagnostic"]["phase"], "signal")
        self.assertEqual(by_name[skipped_id]["status"], "skipped")
        self.assertNotIn("diagnostic", by_name[skipped_id])
        self.assertNotIn(SECRET, json.dumps(report))

    def test_missing_or_invalid_diagnostics_never_create_a_pass(self):
        error_id = REQUIRED_CASES[2]
        result = _ResultShape(errors=[(_case(error_id), "raw error detail " + SECRET)])
        report = _report_payload(
            scheduled=REQUIRED_CASES, result=result, imported=True,
            diagnostics={"not-the-case": {"phase": "signal"}})

        self.assertFalse(report["passed"])
        self.assertEqual(report["counts"]["error"], 1)
        case = next(case for case in report["cases"] if case["name"] == error_id)
        self.assertEqual(case["diagnostic"], _unknown_diagnostic())
        self.assertNotIn(SECRET, json.dumps(report))

        passing = _report_payload(
            scheduled=REQUIRED_CASES, result=_ResultShape(), imported=True,
            diagnostics={"junk": {"phase": "signal"}})
        self.assertTrue(passing["passed"])
        self.assertTrue(all("diagnostic" not in case for case in passing["cases"]))

    def test_allowed_type_set_is_closed(self):
        self.assertLessEqual({"AssertionError", "OSError", "NormalShutdownError"},
                             DIAGNOSTIC_FAILURE_TYPES)
        self.assertNotIn("_HiddenError", DIAGNOSTIC_FAILURE_TYPES)


if __name__ == "__main__":
    unittest.main()
