#!/usr/bin/env python3
"""Run the four workspace FUSE helper-authority cases in one process.

The runner selects the canonical source-bound CI binary first, then imports the
original test classes with ROOTYARD_TEST_FUSE_BACKEND=fuse-helper already set.
It intentionally does not replace, monkeypatch, or reimplement any test body,
timeout, assertion, wrapper, or pass condition.  The original tests continue to
create their own transitive ``unshare`` launchers around the real binary; this
report binds the canonical binary by hash and never claims the launcher bytes
are a new Rust product or a wrapper receipt.
"""
from __future__ import annotations

import argparse
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import traceback
import unittest
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
for path in (TESTS, ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from tests.workspace_capture_acceptance import TimedTextTestResult

REPORT_SCHEMA = "rootyard/issues91-95/workspace-fuse-service-acceptance/v1"
REQUIRED_CASES = (
    "tests.test_workspace_fuse_service.WorkspaceFuseServiceTest.test_live_editor_capture_checkpoint_and_remount",
    "tests.test_workspace_handoff.WorkspaceHandoffTest.test_expired_host_reattach_from_remote_checkpoint",
    "tests.test_workspace_fuse_service.WorkspaceFuseServiceTest.test_normal_sigterm_helper_unmount_precedes_parked_git_join",
    "tests.test_workspace_fuse_service.WorkspaceFuseServiceTest.test_api_sigkill_with_pending_kernel_writer",
)
SOURCE_PATHS = (
    "tests/test_workspace_fuse_service.py",
    "tests/test_workspace_handoff.py",
    "tests/workspace_normal_shutdown_support.py",
)
SAFE_FAILURE_TYPES = frozenset((
    "RuntimeError", "OSError", "ImportError", "ModuleNotFoundError",
    "SourceBindingError", "RuntimeBinarySelectionError", "AssertionError",
    "ValueError", "TypeError", "KeyError", "AttributeError", "FileNotFoundError",
    "NormalShutdownError",
))
DIAGNOSTIC_FAILURE_TYPES = SAFE_FAILURE_TYPES | frozenset((
    "HTTPError", "URLError", "CalledProcessError", "TimeoutExpired", "TimeoutError",
))
FAILURE_PHASES = frozenset((
    "setup", "API", "workspace", "capturefreeze", "Gitpark", "signal", "joins", "cleanup",
))
MAX_DIAGNOSTIC_LINE = 100_000

SHUTDOWN_OUTCOME_UNKNOWN = "unknown"
SHUTDOWN_OUTCOME_MULTIPLE = "multiple"
SHUTDOWN_OUTCOMES = frozenset((
    "helper_internal_503",
    "helper_deadline",
    "capture_scan",
    "git_drain",
    "http_join",
    "background_join",
    "native_quiescence",
    SHUTDOWN_OUTCOME_MULTIPLE,
    SHUTDOWN_OUTCOME_UNKNOWN,
))
MAX_SHUTDOWN_TAIL_BYTES = 64 * 1024
MAX_SHUTDOWN_RECORD_BYTES = 8 * 1024

_SHUTDOWN_TERMINAL_PREFIXES = (
    "Error: normal shutdown incomplete: ",
    "Error: service cleanup incomplete: ",
)
_SHUTDOWN_CONTAINER_PREFIXES = (
    "workspace capture/helper shutdown did not complete cleanly: ",
)
_SHUTDOWN_HELPER_CONTAINER = "workspace FUSE helper shutdown failed: "


def _shutdown_pattern(text):
    return re.compile(re.escape(text))


_SHUTDOWN_HELPER_PATTERNS = (
    (_shutdown_pattern("HTTP 503: service temporarily unavailable"),
     "helper_internal_503"),
    (_shutdown_pattern(
        "HTTP 504: workspace FUSE helper shutdown exceeded the shared "
        "normal-shutdown deadline"), "helper_deadline"),
    (_shutdown_pattern(
        "HTTP 504: workspace FUSE legacy mount teardown exceeded the shared "
        "normal-shutdown deadline"), "helper_deadline"),
)
_SHUTDOWN_TOP_LEVEL_PATTERNS = (
    (_shutdown_pattern(
        "owned workspace Git jobs/process cleanup did not complete cleanly"),
     "git_drain"),
    (_shutdown_pattern(
        "late owned workspace Git jobs/process cleanup did not complete cleanly"),
     "git_drain"),
    (_shutdown_pattern("HTTP server did not stop cleanly"), "http_join"),
    (_shutdown_pattern(
        "HTTP server did not join within the shutdown deadline"), "http_join"),
    (_shutdown_pattern("background worker did not stop cleanly"),
     "background_join"),
    (_shutdown_pattern("session GC task did not join cleanly"),
     "background_join"),
    (_shutdown_pattern("sharding controller did not stop cleanly"),
     "background_join"),
    (_shutdown_pattern("workspace maintenance task did not stop cleanly"),
     "background_join"),
    (_shutdown_pattern("dispatch publisher did not stop cleanly"),
     "background_join"),
    (_shutdown_pattern("dispatch delivery worker did not stop cleanly"),
     "background_join"),
    (_shutdown_pattern("webhook worker did not stop cleanly"),
     "background_join"),
    (_shutdown_pattern("metrics worker did not stop cleanly"),
     "background_join"),
    (_shutdown_pattern("native Git process cleanup did not prove quiescence"),
     "native_quiescence"),
    (_shutdown_pattern(
        "workspace capture worker did not stop before the abort-confirmation "
        "window"), "capture_scan"),
    (re.compile(
        r"workspace capture worker abort was requested but its JoinHandle did "
        r"not complete within the final \d+ms grace; producer-before-helper "
        r"ordering is not claimed"), "capture_scan"),
    (re.compile(r"workspace scan workers did not drain within \d+ms"),
     "capture_scan"),
    (re.compile(
        r"workspace capture worker did not finish cleanly during shutdown "
        r"\([^;\r\n]*\)"), "capture_scan"),
    (re.compile(
        r"workspace capture worker did not release cleanly after abort "
        r"\([^;\r\n]*\)"), "capture_scan"),
)


def _match_shutdown_clause(text, patterns):
    """Match one exact source-defined clause and return its tail/category."""
    for pattern, category in patterns:
        match = pattern.match(text)
        if match is None:
            continue
        tail = text[match.end():]
        if tail and not tail.startswith("; "):
            continue
        return category, tail[2:] if tail else ""
    return None, text


def _classify_shutdown_payload(payload):
    """Classify only complete, source-defined cleanup clauses."""
    categories = []
    rest = payload
    while rest:
        if rest.startswith(_SHUTDOWN_HELPER_CONTAINER):
            rest = rest[len(_SHUTDOWN_HELPER_CONTAINER):]
            if not rest:
                return SHUTDOWN_OUTCOME_UNKNOWN
            category, rest = _match_shutdown_clause(
                rest, _SHUTDOWN_HELPER_PATTERNS)
            if category is None:
                return SHUTDOWN_OUTCOME_UNKNOWN
            categories.append(category)
            continue
        for prefix in _SHUTDOWN_CONTAINER_PREFIXES:
            if rest.startswith(prefix):
                rest = rest[len(prefix):]
                break
        else:
            category, rest = _match_shutdown_clause(
                rest, _SHUTDOWN_TOP_LEVEL_PATTERNS)
            if category is None:
                return SHUTDOWN_OUTCOME_UNKNOWN
            categories.append(category)
            continue
        if not rest:
            return SHUTDOWN_OUTCOME_UNKNOWN
    if not categories:
        return SHUTDOWN_OUTCOME_UNKNOWN
    if len(set(categories)) == 1:
        return categories[0]
    return SHUTDOWN_OUTCOME_MULTIPLE


def project_shutdown_outcome(data):
    """Project one bounded harness-owned output tail to a closed outcome.

    Only the final complete ``Error:`` terminal record is considered.  The
    parser returns a fixed category or ``unknown``; it never returns or stores
    log text, paths, ids, dynamic payloads, request ids, stacks or output.
    """
    if not isinstance(data, (bytes, bytearray)):
        return SHUTDOWN_OUTCOME_UNKNOWN
    if len(data) > MAX_SHUTDOWN_TAIL_BYTES:
        return SHUTDOWN_OUTCOME_UNKNOWN
    try:
        text = bytes(data).decode("utf-8")
    except UnicodeDecodeError:
        return SHUTDOWN_OUTCOME_UNKNOWN
    terminal = None
    for line in text.splitlines():
        if any(line.startswith(prefix) for prefix in _SHUTDOWN_TERMINAL_PREFIXES):
            terminal = line
    if terminal is None:
        return SHUTDOWN_OUTCOME_UNKNOWN
    if len(terminal.encode("utf-8")) > MAX_SHUTDOWN_RECORD_BYTES:
        return SHUTDOWN_OUTCOME_UNKNOWN
    for prefix in _SHUTDOWN_TERMINAL_PREFIXES:
        if terminal.startswith(prefix):
            return _classify_shutdown_payload(terminal[len(prefix):])
    return SHUTDOWN_OUTCOME_UNKNOWN


def _shutdown_log_path(source):
    if isinstance(source, (str, os.PathLike)):
        return Path(source)
    name = getattr(source, "name", None)
    if isinstance(name, (str, os.PathLike)):
        return Path(name)
    return None


def read_shutdown_outcome(source):
    """Read only a bounded tail of harness-owned output and classify it."""
    try:
        path = _shutdown_log_path(source)
        if path is None:
            return SHUTDOWN_OUTCOME_UNKNOWN
        with open(path, "rb") as stream:
            stream.seek(0, os.SEEK_END)
            size = stream.tell()
            start = max(0, size - MAX_SHUTDOWN_TAIL_BYTES)
            stream.seek(start)
            data = stream.read(MAX_SHUTDOWN_TAIL_BYTES)
    except BaseException:
        return SHUTDOWN_OUTCOME_UNKNOWN
    if start:
        newline = data.find(b"\n")
        if newline < 0:
            return SHUTDOWN_OUTCOME_UNKNOWN
        data = data[newline + 1:]
    return project_shutdown_outcome(data)


def _flatten(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from _flatten(test)
        else:
            yield test


def _binding_value(binding, name):
    if not isinstance(binding, dict):
        return None
    value = binding.get(name)
    return value if isinstance(value, (str, int)) and not isinstance(value, bool) else None


def _failure_type(error):
    name = type(error).__name__
    return name if name in SAFE_FAILURE_TYPES else "unknown"


def _bounded_int(value, minimum, maximum):
    """Return only an exact integer inside a fixed closed range."""
    if type(value) is int and minimum <= value <= maximum:
        return value
    return None


def _exception_kind(error):
    name = type(error).__name__
    return name if name in DIAGNOSTIC_FAILURE_TYPES else "unknown"


def _http_status(error):
    if isinstance(error, urllib.error.HTTPError):
        return _bounded_int(getattr(error, "code", None), 100, 599)
    return None


def _errno(error):
    if isinstance(error, OSError):
        return _bounded_int(getattr(error, "errno", None), 1, 4095)
    return None


def _child_exit(error):
    if isinstance(error, subprocess.CalledProcessError):
        return _bounded_int(getattr(error, "returncode", None), -255, 255)
    return None


def _diagnostic_child_exit(test, error):
    """Use the original process code, else the test's returned API exit."""
    value = _child_exit(error)
    if value is not None:
        return value
    try:
        value = getattr(test, "_rootyard_diagnostic_api_exit", None)
    except BaseException:
        return None
    return _bounded_int(value, -255, 255)


def _relative_source_path(filename):
    try:
        return Path(filename).resolve().relative_to(ROOT).as_posix()
    except (OSError, ValueError):
        return None


def _source_location(tb):
    """Freeze one allowed source path/line, never a traceback or message."""
    if tb is None:
        return None
    try:
        frames = traceback.extract_tb(tb)
    except (AttributeError, TypeError, ValueError):
        return None
    for frame in reversed(frames):
        relative = _relative_source_path(frame.filename)
        if relative not in SOURCE_PATHS:
            continue
        line = _bounded_int(frame.lineno, 1, MAX_DIAGNOSTIC_LINE)
        if line is None:
            continue
        try:
            total = len((ROOT / relative).read_text(encoding="utf-8").splitlines())
        except (OSError, UnicodeError):
            return None
        if line > total:
            return None
        return {"path": relative, "line": line}
    return None


def _failure_phase(test):
    for attribute in ("_rootyard_diagnostic_primary_phase", "_rootyard_diagnostic_phase"):
        phase = getattr(test, attribute, None)
        if phase in FAILURE_PHASES:
            return phase
    return None


def _shutdown_outcome(test):
    """Read only the test's already projected fixed outcome, never raw output."""
    try:
        value = getattr(test, "_rootyard_diagnostic_shutdown_outcome", None)
        if isinstance(value, str) and value in SHUTDOWN_OUTCOMES:
            return value
    except BaseException:
        pass
    return SHUTDOWN_OUTCOME_UNKNOWN


def _unknown_diagnostic():
    return {
        "phase": None,
        "exception": "unknown",
        "source": None,
        "http_status": None,
        "errno": None,
        "child_exit": None,
        "shutdown_outcome": SHUTDOWN_OUTCOME_UNKNOWN,
    }


def _diagnostic_record(test, error, tb):
    return {
        "phase": _failure_phase(test),
        "exception": _exception_kind(error),
        "source": _source_location(tb),
        "http_status": _http_status(error),
        "errno": _errno(error),
        "child_exit": _diagnostic_child_exit(test, error),
        "shutdown_outcome": _shutdown_outcome(test),
    }


class WorkspaceFuseDiagnosticResult(TimedTextTestResult):
    """Timed result that freezes safe failure scalars before formatting."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.diagnostics = {}

    def _capture(self, test, err):
        try:
            test_id = test.id()
            if not isinstance(test_id, str) or test_id not in REQUIRED_CASES:
                return
            if not isinstance(err, tuple) or len(err) < 3:
                return
            error = err[1]
            if not isinstance(error, BaseException):
                return
            self.diagnostics[test_id] = _diagnostic_record(test, error, err[2])
        except BaseException:
            # A diagnostic failure remains an unknown/null record; it can
            # neither mask the original failure nor turn it into a pass.
            return

    def addError(self, test, err):
        self._capture(test, err)
        super().addError(test, err)

    def addFailure(self, test, err):
        self._capture(test, err)
        super().addFailure(test, err)


def _report_payload(binary_sha256=None, receipt_sha256=None, source_head=None,
                    expected_commit=None, failure_type=None, scheduled=(),
                    result=None, imported=True, diagnostics=None):
    diagnostics = diagnostics if isinstance(diagnostics, dict) else {}
    cases = []
    counts = {key: 0 for key in (
        "success", "failure", "error", "skipped",
        "expected_failure", "unexpected_success",
    )}
    tests_run = 0
    if result is not None:
        failure_ids = {test.id() for test, _ in result.failures}
        error_ids = {test.id() for test, _ in result.errors}
        skipped_ids = {test.id() for test, _ in result.skipped}
        expected_ids = {test.id() for test, _ in result.expectedFailures}
        unexpected_ids = {test.id() for test in result.unexpectedSuccesses}
        # Project only the cases actually scheduled by this run.  A missing
        # required case must not be reported as a passed case; the exact
        # scheduled/required comparison below rejects it, and the manifest then
        # sees that required name absent.
        for name in scheduled:
            if name in error_ids:
                status = "error"
            elif name in failure_ids:
                status = "failed"
            elif name in skipped_ids:
                status = "skipped"
            elif name in expected_ids:
                status = "expected_failure"
            elif name in unexpected_ids:
                status = "unexpected_success"
            else:
                status = "passed"
            case = {"name": name, "status": status}
            if status in ("failed", "error"):
                case["diagnostic"] = diagnostics.get(name) or _unknown_diagnostic()
            cases.append(case)
            counts[{"passed": "success", "failed": "failure"}.get(status, status)] += 1
        tests_run = int(result.testsRun)
    passed = bool(
        imported
        and result is not None
        and tuple(scheduled) == REQUIRED_CASES
        and tests_run == len(REQUIRED_CASES)
        and counts["success"] == len(REQUIRED_CASES)
        and counts["failure"] == 0
        and counts["error"] == 0
        and counts["skipped"] == 0
        and counts["expected_failure"] == 0
        and counts["unexpected_success"] == 0
    )
    return {
        "schema": REPORT_SCHEMA,
        "status": "passed" if passed else "failed",
        "passed": passed,
        "binary_sha256": binary_sha256,
        "receipt_sha256": receipt_sha256,
        "source_head": source_head,
        "expected_source_commit": expected_commit,
        "launcher": "original-tests-unshare-wrapper",
        "source_paths": list(SOURCE_PATHS),
        "scheduled": list(scheduled),
        "tests_run": tests_run,
        "cases": cases,
        "counts": counts,
        "summary": {
            "required": len(REQUIRED_CASES),
            "scheduled": len(scheduled),
            "tests_run": tests_run,
            **counts,
        },
        "failure_type": failure_type,
    }


def main(argv=None):
    # Must precede any import of tests.test_workspace_fuse_service or
    # tests.test_workspace_handoff: both select their original behavior at import.
    os.environ["ROOTYARD_TEST_FUSE_BACKEND"] = "fuse-helper"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True,
                        help="safe JSON acceptance report path")
    args = parser.parse_args(argv)

    binary_sha256 = None
    receipt_sha256 = None
    source_head = None
    expected_commit = os.environ.get("GITHUB_SHA")
    failure_type = None
    scheduled = ()
    result = None
    imported = False
    try:
        from tests.runtime_binary import select_runtime_binary
        _binary, binding = select_runtime_binary()
        binary_sha256 = _binding_value(binding, "binary_sha256")
        receipt_sha256 = _binding_value(binding, "receipt_sha256")
        source_head = _binding_value(binding, "workspace_commit")
        expected_from_binding = _binding_value(binding, "expected_commit")
        if expected_from_binding is not None:
            expected_commit = expected_from_binding
        from tests.test_workspace_fuse_service import WorkspaceFuseServiceTest  # noqa: F401
        from tests.test_workspace_handoff import WorkspaceHandoffTest  # noqa: F401
        suite = unittest.TestLoader().loadTestsFromNames(REQUIRED_CASES)
        scheduled = tuple(test.id() for test in _flatten(suite))
        imported = True
        stream = io.StringIO()
        result = unittest.TextTestRunner(
            stream=stream, verbosity=0, resultclass=WorkspaceFuseDiagnosticResult
        ).run(suite)
    except BaseException as error:
        failure_type = _failure_type(error)
        imported = False

    report = _report_payload(
        binary_sha256=binary_sha256,
        receipt_sha256=receipt_sha256,
        source_head=source_head,
        expected_commit=expected_commit,
        failure_type=failure_type,
        scheduled=scheduled,
        result=result,
        imported=imported,
        diagnostics=getattr(result, "diagnostics", None),
    )
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
