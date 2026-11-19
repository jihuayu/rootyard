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
    "helper_child_exit",
    "helper_child_exit_101",
    "helper_child_exit_102",
    "helper_child_exit_103",
    "helper_child_exit_104",
    "helper_child_exit_105",
    "helper_child_exit_1",
    "helper_child_sigkill",
    "helper_child_sigterm",
    "helper_child_absent",
    "helper_child_reap_deadline",
    "helper_child_reap_error",
    "helper_timeout",
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
_SHUTDOWN_CAPTURE_CONTAINER = (
    "workspace capture/helper shutdown did not complete cleanly: ")
_SHUTDOWN_HELPER_CONTAINER = "workspace FUSE helper shutdown failed: "

_SHUTDOWN_HELPER_CLAUSES = {
    "HTTP 503: service temporarily unavailable": "helper_internal_503",
    "HTTP 503: workspace FUSE helper child exited unsuccessfully": "helper_child_exit",
    "HTTP 503: workspace FUSE helper child exited with code 101": "helper_child_exit_101",
    "HTTP 503: workspace FUSE helper child exited with code 102": "helper_child_exit_102",
    "HTTP 503: workspace FUSE helper child exited with code 103": "helper_child_exit_103",
    "HTTP 503: workspace FUSE helper child exited with code 104": "helper_child_exit_104",
    "HTTP 503: workspace FUSE helper child exited with code 105": "helper_child_exit_105",
    "HTTP 503: workspace FUSE helper child exited with code 1": "helper_child_exit_1",
    "HTTP 503: workspace FUSE helper child was killed by SIGKILL": "helper_child_sigkill",
    "HTTP 503: workspace FUSE helper child was terminated by SIGTERM": "helper_child_sigterm",
    "HTTP 503: workspace FUSE helper child exit was not observed": "helper_child_absent",
    "HTTP 503: workspace FUSE helper child reap deadline expired": "helper_child_reap_deadline",
    "HTTP 503: workspace FUSE helper child wait failed": "helper_child_reap_error",
    "HTTP 503: workspace FUSE helper teardown timed out": "helper_timeout",
    "HTTP 504: workspace FUSE helper shutdown exceeded the shared "
    "normal-shutdown deadline": "helper_deadline",
    "HTTP 504: workspace FUSE legacy mount teardown exceeded the shared "
    "normal-shutdown deadline": "helper_deadline",
}
_SHUTDOWN_CLAUSES = {
    "workspace capture worker did not stop before the abort-confirmation window":
        "capture_scan",
    "owned workspace Git jobs/process cleanup did not complete cleanly":
        "git_drain",
    "late owned workspace Git jobs/process cleanup did not complete cleanly":
        "git_drain",
    "HTTP server did not stop cleanly": "http_join",
    "HTTP server did not join within the shutdown deadline": "http_join",
    "background worker did not stop cleanly": "background_join",
    "native Git process cleanup did not prove quiescence": "native_quiescence",
}


def _classify_shutdown_payload(payload):
    """Classify only complete, source-defined cleanup clauses."""
    categories = []
    for part in payload.split("; "):
        helper_scope = False
        changed = True
        while changed:
            changed = False
            if part.startswith(_SHUTDOWN_CAPTURE_CONTAINER):
                part = part[len(_SHUTDOWN_CAPTURE_CONTAINER):]
                changed = True
            elif part.startswith(_SHUTDOWN_HELPER_CONTAINER):
                part = part[len(_SHUTDOWN_HELPER_CONTAINER):]
                helper_scope = True
                changed = True
        if not part:
            return SHUTDOWN_OUTCOME_UNKNOWN
        category = (
            _SHUTDOWN_HELPER_CLAUSES if helper_scope else _SHUTDOWN_CLAUSES
        ).get(part)
        if category is None:
            return SHUTDOWN_OUTCOME_UNKNOWN
        categories.append(category)
    if not categories:
        return SHUTDOWN_OUTCOME_UNKNOWN
    if len(set(categories)) == 1:
        return categories[0]
    return SHUTDOWN_OUTCOME_MULTIPLE


def project_shutdown_outcome(data):
    """Project one complete, unique terminal record to a closed outcome.

    The final non-blank line must be the only ``Error:`` line in the bounded
    snapshot and a source-known complete record.  The parser returns a fixed
    category or ``unknown``; it never returns or stores log text, paths, ids,
    dynamic payloads, request ids, stacks or output.
    """
    if not isinstance(data, (bytes, bytearray)):
        return SHUTDOWN_OUTCOME_UNKNOWN
    if len(data) > MAX_SHUTDOWN_TAIL_BYTES or not data.endswith(b"\n"):
        return SHUTDOWN_OUTCOME_UNKNOWN
    try:
        text = bytes(data).decode("utf-8")
    except UnicodeDecodeError:
        return SHUTDOWN_OUTCOME_UNKNOWN
    nonempty = [line for line in text.splitlines() if line.strip()]
    if not nonempty:
        return SHUTDOWN_OUTCOME_UNKNOWN
    terminal = nonempty[-1]
    error_lines = [line for line in nonempty if line.startswith("Error:")]
    if len(error_lines) != 1 or error_lines[0] != terminal:
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


def _bound_source(source):
    """Return the harness-owned descriptor identity, never just its path."""
    path = _shutdown_log_path(source)
    if isinstance(source, (str, os.PathLike)) or not hasattr(source, "fileno"):
        return None, path
    fd = source.fileno()
    if type(fd) is not int or fd < 0:
        raise OSError("source descriptor is unavailable")
    return (fd, os.fstat(fd)), path


def _open_bound_snapshot(fd, path, proc_fd_root):
    """Open the exact bound inode; only a confirmed path/proc ENOENT falls back."""
    try:
        return os.open(Path(proc_fd_root) / str(fd), os.O_RDONLY)
    except (FileNotFoundError, ProcessLookupError):
        if path is None:
            raise
        return os.open(path, os.O_RDONLY)


def read_shutdown_outcome(source, proc_fd_root=Path("/proc/self/fd")):
    """Read a bounded tail tied to the exact source descriptor identity."""
    try:
        bound, path = _bound_source(source)
        if bound is None:
            if path is None:
                return SHUTDOWN_OUTCOME_UNKNOWN
            read_fd = os.open(path, os.O_RDONLY)
            target = None
        else:
            fd, target = bound
            read_fd = _open_bound_snapshot(fd, path, proc_fd_root)
        with os.fdopen(read_fd, "rb") as stream:
            current = os.fstat(stream.fileno())
            if target is not None and (
                    (current.st_dev, current.st_ino)
                    != (target.st_dev, target.st_ino)):
                return SHUTDOWN_OUTCOME_UNKNOWN
            size = target.st_size if target is not None else current.st_size
            start = max(0, size - MAX_SHUTDOWN_TAIL_BYTES)
            previous = b""
            if start:
                stream.seek(start - 1)
                previous = stream.read(1)
            stream.seek(start)
            data = stream.read(size - start)
    except (OSError, TypeError, ValueError):
        return SHUTDOWN_OUTCOME_UNKNOWN
    if start and previous != b"\n":
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
        "child_exit": _child_exit(error),
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
