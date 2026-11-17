#!/usr/bin/env python3
"""Safe inventory, report, and runner for the legacy shutdown acceptance cases.

This private module is owned by ``tests/workspace_legacy_fuse_shutdown_acceptance.py``.
It selects the canonical source-bound binary, runs only the exact required case
selectors, and persists a bounded JSON report. It never stores raw exception
text, arbitrary paths, environment values, source payloads, or service logs.
Failure diagnostics contain only a closed exception name, a closed unittest
stage, and repo-relative frames verified against the whitelisted source files.
"""
from __future__ import annotations

import argparse
import ast
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
for path in (TESTS, ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from tests import fuse_helper_native_support as support  # noqa: E402
from tests import workspace_legacy_fuse_shutdown_acceptance as acceptance  # noqa: E402
from tests.runtime_binary import select_runtime_binary  # noqa: E402

SAFE_FAILURE_TYPES = frozenset((
    "RuntimeError", "OSError", "ImportError", "ModuleNotFoundError",
    "SourceBindingError", "RuntimeBinarySelectionError", "AssertionError",
    "ValueError", "TypeError", "KeyError", "AttributeError", "FileNotFoundError",
    "HarnessError", "LegacyAcceptanceError", "TimeoutError",
    "CalledProcessError",
))

DIAGNOSTIC_SCHEMA = "rootyard/issues91-95/legacy-fuse-failure-projection/v1"
DIAGNOSTIC_FRAME_CAP = 8
DIAGNOSTIC_SOURCE_PATHS = tuple(dict.fromkeys((
    *acceptance.SOURCE_PATHS,
    "tests/e2e.py",
    "tests/runtime_binary.py",
    "tests/native_evidence.py",
    "tests/fuse_helper_native_support.py",
)))
_CASE_ID = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{0,255}$")
_STAGE_BY_MARKER = {
    "_handleClassSetUp": "class_setup",
    "_tearDownPreviousClass": "class_teardown",
    "_handleModuleFixture": "module_setup",
    "_handleModuleTearDown": "module_teardown",
    "_callSetUp": "setup",
    "_callTestMethod": "test",
    "_callTearDown": "teardown",
    "_callCleanup": "cleanup",
}
_SOURCE_FACTS = None


def _static_function_index():
    """Return only statically verified functions from the closed source list."""
    global _SOURCE_FACTS
    if _SOURCE_FACTS is not None:
        return _SOURCE_FACTS
    root = ROOT.resolve()
    facts = {}
    for relative in DIAGNOSTIC_SOURCE_PATHS:
        try:
            path = (root / relative).resolve()
            path.relative_to(root)
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8")
            tree = ast.parse(text, filename=relative)
        except (OSError, UnicodeError, SyntaxError, ValueError):
            continue
        line_count = len(text.splitlines())
        if line_count < 1:
            continue
        functions = []
        pending = [(tree, "")]
        while pending:
            node, prefix = pending.pop()
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    end = getattr(child, "end_lineno", None)
                    if isinstance(end, int) and end >= child.lineno:
                        functions.append(
                            (child.name, prefix + child.name, child.lineno, end)
                        )
                    pending.append((child, prefix + child.name + "."))
                elif isinstance(child, ast.ClassDef):
                    pending.append((child, prefix + child.name + "."))
                else:
                    pending.append((child, prefix))
        facts[relative] = (path, line_count, tuple(functions))
    _SOURCE_FACTS = facts
    return facts


def _frame_record(frame):
    """Project one traceback frame only when it exactly matches static source."""
    code = getattr(frame, "f_code", None)
    filename = getattr(code, "co_filename", None)
    name = getattr(code, "co_name", None)
    line = getattr(frame, "f_lineno", None)
    if not isinstance(filename, str) or not isinstance(name, str) or not isinstance(line, int):
        return None
    try:
        resolved = Path(filename)
        if not resolved.is_absolute():
            resolved = ROOT / resolved
        resolved = resolved.resolve()
    except (OSError, RuntimeError, ValueError):
        return None
    for relative, (path, line_count, functions) in _static_function_index().items():
        if resolved != path:
            continue
        if line < 1 or line > line_count:
            return None
        for static_name, qualified, start, end in functions:
            if static_name == name and start <= line <= end:
                return {"path": relative, "line": line, "function": qualified}
        return None
    return None


def _failure_stage(err):
    """Map only known unittest phase markers to a closed stage name."""
    tb = err[2] if isinstance(err, tuple) and len(err) >= 3 else None
    while tb is not None:
        code = getattr(getattr(tb, "tb_frame", None), "f_code", None)
        marker = getattr(code, "co_name", None)
        if isinstance(marker, str) and marker in _STAGE_BY_MARKER:
            return _STAGE_BY_MARKER[marker]
        tb = getattr(tb, "tb_next", None)
    return "unknown"


def _exception_class(err):
    if not isinstance(err, tuple) or len(err) < 2:
        return "unknown"
    return _failure_type(err[1])


def _safe_case_id(test):
    try:
        value = test.id()
    except Exception:
        return None
    if not isinstance(value, str) or not _CASE_ID.match(value):
        return None
    return value


def _project_failure(err, case_id=None, started=False, kind="error"):
    """Build a finite safe diagnostic without formatting the error or traceback."""
    diagnostic = {
        "schema": DIAGNOSTIC_SCHEMA,
        "kind": kind if kind in ("error", "failure") else "unknown",
        "case_id": case_id if isinstance(case_id, str) and _CASE_ID.match(case_id) else None,
        "started": bool(started),
        "stage": _failure_stage(err),
        "exception_class": _exception_class(err),
        "locus": "unknown",
        "frames": [],
        "frames_truncated": False,
    }
    tb = err[2] if isinstance(err, tuple) and len(err) >= 3 else None
    frames = []
    truncated = False
    while tb is not None:
        record = _frame_record(getattr(tb, "tb_frame", None))
        if record is not None:
            if len(frames) < DIAGNOSTIC_FRAME_CAP:
                frames.append(record)
            else:
                truncated = True
        tb = getattr(tb, "tb_next", None)
    diagnostic["frames"] = frames
    diagnostic["frames_truncated"] = truncated
    diagnostic["locus"] = "verified_source" if frames else "unknown"
    return diagnostic


class InventoryResult(unittest.TextTestResult):
    """Record started cases plus finite safe diagnostics for failures/errors."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.started_ids = []
        self.diagnostics = {}
        self.unstarted_diagnostics = []

    def startTest(self, test):
        self.started_ids.append(test.id())
        super().startTest(test)

    def _capture(self, test, err, kind):
        case_id = _safe_case_id(test)
        started = case_id is not None and case_id in self.started_ids
        try:
            diagnostic = _project_failure(
                err, case_id=case_id, started=started, kind=kind
            )
        except Exception:
            diagnostic = {
                "schema": DIAGNOSTIC_SCHEMA,
                "kind": kind,
                "case_id": case_id,
                "started": started,
                "stage": "unknown",
                "exception_class": "unknown",
                "locus": "unknown",
                "frames": [],
                "frames_truncated": False,
            }
        if started:
            self.diagnostics[case_id] = diagnostic
        else:
            # Class/module setup has no executed case id; keep it separate.
            self.unstarted_diagnostics.append(diagnostic)

    def addError(self, test, err):
        self._capture(test, err, "error")
        super().addError(test, err)

    def addFailure(self, test, err):
        self._capture(test, err, "failure")
        super().addFailure(test, err)


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


def _git_field(argument):
    try:
        result = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", argument],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    value = result.stdout.decode("ascii", "replace").strip()
    return value if value else None


def _input_digest():
    paths = [ROOT / name for name in acceptance.SOURCE_PATHS]
    digest, _rows = support.digest_files(paths)
    return digest


def _case_inventory(result, scheduled):
    cases = []
    counts = {key: 0 for key in (
        "success", "failure", "error", "skipped",
        "expected_failure", "unexpected_success", "not_run",
    )}
    tests_run = 0
    diagnostics = getattr(result, "diagnostics", None) if result is not None else None
    if result is not None:
        started_ids = set(getattr(result, "started_ids", ()))
        failure_ids = {test.id() for test, _ in result.failures}
        error_ids = {test.id() for test, _ in result.errors}
        skipped_ids = {test.id() for test, _ in result.skipped}
        expected_ids = {test.id() for test, _ in result.expectedFailures}
        unexpected_ids = {test.id() for test in result.unexpectedSuccesses}
        for name in acceptance.REQUIRED_CASES:
            if name not in started_ids:
                status = "not_run"
            elif name in error_ids:
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
            cases.append({
                "name": name,
                "status": status,
                "detail": acceptance.CASE_DETAILS.get(name),
                "diagnostic": (
                    diagnostics.get(name)
                    if isinstance(diagnostics, dict) else None
                ),
            })
            counts[{"passed": "success", "failed": "failure"}.get(status, status)] += 1
        tests_run = int(result.testsRun)
    return cases, counts, tests_run


def _report_payload(binary_sha256=None, receipt_sha256=None, source_inputs_sha256=None,
                    source_head=None, expected_commit=None, source_tree=None,
                    checkout_head=None, input_digest=None, failure_type=None,
                    scheduled=(), result=None, imported=True, containment_owner=None):
    cases, counts, tests_run = _case_inventory(result, scheduled)
    details = [acceptance.CASE_DETAILS.get(name) or {} for name in acceptance.REQUIRED_CASES]
    remaining_values = [detail.get("owned_mounts_remaining") for detail in details]
    remaining_known = all(
        isinstance(value, int) and not isinstance(value, bool) for value in remaining_values
    )
    owned_remaining = (
        sum(value for value in remaining_values if isinstance(value, int))
        if remaining_known else None
    )
    containment = sum(int(detail.get("containment_used") or 0) for detail in details)
    deferred = sum(1 for detail in details if detail.get("fixture_cleanup_deferred"))
    owner = containment_owner if containment_owner is not None else acceptance.CONTAINMENT_OWNER
    containment_state = owner.snapshot()
    unstarted = getattr(result, "unstarted_diagnostics", ()) if result is not None else ()
    unstarted = list(unstarted) if isinstance(unstarted, (list, tuple)) else []
    passed = bool(
        imported
        and result is not None
        and tuple(scheduled) == acceptance.REQUIRED_CASES
        and tests_run == len(acceptance.REQUIRED_CASES)
        and counts["success"] == len(acceptance.REQUIRED_CASES)
        and counts["failure"] == 0
        and counts["error"] == 0
        and counts["skipped"] == 0
        and counts["expected_failure"] == 0
        and counts["unexpected_success"] == 0
        and counts["not_run"] == 0
        and remaining_known
        and owned_remaining == 0
        and int(containment_state["started"]) == 0
        and int(containment_state["pending"]) == 0
        and int(containment_state["deadline_exhausted"]) == 0
        and int(containment_state["errors"]) == 0
    )
    return {
        "schema": acceptance.REPORT_SCHEMA,
        "status": "passed" if passed else "failed",
        "passed": passed,
        "binary_sha256": binary_sha256,
        "receipt_sha256": receipt_sha256,
        "source_inputs_sha256": source_inputs_sha256,
        "source_head": source_head,
        "expected_source_commit": expected_commit,
        "checkout_head": checkout_head,
        "source_tree": source_tree,
        "input_digest": input_digest,
        "source_paths": list(acceptance.SOURCE_PATHS),
        "scheduled": list(scheduled),
        "tests_run": tests_run,
        "cases": cases,
        "counts": counts,
        "containment": containment_state,
        "cleanup": {
            "required": len(acceptance.REQUIRED_CASES),
            "scheduled": len(scheduled),
            "tests_run": tests_run,
            "zero_skips": counts["skipped"] == 0,
            "owned_mounts_remaining": owned_remaining,
            "owned_mounts_remaining_known": remaining_known,
            "containment_used": containment,
            "containment_started": int(containment_state["started"]),
            "containment_pending": int(containment_state["pending"]),
            "containment_deadline_exhausted": int(containment_state["deadline_exhausted"]),
            "containment_errors": int(containment_state["errors"]),
            "fixture_cleanup_deferred": deferred,
        },
        "summary": {
            "required": len(acceptance.REQUIRED_CASES),
            "scheduled": len(scheduled),
            "tests_run": tests_run,
            **counts,
        },
        "failure_type": failure_type,
        "failure_diagnostics": {
            "schema": DIAGNOSTIC_SCHEMA,
            "frame_cap": DIAGNOSTIC_FRAME_CAP,
            "unstarted": unstarted,
        },
    }


def _write_report(path: Path, report) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=acceptance.__doc__)
    parser.add_argument("--report", type=Path, required=True, help="safe JSON acceptance report path")
    args = parser.parse_args(argv)
    acceptance.CONTAINMENT_OWNER.reset()
    acceptance.CASE_DETAILS.clear()

    binary_sha256 = receipt_sha256 = source_inputs_sha256 = None
    source_head = None
    source_tree = None
    checkout_head = None
    input_digest = None
    expected_commit = os.environ.get("GITHUB_SHA")
    failure_type = None
    scheduled = ()
    result = None
    imported = False
    try:
        _binary, binding = select_runtime_binary()
        binary_sha256 = _binding_value(binding, "binary_sha256")
        receipt_sha256 = _binding_value(binding, "receipt_sha256")
        source_inputs_sha256 = _binding_value(binding, "source_inputs_sha256")
        source_head = _binding_value(binding, "workspace_commit")
        expected_from_binding = _binding_value(binding, "expected_commit")
        if expected_from_binding is not None:
            expected_commit = expected_from_binding
        checkout_head = _git_field("HEAD")
        source_tree = _git_field("HEAD^{tree}")
        input_digest = _input_digest()
        suite = unittest.TestLoader().loadTestsFromNames(acceptance.REQUIRED_CASES)
        scheduled = tuple(test.id() for test in _flatten(suite))
        imported = True
        stream = io.StringIO()
        result = unittest.TextTestRunner(
            stream=stream, verbosity=0, resultclass=InventoryResult
        ).run(suite)
    except BaseException as error:
        failure_type = _failure_type(error)
        imported = False
        if not scheduled:
            scheduled = acceptance.REQUIRED_CASES

    payload_kwargs = dict(
        binary_sha256=binary_sha256,
        receipt_sha256=receipt_sha256,
        source_inputs_sha256=source_inputs_sha256,
        source_head=source_head,
        expected_commit=expected_commit,
        source_tree=source_tree,
        checkout_head=checkout_head,
        input_digest=input_digest,
        failure_type=failure_type,
        scheduled=scheduled,
        result=result,
        imported=imported,
    )
    report = _report_payload(**payload_kwargs)
    _write_report(args.report, report)
    if int(report["containment"]["pending"]) > 0:
        # The failed pending report is durable before the explicit late drain.
        # The drain has no positive acceptance grace and cannot revive a pass.
        acceptance.CONTAINMENT_OWNER.late_physical_drain()
        report = _report_payload(**payload_kwargs)
        _write_report(args.report, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
