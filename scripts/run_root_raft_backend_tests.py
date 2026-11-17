#!/usr/bin/env python3
"""Run the exact relocated Root Raft Ref-CAS integration test once.

The binary is produced by ``scripts/build_native_test.py --test
ref_store_real_raft_backend``.  This runner never invokes Cargo, rustc or a
builder: it validates the adjacent v2 build receipt against the current
checkout (including every bound source input), executes the supplied executable
exactly once with ``--test-threads=1`` under a finite 900-second process cap,
and writes a credential-free report.  Only the reviewed libtest case names,
their statuses and one anchored summary are parsed; raw output, panic text,
environment values, certificate material, command argv and paths stay in memory
and are never printed, persisted or uploaded.
"""
from __future__ import annotations

import argparse
import contextlib
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
from threading import Lock, Thread

import native_build_receipt as receipt_contract

ROOT = Path(__file__).resolve().parents[1]
TEST_TARGET = "ref_store_real_raft_backend"
TEST_SOURCE = "tests/ref_store_real_raft_backend.rs"
REQUIRED_CASES = (
    "real_root_refcas_commands_through_quorum_mtls_sqlite_and_restart",
    "pruned_receipts_export_restore_and_sqlite_reopen",
    "scope_drain_support::privileged_scope_drain_query_is_quorum_bound_and_multirepo_complete",
)
EXPECTED_CASE_COUNT = len(REQUIRED_CASES)
TEST_ARGS = ("--test-threads=1",)
MAX_TIMEOUT_SECONDS = 900.0
MAX_TOTAL_CAPTURE_BYTES = 2 * 1024 * 1024
_CAPTURE_CHUNK = 64 * 1024
PHASES = frozenset(("receipt", "source", "execute", "parse", "report", "complete"))
ERROR_CODES = frozenset(
    (
        "missing_expected_commit", "invalid_expected_commit", "expected_commit_conflict",
        "binary_missing", "binary_not_executable", "binary_symlink",
        "receipt_missing", "receipt_symlink", "receipt_invalid",
        "receipt_schema", "receipt_kind", "receipt_not_relocated",
        "receipt_profile", "receipt_features", "receipt_target_mismatch",
        "stale_receipt", "binary_mismatch",
        "source_unavailable", "source_head_mismatch", "worktree_dirty",
        "timeout_invalid", "spawn_failed", "timeout", "signal_killed",
        "nonzero_exit", "zero_suite", "missing_case", "duplicate_case",
        "extra_case", "test_failed", "ignored_case", "measured_case",
        "filtered_case", "count_mismatch", "output_invalid",
        "evidence_changed", "internal_error",
    )
)
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_RUNNING = re.compile(r"^running (\d+) tests?$")
_CASE = re.compile(r"^test ([A-Za-z0-9_:]+) \.\.\. (ok|FAILED|ignored)$")
_SUMMARY = re.compile(
    r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; "
    r"(\d+) ignored; (\d+) measured; (\d+) filtered out; "
    r"finished in [0-9]+(?:\.[0-9]+)?s$"
)
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_COUNT_KEYS = ("passed", "failed", "ignored", "measured", "filtered")
_FAILURE_FRAME = re.compile(
    r"^ROOTYARD_FAILURE_FRAME v1 case=([A-Za-z0-9_:]+) phase=([a-z0-9_]+) class=([a-z0-9_]+)$"
)
_REAL_PHASES = frozenset(
    (
        "bootstrap", "provision", "commit", "refusal", "concurrent", "closing_write",
        "closing_view", "refused_write", "refused_view", "refusal_lookup",
        "refusal_replay", "healthy_write", "healthy_view", "standalone_probe",
        "follower", "isolation", "live_axes", "snapshot", "install", "reopen",
        "partition", "heal", "final_reopen",
    )
)
_SCOPE_PHASES = frozenset(
    (
        "bootstrap", "provision", "install", "close", "recover", "recovery_rejections",
        "initial_drain", "binding_rejections", "foreign_bootstrap", "foreign_advance",
        "foreign_rejection", "pending_bridge", "cancel", "settled_drain",
        "settled_evaluate", "settled_bridge", "follower", "invalid_options",
        "partition", "heal", "shutdown",
    )
)
_FAILURE_CLASSES = frozenset(
    (
        "assertion_panic", "proposal_scope", "command_scope", "stale_gate",
        "follower_redirect", "quorum_unavailable", "apply_barrier", "storage",
        "encode", "wrong_reducer", "recovery_not_observed", "scope_binding",
        "scope_close_recovery", "bridge_database", "bridge_invalid_input",
        "bridge_authority", "backend_other", "unclassified",
    )
)
_FAILURE_CASES = {REQUIRED_CASES[0]: _REAL_PHASES, REQUIRED_CASES[2]: _SCOPE_PHASES}
_FAILURE_STATUS = {"ok": "passed", "FAILED": "failed", "ignored": "ignored"}
_DIAGNOSTIC_KEYS = (
    "exit_code", "signal", "evidence_complete", "suite_counts", "case_failures",
    "failure_phase", "failure_class", "unknown_case", "diagnostics_valid",
    "evidence_unchanged",
)


class RunnerError(RuntimeError):
    """A fail-closed refusal with only an allowlisted phase and code."""

    def __init__(self, phase: str, code: str) -> None:
        if phase not in PHASES or code not in ERROR_CODES:
            raise ValueError("unregistered Root Raft runner failure")
        super().__init__(code)
        self.phase = phase
        self.code = code


def _need(condition, phase: str, code: str) -> None:
    if not condition:
        raise RunnerError(phase, code)


@dataclass(frozen=True)
class ExecutionResult:
    stdout: str
    stderr: str
    returncode: int | None
    signal: int | None
    termination: str
    capture_truncated: bool = False


@dataclass(frozen=True)
class FailureEvidence:
    cases: list[dict[str, str]]
    counts: dict[str, int]
    suite_counts: dict[str, int] | None
    complete: bool
    case_failures: list[dict[str, str]]
    failure_phase: str | None
    failure_class: str | None
    unknown_case: bool
    diagnostics_valid: bool


def _safe_digest(path) -> str | None:
    try:
        if path is not None and Path(path).is_file():
            return receipt_contract.sha256_file(Path(path))
    except OSError:
        pass
    return None


def _safe_head() -> str | None:
    try:
        state = receipt_contract.git_state(ROOT)
        head = state.get("head") if isinstance(state, dict) else None
        return head if isinstance(head, str) and _COMMIT.fullmatch(head) else None
    except Exception:
        return None


def resolve_expected_commit(cli_value, environ=None) -> str:
    """Resolve the mandatory external commit anchor without silently blessing HEAD."""
    environ = os.environ if environ is None else environ
    raw_env = environ.get("GITHUB_SHA")
    cli = cli_value.strip() if isinstance(cli_value, str) else ""
    env = raw_env.strip() if isinstance(raw_env, str) else ""
    if cli and env and cli != env:
        raise RunnerError("source", "expected_commit_conflict")
    value = cli or env
    if not value:
        raise RunnerError("source", "missing_expected_commit")
    if _COMMIT.fullmatch(value) is None:
        raise RunnerError("source", "invalid_expected_commit")
    return value


def _require_timeout(value) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(value)
        or value <= 0
        or value > MAX_TIMEOUT_SECONDS
    ):
        raise RunnerError("execute", "timeout_invalid")
    return float(value)


def _absolute(raw) -> Path:
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = ROOT / path
    return Path(os.path.abspath(path))


def resolve_paths(args) -> tuple[Path, Path]:
    binary = _absolute(args.test_binary)
    if args.build_receipt:
        receipt = _absolute(args.build_receipt)
    else:
        receipt = binary.with_suffix(".build.json")
    return binary, Path(os.path.abspath(receipt))


def _require_target_artifact(payload) -> None:
    rows = payload.get("cargo_artifacts")
    _need(
        isinstance(rows, list) and len(rows) == 1,
        "receipt",
        "receipt_target_mismatch",
    )
    row = rows[0]
    _need(isinstance(row, dict), "receipt", "receipt_target_mismatch")
    _need(
        row.get("target") == TEST_TARGET and row.get("kind") == "test",
        "receipt",
        "receipt_target_mismatch",
    )
    _need(row.get("source") == TEST_SOURCE, "receipt", "receipt_target_mismatch")
    profile = row.get("profile")
    _need(
        isinstance(profile, dict) and profile.get("test") is True,
        "receipt",
        "receipt_target_mismatch",
    )


def load_and_validate(binary: Path, receipt_path: Path, expected_commit: str,
                      *, root: Path = ROOT):
    """Validate the canonical v2 receipt with the shared reader and real source."""
    _need(binary.is_file(), "receipt", "binary_missing")
    _need(not binary.is_symlink(), "receipt", "binary_symlink")
    _need(os.access(binary, os.X_OK), "receipt", "binary_not_executable")
    _need(receipt_path.is_file(), "receipt", "receipt_missing")
    _need(not receipt_path.is_symlink(), "receipt", "receipt_symlink")
    try:
        raw = receipt_path.read_bytes()
    except OSError:
        raise RunnerError("receipt", "receipt_missing") from None
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RunnerError("receipt", "receipt_invalid") from None
    _need(isinstance(payload, dict), "receipt", "receipt_invalid")
    _need(
        payload.get("receipt_schema") == receipt_contract.RECEIPT_SCHEMA_V2,
        "receipt",
        "receipt_schema",
    )
    _need(payload.get("kind") == "rust-integration-test", "receipt", "receipt_kind")
    _need(payload.get("relocated_artifact") is True, "receipt", "receipt_not_relocated")
    _need(payload.get("profile") == "test", "receipt", "receipt_profile")
    features = payload.get("features")
    _need(
        isinstance(features, dict)
        and features.get("enabled") == []
        and features.get("no_default_features") is False,
        "receipt",
        "receipt_features",
    )
    _need(payload.get("workspace_commit") == expected_commit, "receipt", "stale_receipt")
    actual_binary = receipt_contract.sha256_file(binary)
    _need(payload.get("binary_sha256") == actual_binary, "receipt", "binary_mismatch")
    _require_target_artifact(payload)
    receipt_sha = hashlib.sha256(raw).hexdigest()
    try:
        validated = receipt_contract.validate_receipt(
            payload,
            source_root=root,
            receipt_path=receipt_path,
            receipt_sha256=receipt_sha,
            binary_path=binary,
            expected_commit=expected_commit,
            expected_binary_sha256=actual_binary,
            expected_profile="test",
            expected_artifacts=[
                {
                    "target": TEST_TARGET,
                    "kind": "test",
                    "source": TEST_SOURCE,
                    "profile": {"test": True},
                }
            ],
            verify_source_files=True,
            forbid_implicit_build=True,
        )
    except receipt_contract.ReceiptError:
        raise RunnerError("receipt", "receipt_invalid") from None
    _need(validated.schema == "v2", "receipt", "receipt_schema")
    _need(validated.workspace_commit == expected_commit, "receipt", "stale_receipt")
    _need(validated.binary_sha256 == actual_binary, "receipt", "binary_mismatch")
    return validated, receipt_sha, actual_binary


def require_source_state(expected_commit: str, *, root: Path = ROOT) -> str:
    try:
        state = receipt_contract.git_state(root)
    except Exception:
        raise RunnerError("source", "source_unavailable") from None
    _need(isinstance(state, dict), "source", "source_unavailable")
    head = state.get("head")
    _need(
        isinstance(head, str) and _COMMIT.fullmatch(head) is not None,
        "source",
        "source_unavailable",
    )
    _need(head == expected_commit, "source", "source_head_mismatch")
    _need(state.get("clean") is True, "source", "worktree_dirty")
    return head


def parse_test_output(text) -> tuple[list[dict[str, str]], dict[str, int]]:
    """Parse only the reviewed case lines and one anchored full-target summary."""
    _need(isinstance(text, str), "parse", "output_invalid")
    running = []
    summaries = []
    case_lines = []
    for raw_line in text.splitlines():
        line = _ANSI.sub("", raw_line).strip()
        match = _RUNNING.fullmatch(line)
        if match:
            running.append(int(match.group(1)))
            continue
        match = _SUMMARY.fullmatch(line)
        if match:
            summaries.append(match.groups())
            continue
        match = _CASE.fullmatch(line)
        if match:
            case_lines.append((match.group(1), match.group(2)))
        # Every other line is deliberately ignored and never serialized.
    _need(len(running) == 1, "parse", "output_invalid")
    _need(len(summaries) == 1, "parse", "output_invalid")
    running_count = running[0]
    status, passed, failed, ignored, measured, filtered = summaries[0]
    passed, failed, ignored, measured, filtered = (
        int(passed),
        int(failed),
        int(ignored),
        int(measured),
        int(filtered),
    )
    counts = {
        "passed": passed,
        "failed": failed,
        "ignored": ignored,
        "measured": measured,
        "filtered": filtered,
    }
    _need(
        running_count > 0 or passed + failed + ignored + measured > 0,
        "parse",
        "zero_suite",
    )
    _need(
        running_count == passed + failed + ignored + measured,
        "parse",
        "count_mismatch",
    )
    _need(running_count == len(case_lines), "parse", "count_mismatch")
    _need(filtered == 0, "parse", "filtered_case")
    _need(measured == 0, "parse", "measured_case")
    _need(ignored == 0, "parse", "ignored_case")
    _need(failed == 0 and status != "FAILED", "parse", "test_failed")
    _need(passed > 0, "parse", "zero_suite")

    names = [name for name, _outcome in case_lines]
    _need(len(names) == len(set(names)), "parse", "duplicate_case")
    missing = [name for name in REQUIRED_CASES if name not in set(names)]
    _need(not missing, "parse", "missing_case")
    extra = [name for name in names if name not in REQUIRED_CASES]
    _need(not extra, "parse", "extra_case")
    _need(len(case_lines) == EXPECTED_CASE_COUNT, "parse", "count_mismatch")
    for _name, outcome in case_lines:
        _need(
            outcome == "ok",
            "parse",
            "ignored_case" if outcome == "ignored" else "test_failed",
        )
    ok_count = sum(1 for _name, outcome in case_lines if outcome == "ok")
    failed_count = sum(1 for _name, outcome in case_lines if outcome == "FAILED")
    ignored_count = sum(1 for _name, outcome in case_lines if outcome == "ignored")
    _need(
        (ok_count, failed_count, ignored_count) == (passed, failed, ignored),
        "parse",
        "count_mismatch",
    )
    _need(passed == EXPECTED_CASE_COUNT, "parse", "count_mismatch")
    by_name = {name: outcome for name, outcome in case_lines}
    cases = [
        {"name": name, "status": "passed"}
        for name in REQUIRED_CASES
        if by_name.get(name) == "ok"
    ]
    _need(len(cases) == EXPECTED_CASE_COUNT, "parse", "missing_case")
    return cases, counts


def _text_output(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value if isinstance(value, str) else ""


def _read_stream(stream, lock, state, key) -> None:
    chunks = []
    if stream is None:
        with lock:
            state[key] = b""
        return
    while True:
        chunk = stream.read(_CAPTURE_CHUNK)
        if not chunk:
            break
        if isinstance(chunk, str):
            chunk = chunk.encode("utf-8", errors="replace")
        with lock:
            remaining = MAX_TOTAL_CAPTURE_BYTES - state["total"]
            if remaining > 0:
                retained = chunk[:remaining]
                chunks.append(retained)
                state["total"] += len(retained)
            if len(chunk) > max(remaining, 0):
                state["truncated"] = True
    with lock:
        state[key] = b"".join(chunks)


def execute_case(binary: Path, timeout: float, *, run=subprocess.Popen) -> ExecutionResult:
    """Execute the supplied binary once with separately bounded stdout/stderr capture."""
    command = [str(binary), *TEST_ARGS]
    try:
        process = run(
            command,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError:
        raise RunnerError("execute", "spawn_failed") from None
    lock = Lock()
    state = {"total": 0, "truncated": False, "stdout": b"", "stderr": b""}
    stdout_thread = Thread(target=_read_stream, args=(process.stdout, lock, state, "stdout"), daemon=True)
    stderr_thread = Thread(target=_read_stream, args=(process.stderr, lock, state, "stderr"), daemon=True)
    stdout_thread.start()
    stderr_thread.start()
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        stdout_thread.join(timeout=5)
        stderr_thread.join(timeout=5)
        if stdout_thread.is_alive() or stderr_thread.is_alive():
            state["truncated"] = True
        return ExecutionResult(
            _text_output(state["stdout"]),
            _text_output(state["stderr"]),
            None,
            None,
            "timeout",
            state["truncated"],
        )
    stdout_thread.join(timeout=5)
    stderr_thread.join(timeout=5)
    if stdout_thread.is_alive() or stderr_thread.is_alive():
        state["truncated"] = True
    if not isinstance(returncode, int) or isinstance(returncode, bool):
        raise RunnerError("execute", "spawn_failed")
    stdout = _text_output(state["stdout"])
    stderr = _text_output(state["stderr"])
    if returncode < 0:
        return ExecutionResult(stdout, stderr, None, -returncode, "signal", state["truncated"])
    return ExecutionResult(stdout, stderr, returncode, None, "exited", state["truncated"])


def collect_failure_evidence(
    stdout, stderr="", *, capture_truncated=False
) -> FailureEvidence:
    """Collect observed stdout rows plus one anchored suite summary and stderr frames."""
    if not isinstance(stdout, str):
        stdout = ""
    if not isinstance(stderr, str):
        stderr = ""
    running = []
    summaries = []
    case_lines = []
    frame_sets: dict[str, set[tuple[str, str]]] = {}
    unknown_case = False
    diagnostics_invalid = False
    for raw_line in stdout.splitlines():
        line = _ANSI.sub("", raw_line).strip()
        match = _RUNNING.fullmatch(line)
        if match:
            running.append(int(match.group(1)))
            continue
        match = _SUMMARY.fullmatch(line)
        if match:
            summaries.append(match.groups())
            continue
        match = _CASE.fullmatch(line)
        if match:
            name, outcome = match.group(1), match.group(2)
            if name not in REQUIRED_CASES:
                unknown_case = True
            else:
                case_lines.append((name, outcome))
    for raw_line in stderr.splitlines():
        line = _ANSI.sub("", raw_line).strip()
        match = _FAILURE_FRAME.fullmatch(line)
        if match:
            name, phase, class_code = match.groups()
            allowed_phases = _FAILURE_CASES.get(name)
            if allowed_phases is None:
                unknown_case = True
            elif phase not in allowed_phases or class_code not in _FAILURE_CLASSES:
                diagnostics_invalid = True
            else:
                frame_sets.setdefault(name, set()).add((phase, class_code))

    by_name: dict[str, str] = {}
    duplicate_case = False
    for name, outcome in case_lines:
        if name in by_name:
            duplicate_case = True
        else:
            by_name[name] = outcome

    observed = {key: 0 for key in _COUNT_KEYS}
    for outcome in by_name.values():
        if outcome == "ok":
            observed["passed"] += 1
        elif outcome == "FAILED":
            observed["failed"] += 1
        elif outcome == "ignored":
            observed["ignored"] += 1

    summary = summaries[0] if len(summaries) == 1 else None
    summary_status = None
    suite_counts = None
    if summary is not None:
        status, passed, failed, ignored, measured, filtered = summary
        candidate = {
            "passed": int(passed),
            "failed": int(failed),
            "ignored": int(ignored),
            "measured": int(measured),
            "filtered": int(filtered),
        }
        if not any(value > EXPECTED_CASE_COUNT for value in candidate.values()):
            summary_status = status
            suite_counts = candidate

    summary_consistent = (
        suite_counts is not None
        and summary_status is not None
        and suite_counts["passed"] == observed["passed"]
        and suite_counts["failed"] == observed["failed"]
        and suite_counts["ignored"] == observed["ignored"]
        and suite_counts["measured"] == observed["measured"]
        and suite_counts["filtered"] == observed["filtered"]
        and ((summary_status == "FAILED") == (observed["failed"] > 0))
    )
    running_count = running[0] if len(running) == 1 else None
    complete = (
        summary_consistent
        and not capture_truncated
        and running_count is not None
        and not duplicate_case
        and not unknown_case
        and len(case_lines) == EXPECTED_CASE_COUNT
        and len(by_name) == EXPECTED_CASE_COUNT
        and running_count == sum(suite_counts.values())
        and running_count == len(case_lines)
        and suite_counts["measured"] == 0
        and suite_counts["filtered"] == 0
    )
    cases = [
        {"name": name, "status": _FAILURE_STATUS[by_name[name]]}
        for name in REQUIRED_CASES
        if name in by_name
    ]

    case_failures = []
    for case in REQUIRED_CASES:
        frames = frame_sets.get(case, set())
        if len(frames) > 1:
            diagnostics_invalid = True
        elif len(frames) == 1:
            phase, class_code = next(iter(frames))
            case_failures.append({"case": case, "phase": phase, "class": class_code})
    scalar_is_unambiguous = (
        len(case_failures) == 1
        and not diagnostics_invalid
        and not unknown_case
        and not duplicate_case
    )
    failure_phase = case_failures[0]["phase"] if scalar_is_unambiguous else None
    failure_class = case_failures[0]["class"] if scalar_is_unambiguous else None
    return FailureEvidence(
        cases=cases,
        counts=observed,
        suite_counts=suite_counts,
        complete=complete,
        case_failures=case_failures,
        failure_phase=failure_phase,
        failure_class=failure_class,
        unknown_case=unknown_case,
        diagnostics_valid=not diagnostics_invalid,
    )


def _verify_evidence_unchanged(
    binary: Path,
    receipt_path: Path,
    expected_commit: str,
    head: str,
    binary_sha: str,
    receipt_sha: str,
) -> None:
    try:
        current_head = require_source_state(expected_commit)
    except RunnerError:
        raise RunnerError("execute", "evidence_changed") from None
    _need(current_head == head, "execute", "evidence_changed")
    _need(_safe_digest(binary) == binary_sha, "execute", "evidence_changed")
    _need(_safe_digest(receipt_path) == receipt_sha, "execute", "evidence_changed")


def _zero_counts() -> dict[str, int]:
    return {key: 0 for key in _COUNT_KEYS}


def build_report(passed: bool, source_head, binary_sha, receipt_sha, cases, counts,
                 finite_phase: str, error_class, diagnostics=None) -> dict:
    """Build the exact credential-free report allowlist."""
    report = {
        "passed": bool(passed),
        "source_head": source_head,
        "binary_sha256": binary_sha,
        "receipt_sha256": receipt_sha,
        "cases": [
            {"name": case["name"], "status": case["status"]} for case in cases
        ],
        "counts": {key: int(counts[key]) for key in _COUNT_KEYS},
        "finite_phase": finite_phase,
        "error_class": error_class,
    }
    if diagnostics is not None:
        report["diagnostics"] = {key: diagnostics[key] for key in _DIAGNOSTIC_KEYS}
    return report


def write_report(path: Path, payload) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")
    try:
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        os.replace(temporary, destination)
    except BaseException:
        with contextlib.suppress(OSError):
            temporary.unlink()
        raise


def _failure_diagnostics(execution, evidence, evidence_unchanged) -> dict:
    return {
        "exit_code": None if execution is None else execution.returncode,
        "signal": None if execution is None else execution.signal,
        "evidence_complete": evidence.complete,
        "suite_counts": evidence.suite_counts,
        "case_failures": [
            {"case": failure["case"], "phase": failure["phase"], "class": failure["class"]}
            for failure in evidence.case_failures
        ],
        "failure_phase": evidence.failure_phase,
        "failure_class": evidence.failure_class,
        "unknown_case": evidence.unknown_case,
        "diagnostics_valid": evidence.diagnostics_valid,
        "evidence_unchanged": evidence_unchanged,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-binary", required=True,
                        help="relocated rust-integration-test executable")
    parser.add_argument("--build-receipt",
                        help="canonical receipt adjacent to the test binary by default")
    parser.add_argument("--report", type=Path, required=True,
                        help="credential-free JSON report")
    parser.add_argument("--expected-commit",
                        help="mandatory external commit; defaults to GITHUB_SHA")
    parser.add_argument("--timeout-seconds", type=float, default=MAX_TIMEOUT_SECONDS,
                        help="finite process cap, at most 900 seconds")
    args = parser.parse_args(argv)

    binary, receipt_path = resolve_paths(args)
    binary_sha = _safe_digest(binary)
    receipt_sha = _safe_digest(receipt_path)
    head = _safe_head()
    phase = "receipt"
    error_class = None
    cases = []
    counts = _zero_counts()
    status = 1
    execution = None
    evidence = None
    evidence_unchanged = None
    try:
        expected_commit = resolve_expected_commit(args.expected_commit)
        timeout = _require_timeout(args.timeout_seconds)
        head = require_source_state(expected_commit)
        phase = "receipt"
        _validated, receipt_sha, binary_sha = load_and_validate(
            binary, receipt_path, expected_commit
        )
        phase = "execute"
        execution = execute_case(binary, timeout)
        if execution.termination == "timeout":
            error_class = "timeout"
        elif execution.termination == "signal":
            error_class = "signal_killed"
        elif execution.returncode != 0:
            error_class = "nonzero_exit"
        else:
            phase = "parse"
            try:
                cases, counts = parse_test_output(execution.stdout)
            except RunnerError as error:
                phase = error.phase
                error_class = error.code
            else:
                if execution.capture_truncated:
                    error_class = "output_invalid"
                else:
                    phase = "execute"
                    status = 0
        if status != 0:
            evidence = collect_failure_evidence(
                execution.stdout,
                execution.stderr,
                capture_truncated=execution.capture_truncated,
            )
            cases = evidence.cases
            counts = evidence.counts
        if execution is not None:
            try:
                _verify_evidence_unchanged(
                    binary, receipt_path, expected_commit, head, binary_sha, receipt_sha
                )
                evidence_unchanged = True
            except RunnerError:
                evidence_unchanged = False
                if status == 0:
                    status = 1
                    phase = "execute"
                    error_class = "evidence_changed"
                    evidence = collect_failure_evidence(
                        execution.stdout,
                        execution.stderr,
                        capture_truncated=execution.capture_truncated,
                    )
                    cases = evidence.cases
                    counts = evidence.counts
        if status == 0:
            phase = "complete"
    except RunnerError as error:
        phase = error.phase
        error_class = error.code
    except Exception:
        if phase not in PHASES:
            phase = "report"
        error_class = "internal_error"

    if status != 0:
        if evidence is None:
            evidence = collect_failure_evidence("")
        diagnostics = _failure_diagnostics(execution, evidence, evidence_unchanged)
    else:
        diagnostics = None
    report = build_report(
        passed=status == 0,
        source_head=head,
        binary_sha=binary_sha,
        receipt_sha=receipt_sha,
        cases=cases,
        counts=counts,
        finite_phase=phase,
        error_class=error_class,
        diagnostics=diagnostics,
    )
    try:
        write_report(args.report, report)
    except (OSError, TypeError, ValueError):
        print("root raft backend: report write failed", file=sys.stderr, flush=True)
        return 1
    if status == 0:
        print(f"root raft backend: passed ({EXPECTED_CASE_COUNT} cases)", flush=True)
    else:
        print(f"root raft backend: failed ({phase}/{error_class})", flush=True)
    return status


if __name__ == "__main__":
    sys.exit(main())
