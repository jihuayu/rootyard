#!/usr/bin/env python3
"""Run the exact relocated Root Raft Ref-CAS integration test once.

The binary is produced by ``scripts/build_native_test.py --test
ref_store_real_raft_backend``.  This runner never invokes Cargo, rustc or a
builder: it validates the adjacent v2 build receipt against the current
checkout (including every bound source input), executes the supplied executable
exactly once with ``--test-threads=1`` under a finite 900-second process cap,
and writes a credential-free report.  Only the two reviewed libtest case names,
their statuses and one anchored summary are parsed; raw output, panic text,
environment values, certificate material, command argv and paths stay in memory
and are never printed, persisted or uploaded.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys

import native_build_receipt as receipt_contract

ROOT = Path(__file__).resolve().parents[1]
TEST_TARGET = "ref_store_real_raft_backend"
TEST_SOURCE = "tests/ref_store_real_raft_backend.rs"
REQUIRED_CASES = (
    "real_root_refcas_commands_through_quorum_mtls_sqlite_and_restart",
    "pruned_receipts_export_restore_and_sqlite_reopen",
)
EXPECTED_CASE_COUNT = len(REQUIRED_CASES)
TEST_ARGS = ("--test-threads=1",)
MAX_TIMEOUT_SECONDS = 900.0
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


def execute_case(binary: Path, timeout: float, *, run=subprocess.run) -> str:
    """Execute the supplied binary exactly once; return RAM-only stdout."""
    command = [str(binary), *TEST_ARGS]
    try:
        result = run(
            command,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise RunnerError("execute", "timeout") from None
    except OSError:
        raise RunnerError("execute", "spawn_failed") from None
    returncode = getattr(result, "returncode", None)
    _need(
        isinstance(returncode, int) and not isinstance(returncode, bool),
        "execute",
        "spawn_failed",
    )
    if returncode < 0:
        raise RunnerError("execute", "signal_killed")
    if returncode != 0:
        raise RunnerError("execute", "nonzero_exit")
    stdout = getattr(result, "stdout", "")
    _need(isinstance(stdout, str), "execute", "spawn_failed")
    return stdout


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
                 finite_phase: str, error_class) -> dict:
    """Build the exact credential-free report allowlist."""
    return {
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
    try:
        expected_commit = resolve_expected_commit(args.expected_commit)
        timeout = _require_timeout(args.timeout_seconds)
        head = require_source_state(expected_commit)
        phase = "receipt"
        _validated, receipt_sha, binary_sha = load_and_validate(
            binary, receipt_path, expected_commit
        )
        phase = "execute"
        output = execute_case(binary, timeout)
        phase = "parse"
        cases, counts = parse_test_output(output)
        phase = "execute"
        _verify_evidence_unchanged(
            binary, receipt_path, expected_commit, head, binary_sha, receipt_sha
        )
        phase = "complete"
        status = 0
    except RunnerError as error:
        phase = error.phase
        error_class = error.code
    except Exception:
        if phase not in PHASES:
            phase = "report"
        error_class = "internal_error"

    report = build_report(
        passed=status == 0,
        source_head=head,
        binary_sha=binary_sha,
        receipt_sha=receipt_sha,
        cases=cases if status == 0 else [],
        counts=counts if status == 0 else _zero_counts(),
        finite_phase=phase,
        error_class=error_class,
    )
    try:
        write_report(args.report, report)
    except (OSError, TypeError, ValueError):
        print("root raft backend: report write failed", file=sys.stderr, flush=True)
        return 1
    if status == 0:
        print("root raft backend: passed (2 cases)", flush=True)
    else:
        print(f"root raft backend: failed ({phase}/{error_class})", flush=True)
    return status


if __name__ == "__main__":
    sys.exit(main())
