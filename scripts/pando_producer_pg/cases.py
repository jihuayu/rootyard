"""Exact producer PG case set and anchored libtest result parsing.

The names are the fully-qualified bin-unit-test paths from the approved plan.
Each case is executed serially through the selected harness with ``--exact``,
``--ignored`` and ``--test-threads=1``.  Only finite counts and fixed codes leave
this module; raw stdout/stderr stays in RAM.
"""
from __future__ import annotations

import re

from .errors import RunnerError, require
from .process import CLEANUP_RESERVE_SECONDS

FAMILIES = ("migration", "repack", "snapshot")
CASES = (
    (
        "pando_lab::migration::pg_tests::pg_copy_authenticated_publication_commits_pair_rows_and_mirror_together",
        "migration",
    ),
    (
        "pando_lab::migration::pg_tests::pg_drain_authenticated_incremental_publication_is_atomic_and_targeted",
        "migration",
    ),
    (
        "pando_lab::migration::pg_tests::pg_publication_rollback_leaves_no_authority_rows_or_mirror",
        "migration",
    ),
    (
        "pando_lab::migration::pg_tests::pg_exact_preparation_retry_returns_same_physical_winner",
        "migration",
    ),
    (
        "pando_lab::migration::pg_tests::pg_stale_repository_generation_fails_before_commit",
        "migration",
    ),
    (
        "pando_lab::migration::pg_tests::pg_shared_gate_blocks_exclusive_rotation_and_stale_target_fails_cleanly",
        "migration",
    ),
    (
        "pando_lab::migration::pg_tests::pg_local_default_and_legacy_completed_epoch_zero_keep_raw_behavior",
        "migration",
    ),
    (
        "pando_lab::repack::pg_tests::pg_repack_default_local_publishes_one_authority_and_retains_pinned_data",
        "repack",
    ),
    (
        "pando_lab::repack::pg_tests::pg_repack_generation_race_fails_cleanly_without_authority",
        "repack",
    ),
    (
        "pando_lab::repack::pg_tests::pg_repack_forced_final_failure_rolls_back_authority_and_mirror",
        "repack",
    ),
    (
        "pando_lab::repack::pg_tests::pg_repack_rotation_barrier_keeps_exact_target_and_shared_gate",
        "repack",
    ),
    (
        "pando_lab::repack::pg_tests::pg_repack_no_sync_local_legacy_and_active_target_narrow_reject",
        "repack",
    ),
    (
        "pando_lab::store::snapshot_pg_tests::pg_snapshot_wins_retains_old_pack_before_insert",
        "snapshot",
    ),
    (
        "pando_lab::store::snapshot_pg_tests::pg_repack_wins_snapshot_selects_replacement_after_commit",
        "snapshot",
    ),
    (
        "pando_lab::store::snapshot_race_pg_tests::pg_snapshot_fault_rolls_back_without_token_and_releases_lock",
        "snapshot",
    ),
    (
        "pando_lab::store::snapshot_race_pg_tests::pg_snapshot_retention_uses_live_expiry_not_expired_rows",
        "snapshot",
    ),
    (
        "pando_lab::store::snapshot_race_pg_tests::pg_ordinary_snapshot_still_does_not_retain",
        "snapshot",
    ),
)
CASE_NAMES = tuple(name for name, _ in CASES)
MIN_CASE_SECONDS = 1.0
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_RUNNING = re.compile(r"^running (\d+) tests?$", re.MULTILINE)
_SUMMARY = re.compile(
    r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; "
    r"(\d+) ignored; (\d+) measured; (\d+) filtered out; "
    r"finished in [0-9]+(?:\.[0-9]+)?s$",
    re.MULTILINE,
)
_CASE = re.compile(r"^test (.+?) \.\.\. (ok|FAILED|ignored)$", re.MULTILINE)


def _record(name, family):
    return {
        "name": name,
        "family": family,
        "status": "not_run",
        "executed": False,
        "exit_code": None,
        "passed": 0,
        "failed": 0,
        "ignored": 0,
        "filtered": 0,
        "code": "not_run",
        "primary_code": None,
    }


def not_run_records(code="not_run"):
    rows = []
    for name, family in CASES:
        row = _record(name, family)
        row["code"] = code
        rows.append(row)
    return rows


def parse_libtest(raw, requested):
    """Require exactly the requested case with an anchored passing summary.

    The caller selects one test from the same bin harness with ``--exact``; the
    other tests in that harness are expected to be filtered out, so a passing
    summary may legitimately carry a nonzero ``filtered`` count.  That count is
    captured and returned, not required to be zero.
    """
    if not isinstance(raw, (bytes, str)):
        raise RunnerError("execute", "output_invalid")
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
    text = _ANSI.sub("", text).replace("\r\n", "\n").replace("\r", "\n")
    running = _RUNNING.findall(text)
    require(len(running) == 1, "execute", "output_invalid")
    count = int(running[0], 10)
    require(count != 0, "execute", "zero_tests")
    require(count == 1, "execute", "output_invalid")
    summary = _SUMMARY.findall(text)
    require(len(summary) == 1, "execute", "summary_missing")
    status, passed, failed, ignored, measured, filtered = summary[0]
    lines = _CASE.findall(text)
    require(bool(lines), "execute", "case_missing")
    if len(lines) != 1:
        if any(name == requested for name, _ in lines):
            raise RunnerError("execute", "duplicate_case")
        raise RunnerError("execute", "unexpected_case")
    name, outcome = lines[0]
    require(name == requested, "execute", "case_mismatch")
    require(outcome != "ignored", "execute", "case_ignored")
    require(outcome != "FAILED", "execute", "case_failed")
    require(outcome == "ok", "execute", "case_failed")
    counts = {
        "passed": int(passed, 10),
        "failed": int(failed, 10),
        "ignored": int(ignored, 10),
        "filtered": int(filtered, 10),
    }
    if (
        status != "ok"
        or counts["passed"] != 1
        or counts["failed"] != 0
        or counts["ignored"] != 0
        or int(measured, 10) != 0
    ):
        raise RunnerError("execute", "summary_mismatch")
    return counts


def execute_cases(
    binary,
    environment,
    runner,
    *,
    work_deadline,
    case_timeout,
    clock,
    cases=CASES,
    cwd=None,
):
    """Execute the exact cases serially; stop at the first failure."""
    require(
        isinstance(binary, str) and bool(binary),
        "execute",
        "invalid_arguments",
    )
    require(isinstance(environment, dict), "execute", "invalid_arguments")
    require(
        isinstance(case_timeout, (int, float))
        and not isinstance(case_timeout, bool)
        and case_timeout > 0,
        "execute",
        "invalid_arguments",
    )
    records = []
    stopped = False
    for name, family in cases:
        row = _record(name, family)
        if stopped:
            records.append(row)
            continue
        remaining = work_deadline - clock() - CLEANUP_RESERVE_SECONDS
        if remaining <= MIN_CASE_SECONDS:
            row["code"] = "not_run_deadline"
            records.append(row)
            stopped = True
            continue
        timeout = min(float(case_timeout), remaining)
        try:
            result = runner.run(
                [binary, name, "--exact", "--ignored", "--test-threads=1"],
                env=environment,
                cwd=cwd,
                timeout=timeout,
                stage="execute",
                timeout_code="case_timeout",
                spawn_code="case_spawn_failed",
            )
        except RunnerError as error:
            row["status"] = "failed"
            row["executed"] = error.code not in ("case_spawn_failed", "process_spawn_failed")
            row["code"] = error.code
            row["primary_code"] = getattr(error, "primary_code", None)
            records.append(row)
            stopped = True
            continue
        row["executed"] = True
        row["exit_code"] = result.returncode
        if result.returncode != 0:
            row["status"] = "failed"
            row["code"] = "nonzero_exit"
            records.append(row)
            stopped = True
            continue
        try:
            counts = parse_libtest(result.stdout, name)
        except RunnerError as error:
            row["status"] = "failed"
            row["code"] = error.code
            records.append(row)
            stopped = True
            continue
        row.update(counts)
        row["status"] = "passed"
        row["code"] = "passed"
        records.append(row)
    return records


def family_counts(records):
    result = {}
    for family in FAMILIES:
        rows = [row for row in records if row.get("family") == family]
        result[family] = {
            "total": len(rows),
            "passed": sum(1 for row in rows if row.get("status") == "passed"),
            "failed": sum(1 for row in rows if row.get("status") == "failed"),
            "not_run": sum(1 for row in rows if row.get("status") == "not_run"),
        }
    return result
