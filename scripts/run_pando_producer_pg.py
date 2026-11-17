#!/usr/bin/env python3
"""Source-bound executor for all 17 ignored producer PostgreSQL cases.

The runner resolves exactly one existing bin-unit-test executable from captured
Cargo JSON, proves the clean expected source/tree and Pando schema identity,
starts one owned loopback PostgreSQL 17 database and private temporary root,
applies the real schema to that owned database, runs the exact case list
serially, rechecks source/binary identity, tears down only the owned resources
and writes a fixed-allowlist report.  The exported Pando product receipt is
validated as same-source evidence only and is never used as the test receipt.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import sys
import time

SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
for entry in (str(SCRIPTS), str(ROOT / "tests")):
    if entry not in sys.path:
        sys.path.insert(0, entry)

from pando_producer_pg import artifacts, cases, report, resources, source  # noqa: E402
from pando_producer_pg.errors import RunnerError, require  # noqa: E402
from pando_producer_pg.process import ProcessRunner  # noqa: E402

REPORT_SCHEMA = report.REPORT_SCHEMA
DEFAULT_REPORT = "test-results/pando-producer-pg.json"
DEFAULT_TOTAL_SECONDS = 570.0
DEFAULT_CLEANUP_RESERVE_SECONDS = 90.0
DEFAULT_SELECTION_TIMEOUT_SECONDS = 180.0
DEFAULT_SETUP_TIMEOUT_SECONDS = 120.0
DEFAULT_CASE_TIMEOUT_SECONDS = 60.0
MIN_POST_CASE_SECONDS = 5.0
MIN_BINARY_RECHECK_SECONDS = 2.0


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise RunnerError("input", "invalid_arguments")


@dataclass(frozen=True)
class Config:
    source_root: Path
    expected_commit: str
    expected_tree: str | None
    report: Path
    product_receipt: Path | None
    total_seconds: float
    cleanup_reserve_seconds: float
    selection_timeout_seconds: float
    setup_timeout_seconds: float
    case_timeout_seconds: float
    prepare_only: bool


def _positive(value, code="timeout_invalid"):
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(value)
        or value <= 0
    ):
        raise RunnerError("input", code)
    return float(value)


def parse_args(argv=None, environ=None):
    env = os.environ if environ is None else environ
    parser = _Parser(add_help=True)
    parser.add_argument("--source-root", default=str(ROOT))
    parser.add_argument(
        "--expected-commit",
        default=env.get("ROOTYARD_EXPECTED_COMMIT") or env.get("GITHUB_SHA"),
    )
    parser.add_argument("--expected-tree", default=None)
    parser.add_argument("--report", default=DEFAULT_REPORT)
    parser.add_argument(
        "--product-receipt", default=env.get("ROOTYARD_PANDO_BUILD_RECEIPT")
    )
    parser.add_argument("--timeout-seconds", type=float, default=DEFAULT_TOTAL_SECONDS)
    parser.add_argument(
        "--cleanup-reserve-seconds",
        type=float,
        default=DEFAULT_CLEANUP_RESERVE_SECONDS,
    )
    parser.add_argument(
        "--selection-timeout-seconds",
        type=float,
        default=DEFAULT_SELECTION_TIMEOUT_SECONDS,
    )
    parser.add_argument(
        "--setup-timeout-seconds",
        type=float,
        default=DEFAULT_SETUP_TIMEOUT_SECONDS,
    )
    parser.add_argument(
        "--case-timeout-seconds", type=float, default=DEFAULT_CASE_TIMEOUT_SECONDS
    )
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args(argv)
    require(bool(args.expected_commit), "input", "missing_expected_commit")
    require(bool(args.report), "input", "missing_report")
    total = _positive(args.timeout_seconds)
    reserve = _positive(args.cleanup_reserve_seconds)
    require(total <= 600.0 and total > reserve + 10.0, "input", "timeout_invalid")
    return Config(
        source_root=Path(args.source_root),
        expected_commit=args.expected_commit,
        expected_tree=args.expected_tree,
        report=Path(args.report),
        product_receipt=Path(args.product_receipt) if args.product_receipt else None,
        total_seconds=total,
        cleanup_reserve_seconds=reserve,
        selection_timeout_seconds=_positive(args.selection_timeout_seconds),
        setup_timeout_seconds=_positive(args.setup_timeout_seconds),
        case_timeout_seconds=_positive(args.case_timeout_seconds),
        prepare_only=bool(args.prepare_only),
    )


def _selection_binding(selection):
    return {
        "command": list(selection.get("command") or artifacts.CARGO_COMMAND),
        "features": list(selection.get("features") or artifacts.FEATURES),
        "target": selection.get("target"),
        "kind": list(selection.get("kind") or []),
        "profile_test": bool((selection.get("profile") or {}).get("test")),
        "fresh": bool(selection.get("fresh")),
    }


def _first_failure(records):
    for row in records:
        if row.get("status") == "failed":
            return RunnerError("execute", row.get("code") or "case_failed")
    for row in records:
        if row.get("status") != "passed":
            return RunnerError("execute", row.get("code") or "not_run")
    return None


def _prepare_summary(payload):
    return {
        "schema": payload.get("schema"),
        "prepared": bool(payload.get("passed")),
        "test_binary_sha256": payload.get("test_binary_sha256"),
        "actual_fresh": payload.get("actual_fresh", {}),
        "cleanup": payload.get("cleanup", {}),
    }


def run(
    config,
    *,
    runner=None,
    clock=time.monotonic,
    capture_source=None,
    select_binary=None,
    fixture_factory=None,
    execute_cases_fn=None,
    write_report_fn=None,
    validate_product=None,
    environ=None,
):
    runner = runner or ProcessRunner(clock=clock)
    capture_source = capture_source or source.capture
    select_binary = select_binary or artifacts.select_test_binary
    fixture_factory = fixture_factory or resources.OwnedFixture
    execute_cases_fn = execute_cases_fn or cases.execute_cases
    write_report_fn = write_report_fn or report.write_report
    validate_product = validate_product or source.validate_product_receipt
    environ = dict(os.environ if environ is None else environ)
    resources.require_escape_absent(environ)
    require(
        config.prepare_only or config.product_receipt is not None,
        "source",
        "product_receipt_missing",
    )
    bootstrap = environ.get("ROOTYARD_TEST_DATABASE_URL")
    require(bool(bootstrap), "input", "missing_bootstrap")
    started = clock()
    overall = started + config.total_seconds
    work = overall - config.cleanup_reserve_seconds
    records = cases.not_run_records()
    binding = None
    selection = None
    product = {
        "provided": False,
        "same_source": False,
        "used_as_test_binary_receipt": False,
        "attached_to_native_gate": False,
    }
    cleanup = resources.empty_cleanup()
    fixture = None
    error = None
    try:
        binding = capture_source(
            config.source_root,
            config.expected_commit,
            expected_tree=config.expected_tree,
            environ=environ,
            deadline=work,
            clock=clock,
        )
        product = validate_product(
            config.product_receipt,
            config.source_root,
            config.expected_commit,
            binding["source_inputs_sha256"],
        )
        remaining = min(config.selection_timeout_seconds, work - clock())
        require(remaining > 0, "selection", "setup_deadline_exceeded")
        selection = select_binary(
            config.source_root,
            runner,
            remaining,
            deadline=work,
            clock=clock,
        )
        binding["cargo_selection"] = _selection_binding(selection)
        binding["source_rechecked"] = False
        binding["source_unchanged"] = False
        binding["test_binary_unchanged"] = False
        binding["fresh_verification"] = False
        binding["verification_code"] = None
        fixture = fixture_factory(
            config.source_root,
            bootstrap,
            environ,
            runner,
            schema_sha256=binding["schema_sha256"],
            clock=clock,
        )
        setup_deadline = min(work, clock() + config.setup_timeout_seconds)
        fixture.start(deadline=setup_deadline)
        if not config.prepare_only:
            records = execute_cases_fn(
                selection["executable_path"],
                fixture.child_environment,
                runner,
                work_deadline=work,
                case_timeout=config.case_timeout_seconds,
                clock=clock,
            )
            if work - clock() <= MIN_POST_CASE_SECONDS:
                binding["verification_code"] = "post_case_deadline_exceeded"
                raise RunnerError("binding", "post_case_deadline_exceeded")
            try:
                after = capture_source(
                    config.source_root,
                    config.expected_commit,
                    expected_tree=config.expected_tree,
                    environ=environ,
                    deadline=work,
                    clock=clock,
                )
            except RunnerError as caught:
                binding["source_rechecked"] = False
                binding["source_unchanged"] = False
                code = (
                    "source_recheck_deadline_exceeded"
                    if caught.code in (
                        "source_capture_deadline_exceeded",
                        "source_recheck_deadline_exceeded",
                    )
                    else "source_recheck_failed"
                )
                binding["verification_code"] = code
                raise RunnerError("binding", code) from None
            binding["source_rechecked"] = True
            binding["source_unchanged"] = source.same(binding, after)
            if not binding["source_unchanged"]:
                binding["verification_code"] = "source_drift"
                raise RunnerError("binding", "source_drift")
            if work - clock() <= MIN_BINARY_RECHECK_SECONDS:
                binding["verification_code"] = "binary_recheck_deadline_exceeded"
                raise RunnerError("binding", "binary_recheck_deadline_exceeded")
            try:
                artifacts.verify_selected_binary(
                    selection, deadline=work, clock=clock
                )
            except RunnerError as caught:
                binding["test_binary_unchanged"] = False
                if caught.code in (
                    "binary_rehash_deadline_exceeded",
                    "binary_recheck_deadline_exceeded",
                ):
                    binding["verification_code"] = "binary_recheck_deadline_exceeded"
                    raise RunnerError(
                        "binding", "binary_recheck_deadline_exceeded"
                    ) from None
                raise
            binding["test_binary_unchanged"] = True
            binding["fresh_verification"] = True
            error = _first_failure(records)
    except RunnerError as caught:
        error = caught
    finally:
        if fixture is not None:
            try:
                cleanup = fixture.cleanup(overall)
            except RunnerError:
                cleanup = resources.unresolved_cleanup("cleanup_unresolved")
            except Exception:
                cleanup = resources.unresolved_cleanup("cleanup_unresolved")
        else:
            cleanup = resources.empty_cleanup()
    if error is None and not cleanup.get("cleanup_ok"):
        error = RunnerError(
            "cleanup", cleanup.get("error_code", "cleanup_unresolved")
        )
    if error is None and not cleanup.get("cleanup_within_deadline", False):
        error = RunnerError("cleanup", "cleanup_deadline_exceeded")
    if error is None and clock() > overall:
        error = RunnerError("cleanup", "overall_deadline_exceeded")
    if (
        error is not None
        and cleanup.get("error_code")
        and cleanup.get("error_code") != error.code
    ):
        cleanup["secondary_error_code"] = cleanup["error_code"]
    if not config.prepare_only:
        failure = _first_failure(records)
        if failure is not None and error is None:
            error = failure
    passed = error is None and bool(cleanup.get("cleanup_ok"))
    passed = passed and clock() <= overall
    if not config.prepare_only:
        passed = passed and all(row.get("status") == "passed" for row in records)
    fresh_verification = bool(
        not config.prepare_only
        and isinstance(binding, dict)
        and binding.get("source_rechecked") is True
        and binding.get("source_unchanged") is True
        and binding.get("test_binary_unchanged") is True
        and binding.get("fresh_verification") is True
    )
    actual_fresh = {
        "selected_test_binary": bool(
            isinstance(selection, dict) and selection.get("fresh")
        ),
        "cargo_selection_reused_cache": bool(
            isinstance(selection, dict) and selection.get("fresh")
        ),
    }
    payload = report.build_report(
        passed=passed,
        records=records,
        binding=binding,
        selection=selection,
        product_receipt=product,
        cleanup=cleanup,
        actual_fresh=actual_fresh,
        error_code=error.code if error is not None else None,
        stage=error.stage if error is not None else None,
        fresh_verification=fresh_verification,
    )
    if not config.prepare_only:
        write_report_fn(
            config.report,
            payload,
            forbidden_root=(
                fixture.root.path
                if fixture is not None and fixture.root is not None
                else None
            ),
        )
    return payload


def main(argv=None):
    try:
        config = parse_args(argv)
        payload = run(config)
        if config.prepare_only:
            print(json.dumps(_prepare_summary(payload), sort_keys=True))
        return 0 if payload.get("passed") else 1
    except RunnerError as error:
        print(
            "pando producer pg runner failed: %s/%s" % (error.stage, error.code),
            file=sys.stderr,
        )
        return 1
    except Exception:
        print(
            "pando producer pg runner failed: internal/internal_error",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
