#!/usr/bin/env python3
"""Source-bound producer PostgreSQL runner (preparation checkpoint).

This checkpoint resolves one existing bin-unit-test executable from the Cargo
JSON cache, proves the clean expected source/tree and Pando schema identity,
starts one owned loopback PostgreSQL 17 database and private temporary root,
applies the real schema to that owned database, and tears both down with the
approved ownership helpers.  The next checkpoint adds the 17 exact case
executions and the report.
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

from pando_producer_pg import artifacts, resources, source  # noqa: E402
from pando_producer_pg.errors import RunnerError, require  # noqa: E402
from pando_producer_pg.process import ProcessRunner  # noqa: E402

REPORT_SCHEMA = "rootyard/issue21-pando-producer-pg/v1"
DEFAULT_REPORT = "test-results/pando-producer-pg.json"
DEFAULT_TOTAL_SECONDS = 570.0
DEFAULT_CLEANUP_RESERVE_SECONDS = 90.0
DEFAULT_SELECTION_TIMEOUT_SECONDS = 180.0
DEFAULT_SETUP_TIMEOUT_SECONDS = 120.0
DEFAULT_CASE_TIMEOUT_SECONDS = 60.0


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
        prepare_only=True,
    )


def _remaining(clock, deadline):
    return deadline - clock()


def _safe_summary(selection, cleanup):
    return {
        "schema": REPORT_SCHEMA,
        "prepared": True,
        "test_binary_sha256": selection.get("executable_sha256"),
        "actual_fresh": {
            "selected_test_binary": bool(selection.get("fresh")),
            "cargo_selection_reused_cache": bool(selection.get("fresh")),
        },
        "cleanup": cleanup,
    }


def main(argv=None):
    clock = time.monotonic
    try:
        config = parse_args(argv)
        environ = dict(os.environ)
        bootstrap = environ.get("ROOTYARD_TEST_DATABASE_URL")
        require(bool(bootstrap), "input", "missing_bootstrap")
        overall = clock() + config.total_seconds
        work = overall - config.cleanup_reserve_seconds
        binding = source.capture(
            config.source_root, config.expected_commit, environ=environ
        )
        source.validate_product_receipt(
            config.product_receipt,
            config.source_root,
            config.expected_commit,
            binding["source_inputs_sha256"],
        )
        remaining = min(
            config.selection_timeout_seconds, _remaining(clock, work)
        )
        require(remaining > 0, "selection", "setup_deadline_exceeded")
        selection = artifacts.select_test_binary(
            config.source_root, ProcessRunner(clock=clock), remaining
        )
        fixture = resources.OwnedFixture(
            config.source_root,
            bootstrap,
            environ,
            ProcessRunner(clock=clock),
            schema_sha256=binding["schema_sha256"],
            clock=clock,
        )
        cleanup = resources.empty_cleanup()
        try:
            setup_deadline = min(
                work, clock() + config.setup_timeout_seconds
            )
            fixture.start(deadline=setup_deadline)
        finally:
            cleanup = fixture.cleanup(overall)
        if not cleanup["cleanup_ok"]:
            code = cleanup.get("error_code", "cleanup_unresolved")
            raise RunnerError("cleanup", code)
        print(json.dumps(_safe_summary(selection, cleanup), sort_keys=True))
        return 0
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
