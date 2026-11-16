#!/usr/bin/env python3
"""Standalone literal acceptance runner for Issue #85 / PR #259.

The runner executes exactly the four plan case IDs against the real supplied
service binary, a real isolated PostgreSQL schema, real stock Git objects and
real LFS bytes: three DB-backed purge holds plus rename-alias real Git/LFS
writes.  The existing author suite, production Rust and CI workflow are
untouched.

Provenance is fail-closed.  The complete tracked and non-ignored untracked
worktree must be clean, the trusted expected source commit must equal HEAD,
the canonical build receipt is validated against the exact current source root
with ``verify_source_files=True``, and every new acceptance input is hashed
against its committed HEAD blob.  The runner never invokes Cargo, rustc, a
builder, Docker or a network peer.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import sys
import time
import traceback

TESTS_DIR = Path(__file__).resolve().parent
ROOT = TESTS_DIR.parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from repository_lifecycle import RepositoryLifecycleHarness  # noqa: E402
from repository_lifecycle_acceptance_alias import (  # noqa: E402
    rename_alias_accepts_real_git_and_lfs_writes,
)
from repository_lifecycle_acceptance_holds import (  # noqa: E402
    backup_root_blocks_purge,
    ci_pin_blocks_purge,
    serving_read_header_blocks_purge,
)
from repository_lifecycle_acceptance_support import (  # noqa: E402
    ACCEPTANCE_INPUT_PATHS,
    PLAN_CASE_NAMES,
    REPORT_SCHEMA,
    bind_build_receipt,
    classify_error,
    evaluate_binding,
    expected_receipt_sha256,
    expected_source_commit,
    helper_input_manifest,
    safe_detail,
    select_receipt,
    sha256_file,
    source_identity,
    summarize,
)


class AcceptanceHarness(RepositoryLifecycleHarness):
    def __init__(self, args):
        super().__init__(args)
        self.current_phase = "prepare"

    def phase(self, name):
        self.current_phase = name


CASES = (
    ("backup_root_blocks_purge", backup_root_blocks_purge),
    ("serving_read_header_blocks_purge", serving_read_header_blocks_purge),
    ("ci_pin_blocks_purge", ci_pin_blocks_purge),
    (
        "rename_alias_accepts_real_git_and_lfs_writes",
        rename_alias_accepts_real_git_and_lfs_writes,
    ),
)


def _run_case(harness, name, function):
    harness.phase("start")
    started = time.monotonic()
    try:
        detail = function(harness)
        status = "passed"
        error_class = None
    except Exception as error:
        status = "failed"
        error_class = classify_error(error)
        print(harness.redact(traceback.format_exc()), file=sys.stderr)
        detail = {}
    return {
        "name": name,
        "status": status,
        "phase": harness.current_phase,
        "error_class": error_class,
        "seconds": round(time.monotonic() - started, 4),
        "detail": safe_detail(detail),
    }


def _failed_inventory(phase, error_class):
    return [
        {
            "name": name,
            "status": "failed",
            "phase": phase,
            "error_class": error_class,
            "seconds": 0.0,
            "detail": {},
        }
        for name, _ in CASES
    ]


def _empty_helper_inputs():
    return {
        "bound": False,
        "manifest_sha256": None,
        "count": 0,
        "expected_count": len(ACCEPTANCE_INPUT_PATHS),
        "files": [],
        "error_class": "helper_inputs_unavailable",
    }


def _empty_source():
    return {
        "commit": None,
        "tree": None,
        "parents": [],
        "working_tree_dirty": None,
        "tracked_dirty": None,
        "untracked_count": None,
        "clean": False,
        "error_class": None,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--build-receipt", type=Path)
    parser.add_argument("--expected-source-commit")
    parser.add_argument("--expected-receipt-sha256")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error(
            "ROOTYARD_TEST_DATABASE_URL is required; use a dedicated test database"
        )
    for executable in ("git", "psql", args.binary):
        if not shutil.which(executable):
            parser.error("Required executable not found: " + executable)

    source = _empty_source()
    try:
        source.update(source_identity(ROOT))
    except Exception as error:
        source["error_class"] = classify_error(error)
        print(traceback.format_exc(), file=sys.stderr)

    expected_commit, expected_commit_error = expected_source_commit(
        args.expected_source_commit, os.environ
    )
    receipt_anchor, receipt_anchor_error = expected_receipt_sha256(
        args.expected_receipt_sha256, os.environ
    )
    if receipt_anchor_error not in (None, "receipt_anchor_missing"):
        print("expected receipt digest: " + receipt_anchor_error, file=sys.stderr)

    receipt_path, receipt_origin = select_receipt(
        args.binary, args.build_receipt, os.environ
    )
    helper_inputs = _empty_helper_inputs()
    try:
        helper_inputs = helper_input_manifest(ROOT)
    except Exception as error:
        helper_inputs["error_class"] = classify_error(error)
        print(traceback.format_exc(), file=sys.stderr)

    if source.get("commit"):
        build_receipt = bind_build_receipt(
            args.binary,
            receipt_path,
            source["commit"],
            ROOT,
            module_root=ROOT,
            helper_files=helper_inputs.get("files") or [],
            expected_receipt_sha256=receipt_anchor,
        )
    else:
        build_receipt = {
            "present": False,
            "bound": False,
            "error_class": "source_unavailable",
        }
    binary_sha256 = sha256_file(args.binary)
    binding = evaluate_binding(
        source, expected_commit, build_receipt, binary_sha256, helper_inputs
    )

    harness = AcceptanceHarness(args)
    setup = {"status": "not_run", "error_class": None}
    cleanup = {"status": "not_run", "error_class": None}
    case_results = []
    try:
        try:
            harness.setup()
            setup = {"status": "passed", "error_class": None}
        except Exception as error:
            setup = {"status": "failed", "error_class": classify_error(error)}
            print(harness.redact(traceback.format_exc()), file=sys.stderr)
            case_results = _failed_inventory("setup", "setup")
        else:
            for name, function in CASES:
                case_results.append(_run_case(harness, name, function))
    finally:
        try:
            harness.cleanup()
            cleanup = {"status": "passed", "error_class": None}
        except Exception as error:
            cleanup = {"status": "failed", "error_class": classify_error(error)}
            print(harness.redact(traceback.format_exc()), file=sys.stderr)

    inventory = summarize(
        case_results,
        PLAN_CASE_NAMES,
        cleanup_ok=cleanup["status"] == "passed",
        binding_ok=binding["bound"],
    )
    passed_count = sum(row["status"] == "passed" for row in case_results)
    failed_count = sum(row["status"] == "failed" for row in case_results)
    report = {
        "report_schema": REPORT_SCHEMA,
        "passed": inventory["passed"],
        "skipped": 0,
        "case_inventory": {
            "expected": list(PLAN_CASE_NAMES),
            "executed": [row["name"] for row in case_results],
            "exact": inventory["exact"],
            "missing": inventory["missing"],
            "unexpected": inventory["unexpected"],
            "duplicate": inventory["duplicate"],
        },
        "counts": {
            "expected": len(PLAN_CASE_NAMES),
            "executed": len(case_results),
            "passed": passed_count,
            "failed": failed_count,
            "skipped": 0,
        },
        "cases": case_results,
        "setup": setup,
        "cleanup": cleanup,
        "source": source,
        "source_binding": {
            "bound": binding["bound"],
            "expected_commit": expected_commit,
            "expected_commit_error": expected_commit_error,
            "receipt_origin": receipt_origin,
            "receipt_anchor": receipt_anchor,
            "receipt_anchor_present": receipt_anchor is not None,
            "checks": binding["checks"],
        },
        "helper_inputs": helper_inputs,
        "binary": {"sha256": binary_sha256},
        "build_receipt": build_receipt,
    }
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
