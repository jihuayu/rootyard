#!/usr/bin/env python3
"""Run the four exact issue #111 cache HTTP cases on one owned native fixture.

This is a small binder around the existing #174 libtest binary and receipt; it
does not build, migrate, start a service or invent a test report shape. The
workflow has already run the original #174 cases, exported the immutable lib
alias/receipt, created the exact run-owned database and started the job-owned
Garage fixture. This script only:

* asserts the two whole-fixture ownership markers and the exact run/attempt
  database and Blob prefixes;
* validates the immutable lib receipt against the current source tree and the
  #174 preflight anchors;
* runs the four exact `#[ignore]` selectors with one libtest summary each;
* writes a bounded report and fixed summary line containing no raw test output,
  connection string, credential or generated URL.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
import issue107_native11_runner as bounded_runner  # noqa: E402
import native_build_receipt as receipts  # noqa: E402

CASES = (
    "blob_git_gateway::session_http_acceptance::cache_tests::"
    "exact_commit_http_warm_miss_then_actual_hit_is_byte_equal",
    "blob_git_gateway::session_http_acceptance::cache_tests::"
    "exact_commit_http_hit_still_enforces_final_live_authorization",
    "blob_git_gateway::session_http_acceptance::cache_tests::"
    "exact_commit_http_hit_still_enforces_restore_incarnation_fence",
    "blob_git_gateway::session_http_acceptance::cache_tests::"
    "exact_commit_http_cached_oid_is_not_served_after_it_becomes_unreachable",
)
OWNED_POSTGRES_OPT_IN = "ROOTYARD_TEST_OWNED_DISPOSABLE_POSTGRES"
OWNED_BLOB_OPT_IN = "ROOTYARD_TEST_OWNED_DISPOSABLE_BLOB"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SUMMARY = re.compile(
    r"^test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; "
    r"(\d+) measured; (\d+) filtered out; finished in ([0-9.]+)s$",
    re.MULTILINE,
)
CASE_TIMEOUT_SECONDS = 300
SCOPE = "session174-cache-4-cases"
FAILURE_CODES = {
    "native_timeout": "timeout",
    "native_process_failed": "process_failed",
    "native_output_too_large": "output_too_large",
    "cleanup_unresolved": "cleanup_unresolved",
}
SUCCESS_SUMMARY = (
    "session174 cache proof: 4/4 passed; 0 failed; 0 skipped"
)


class ProofError(Exception):
    """A fixed ownership, receipt or exact-case binding refused the proof."""


def fail(message):
    raise ProofError(message)


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path, label):
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as error:
        fail(label + " is not readable JSON: " + type(error).__name__)
    if not isinstance(value, dict):
        fail(label + " is not a JSON object")
    return value


def readonly_regular(path, label):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        fail(label + " is not a safe absolute path")
    if path.is_symlink() or not path.is_file():
        fail(label + " is not a regular non-symlink file")
    info = path.stat()
    if info.st_uid != os.geteuid():
        fail(label + " is not owned by the current user")
    if info.st_mode & 0o222:
        fail(label + " must be readonly")
    return path


def run_exact_case(lib, name):
    try:
        output = bounded_runner.run_bounded(
            [lib, "--ignored", "--exact", name, "--test-threads=1"],
            timeout=CASE_TIMEOUT_SECONDS,
            env=os.environ.copy(),
        )
    except bounded_runner.RunnerError as error:
        return {
            "name": name,
            "status": "failed",
            "failure": FAILURE_CODES.get(getattr(error, "code", None), "runner_failed"),
        }
    except OSError:
        return {"name": name, "status": "failed", "failure": "exec"}
    text = output.decode("utf-8", "replace")
    rows = SUMMARY.findall(text)
    ran = [
        line[5:-len(" ... ok")]
        for line in text.splitlines()
        if line.startswith("test ") and line.endswith(" ... ok")
    ]
    if len(rows) != 1:
        return {"name": name, "status": "failed", "failure": "summary_count"}
    state, passed, failed, ignored, measured, filtered, elapsed = rows[0]
    if (state, passed, failed, ignored, measured) != ("ok", "1", "0", "0", "0"):
        return {"name": name, "status": "failed", "failure": "summary_not_exact_one"}
    if ran != [name]:
        return {"name": name, "status": "failed", "failure": "case_outcome_missing"}
    return {
        "name": name,
        "status": "passed",
        "summary": "1 passed; 0 failed; 0 ignored; 0 skipped",
        "elapsed_seconds": float(elapsed),
    }


def exact_run_identity():
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    if not run_id.isdigit() or not attempt.isdigit():
        fail("GITHUB_RUN_ID and GITHUB_RUN_ATTEMPT must be numeric")
    return run_id, attempt


def validate(args, report):
    if args.scope != SCOPE:
        fail("scope marker differs from the fixed four-case scope")
    for marker in (OWNED_POSTGRES_OPT_IN, OWNED_BLOB_OPT_IN):
        if os.environ.get(marker) != "1":
            fail(marker + " is not 1")
    run_id, attempt = exact_run_identity()
    database = os.environ.get("SESSION174_DATABASE_PREFIX", "")
    expected_database = database + "_r" + run_id + "_a" + attempt
    if args.database != expected_database:
        fail("database is not this exact run/attempt")
    expected_blob = "session174-cache-" + run_id + "-" + attempt
    if os.environ.get("ROOTYARD_BLOB_ROOT") != expected_blob:
        fail("Blob root is not this exact run/attempt cache prefix")
    if not os.environ.get("DATABASE_URL") or not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        fail("owned database URLs are absent")
    source = receipts.git_state(ROOT)
    if source.get("clean") is not True:
        fail("source tree is not clean")
    if source.get("commit") != args.expected_commit:
        fail("source commit differs from the expected commit")
    source_tree = source.get("tree")
    if not isinstance(source_tree, str) or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", source_tree) is None:
        fail("source tree is not a lowercase full Git tree id")
    preflight_path = Path(args.preflight)
    preflight = load_json(preflight_path, "preflight evidence")
    lib = readonly_regular(args.lib, "lib alias")
    receipt = readonly_regular(args.receipt, "lib receipt")
    validated = receipts.load_receipt(
        receipt,
        source_root=ROOT,
        binary_path=lib,
        expected_commit=args.expected_commit,
        verify_source_files=True,
    )
    payload = validated.payload
    binary_sha = payload.get("binary_sha256")
    source_sha = payload.get("source_inputs_sha256")
    if not isinstance(binary_sha, str) or HEX64.fullmatch(binary_sha) is None:
        fail("lib receipt has no lowercase 64-hex binary digest")
    if not isinstance(source_sha, str) or HEX64.fullmatch(source_sha) is None:
        fail("lib receipt has no lowercase 64-hex source digest")
    if preflight.get("head") != args.expected_commit:
        fail("preflight head differs from the expected commit")
    lib_record = preflight.get("lib_receipt")
    if not isinstance(lib_record, dict) or lib_record.get("sha256") != validated.receipt_sha256:
        fail("preflight lib receipt anchor differs from the consumed receipt")
    if preflight.get("lib_binary_sha256") != binary_sha:
        fail("preflight lib binary anchor differs from the consumed receipt")
    if preflight.get("source_inputs_sha256") != source_sha:
        fail("preflight source-input anchor differs from the consumed receipt")
    report.update(
        {
            "schema": "rootyard/refstore-issue111-cache-proof/v1",
            "issue": 111,
            "scope": args.scope,
            "source_head": source["commit"],
            "source_commit": source["commit"],
            "source_tree": source_tree,
            "source_inputs_sha256": source_sha,
            "binary_sha256": binary_sha,
            "build_receipt_sha256": validated.receipt_sha256,
            "receipt_sha256": validated.receipt_sha256,
            "preflight_sha256": sha256(preflight_path),
            "cases": [],
            "passed": False,
        }
    )
    return str(lib)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--lib", required=True)
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--preflight", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--database", required=True)
    parser.add_argument("--scope", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--summary-log", required=True)
    args = parser.parse_args(argv)

    report = {
        "schema": "rootyard/refstore-issue111-cache-proof/v1",
        "issue": 111,
        "scope": args.scope,
        "source_head": args.expected_commit,
        "cases": [],
        "passed": False,
    }
    summary = "session174 cache proof: failed before completion; 0 skipped"
    try:
        lib = validate(args, report)
        for name in CASES:
            report["cases"].append(run_exact_case(lib, name))
        passed = sum(1 for case in report["cases"] if case.get("status") == "passed")
        report["case_count"] = len(CASES)
        report["skipped"] = 0
        report["passed"] = passed == len(CASES)
        summary = (
            SUCCESS_SUMMARY
            if report["passed"]
            else "session174 cache proof: "
            + str(passed)
            + "/"
            + str(len(CASES))
            + " passed; "
            + str(len(CASES) - passed)
            + " failed; 0 skipped"
        )
    except ProofError:
        report["error"] = "proof_refused"
        summary = "session174 cache proof: failed before completion; 0 skipped"
    except receipts.ReceiptError:
        report["error"] = "receipt_refused"
        summary = "session174 cache proof: failed before completion; 0 skipped"
    except subprocess.SubprocessError:
        report["error"] = "source_git_failed"
        summary = "session174 cache proof: failed before completion; 0 skipped"
    except OSError:
        report["error"] = "io_error"
        summary = "session174 cache proof: failed before completion; 0 skipped"
    except (ValueError, TypeError, KeyError):
        report["error"] = "validation_failed"
        summary = "session174 cache proof: failed before completion; 0 skipped"
    except Exception:
        # Never let an unclassified binder failure print a traceback or raw
        # child text; the artifact still records one fixed failure code.
        report["error"] = "internal_error"
        summary = "session174 cache proof: failed before completion; 0 skipped"
    finally:
        report_path = Path(args.report)
        summary_path = Path(args.summary_log)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        summary_path.write_text(summary + "\n")
    print(summary)
    return 0 if report.get("passed") is True else 1


if __name__ == "__main__":
    sys.exit(main())
