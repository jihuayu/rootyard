#!/usr/bin/env python3
"""Write one sanitized receipt for the hosted FUSE compatibility witness.

The raw unittest stream is read only to count the exact selected case and the
unittest summary.  Its bytes, exception text and any database URL are never
copied into the receipt or printed.  The caller owns that raw file and must
keep it outside the uploaded receipt directory.

This is a focused proof-capture helper, not a test module and not a generic
acceptance framework.  It never runs the witness, starts a service, builds a
binary, contacts a network or rewrites provenance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import sys
import time
from pathlib import Path

SCHEMA = "rootyard/workspace-fuse-compat-receipt/v1"
SCOPE = (
    "local checkpoint restore and inert LFS pointer only; no remote publish, "
    "cross-host restore, clean/smudge hydration, or issue closure claim"
)
DEFAULT_TEST_CASE = "test_detached_inert_lfs_checkpoint_remount_and_local_restore"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
MAX_RAW_BYTES = 16 * 1024 * 1024
SUMMARY_RAN = re.compile(r"^Ran (\d+) tests? in ")
SUMMARY_OK = re.compile(r"^OK(?: \(skipped=(\d+)\))?$")
SUMMARY_FAILED = re.compile(r"^FAILED \((.*)\)$")


def digest(path):
    """Return a file SHA-256, or None when the file is unavailable."""
    if not path:
        return None
    try:
        hasher = hashlib.sha256()
        with open(path, "rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except OSError:
        return None


def bounded(value, limit=240):
    """Keep receipt metadata short and single-line."""
    text = " ".join(str(value or "").split())
    return text[:limit]


def parse_unittest(raw_log, exit_code, expected_case):
    """Parse only counts and the exact selected case from the private stream."""
    result = {
        "tests_run": 0,
        "skipped": 0,
        "failures": 0,
        "errors": 0,
        "expected_case_selected": False,
        "case_outcome": "missing",
        "summary": "missing",
        "passed": False,
        "classification": "unittest_output_missing",
    }
    try:
        with open(raw_log, "rb") as source:
            text = source.read(MAX_RAW_BYTES).decode("utf-8", errors="replace")
    except OSError:
        return result
    lines = text.splitlines()
    case_line = re.compile(
        r"^" + re.escape(expected_case)
        + r" \(.*\) \.\.\. (ok|FAIL|ERROR|skipped)(?:\b.*)?$"
    )
    case_lines = [line for line in lines if case_line.match(line)]
    result["expected_case_selected"] = len(case_lines) == 1
    if len(case_lines) == 1:
        match = case_line.match(case_lines[0])
        outcome = match.group(1) if match else "missing"
        result["case_outcome"] = (
            "ok" if outcome == "ok" else outcome.lower()
        )
    ran = [int(match.group(1)) for line in lines if (match := SUMMARY_RAN.match(line))]
    if ran:
        result["tests_run"] = ran[-1]
    skipped = 0
    failures = 0
    errors = 0
    summary = "missing"
    for line in reversed(lines):
        match = SUMMARY_OK.match(line)
        if match:
            summary = "ok"
            skipped = int(match.group(1) or 0)
            break
        match = SUMMARY_FAILED.match(line)
        if match:
            summary = "failed"
            for part in match.group(1).split(","):
                key, _, value = part.strip().partition("=")
                if key == "failures" and value.isdigit():
                    failures = int(value)
                elif key == "errors" and value.isdigit():
                    errors = int(value)
                elif key == "skipped" and value.isdigit():
                    skipped = int(value)
            break
    result["summary"] = summary
    result["skipped"] = skipped
    result["failures"] = failures
    result["errors"] = errors
    result["passed"] = bool(
        exit_code == 0
        and summary == "ok"
        and result["tests_run"] == 1
        and skipped == 0
        and failures == 0
        and errors == 0
        and result["expected_case_selected"]
        and result["case_outcome"] == "ok"
    )
    if result["passed"]:
        result["classification"] = "passed"
    elif not result["expected_case_selected"]:
        result["classification"] = "expected_case_not_selected_exactly_once"
    elif result["case_outcome"] != "ok":
        result["classification"] = "expected_case_" + result["case_outcome"]
    elif result["tests_run"] != 1:
        result["classification"] = "unexpected_test_count"
    elif result["skipped"] != 0:
        result["classification"] = "unexpected_skip"
    elif summary != "ok":
        result["classification"] = "unittest_summary_" + summary
    else:
        result["classification"] = "unittest_nonzero_exit"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--raw-log", default="")
    parser.add_argument("--exit-code", type=int, default=1)
    parser.add_argument("--source-commit", default="")
    parser.add_argument("--source-tree", default="")
    parser.add_argument("--binary", default="")
    parser.add_argument("--build-receipt", default="")
    parser.add_argument("--harness", default="tests/workspace_fuse_compat_witness.py")
    parser.add_argument(
        "--workflow", default=".github/workflows/native-kernel-acceptance.yml"
    )
    parser.add_argument("--test-case", default=DEFAULT_TEST_CASE)
    parser.add_argument("--database-name", default="")
    parser.add_argument("--pg-version", default="")
    parser.add_argument("--dev-fuse", default="")
    parser.add_argument("--unshare-status", default="")
    parser.add_argument("--bwrap-status", default="")
    parser.add_argument("--fusermount-version", default="")
    parser.add_argument("--blocked", action="store_true")
    parser.add_argument("--classification", default="")
    args = parser.parse_args()

    missing = [
        name
        for name, value in (
            ("source_commit", args.source_commit),
            ("source_tree", args.source_tree),
            ("binary", args.binary),
            ("build_receipt", args.build_receipt),
        )
        if not value
    ]
    source_commit_ok = bool(HEX40.match(args.source_commit or ""))
    source_tree_ok = bool(HEX40.match(args.source_tree or ""))
    if not source_commit_ok and "source_commit" not in missing:
        missing.append("source_commit")
    if not source_tree_ok and "source_tree" not in missing:
        missing.append("source_tree")

    binary_sha256 = digest(args.binary)
    build_receipt_sha256 = digest(args.build_receipt)
    harness_sha256 = digest(args.harness)
    workflow_sha256 = digest(args.workflow)
    unavailable = [
        name
        for name, value in (
            ("binary", binary_sha256),
            ("build_receipt", build_receipt_sha256),
            ("harness", harness_sha256),
            ("workflow", workflow_sha256),
        )
        if value is None
    ]

    parsed = {
        "tests_run": 0,
        "skipped": 0,
        "failures": 0,
        "errors": 0,
        "expected_case_selected": False,
        "case_outcome": "not_run",
        "summary": "not_run",
        "passed": False,
        "classification": "blocked",
    }
    if not args.blocked:
        if missing or unavailable:
            parsed["classification"] = "input_unavailable"
        elif not args.raw_log:
            parsed["classification"] = "unittest_output_missing"
        else:
            parsed.update(parse_unittest(args.raw_log, args.exit_code, args.test_case))

    if args.blocked:
        status = "blocked"
        classification = args.classification or "blocked"
    else:
        status = "passed" if parsed["passed"] else "failed"
        classification = args.classification or parsed["classification"]

    receipt = {
        "schema": SCHEMA,
        "status": status,
        "classification": classification,
        "source_commit": args.source_commit,
        "source_tree": args.source_tree,
        "binary_sha256": binary_sha256,
        "build_receipt_sha256": build_receipt_sha256,
        "harness_sha256": harness_sha256,
        "workflow_sha256": workflow_sha256,
        "test_file": "tests/workspace_fuse_compat_witness.py",
        "test_case": args.test_case,
        "expected_case_selected": parsed["expected_case_selected"],
        "case_outcome": parsed["case_outcome"],
        "tests_run": parsed["tests_run"],
        "skipped": parsed["skipped"],
        "failures": parsed["failures"],
        "errors": parsed["errors"],
        "summary": parsed["summary"],
        "unittest_exit_code": args.exit_code,
        "selection": {
            "gate": "ROOTYARD_TEST_FUSE_COMPAT_WITNESS=1",
            "backend": "ROOTYARD_TEST_FUSE_BACKEND=fuse",
        },
        "database": {
            "name": args.database_name,
            "server_version": bounded(args.pg_version, 40),
        },
        "preflight": {
            "dev_fuse": bounded(args.dev_fuse),
            "unshare": bounded(args.unshare_status),
            "bwrap": bounded(args.bwrap_status),
            "fusermount3": bounded(args.fusermount_version),
        },
        "runner": {
            "os": bounded(platform.platform()),
            "kernel": bounded(os.uname().release),
            "python": platform.python_version(),
        },
        "raw_unittest_output_retained": False,
        "database_url_retained": False,
        "scope": SCOPE,
        "generated_unix": int(time.time()),
    }

    output = Path(args.output)
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_name(output.name + ".tmp")
        temporary.write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, output)
    except OSError as error:
        print(
            "fuse compat receipt could not be written: "
            + type(error).__name__,
            file=sys.stderr,
        )
        return 2

    print(
        "fuse compat receipt: "
        f"{status} ({classification}); tests_run={parsed['tests_run']} "
        f"skipped={parsed['skipped']} failures={parsed['failures']} "
        f"errors={parsed['errors']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
