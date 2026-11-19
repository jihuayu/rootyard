#!/usr/bin/env python3
"""Run the two reviewed #42 private slot-one handoff native cases serially.

The workflow owns one preflighted immutable #174 libtest, one run-owned
PostgreSQL database and one dedicated Blob prefix.  This module does not build,
provision or clean those resources.  It reuses the exact single-case runner for
each selector, one at a time because the fixture changes the cluster authority,
and writes one closed manifest plus one closed report per case.

No child stdout/stderr, database URL, credential or full runtime path is kept
or printed.  The per-case report uses a fixed anonymous libtest label.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from types import SimpleNamespace

SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
import refstore_issue42_slot_one_checkpoint as checkpoint  # noqa: E402

CASES = (
    "ref_store::pg::slot_one::tests::native::gateway::"
    "slot_one_handoff_commits_fresh_private_attempt_on_real_a3_a4_a5",
    "ref_store::pg::slot_one::tests::native::gateway::"
    "slot_one_handoff_revoked_fresh_rolls_back_and_replays_after_later_gate",
)
REPORTS = (
    "slot-one-handoff-fresh.json",
    "slot-one-handoff-replay.json",
)
CASE_SCHEMA = "rootyard/refstore-issue42-slot-one-handoff-case/v1"
MANIFEST_SCHEMA = "rootyard/refstore-issue42-slot-one-handoff-qualification/v1"
LIB_LABEL = "preflighted-#174-libtest"
ISSUE = 42
PROBE_COUNT = 2

if len(CASES) != PROBE_COUNT or len(REPORTS) != PROBE_COUNT:
    raise RuntimeError("slot-one handoff probe inventory is not exactly two")

CASE_FIELDS = (
    "case", "report_label", "result", "probe_count", "ran", "passed",
    "failed", "ignored", "complete", "error_class", "selection",
)
MANIFEST_FIELDS = (
    "schema", "issue", "expected_commit", "head", "tree",
    "source_inputs_sha256", "lib_test_support_inputs_sha256",
    "receipt_sha256", "binary_sha256", "lib_label", "preflight_sha256",
    "probe_count", "cases", "result", "error_class",
)
ATTESTATION_FIELDS = MANIFEST_FIELDS[2:11]
REPORT_ATTESTATION_FIELDS = tuple(
    "lib_alias" if key == "lib_label" else key for key in ATTESTATION_FIELDS)
CASE_ERROR_CLASSES = frozenset(
    set(checkpoint.ERROR_CLASSES) | {"setup", "report_invalid", "attestation_mismatch"})
MANIFEST_ERROR_CLASSES = frozenset(
    set(CASE_ERROR_CLASSES) | {"probe_count", "manifest"})
SAFE_LABEL = re.compile(r"^[A-Za-z0-9._#-]{1,64}$")

checkpoint_failed = checkpoint.CheckpointError


def _closed_failure(case, label, error_class):
    return {
        "case": case,
        "report_label": label,
        "result": "failed",
        "probe_count": 1,
        "ran": 0,
        "passed": 0,
        "failed": 1,
        "ignored": 0,
        "complete": False,
        "error_class": error_class,
        "selection": "unavailable",
    }


def _case_record(report, label):
    return {
        "case": report["case"],
        "report_label": label,
        "result": report["result"],
        "probe_count": 1,
        "ran": report["ran"],
        "passed": report["passed"],
        "failed": report["failed"],
        "ignored": report["ignored"],
        "complete": report["complete"],
        "error_class": report["error_class"],
        "selection": report["selection"],
    }


def _attestation(report):
    return {
        key: report[report_key]
        for key, report_key in zip(ATTESTATION_FIELDS, REPORT_ATTESTATION_FIELDS)
    }


def _same_attestation(expected, report):
    actual = _attestation(report)
    return all(expected.get(key) == actual.get(key) for key in ATTESTATION_FIELDS)


def _read_report(path):
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    return payload


def _case_args(args, case, report):
    return SimpleNamespace(
        lib=args.lib,
        receipt=args.receipt,
        preflight=args.preflight,
        workspace=args.workspace,
        expected_commit=args.expected_commit,
        case=case,
        report_schema=CASE_SCHEMA,
        lib_alias_label=LIB_LABEL,
        report=str(report),
        timeout=args.timeout,
        stdout_limit=args.stdout_limit,
    )


def run_qualification(args, run_checkpoint=None):
    """Run both cases serially and return the validated closed manifest."""
    runner = checkpoint.run_checkpoint if run_checkpoint is None else run_checkpoint
    attestation = checkpoint.build_attestation(
        args.lib, args.receipt, args.preflight, args.workspace,
        args.expected_commit, schema=CASE_SCHEMA, case=CASES[0])
    checkpoint.apply_lib_alias_label(attestation, LIB_LABEL)
    attestation = _attestation(attestation)
    report_dir = Path(args.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    records = []
    for case, label in zip(CASES, REPORTS):
        report_path = report_dir / label
        try:
            report_path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            records.append(_closed_failure(case, label, "setup"))
            continue
        candidate = None
        try:
            candidate = runner(_case_args(args, case, report_path))
        except Exception:
            candidate = None
        if candidate is None:
            candidate = _read_report(report_path)
        if candidate is None:
            records.append(_closed_failure(case, label, "setup"))
            continue
        try:
            checkpoint.validate_report(candidate, schema=CASE_SCHEMA, case=case)
        except checkpoint_failed:
            records.append(_closed_failure(case, label, "report_invalid"))
            continue
        if not _same_attestation(attestation, candidate):
            records.append(_closed_failure(case, label, "attestation_mismatch"))
            continue
        try:
            checkpoint.write_report(report_path, candidate)
        except OSError:
            records.append(_closed_failure(case, label, "setup"))
            continue
        records.append(_case_record(candidate, label))

    if len(records) != PROBE_COUNT or tuple(item["case"] for item in records) != CASES:
        raise checkpoint_failed("probe_count")
    result = "passed" if all(item["result"] == "passed" for item in records) else "failed"
    error_class = (
        None if result == "passed"
        else next(item["error_class"] for item in records if item["result"] == "failed")
    )
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "issue": ISSUE,
        **attestation,
        "probe_count": PROBE_COUNT,
        "cases": records,
        "result": result,
        "error_class": error_class,
    }
    validate_manifest(manifest)
    checkpoint.write_report(report_dir / "slot-one-handoff-qualification.json", manifest)
    return manifest


def validate_manifest(manifest):
    """Reject anything that is not the one closed qualification manifest."""
    if not isinstance(manifest, dict) or set(manifest) != set(MANIFEST_FIELDS):
        raise checkpoint_failed("manifest_shape")
    if manifest.get("schema") != MANIFEST_SCHEMA:
        raise checkpoint_failed("manifest_schema")
    if manifest.get("issue") != ISSUE:
        raise checkpoint_failed("manifest_issue")
    for key in ("expected_commit", "head"):
        value = manifest.get(key)
        if not isinstance(value, str) or checkpoint.COMMIT.fullmatch(value) is None:
            raise checkpoint_failed("manifest_" + key)
    if manifest["expected_commit"] != manifest["head"]:
        raise checkpoint_failed("manifest_head")
    if not isinstance(manifest.get("tree"), str) or checkpoint.TREE.fullmatch(manifest["tree"]) is None:
        raise checkpoint_failed("manifest_tree")
    for key in ("source_inputs_sha256", "lib_test_support_inputs_sha256",
                "receipt_sha256", "binary_sha256", "preflight_sha256"):
        value = manifest.get(key)
        if not isinstance(value, str) or checkpoint.HEX64.fullmatch(value) is None:
            raise checkpoint_failed("manifest_" + key)
    if not isinstance(manifest.get("lib_label"), str) or SAFE_LABEL.fullmatch(manifest["lib_label"]) is None:
        raise checkpoint_failed("manifest_lib_label")
    if manifest.get("probe_count") != PROBE_COUNT:
        raise checkpoint_failed("manifest_probe_count")
    cases = manifest.get("cases")
    if not isinstance(cases, list) or len(cases) != PROBE_COUNT:
        raise checkpoint_failed("manifest_cases")
    if tuple(item.get("case") for item in cases if isinstance(item, dict)) != CASES:
        raise checkpoint_failed("manifest_case_names")
    if tuple(item.get("report_label") for item in cases) != REPORTS:
        raise checkpoint_failed("manifest_report_labels")
    for item in cases:
        if not isinstance(item, dict) or set(item) != set(CASE_FIELDS):
            raise checkpoint_failed("manifest_case_shape")
        if item.get("result") not in ("passed", "failed"):
            raise checkpoint_failed("manifest_case_result")
        if item.get("probe_count") != 1:
            raise checkpoint_failed("manifest_case_probe")
        for key in ("ran", "passed", "failed", "ignored"):
            value = item.get(key)
            if not isinstance(value, int) or isinstance(value, bool) or value not in (0, 1):
                raise checkpoint_failed("manifest_case_" + key)
        if not isinstance(item.get("complete"), bool):
            raise checkpoint_failed("manifest_case_complete")
        if item.get("selection") not in ("unique", "unavailable"):
            raise checkpoint_failed("manifest_case_selection")
        error = item.get("error_class")
        if error is not None and (not isinstance(error, str) or error not in CASE_ERROR_CLASSES):
            raise checkpoint_failed("manifest_case_error")
        if item["complete"]:
            if (item["result"] != "passed" or item["ran"] != 1 or item["passed"] != 1
                    or item["failed"] != 0 or item["ignored"] != 0
                    or item["selection"] != "unique" or error is not None):
                raise checkpoint_failed("manifest_case_complete_inconsistent")
        elif (item["result"] != "failed" or item["passed"] != 0
              or item["failed"] != 1 or not error):
            raise checkpoint_failed("manifest_case_failure_inconsistent")
    result = manifest.get("result")
    error = manifest.get("error_class")
    if result not in ("passed", "failed"):
        raise checkpoint_failed("manifest_result")
    if error is not None and (not isinstance(error, str) or error not in MANIFEST_ERROR_CLASSES):
        raise checkpoint_failed("manifest_error")
    if result == "passed":
        if (error is not None or any(item["result"] != "passed" for item in cases)):
            raise checkpoint_failed("manifest_complete_inconsistent")
    elif error is None or not any(item["result"] == "failed" for item in cases):
        raise checkpoint_failed("manifest_failure_inconsistent")
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lib", required=True)
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--preflight", required=True)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--timeout", type=float,
                        default=checkpoint.DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--stdout-limit", type=int,
                        default=checkpoint.DEFAULT_STDOUT_LIMIT)
    args = parser.parse_args(argv)
    try:
        manifest = run_qualification(args)
    except checkpoint_failed as error:
        print("slot-one handoff qualification failed: " + str(error),
              file=sys.stderr)
        return 1
    except Exception as error:  # never echo child output or environment values
        print("slot-one handoff qualification failed: internal "
              + type(error).__name__, file=sys.stderr)
        return 1
    print("slot-one handoff qualification: " + manifest["result"]
          + " probes=" + str(manifest["probe_count"]))
    print("  head=" + manifest["head"] + " tree=" + manifest["tree"])
    print("  source_inputs_sha256=" + manifest["source_inputs_sha256"])
    print("  lib_test_support_inputs_sha256="
          + manifest["lib_test_support_inputs_sha256"])
    print("  binary_sha256=" + manifest["binary_sha256"])
    for item in manifest["cases"]:
        print("  " + item["case"] + " " + item["result"]
              + " passed=" + str(item["passed"])
              + " failed=" + str(item["failed"])
              + " ignored=" + str(item["ignored"]))
    return 0 if manifest["result"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
