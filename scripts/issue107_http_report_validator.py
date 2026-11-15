#!/usr/bin/env python3
"""Strict standalone validation of the four fixed issue107 HTTP reports.

Consumes existing reports and a prebuilt sealed standalone CLI/receipt only.
It never invokes Cargo/rustc, a native test binary, Git, HTTP, PostgreSQL or a
Blob provider.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import http_report_contract as contract  # noqa: E402
import native_build_receipt as receipts  # noqa: E402

SHA256 = re.compile(r"^[0-9a-f]{64}$")
SAFE_INPUT_KEYS = frozenset(contract.INPUT_PATHS)


class ValidationError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _fail(code):
    raise ValidationError(code)


def _require(condition, code):
    if not condition:
        _fail(code)


def _sha(value):
    return isinstance(value, str) and SHA256.fullmatch(value) is not None


def _pairs(values, flag):
    result = {}
    for value in values or []:
        name, separator, item = str(value).partition("=")
        _require(bool(separator and name and item), "invalid_" + flag)
        _require(name not in result, "duplicate_" + flag)
        result[name] = item
    return result


def _cli_identity(binary, receipt, source_root, source_head):
    validated = receipts.load_receipt(
        receipt,
        source_root=source_root,
        binary_path=binary,
        expected_commit=source_head,
        verify_source_files=True,
    )
    toolchain = validated.toolchain or {}
    rustc = toolchain.get("rustc") if isinstance(toolchain, dict) else None
    rustc_version = rustc.get("version") if isinstance(rustc, dict) else None
    return {
        "schema": validated.schema,
        "binary_sha256": validated.binary_sha256,
        "source_inputs_sha256": validated.source_inputs_sha256,
        "workspace_commit": validated.workspace_commit,
        "config_digest": validated.config_digest,
        "receipt_sha256": validated.receipt_sha256,
        "rustc_version": rustc_version,
    }


def _validate_inputs(report, suite, cli, expected_input_hashes):
    mapping = report.get("harness_inputs_sha256")
    _require(isinstance(mapping, dict), "missing_harness_inputs")
    _require(set(mapping) == SAFE_INPUT_KEYS, "harness_input_closure_mismatch")
    _require(all(_sha(value) for value in mapping.values()), "invalid_harness_input_hash")
    _require(mapping == expected_input_hashes, "harness_input_drift")
    direct = mapping.get(suite["source"])
    _require(direct is not None and report.get("checkpoint_sha256") == direct, "checkpoint_input_mismatch")
    envelope = report.get("harness_inputs")
    _require(isinstance(envelope, dict) and envelope.get("input_hashes") == mapping,
             "harness_input_envelope_mismatch")
    _require(envelope.get("before_sha256") == expected_input_hashes,
             "harness_input_before_mismatch")
    _require(report.get("harness_sha256") == mapping.get("tests/blob_only_service.py"),
             "harness_sha_mismatch")


def _validate_report(report, suite, source_head, cli, expected_input_hashes):
    _require(isinstance(report, dict), "report_not_object")
    _require(report.get("kind") == suite["kind"], "wrong_report_kind")
    _require(report.get("passed") is True, "report_not_passed")
    _require(report.get("measurement_kind") == "native_execution", "not_native_execution")
    _require(report.get("simulated_fields") is False, "simulated_evidence")
    _require(report.get("qualification_kind") == "clean-candidate", "not_clean_candidate")
    _require(report.get("inputs_unchanged") is True, "inputs_changed")
    _require("binding_error" not in report and "failure_traceback" not in report, "report_binding_error")
    _require(report.get("source_head") == source_head, "wrong_source_head")
    _require(report.get("binary_sha256") == cli["binary_sha256"], "wrong_cli_binary")
    _require(report.get("source_inputs_sha256") == cli["source_inputs_sha256"], "wrong_source_inputs")
    _require(_sha(report.get("git_sha256")), "missing_git_identity")
    profile = report.get("native_profile")
    _require(isinstance(profile, dict) and profile.get("attested") is True, "missing_native_profile")
    _require(profile.get("receipt_schema") == cli["schema"], "wrong_receipt_schema")
    _require(profile.get("binary_sha256") == cli["binary_sha256"], "wrong_profile_binary")
    _require(profile.get("source_inputs_sha256") == cli["source_inputs_sha256"], "wrong_profile_source")
    _require(profile.get("config_digest") == cli["config_digest"], "wrong_profile_config")
    _require(profile.get("workspace_commit") == source_head, "wrong_profile_commit")
    _require(profile.get("build_receipt_sha256") == cli["receipt_sha256"], "wrong_build_receipt")
    if cli["rustc_version"] is not None:
        _require(profile.get("rustc") == cli["rustc_version"], "wrong_toolchain")
    blob_profile = report.get("blob_profile")
    _require(isinstance(blob_profile, dict), "missing_blob_profile")
    _require(blob_profile.get("driver") == "opendal", "wrong_blob_driver")
    _require(blob_profile.get("service") == "s3", "wrong_blob_service")
    _require(blob_profile.get("endpoint_loopback") is True, "wrong_blob_loopback")
    _require(blob_profile.get("delete_policy") == "disabled", "wrong_blob_delete_policy")
    _validate_inputs(report, suite, cli, expected_input_hashes)
    expected_cases = list(suite["cases"])
    cases = report.get("cases")
    _require(isinstance(cases, list), "missing_cases")
    _require(report.get("expected_cases") == expected_cases, "wrong_expected_cases")
    _require([case.get("name") for case in cases if isinstance(case, dict)] == expected_cases,
             "case_inventory_mismatch")
    _require(len(cases) == len(expected_cases), "case_count_mismatch")
    case_count = report.get("case_count")
    expected_count = report.get("expected_count")
    skips = report.get("skips")
    _require(isinstance(case_count, int) and not isinstance(case_count, bool)
             and case_count == len(expected_cases), "case_count_field_mismatch")
    _require(isinstance(expected_count, int) and not isinstance(expected_count, bool)
             and expected_count == len(expected_cases), "expected_count_mismatch")
    _require(isinstance(skips, int) and not isinstance(skips, bool) and skips == 0,
             "skipped_cases")
    _require(report.get("pending_cases") == [], "pending_cases")
    _require("partial" not in report, "partial_report")
    _require("preflight_failed" not in report, "preflight_failed")
    for case in cases:
        _require(isinstance(case, dict), "invalid_case")
        _require(case.get("status") == "passed", "case_not_passed")
        _require("error" not in case and "trace" not in case, "case_failure_evidence")
    return len(cases)


def validate_reports(
    reports,
    *,
    source_head,
    cli,
    source_root=None,
    expected_input_hashes=None,
    verify_sources=True,
):
    _require(isinstance(reports, dict), "missing_reports")
    expected_names = [suite["report"] for suite in contract.EXPECTED_SUITES]
    _require(set(reports) == set(expected_names), "report_set_mismatch")
    if expected_input_hashes is None:
        _require(source_root is not None, "missing_source_root")
        try:
            expected_input_hashes = contract.hash_inputs(source_root)
        except contract.ContractError:
            _fail("harness_input_closure_unavailable")
    _require(set(expected_input_hashes) == SAFE_INPUT_KEYS, "harness_input_closure_mismatch")
    if verify_sources:
        _require(source_root is not None, "missing_source_root")
        try:
            actual = contract.hash_inputs(source_root)
        except contract.ContractError:
            _fail("harness_input_closure_unavailable")
        _require(actual == expected_input_hashes, "harness_input_drift")
    total = 0
    for suite in contract.EXPECTED_SUITES:
        source = reports[suite["report"]]
        if isinstance(source, dict):
            report = source
        else:
            try:
                report = json.loads(Path(source).read_text())
            except Exception:
                _fail("report_unreadable")
        total += _validate_report(report, suite, source_head, cli, expected_input_hashes)
    _require(total == contract.EXPECTED_CASE_COUNT, "total_case_count_mismatch")
    return {"suites": len(contract.EXPECTED_SUITES), "cases": total}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-head", required=True)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--cli-binary", required=True)
    parser.add_argument("--cli-receipt", required=True)
    parser.add_argument("--report", action="append", default=[], metavar="NAME=PATH")
    args = parser.parse_args(argv)
    try:
        reports = _pairs(args.report, "report")
        _require(len(reports) == len(contract.EXPECTED_SUITES), "report_set_mismatch")
        cli = _cli_identity(args.cli_binary, args.cli_receipt, args.source_root, args.source_head)
        result = validate_reports(
            reports, source_head=args.source_head, cli=cli,
            source_root=args.source_root, verify_sources=True)
    except ValidationError as error:
        print(json.dumps({"validated": False, "error": error.code}), file=sys.stderr)
        return 1
    except receipts.ReceiptError:
        print(json.dumps({"validated": False, "error": "cli_receipt_invalid"}), file=sys.stderr)
        return 1
    except Exception:
        print(json.dumps({"validated": False, "error": "validation_failed"}), file=sys.stderr)
        return 1
    print(json.dumps({"validated": True, **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
