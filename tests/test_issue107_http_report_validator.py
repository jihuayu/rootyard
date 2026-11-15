#!/usr/bin/env python3
"""Pure mutation tests for the fixed issue107 HTTP report validator."""
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "scripts", ROOT / "tests"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
import http_report_contract as contract  # noqa: E402
import issue107_http_report_validator as validator  # noqa: E402

SHA = "a" * 64
BINARY = "b" * 64
SOURCE = "c" * 64
CONFIG = "d" * 64
RECEIPT = "e" * 64
GIT = "f" * 64
HEAD = "1" * 40
INPUT_HASHES = {path: SHA for path in contract.INPUT_PATHS}
CLI = {
    "schema": "v2",
    "binary_sha256": BINARY,
    "source_inputs_sha256": SOURCE,
    "workspace_commit": HEAD,
    "config_digest": CONFIG,
    "receipt_sha256": RECEIPT,
    "rustc_version": "rustc-test",
}


def suite_reports():
    reports = {}
    for suite in contract.EXPECTED_SUITES:
        cases = [{"name": name, "status": "passed"} for name in suite["cases"]]
        reports[suite["report"]] = {
            "kind": suite["kind"],
            "passed": True,
            "measurement_kind": "native_execution",
            "simulated_fields": False,
            "qualification_kind": "clean-candidate",
            "inputs_unchanged": True,
            "source_head": HEAD,
            "source_inputs_sha256": SOURCE,
            "binary_sha256": BINARY,
            "git_sha256": GIT,
            "harness_sha256": SHA,
            "checkpoint_sha256": INPUT_HASHES[suite["source"]],
            "harness_inputs_sha256": dict(INPUT_HASHES),
            "harness_inputs": {
                "before_sha256": dict(INPUT_HASHES),
                "input_hashes": dict(INPUT_HASHES),
            },
            "native_profile": {
                "attested": True,
                "receipt_schema": "v2",
                "binary_sha256": BINARY,
                "source_inputs_sha256": SOURCE,
                "config_digest": CONFIG,
                "workspace_commit": HEAD,
                "rustc": "rustc-test",
                "build_receipt_sha256": RECEIPT,
            },
            "blob_profile": {
                "driver": "opendal",
                "service": "s3",
                "endpoint_loopback": True,
                "delete_policy": "disabled",
            },
            "expected_cases": list(suite["cases"]),
            "cases": cases,
            "case_count": len(cases),
            "expected_count": len(cases),
            "skips": 0,
            "pending_cases": [],
        }
    return reports


class ValidatorMutationTests(unittest.TestCase):
    def assert_code(self, reports, code):
        with self.assertRaises(validator.ValidationError) as raised:
            validator.validate_reports(
                reports, source_head=HEAD, cli=CLI,
                expected_input_hashes=dict(INPUT_HASHES), verify_sources=False)
        self.assertEqual(raised.exception.code, code)

    def test_valid_synthetic_inventory(self):
        result = validator.validate_reports(
            suite_reports(), source_head=HEAD, cli=CLI,
            expected_input_hashes=dict(INPUT_HASHES), verify_sources=False)
        self.assertEqual(result, {"suites": 4, "cases": 13})

    def test_missing_extra_duplicate_reorder_cases(self):
        base = suite_reports()
        missing = copy.deepcopy(base)
        missing["snapshot"]["cases"].pop()
        self.assert_code(missing, "case_inventory_mismatch")
        extra = copy.deepcopy(base)
        extra["roots"]["cases"].append({"name": "cleanup", "status": "failed"})
        extra["roots"]["case_count"] = 2
        extra["roots"]["expected_count"] = 2
        self.assert_code(extra, "case_inventory_mismatch")
        duplicate = copy.deepcopy(base)
        duplicate["cancel-scope-race"]["cases"][1] = copy.deepcopy(
            duplicate["cancel-scope-race"]["cases"][0])
        self.assert_code(duplicate, "case_inventory_mismatch")
        reordered = copy.deepcopy(base)
        reordered["snapshot"]["cases"][0], reordered["snapshot"]["cases"][1] = (
            reordered["snapshot"]["cases"][1], reordered["snapshot"]["cases"][0])
        self.assert_code(reordered, "case_inventory_mismatch")

    def test_missing_report_and_wrong_kind(self):
        reports = suite_reports()
        reports.pop("root-browse")
        self.assert_code(reports, "report_set_mismatch")
        wrong = suite_reports()
        wrong["roots"]["kind"] = "wrong/kind"
        self.assert_code(wrong, "wrong_report_kind")

    def test_case_failure_and_unresolved_inputs(self):
        wrong = suite_reports()
        wrong["roots"]["cases"][0]["status"] = "failed"
        self.assert_code(wrong, "case_not_passed")
        wrong = suite_reports()
        wrong["roots"]["inputs_unchanged"] = False
        self.assert_code(wrong, "inputs_changed")
        wrong = suite_reports()
        wrong["roots"]["partial"] = True
        self.assert_code(wrong, "partial_report")

    def test_wrong_source_binary_receipt_config_profile(self):
        wrong = suite_reports(); wrong["snapshot"]["source_head"] = "0" * 40
        self.assert_code(wrong, "wrong_source_head")
        wrong = suite_reports(); wrong["snapshot"]["binary_sha256"] = "0" * 64
        self.assert_code(wrong, "wrong_cli_binary")
        wrong = suite_reports(); wrong["snapshot"]["native_profile"]["build_receipt_sha256"] = "0" * 64
        self.assert_code(wrong, "wrong_build_receipt")
        wrong = suite_reports(); wrong["snapshot"]["native_profile"]["config_digest"] = "0" * 64
        self.assert_code(wrong, "wrong_profile_config")
        wrong = suite_reports(); wrong["snapshot"]["blob_profile"]["service"] = "fs"
        self.assert_code(wrong, "wrong_blob_service")

    def test_changed_input_skipped_pending_failed_and_simulated(self):
        wrong = suite_reports()
        wrong["root-browse"]["harness_inputs_sha256"]["tests/blob_only_service.py"] = "0" * 64
        self.assert_code(wrong, "harness_input_drift")
        wrong = suite_reports(); wrong["roots"]["skips"] = 1
        self.assert_code(wrong, "skipped_cases")
        wrong = suite_reports(); wrong["roots"]["pending_cases"] = ["pending"]
        self.assert_code(wrong, "pending_cases")
        wrong = suite_reports(); wrong["roots"]["passed"] = False
        self.assert_code(wrong, "report_not_passed")
        wrong = suite_reports(); wrong["roots"]["simulated_fields"] = True
        self.assert_code(wrong, "simulated_evidence")
        wrong = suite_reports(); wrong["roots"]["measurement_kind"] = "source"
        self.assert_code(wrong, "not_native_execution")
        wrong = suite_reports(); wrong["roots"]["binding_error"] = "input changed"
        self.assert_code(wrong, "report_binding_error")


if __name__ == "__main__":
    unittest.main()
