#!/usr/bin/env python3
"""Pure receipt-shape tests for the issue #21 Vault qualification gate.

No product binary, Vault, PostgreSQL, Docker, Git fixture, network, compiler,
Cargo or CI is used.  A temporary executable-shaped file and receipt-shaped
file stand in only so the shared validator can be reached with mocked receipt
contents.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest import mock

TESTS = Path(__file__).resolve().parent
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

import pando_vault_rotation as main  # noqa: E402
import pando_vault_rotation_support as support  # noqa: E402

COMMIT = "a" * 40
TREE = "c" * 40
ENVIRONMENT = {"ROOTYARD_TEST_DATABASE_URL": "postgresql://u:p@127.0.0.1/db"}


def validated_v2(binary_sha, commit=COMMIT, artifacts=None):
    if artifacts is None:
        artifacts = (
            {
                "kind": "bin",
                "target": "rootyard",
                "executable_sha256": binary_sha,
            },
            {
                "kind": "bin",
                "target": "rootyard-pando-lab",
                "executable_sha256": binary_sha,
            },
        )
    return SimpleNamespace(
        schema="v2",
        payload={"receipt_schema": main.receipts.RECEIPT_SCHEMA_V2},
        artifacts=artifacts,
        binary_sha256=binary_sha,
        workspace_commit=commit,
        receipt_sha256="b" * 64,
    )


def validated_v1(binary_sha, commit=COMMIT, artifacts=None):
    if artifacts is None:
        # The accepted legacy shape: a ROOTYARD primary receipt that also
        # lists a secondary Pando artifact row without an executable digest.
        artifacts = (
            {"kind": "bin", "target": "rootyard", "fresh": False},
            {"kind": "bin", "target": "rootyard-pando-lab", "fresh": False},
        )
    return SimpleNamespace(
        schema="v1",
        payload={"version": 1},
        artifacts=artifacts,
        binary_sha256=binary_sha,
        workspace_commit=commit,
        receipt_sha256="b" * 64,
    )


class ReceiptV2GateTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.binary = self.root / "rootyard-pando-lab"
        self.binary.write_bytes(b"not-a-real-product-binary")
        self.binary.chmod(0o755)
        self.receipt = self.root / "receipt.json"
        self.receipt.write_text("{}")
        self.report = self.root / "report.json"
        self.binary_sha = support.sha256_file(self.binary)

    def args(self):
        return main.parse_args([
            "--binary", str(self.binary),
            "--receipt", str(self.receipt),
            "--source-root", str(self.root),
            "--expected-commit", COMMIT,
            "--report", str(self.report),
        ])

    def validate(self, validated):
        with mock.patch.object(main, "_source_state", return_value={
                "commit": COMMIT, "tree": TREE, "clean": True}), \
             mock.patch.object(main.receipts, "load_receipt",
                               return_value=validated), \
             mock.patch.object(main.shutil, "which",
                               return_value="/usr/bin/tool"):
            return main.validate_inputs(self.args(), ENVIRONMENT)

    def reject(self, validated, code):
        with self.assertRaises(support.QualificationError) as caught:
            self.validate(validated)
        self.assertEqual(caught.exception.code, code)

    def test_v1_rootyard_primary_with_secondary_pando_row_is_rejected(self):
        # The primary binary digest matches the selected executable, but the
        # legacy secondary Pando row carries no per-artifact digest or path.
        self.reject(validated_v1(self.binary_sha), "receipt_pando_receipt_not_v2")

    def test_v1_without_secondary_row_is_still_rejected(self):
        self.reject(
            validated_v1(self.binary_sha,
                         artifacts=({"kind": "bin", "target": "rootyard"},)),
            "receipt_pando_receipt_not_v2",
        )

    def test_v1_rejection_precedes_context_and_owned_resources(self):
        context = mock.patch.object(main, "Context").start()
        self.addCleanup(mock.patch.stopall)
        with mock.patch.object(main, "_source_state", return_value={
                "commit": COMMIT, "tree": TREE, "clean": True}), \
             mock.patch.object(main.receipts, "load_receipt",
                               return_value=validated_v1(self.binary_sha)), \
             mock.patch.object(main.shutil, "which",
                               return_value="/usr/bin/tool"):
            report = main.run_qualification(self.args(), ENVIRONMENT)
        context.assert_not_called()
        self.assertFalse(report["passed"])
        self.assertEqual(report["error_code"], "receipt_pando_receipt_not_v2")
        self.assertEqual(report["case_count"], 5)
        self.assertTrue(all(case["status"] == "failed"
                            for case in report["cases"]))
        self.assertTrue(self.report.is_file())

    def test_valid_v2_pando_artifact_is_accepted(self):
        inputs = self.validate(validated_v2(self.binary_sha))
        self.assertEqual(inputs["binary_sha256"], self.binary_sha)
        self.assertEqual(inputs["source_commit"], COMMIT)
        self.assertEqual(inputs["source_tree"], TREE)
        self.assertIs(inputs["source_clean"], True)
        self.assertEqual(inputs["receipt_sha256"], "b" * 64)

    def test_v2_pando_executable_digest_must_equal_actual_binary(self):
        self.reject(
            validated_v2(self.binary_sha, artifacts=({
                "kind": "bin",
                "target": "rootyard-pando-lab",
                "executable_sha256": "0" * 64,
            },)),
            "receipt_pando_artifact_mismatch",
        )

    def test_v2_pando_row_without_executable_digest_is_rejected(self):
        self.reject(
            validated_v2(self.binary_sha, artifacts=({
                "kind": "bin",
                "target": "rootyard-pando-lab",
            },)),
            "receipt_pando_artifact_mismatch",
        )

    def test_v2_missing_pando_row_is_rejected(self):
        self.reject(
            validated_v2(self.binary_sha,
                         artifacts=({"kind": "bin", "target": "rootyard"},)),
            "receipt_pando_artifact_missing",
        )

    def test_v2_ambiguous_pando_rows_are_rejected(self):
        row = {
            "kind": "bin",
            "target": "rootyard-pando-lab",
            "executable_sha256": self.binary_sha,
        }
        self.reject(validated_v2(self.binary_sha, artifacts=(row, dict(row))),
                    "receipt_pando_artifact_ambiguous")

    def test_v2_receipt_schema_constant_must_match(self):
        validated = validated_v2(self.binary_sha)
        validated.payload = {"receipt_schema": "rootyard/native-build-receipt/v1"}
        self.reject(validated, "receipt_pando_schema_mismatch")

    def test_v2_missing_payload_is_rejected(self):
        validated = validated_v2(self.binary_sha)
        validated.payload = None
        self.reject(validated, "receipt_pando_schema_mismatch")


if __name__ == "__main__":
    unittest.main()
