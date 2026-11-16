"""Offline contract tests for the Issue #85 literal acceptance runner.

These tests are pure: they execute no service, database, Git, LFS, network or
Cargo operation.  They lock the checkpoint case inventory, the fixed report
detail allowlist, the no-skip summary semantics and the canonical receipt
selection order.
"""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import repository_lifecycle_acceptance_support as support


class AcceptanceContractTest(unittest.TestCase):
    def test_checkpoint_inventory_is_exact(self):
        self.assertEqual(
            support.PLAN_CASE_NAMES,
            (
                "backup_root_blocks_purge",
                "serving_read_header_blocks_purge",
                "ci_pin_blocks_purge",
            ),
        )

    def test_safe_detail_drops_unknown_nested_and_unsafe_values(self):
        detail = support.safe_detail(
            {
                "fixture": "migration148_retention_metadata",
                "fixture_scope": "metadata_only",
                "hold_count": 1,
                "not_in_allowlist": True,
                "nested": {"sql": "SELECT 1"},
                "too_long": "x" * 200,
                "path_like": "/tmp/secret",
                "negative": -1,
            }
        )
        self.assertEqual(
            detail,
            {
                "fixture": "migration148_retention_metadata",
                "fixture_scope": "metadata_only",
                "hold_count": 1,
            },
        )

    def test_failure_is_a_failure_not_a_skip(self):
        results = [
            {
                "name": "backup_root_blocks_purge",
                "status": "failed",
                "phase": "blocked_purge",
                "error_class": "assertion",
                "seconds": 0.1,
                "detail": {},
            },
            {
                "name": "serving_read_header_blocks_purge",
                "status": "passed",
                "phase": "control_purge",
                "error_class": None,
                "seconds": 0.2,
                "detail": {},
            },
            {
                "name": "ci_pin_blocks_purge",
                "status": "passed",
                "phase": "control_purge",
                "error_class": None,
                "seconds": 0.3,
                "detail": {},
            },
        ]
        summary = support.summarize(
            results,
            support.PLAN_CASE_NAMES,
            cleanup_ok=True,
            binding_ok=True,
        )
        self.assertFalse(summary["passed"])
        self.assertTrue(summary["exact"])
        self.assertEqual(summary["missing"], [])
        self.assertEqual(summary["unexpected"], [])

    def test_missing_and_unexpected_cases_fail_exact_inventory(self):
        results = [
            {
                "name": "backup_root_blocks_purge",
                "status": "passed",
                "phase": "control_purge",
                "error_class": None,
                "seconds": 0.1,
                "detail": {},
            },
            {
                "name": "unexpected_case",
                "status": "passed",
                "phase": "control_purge",
                "error_class": None,
                "seconds": 0.1,
                "detail": {},
            },
        ]
        summary = support.summarize(
            results,
            support.PLAN_CASE_NAMES,
            cleanup_ok=True,
            binding_ok=True,
        )
        self.assertFalse(summary["passed"])
        self.assertFalse(summary["exact"])
        self.assertEqual(len(summary["missing"]), 2)
        self.assertEqual(summary["unexpected"], ["unexpected_case"])

    def test_error_classes_are_fixed_and_message_free(self):
        self.assertEqual(support.classify_error(AssertionError("secret")), "assertion")
        self.assertEqual(
            support.classify_error(subprocess.TimeoutExpired(["git"], 1)), "timeout"
        )
        self.assertEqual(
            support.classify_error(subprocess.CalledProcessError(1, ["git"])), "command"
        )
        self.assertEqual(
            support.classify_error(json.JSONDecodeError("x", "", 0)), "decode"
        )
        self.assertEqual(support.classify_error(TimeoutError()), "timeout")
        self.assertEqual(support.classify_error(OSError()), "io")
        self.assertEqual(support.classify_error(RuntimeError("secret")), "other")

    def test_receipt_selection_order(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "rootyard"
            binary.write_bytes(b"binary")
            explicit = root / "explicit.json"
            explicit.write_text("{}")
            adjacent = root / "rootyard.build.json"
            adjacent.write_text("{}")

            chosen, origin = support.select_receipt(binary, explicit, {})
            self.assertEqual((chosen, origin), (explicit, "cli"))

            chosen, origin = support.select_receipt(
                binary, None, {"ROOTYARD_BUILD_RECEIPT": str(adjacent)}
            )
            self.assertEqual((chosen, origin), (adjacent, "environment"))

            chosen, origin = support.select_receipt(binary, None, {})
            self.assertEqual(
                (chosen, origin),
                (Path(binary).resolve().with_suffix(".build.json"), "adjacent"),
            )


if __name__ == "__main__":
    unittest.main()
