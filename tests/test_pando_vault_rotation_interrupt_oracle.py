#!/usr/bin/env python3
"""Pure oracle tests for the interrupted rotation checkpoint contract.

No Vault, PostgreSQL, CLI, subprocess or live I/O is involved.  The expected
target set is an explicit pre-rotation pack set, exactly as the real selector
snapshots manifests.  Foreign, duplicate and count-inconsistent IDs are refused.
"""
from __future__ import annotations

from pathlib import Path
import sys
import unittest

TESTS = Path(__file__).resolve().parent
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

import pando_vault_rotation_cases as cases  # noqa: E402
import pando_vault_rotation_support as support  # noqa: E402

A = "11111111-1111-4111-8111-111111111111"
B = "22222222-2222-4222-8222-222222222222"
C = "33333333-3333-4333-8333-333333333333"


def checkpoint(targets, completed, failed):
    return {
        "target_pack_ids": list(targets),
        "completed_pack_ids": list(completed),
        "failed_pack_id": failed,
    }


def report(total, completed):
    return {
        "rotation_total_packs": total,
        "rotation_completed_packs": completed,
    }


class InterruptCheckpointOracleTest(unittest.TestCase):
    def test_current_valid_checkpoint_target_completed_failed_set_is_accepted(self):
        result = cases.validate_interrupt_checkpoint(
            checkpoint([A, B], [A], B), [A, B], report(2, 1))
        self.assertEqual(result["targets"], [A, B])
        self.assertEqual(result["completed"], [A])
        self.assertEqual(result["failed"], B)
        self.assertEqual(result["remaining"], [B])

    def test_foreign_completed_id_is_rejected(self):
        with self.assertRaises(support.QualificationError) as caught:
            cases.validate_interrupt_checkpoint(
                checkpoint([A, B], [C], B), [A, B])
        self.assertEqual(caught.exception.code, "rotation_completed_foreign")

    def test_foreign_failed_id_is_rejected(self):
        with self.assertRaises(support.QualificationError) as caught:
            cases.validate_interrupt_checkpoint(
                checkpoint([A, B], [A], C), [A, B])
        self.assertEqual(caught.exception.code, "rotation_failed_foreign")

    def test_failed_id_that_is_completed_is_rejected(self):
        with self.assertRaises(support.QualificationError) as caught:
            cases.validate_interrupt_checkpoint(
                checkpoint([A, B], [A], A), [A, B])
        self.assertEqual(caught.exception.code, "rotation_failed_completed")

    def test_duplicate_target_id_is_rejected(self):
        with self.assertRaises(support.QualificationError) as caught:
            cases.validate_interrupt_checkpoint(
                checkpoint([A, B, B], [A], B), [A, B])
        self.assertEqual(caught.exception.code, "rotation_target_duplicate")

    def test_duplicate_completed_id_is_rejected(self):
        with self.assertRaises(support.QualificationError) as caught:
            cases.validate_interrupt_checkpoint(
                checkpoint([A, B], [A, A], B), [A, B])
        self.assertEqual(caught.exception.code, "rotation_completed_duplicate")

    def test_completed_count_must_be_exactly_one_for_existing_source(self):
        with self.assertRaises(support.QualificationError) as caught:
            cases.validate_interrupt_checkpoint(
                checkpoint([A, B], [A, B], B), [A, B])
        self.assertEqual(caught.exception.code, "rotation_completed_count_invalid")

    def test_target_set_must_match_actual_pre_interruption_pack_set(self):
        with self.assertRaises(support.QualificationError) as caught:
            cases.validate_interrupt_checkpoint(
                checkpoint([A, C], [A], C), [A, B])
        self.assertEqual(caught.exception.code, "rotation_target_set_mismatch")

    def test_report_total_count_must_match_checkpoint_targets(self):
        with self.assertRaises(support.QualificationError) as caught:
            cases.validate_interrupt_checkpoint(
                checkpoint([A, B], [A], B), [A, B], report(1, 1))
        self.assertEqual(caught.exception.code, "rotation_total_count_inconsistent")

    def test_report_completed_count_must_match_checkpoint_completed(self):
        with self.assertRaises(support.QualificationError) as caught:
            cases.validate_interrupt_checkpoint(
                checkpoint([A, B], [A], B), [A, B], report(2, 2))
        self.assertEqual(caught.exception.code,
                         "rotation_completed_count_inconsistent")


if __name__ == "__main__":
    unittest.main()
