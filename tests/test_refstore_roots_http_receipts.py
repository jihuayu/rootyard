#!/usr/bin/env python3
"""Pure behavior tests for the roots HTTP receipt lifecycle assertions.

These tests call the real ``RootsHttpHarness._assert_receipt`` and
``_assert_metadata`` methods on a minimal ``object.__new__`` instance. They do
not construct the Base harness, start the service, or need PostgreSQL, Git,
Blob/profile environment, or network access.
"""
from __future__ import annotations

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from refstore_roots_http import RootsHttpHarness  # noqa: E402

ROOT_ID = "11111111-1111-4111-8111-111111111111"
HEAD_OID = "a" * 40


def receipt(action, generation, receipt_state, replayed=False):
    return {
        "action": action,
        "root_id": ROOT_ID,
        "generation": generation,
        "replayed": replayed,
        "created_at_unix_micros": 1700000000000000,
        "receipt_only": True,
        "receipt_state": receipt_state,
    }


def metadata(current_state, generation):
    return {
        "root_id": ROOT_ID,
        "current_state": current_state,
        "generation": generation,
        "purpose": "ci",
        "selector_kind": "snapshot",
        "object_format": "sha1",
        "head_ref": "refs/heads/main",
        "head_oid": HEAD_OID,
        "ref_count": 1,
        "pack_count": 1,
        "oid_count": 1,
    }


class RootsReceiptLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.harness = object.__new__(RootsHttpHarness)

    def test_register_receipt_accepts_active_generation_one(self):
        self.harness._assert_receipt(receipt("register", 1, "active"), "register")

    def test_release_receipt_accepts_released_generation_two(self):
        self.harness._assert_receipt(receipt("release", 2, "released"), "release")

    def test_finite_expected_action_is_validated(self):
        with self.assertRaisesRegex(
                AssertionError, "receipt expected action is not in the finite source allowlist"):
            self.harness._assert_receipt(receipt("register", 1, "active"), "delete")

    def test_cross_action_generation_and_state_are_rejected(self):
        cases = (
            ("register generation", dict(receipt("register", 2, "active")),
             "register", "receipt generation differs"),
            ("register state", dict(receipt("register", 1, "released")),
             "register", "receipt state differs"),
            ("release generation", dict(receipt("release", 1, "released")),
             "release", "receipt generation differs"),
            ("release state", dict(receipt("release", 2, "active")),
             "release", "receipt state differs"),
            ("wrong action", dict(receipt("release", 1, "active")),
             "register", "receipt action differs"),
        )
        for label, data, expected_action, message in cases:
            with self.subTest(case=label):
                with self.assertRaisesRegex(AssertionError, message):
                    self.harness._assert_receipt(data, expected_action)

    def test_idempotent_replay_keeps_the_same_expected_action(self):
        for replayed in (False, True):
            with self.subTest(replayed=replayed, action="register"):
                register = receipt("register", 1, "active", replayed=replayed)
                self.harness._assert_receipt(register, "register")
                with self.assertRaisesRegex(AssertionError, "receipt action differs"):
                    self.harness._assert_receipt(register, "release")
            with self.subTest(replayed=replayed, action="release"):
                release = receipt("release", 2, "released", replayed=replayed)
                self.harness._assert_receipt(release, "release")
                with self.assertRaisesRegex(AssertionError, "receipt action differs"):
                    self.harness._assert_receipt(release, "register")

    def test_retained_metadata_generation_one_is_independent_of_receipt_state(self):
        for current_state in ("active", "released"):
            with self.subTest(current_state=current_state):
                self.harness._assert_metadata(metadata(current_state, 1))
        with self.assertRaisesRegex(
                AssertionError, "metadata retained capture generation is not 1"):
            self.harness._assert_metadata(metadata("released", 2))


if __name__ == "__main__":
    unittest.main()
