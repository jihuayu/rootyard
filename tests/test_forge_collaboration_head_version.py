#!/usr/bin/env python3
"""Hermetic tests for the post-push pull head/version resolver."""

import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from forge_collaboration import resolve_pull_head_after_push


class PullHeadAfterPushResolverTests(unittest.TestCase):
    BASE = "b" * 40
    V1 = "1" * 40
    V2 = "2" * 40
    FOREIGN = "3" * 40
    CREATED = 1

    def setUp(self):
        self.get_calls = 0
        self.patch_calls = 0

    def snapshot(self, head, version, *, base=None, state="open"):
        return {
            "head_oid": head,
            "base_oid": self.BASE if base is None else base,
            "state": state,
            "version": version,
        }

    def resolve(self, get_results, patch_results):
        def fetch_pull():
            index = self.get_calls
            self.get_calls += 1
            if index >= len(get_results):
                raise AssertionError("resolver issued an unexpected extra GET")
            return get_results[index]

        def patch_pull(expected_version):
            index = self.patch_calls
            self.patch_calls += 1
            self.assertEqual(expected_version, self.CREATED)
            if index >= len(patch_results):
                raise AssertionError("resolver issued an unexpected extra PATCH")
            return patch_results[index]

        return resolve_pull_head_after_push(
            fetch_pull,
            patch_pull,
            expected_version=self.CREATED,
            base_oid=self.BASE,
            old_head_oid=self.V1,
            new_head_oid=self.V2,
        )

    def test_before_refsync_get_patches_once_and_accepts_single_increment(self):
        outcome = self.resolve(
            [(200, self.snapshot(self.V1, self.CREATED))],
            [(200, self.snapshot(self.V2, self.CREATED + 1))],
        )
        self.assertEqual(outcome, "patched")
        self.assertEqual((self.get_calls, self.patch_calls), (1, 1))

    def test_after_refsync_get_accepts_single_increment_without_patch(self):
        outcome = self.resolve(
            [(200, self.snapshot(self.V2, self.CREATED + 1))],
            [],
        )
        self.assertEqual(outcome, "refsync")
        self.assertEqual((self.get_calls, self.patch_calls), (1, 0))

    def test_stale_cas_409_allows_exactly_one_readback(self):
        outcome = self.resolve(
            [
                (200, self.snapshot(self.V1, self.CREATED)),
                (200, self.snapshot(self.V2, self.CREATED + 1)),
            ],
            [(409, b'{"error":"pull request version conflict"}')],
        )
        self.assertEqual(outcome, "readback")
        self.assertEqual((self.get_calls, self.patch_calls), (2, 1))

    def test_initial_get_rejects_foreign_head(self):
        with self.assertRaisesRegex(AssertionError, "expected head"):
            self.resolve([(200, self.snapshot(self.FOREIGN, self.CREATED))], [])
        self.assertEqual((self.get_calls, self.patch_calls), (1, 0))

    def test_initial_get_rejects_non_created_version(self):
        with self.assertRaisesRegex(AssertionError, "expected version"):
            self.resolve([(200, self.snapshot(self.V1, self.CREATED + 1))], [])
        self.assertEqual((self.get_calls, self.patch_calls), (1, 0))

    def test_initial_get_failure_is_not_retried(self):
        with self.assertRaisesRegex(AssertionError, "expected 200"):
            self.resolve([(503, b"unavailable")], [])
        self.assertEqual((self.get_calls, self.patch_calls), (1, 0))

    def test_unexpected_patch_status_is_not_accepted(self):
        with self.assertRaisesRegex(AssertionError, "expected 200 or 409"):
            self.resolve(
                [(200, self.snapshot(self.V1, self.CREATED))],
                [(500, b"internal error")],
            )
        self.assertEqual((self.get_calls, self.patch_calls), (1, 1))

    def test_patch_success_rejects_wrong_version(self):
        with self.assertRaisesRegex(AssertionError, "expected version"):
            self.resolve(
                [(200, self.snapshot(self.V1, self.CREATED))],
                [(200, self.snapshot(self.V2, self.CREATED + 2))],
            )
        self.assertEqual((self.get_calls, self.patch_calls), (1, 1))

    def test_readback_rejects_foreign_head(self):
        with self.assertRaisesRegex(AssertionError, "expected head"):
            self.resolve(
                [
                    (200, self.snapshot(self.V1, self.CREATED)),
                    (200, self.snapshot(self.FOREIGN, self.CREATED + 1)),
                ],
                [(409, b"conflict")],
            )
        self.assertEqual((self.get_calls, self.patch_calls), (2, 1))

    def test_readback_rejects_changed_base(self):
        with self.assertRaisesRegex(AssertionError, "expected base"):
            self.resolve(
                [
                    (200, self.snapshot(self.V1, self.CREATED)),
                    (200, self.snapshot(self.V2, self.CREATED + 1, base="c" * 40)),
                ],
                [(409, b"conflict")],
            )
        self.assertEqual((self.get_calls, self.patch_calls), (2, 1))

    def test_readback_rejects_missing_increment(self):
        with self.assertRaisesRegex(AssertionError, "expected version"):
            self.resolve(
                [
                    (200, self.snapshot(self.V1, self.CREATED)),
                    (200, self.snapshot(self.V2, self.CREATED)),
                ],
                [(409, b"conflict")],
            )
        self.assertEqual((self.get_calls, self.patch_calls), (2, 1))

    def test_readback_rejects_extra_increment(self):
        with self.assertRaisesRegex(AssertionError, "expected version"):
            self.resolve(
                [
                    (200, self.snapshot(self.V1, self.CREATED)),
                    (200, self.snapshot(self.V2, self.CREATED + 2)),
                ],
                [(409, b"conflict")],
            )
        self.assertEqual((self.get_calls, self.patch_calls), (2, 1))

    def test_readback_rejects_non_open_state(self):
        with self.assertRaisesRegex(AssertionError, "expected open state"):
            self.resolve(
                [
                    (200, self.snapshot(self.V1, self.CREATED)),
                    (200, self.snapshot(self.V2, self.CREATED + 1, state="closed")),
                ],
                [(409, b"conflict")],
            )
        self.assertEqual((self.get_calls, self.patch_calls), (2, 1))

    def test_readback_is_bounded_without_retrying_patch(self):
        with self.assertRaisesRegex(AssertionError, "expected head"):
            self.resolve(
                [
                    (200, self.snapshot(self.V1, self.CREATED)),
                    (200, self.snapshot(self.V1, self.CREATED)),
                ],
                [(409, b"conflict")],
            )
        self.assertEqual((self.get_calls, self.patch_calls), (2, 1))


if __name__ == "__main__":
    unittest.main()
