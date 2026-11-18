"""Offline source checks for the crate-private slot-zero admission slice.

The hosted PostgreSQL tests are ignored. These checks pin the executable order
and the closed gateway boundary so a refactor cannot silently write the private
operation before its wrapper/attempt, skip the locked preview, or wire the
wrapper into the legacy production path.
"""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SLOT_ZERO = ROOT / 'src/ref_store/pg/slot_zero.rs'
SLOT_ZERO_TESTS = ROOT / 'src/ref_store/pg/slot_zero/tests.rs'
PUBLISH = ROOT / 'src/blob_git_gateway/publish.rs'


class SlotZeroSourceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SLOT_ZERO.read_text()
        cls.production = cls.source.split('#[cfg(test)]', 1)[0]
        cls.tests = SLOT_ZERO_TESTS.read_text()

    def test_locked_preview_precedes_wrapper_attempt_advance_operation_binding(self):
        markers = [
            'rootyard_ref_store_lock_public_operation',
            'LockedSequence::preview(',
            'insert_wrapper(tx, request).await?',
            'insert_attempt(tx, request, plan_digest, proof, base_revision).await?',
            'advance_sequence(',
            'insert_operation(tx, plan.identity(), OperationState::Pending, None)',
            'bind_existing_serving_pending_in_tx',
        ]
        positions = [self.production.index(marker) for marker in markers]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("SET LOCAL synchronous_commit = 'on'", self.production)
        self.assertLess(
            self.production.index("SET LOCAL synchronous_commit = 'on'"),
            self.production.index('insert_wrapper(tx, request)'),
        )

    def test_slice_never_commits_rolls_back_or_opens_another_connection(self):
        self.assertNotIn('.commit(', self.production)
        self.assertNotIn('.rollback(', self.production)
        self.assertNotIn('pool.get()', self.production)
        self.assertIn('timeout_at(deadline, admit_slot_zero_inner', self.production)
        self.assertIn('bound(tx, deadline)', self.production)

    def test_gateway_keeps_the_legacy_reservation_and_binding_path(self):
        publish = PUBLISH.read_text()
        self.assertIn('reserve_sequence', publish)
        self.assertIn('begin_serving_pending_in_tx', publish)
        self.assertNotIn('admit_slot_zero', publish)
        self.assertNotIn('slot_zero', publish)

    def test_ignored_tests_drive_the_real_admission_entry(self):
        self.assertGreaterEqual(self.tests.count('.admit_slot_zero_in_tx('), 4)
        self.assertIn('plan_for(&fixture, &request, preview)', self.tests)
        self.assertIn('assert_eq!(receipt.sequence, 1)', self.tests)
        self.assertIn('assert_eq!(next.sequence, 2)', self.tests)
        self.assertIn('slot zero serving producer binding is missing', self.tests)
        self.assertIn('slot zero serving producer binding differs from the wrapper', self.tests)
        self.assertIn('tx.rollback().await?', self.tests)
        self.assertIn('tx.commit().await?', self.tests)


if __name__ == '__main__':
    unittest.main()
