"""Offline source guards for the unwired #42 private slot-zero adapter.

Pins the nested timeout result match and the public/private routing boundary:
private preflight uses the typed migration-152 public lookup in the same
authenticated transaction, only an explicit LegacyPath marker enters the
guarded legacy lookup, and verified private replay bypasses that guard through
one internal evidence/lock-scoped helper. No database, Cargo or service runs.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PUBLISH = ROOT / 'src/blob_git_gateway/publish.rs'
OPERATION = ROOT / 'src/blob_git_gateway/operation.rs'
PG = ROOT / 'src/ref_store/pg.rs'


def slice_between(source, start, end):
    assert start in source, start
    assert end in source, end
    return source.split(start, 1)[1].split(end, 1)[0]


class PrivateAdmissionSourceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.publish = PUBLISH.read_text()
        cls.operation = OPERATION.read_text()
        cls.pg = PG.read_text()

    def test_timeout_result_is_matched_before_into_parts(self):
        body = slice_between(
            self.publish,
            'let (savepoint, admission_result) = match outcome {',
            'match admission_result {',
        )
        self.assertIn('Ok(Ok(admission)) => admission.into_parts()', body)
        self.assertIn('Ok(Err(error)) => {', body)
        self.assertIn('return Err(GatewayError::from(error));', body)
        self.assertIn('Err(_) => {', body)
        self.assertIn('return Err(GatewayError::Timeout);', body)
        self.assertIn('rollback_deadpool_bounded(tx, deadline).await', body)
        self.assertNotIn('Ok(admission) => admission.into_parts()', body)

    def test_private_entry_does_not_use_the_legacy_public_lookup(self):
        entry = slice_between(
            self.publish,
            'pub(super) async fn begin_slot_zero(',
            'enum SlotZeroPreflight',
        )
        self.assertIn('public_attempt_request(', entry)
        self.assertIn('slot_zero_public_preflight(', entry)
        self.assertNotIn('operation::lookup(', entry)


    def test_fresh_admission_reuses_the_authenticated_owning_transaction(self):
        entry = slice_between(
            self.publish,
            'pub(super) async fn begin_slot_zero(',
            'enum SlotZeroPreflight',
        )
        self.assertIn('backend_identity().as_hex().to_owned()', entry)
        self.assertIn('client.transaction()', entry)
        self.assertNotIn('begin_bounded(', entry)
        self.assertIn('begin_slot_zero_fresh(tx,', entry)

        fresh = slice_between(
            self.publish,
            'async fn begin_slot_zero_fresh(',
            '/// Construct the exact typed public request',
        )
        self.assertIn("tx: deadpool_postgres::Transaction<'_>", fresh)
        self.assertIn('tokio_postgres::Transaction::savepoint(&mut *tx, GATEWAY_SLOT_ZERO_SAVEPOINT)', fresh)
        self.assertIn('PgRefStore.admit_slot_zero_in_tx(', fresh)
        self.assertIn('commit_bounded(savepoint, deadline, repository_id', fresh)
        self.assertIn('commit_deadpool_bounded(tx, deadline)', fresh)
        self.assertNotIn('state.pooled(', fresh)
        self.assertNotIn('begin_bounded(', fresh)

    def test_public_preflight_is_locked_authenticated_and_typed(self):
        preflight = slice_between(
            self.publish,
            'async fn slot_zero_public_preflight(',
            '/// One fresh slot-zero admission transaction',
        )
        self.assertIn('lock_public_attempt(', preflight)
        self.assertIn('lock_operation(', preflight)
        self.assertIn('lock_expected_lane(', preflight)
        self.assertIn("tx: &deadpool_postgres::Transaction<'_>", preflight)
        self.assertIn('lookup_in_tx(', preflight)
        self.assertIn('lookup_public_attempt(', preflight)
        self.assertIn('LegacyPath', preflight)
        self.assertLess(preflight.index('lock_expected_lane('), preflight.index('lookup_in_tx('))

        lane_lock = slice_between(
            self.pg,
            'pub(crate) async fn lock_expected_lane(',
            '    /// Reserve the next sequence',
        )
        self.assertIn('SELECT 1 FROM ref_store_issuer_lanes', lane_lock)
        self.assertIn('FOR NO KEY UPDATE', lane_lock)
        self.assertNotIn('last_reserved_sequence + 1', lane_lock)
        self.assertNotIn('INSERT INTO ref_store_issuer_lanes', lane_lock)

        unknown = slice_between(
            preflight,
            'PublicAttemptLookup::Unknown =>',
            'PublicAttemptLookup::PrivateIdentifier =>',
        )
        self.assertNotIn('lookup_in_tx', unknown)
        private = slice_between(
            preflight,
            'PublicAttemptLookup::PrivateIdentifier =>',
            'PublicAttemptLookup::LegacyPath =>',
        )
        self.assertNotIn('lookup_in_tx', private)
        legacy = slice_between(
            preflight,
            'PublicAttemptLookup::LegacyPath =>',
            'PublicAttemptLookup::Pending(evidence)',
        )
        self.assertIn('operation::lookup_in_tx(', legacy)

    def test_verified_private_replay_uses_internal_evidence_helper(self):
        replay = slice_between(
            self.publish,
            'async fn replay_slot_zero_claim(',
            '/// What one fresh-write transaction decided',
        )
        self.assertIn('lookup_public_attempt(', replay)
        self.assertIn('lookup_public_private_in_tx(', replay)
        self.assertNotIn('lookup_in_tx(', replay)

        helper = slice_between(
            self.operation,
            'pub(super) async fn lookup_public_private_in_tx(',
            '#[derive(Clone, Copy, Eq, PartialEq)]\nenum Binding',
        )
        self.assertIn('rootyard_ref_store_require_attempt_lock', helper)
        self.assertIn('read_serving_operation(', helper)
        self.assertIn('PgRefStore.get(tx,', helper)
        self.assertIn('recompute_slot_zero_proof(', helper)
        self.assertIn('recompute_slot_one_proof(', helper)
        self.assertNotIn('get_legacy_locked', helper)
        self.assertNotIn('lookup_in_tx(', helper)

    def test_legacy_guard_remains_closed_for_external_lookup(self):
        legacy = slice_between(
            self.operation,
            'pub(super) async fn lookup_in_tx(',
            '/// Query the immutable operation registry',
        )
        self.assertIn('get_legacy_locked(', legacy)
        self.assertNotIn('PgRefStore.get(tx', legacy)


if __name__ == '__main__':
    unittest.main()
