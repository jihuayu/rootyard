"""Offline source checks for the issuer-lane preview statement budget.

The preview keeps the migration-138 lock order (operation key -> lane row) and
its conditional advance. This test pins only the statement shape Luna reviewed:
an existing lane takes one locked read, a transaction-created lane takes its
initial candidate directly from `INSERT ... ON CONFLICT DO NOTHING RETURNING`,
and the extra locked re-read happens only when a concurrent creator wins.
"""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
PG = ROOT / 'src/ref_store/pg.rs'


class IssuerLanePreviewSourceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = PG.read_text()
        cls.preview = cls.source.split('async fn preview(', 1)[1].split('async fn advance(', 1)[0]
        cls.advance = cls.source.split('async fn advance(', 1)[1].split('async fn advance_sequence(', 1)[0]
        cls.advance_sequence = cls.source.split('async fn advance_sequence(', 1)[1].split('\nstruct Cancellation', 1)[0]
        cls.reserve = cls.source.split('async fn reserve_sequence_inner(', 1)[1].split('/// Register a pending operation', 1)[0]

    def test_existing_lane_uses_one_locked_preview(self):
        self.assertIn(
            'SELECT last_reserved_sequence + 1 FROM ref_store_issuer_lanes',
            self.preview,
        )
        self.assertIn('FOR NO KEY UPDATE', self.preview)
        flow = ' '.join(self.preview.split())
        markers = [
            'tx.query_opt(PREVIEW, params)',
            'match tx.query_opt(CREATE_LANE, params)',
            'tx.query_one(PREVIEW, params)',
            'Ok(Self {',
        ]
        positions = [flow.index(marker) for marker in markers]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(flow.count('tx.query_opt(PREVIEW, params)'), 1)
        self.assertEqual(flow.count('tx.query_opt(CREATE_LANE, params)'), 1)
        self.assertEqual(flow.count('tx.query_one(PREVIEW, params)'), 1)
        # The original single-statement locked read stays first; CREATE is only
        # reachable from its missing-row arm.
        self.assertLess(positions[0], positions[1])

    def test_fresh_lane_takes_the_initial_candidate_from_the_insert(self):
        self.assertIn('INSERT INTO ref_store_issuer_lanes(', self.preview)
        self.assertIn('ON CONFLICT(repository_id,issuer_id,lane) DO NOTHING', self.preview)
        self.assertIn('RETURNING last_reserved_sequence + 1', self.preview)
        self.assertEqual(self.preview.count('INSERT INTO ref_store_issuer_lanes'), 1)
        # The insert is a query, not a bare execute followed by another read, so
        # the no-contention first creation spends one preview statement.
        self.assertNotIn('tx.execute(', self.preview)
        self.assertIn('None => match tx.query_opt(CREATE_LANE, params)', self.preview)

    def test_only_a_lost_insert_race_rereads_under_the_lane_lock(self):
        flow = ' '.join(self.preview.split())
        # The re-read is nested under CREATE's no-row arm, never run after a
        # successful insert or on the existing-lane path.
        fallback = flow.split('match tx.query_opt(CREATE_LANE, params)', 1)[1]
        fallback = fallback.split('Ok(Self {', 1)[0]
        self.assertIn('None => tx.query_one(PREVIEW, params)', fallback)
        self.assertEqual(fallback.count('tx.query_one(PREVIEW, params)'), 1)
        self.assertLess(fallback.index('Some(row) => row.get(0)'), fallback.index('None => tx.query_one(PREVIEW'))

    def test_advance_stays_conditional_and_bound_to_the_previewed_row(self):
        # The preview value is handed to one conditional advance; the slot-zero
        # caller builds its plan between the two without re-reading the lane.
        self.assertIn('advance_sequence(', self.advance)
        self.assertIn('self.operation_id', self.advance)
        self.assertIn('self.sequence', self.advance)
        self.assertIn('last_reserved_sequence=$4::bigint - 1', self.advance_sequence)
        self.assertIn('if changed != 1', self.advance_sequence)
        self.assertIn('RefStoreError::IdentityConflict', self.advance_sequence)
        self.assertIn('SequenceReservation::new(', self.advance_sequence)
        self.assertEqual(self.advance_sequence.count('UPDATE ref_store_issuer_lanes'), 1)
        # The advance is the only write after the preview and still carries the
        # operation UUID chosen by the caller.
        self.assertIn('sequence, operation_id)', self.advance_sequence)

    def test_reservation_keeps_the_operation_then_lane_prefix(self):
        flow = ' '.join(self.reserve.split())
        markers = [
            'lock_operation_key(tx, repository_id, operation_id)',
            'refuse_legacy_collision(tx, repository_id, operation_id)',
            'ensure_repository(tx, repository_id)',
            'LockedSequence::preview(tx, repository_id, issuer_id, operation_id, lane)',
            '.advance()',
        ]
        positions = [flow.index(marker) for marker in markers]
        self.assertEqual(positions, sorted(positions))
        self.assertIn('before_deadline(', self.source.split('pub async fn reserve_sequence(', 1)[1].split('async fn reserve_sequence_inner', 1)[0])


if __name__ == '__main__':
    unittest.main()
