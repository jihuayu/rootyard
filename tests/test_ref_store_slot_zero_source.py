"""Offline source checks for the crate-private slot-zero admission slice.

The hosted PostgreSQL tests are ignored. These checks pin the executable order
and the closed gateway boundary so a refactor cannot silently write the private
operation before its wrapper/attempt, take repository/gate locks before the
issuer lane, skip the shared restore-incarnation fence, put a fresh-lane write
outside the admission savepoint, or wire the wrapper into the legacy production
path. The ignored bodies are checked for positive pg_blocking_pids observations,
bounded release, and failure-path abort/rollback.
"""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SLOT_ZERO = ROOT / 'src/ref_store/pg/slot_zero.rs'
SLOT_ZERO_TESTS = ROOT / 'src/ref_store/pg/slot_zero/tests.rs'
PUBLISH = ROOT / 'src/blob_git_gateway/publish.rs'
PACK_SNAPSHOT_MOD = ROOT / 'src/ref_store/core/pack_snapshot/mod.rs'
SEALED = ROOT / 'src/ref_store/core/pack_snapshot/serving_read_sql/sealed.rs'
PG = ROOT / 'src/ref_store/pg.rs'
CORE_PACK = ROOT / 'src/ref_store/core/pack_commit/pg.rs'
BACKUP_AUTHORITY = ROOT / 'src/backup/authority.rs'
SERVING_AUTH = ROOT / 'src/ref_store/serving/authority.rs'
RETENTION_SQL = ROOT / 'src/ref_store/core/retention_root/sql.rs'


class SlotZeroSourceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SLOT_ZERO.read_text()
        cls.production = cls.source.split('#[cfg(test)]', 1)[0]
        cls.tests = SLOT_ZERO_TESTS.read_text()
        cls.pack_snapshot_mod = PACK_SNAPSHOT_MOD.read_text()
        cls.sealed = SEALED.read_text()
        cls.pg = PG.read_text()
        cls.core_pack = CORE_PACK.read_text()
        cls.backup_authority = BACKUP_AUTHORITY.read_text()
        cls.serving_auth = SERVING_AUTH.read_text()
        cls.retention_sql = RETENTION_SQL.read_text()

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

    def test_slice_never_ends_the_outer_transaction_or_opens_a_connection(self):
        self.assertNotIn('tx.commit(', self.production)
        self.assertNotIn('tx.rollback(', self.production)
        self.assertNotIn('pool.get()', self.production)
        self.assertIn('tx.savepoint(SLOT_ZERO_SAVEPOINT)', self.production)
        self.assertIn('nested.commit().await', self.production)
        self.assertIn('nested.rollback().await', self.production)
        self.assertIn('ROLLBACK TO SAVEPOINT', self.production)
        self.assertIn('RELEASE SAVEPOINT', self.production)
        self.assertIn('bound(&*tx, deadline)', self.production)
        self.assertIn('timeout_at(deadline, admit_slot_zero_preflight', self.production)
        self.assertIn('timeout_at(deadline, admit_slot_zero_fresh', self.production)

    def test_fresh_path_is_one_savepoint_before_any_write(self):
        entry = self.production.split('pub(crate) async fn admit_slot_zero_in_tx', 1)[1].split(
            'async fn admit_slot_zero_preflight', 1
        )[0]
        self.assertIn('tx: &mut Transaction', entry)
        self.assertLess(entry.index('admit_slot_zero_preflight(&*tx'), entry.index('tx.savepoint(SLOT_ZERO_SAVEPOINT)'))
        self.assertLess(entry.index('tx.savepoint(SLOT_ZERO_SAVEPOINT)'), entry.index('admit_slot_zero_fresh(&nested'))
        self.assertIn('nested.commit().await', entry)
        self.assertIn('nested.rollback().await', entry)

        preflight = self.production.split('async fn admit_slot_zero_preflight', 1)[1].split(
            '/// The write-capable prefix', 1
        )[0]
        for write in ('insert_wrapper(', 'insert_attempt(', 'advance_sequence(', 'insert_operation('):
            self.assertNotIn(write, preflight)

        fresh = self.production.split('async fn admit_slot_zero_fresh', 1)[1].split(
            'fn slot_zero_savepoint_begin_failed', 1
        )[0]
        markers = [
            'lock_cluster_incarnation(tx).await',
            'LockedSequence::preview(',
            'LockedScope::lock(',
            'read_gate_in_tx(',
            'build_plan(preview)',
            "SET LOCAL synchronous_commit = 'on'",
            'insert_wrapper(tx, request)',
            'insert_attempt(tx, request',
            'advance_sequence(',
            'insert_operation(tx, plan.identity()',
            'bind_existing_serving_pending_in_tx',
        ]
        positions = [fresh.index(marker) for marker in markers]
        self.assertEqual(positions, sorted(positions))

    def test_gateway_keeps_the_legacy_reservation_and_binding_path(self):
        publish = PUBLISH.read_text()
        self.assertIn('reserve_sequence', publish)
        self.assertIn('begin_serving_pending_in_tx', publish)
        self.assertNotIn('admit_slot_zero', publish)
        self.assertNotIn('slot_zero', publish)

    def test_restore_fence_is_shared_before_lane_and_repository_locks(self):
        markers = [
            'rootyard_ref_store_lock_public_operation',
            'lock_cluster_incarnation(tx).await',
            'LockedSequence::preview(',
            'LockedScope::lock(',
            'read_gate_in_tx(',
            'insert_wrapper(tx, request)',
        ]
        positions = [self.production.index(marker) for marker in markers]
        self.assertEqual(positions, sorted(positions))
        self.assertIn('pack_snapshot::lock_cluster_incarnation', self.production)
        self.assertNotIn('SELECT incarnation FROM cluster_authority', self.production)
        self.assertIn('lock_cluster_incarnation', self.pack_snapshot_mod)
        self.assertIn('FOR SHARE', self.sealed)
        self.assertNotIn('NOWAIT', self.sealed)
        self.assertIn('public.cluster_authority', self.sealed)
        fence = ' '.join(self.backup_authority.split())
        self.assertLess(
            fence.index('UPDATE public.cluster_authority'),
            fence.index('DELETE FROM public.cluster_transport_nonces'),
        )

    def test_post_repository_cluster_readers_stay_nonblocking(self):
        # `serving::authority` intentionally holds token/repository locks before
        # its cluster read, and retention roots holds repository/gate/pin/root.
        # They must keep NOWAIT: a blocking SHARE there would reverse slot-zero's
        # cluster -> lane -> repository/gate order.
        self.assertIn('FOR SHARE NOWAIT', self.serving_auth)
        self.assertIn('FOR SHARE NOWAIT', self.retention_sql)

    def test_legacy_pending_order_is_lane_then_repository_and_gate(self):
        begin = self.pg.split('async fn begin_inner(', 1)[1].split('/// A candidate sequence', 1)[0]
        self.assertLess(
            begin.index('lock_lane(tx, identity)'),
            begin.index('insert_operation(tx, identity, OperationState::Pending'),
        )
        pending = self.core_pack.split('async fn begin_pending_in_tx(', 1)[1].split('/// Capture the closure context', 1)[0]
        self.assertLess(pending.index('PgRefStore.begin('), pending.index('ensure_repository(tx, plan, false)'))
        self.assertLess(pending.index('ensure_repository(tx, plan, false)'), pending.index('sql::gate_locked('))

    def test_ignored_regressions_observe_both_blockers_and_release(self):
        restore = self.tests.split('async fn slot_zero_restore_rotation_waits_for_admission_commit()', 1)[1].split(
            'async fn slot_zero_waits_for_legacy_lane', 1
        )[0]
        lane = self.tests.split('async fn slot_zero_waits_for_legacy_lane_before_scope_and_gate()', 1)[1].split(
            'fn sample_request()', 1
        )[0]
        for body in (restore, lane):
            self.assertIn('pg_blocking_pids', body)
            self.assertIn("wait_event_type='Lock'", body)
            self.assertIn('timeout(Duration::from_secs(10)', body)
            self.assertIn('if waiting', body)
            self.assertIn('.abort()', body)
            self.assertIn('.rollback()', body)
        self.assertIn('UPDATE public.cluster_authority', restore)
        self.assertIn('assert_eq!(receipt.sequence, 1)', restore)
        self.assertIn('assert_ne!(incarnation, fixture.restore)', restore)
        self.assertLess(restore.rindex('tx.commit().await?'), restore.index('&mut restore'))
        self.assertIn('PgRefStore.begin', lane)
        self.assertIn('ref_store_issuer_lanes', lane)
        self.assertIn('pg_locks', lane)
        self.assertIn("l.mode <> 'AccessShareLock'", lane)
        self.assertIn('assert_eq!(receipt.sequence, 2)', lane)
        self.assertLess(lane.index('legacy_tx.commit().await'), lane.index('&mut admission'))
        atomic = self.tests.split('async fn slot_zero_typed_plan_error_rolls_back_only_the_savepoint()', 1)[1].split(
            '#[tokio::test]', 1
        )[0]
        self.assertIn('IssuerLane::new("slot-zero-atomic")', atomic)
        self.assertIn('slot zero plan rejected after preview', atomic)
        self.assertIn('INSERT INTO users(id,username)', atomic)
        self.assertIn('tx.commit().await?', atomic)
        self.assertIn('ref_store_issuer_lanes', atomic)
        self.assertIn('ref_store_public_operations', atomic)
        self.assertIn('ref_store_private_attempts', atomic)
        self.assertIn('ref_store_operations', atomic)
        self.assertIn('ref_store_serving_operations', atomic)
        self.assertIn('for index in 0..5', atomic)
        self.assertGreaterEqual(self.tests.count('#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]'), 7)

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
