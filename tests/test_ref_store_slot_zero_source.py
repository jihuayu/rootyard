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
SERVING_READ_SQL = ROOT / 'src/ref_store/core/pack_snapshot/serving_read_sql.rs'
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
        cls.serving_read_sql = SERVING_READ_SQL.read_text()
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
        self.assertIn('bound(&tx, deadline)', self.production)
        self.assertIn('timeout_at(deadline, admit_slot_zero_preflight', self.production)
        self.assertIn('timeout_at(deadline, admit_slot_zero_fresh', self.production)

    def test_fresh_path_is_one_savepoint_before_any_write(self):
        entry = self.production.split('pub(crate) async fn admit_slot_zero_in_tx', 1)[1].split(
            'async fn admit_slot_zero_preflight', 1
        )[0]
        self.assertIn('mut tx: Transaction<\'a>,', entry)
        self.assertLess(entry.index('admit_slot_zero_preflight(&tx'), entry.index('tx.savepoint(SLOT_ZERO_SAVEPOINT)'))
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
        self.assertIn(
            'pub(crate) use sealed::lock_cluster_incarnation;',
            self.serving_read_sql,
        )
        self.assertNotIn('pub(super) use sealed::lock_cluster_incarnation;', self.serving_read_sql)
        self.assertIn(
            'pub(crate) use serving_read_sql::{ServingReadRow, lock_cluster_incarnation};',
            self.pack_snapshot_mod,
        )
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

    def test_owned_transaction_returns_only_after_confirmed_release_or_rollback(self):
        self.assertIn("pub(crate) enum SlotZeroAdmission<'a>", self.production)
        self.assertIn("Released { tx: Transaction<'a>, receipt: SlotZeroReceipt }", self.production)
        self.assertIn("Refused { tx: Transaction<'a>, error: PackCommitError }", self.production)
        self.assertIn("pub(crate) fn into_parts(self) -> (Transaction<'a>, Result<SlotZeroReceipt, PackCommitError>)", self.production)

        entry = self.production.split('pub(crate) async fn admit_slot_zero_in_tx', 1)[1].split(
            'async fn admit_slot_zero_preflight', 1
        )[0]
        self.assertIn("mut tx: Transaction<'a>,", entry)
        self.assertIn("Result<SlotZeroAdmission<'a>, PackCommitError>", entry)
        self.assertIn('return Err(PackCommitError::from(error));', entry)
        self.assertIn('Err(_) => return Err(PackCommitError::from(RefStoreError::Timeout)),', entry)
        self.assertIn('Ok(Err(error)) => return Err(error),', entry)
        self.assertIn('slot_zero_savepoint_recovered(tx, rollback,', entry)
        self.assertIn('slot_zero_release_failed(release_error, undo)', entry)
        self.assertIn('SlotZeroRecovery::Safe(error) => Ok(SlotZeroAdmission::refused(tx, error))', entry)
        self.assertIn('SlotZeroRecovery::Unsafe(error) => Err(error)', entry)
        self.assertIn('Ok(SlotZeroAdmission::released(tx, receipt))', entry)

        recovery = self.production.split('async fn slot_zero_savepoint_recovered', 1)[1].split(
            '/// Explicit outcome of undoing a savepoint', 1
        )[0]
        self.assertIn('Ok(()) => Ok(SlotZeroAdmission::refused(tx, original))', recovery)
        self.assertIn('savepoint rollback succeeded but releasing the savepoint failed', recovery)
        self.assertIn('savepoint rollback also failed', recovery)

        classifier = self.production.split('fn slot_zero_error_keeps_outer', 1)[1].split(
            'enum SlotZeroRecovery', 1
        )[0]
        for unsafe in ('RefStoreError::Database(_)', 'RefStoreError::Timeout', 'RefStoreError::CommitUnknown'):
            self.assertIn(unsafe, classifier)
        self.assertIn('PackCommitError::CommitUnknown { .. }', classifier)

        release = self.production.split('fn slot_zero_release_failed', 1)[1].split(
            '/// Exact retry:', 1
        )[0]
        safe = release.split('RolledBackAndReleased =>', 1)[1].split('ReleaseAfterRollback', 1)[0]
        self.assertIn('SlotZeroRecovery::Safe(', safe)
        self.assertIn('SlotZeroRecovery::Unsafe(', release.split('ReleaseAfterRollback', 1)[1].split('RollbackFailed', 1)[0])
        self.assertIn('SlotZeroRecovery::Unsafe(', release.split('RollbackFailed', 1)[1])

        typed = self.tests.split('async fn slot_zero_typed_plan_error_rolls_back_only_the_savepoint()', 1)[1].split(
            '#[tokio::test]', 1
        )[0]
        self.assertIn('into_parts();', typed)
        self.assertIn('let error = error.unwrap_err();', typed)
        self.assertIn('tx.commit().await?;', typed)

        self.assertIn(
            '#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]\n'
            'async fn slot_zero_cancelled_owned_tx_cannot_be_committed()',
            self.tests,
        )
        cancelled = self.tests.split('async fn slot_zero_cancelled_owned_tx_cannot_be_committed()', 1)[1].split(
            '#[tokio::test]', 1
        )[0]
        self.assertIn('admission.abort();', cancelled)
        self.assertIn('pg_blocking_pids', cancelled)
        self.assertIn('ref_store_issuer_lanes', cancelled)
        self.assertIn("c.relname IN ('cluster_authority'", cancelled)
        self.assertIn('if waiting', cancelled)
        self.assertIn('if clear', cancelled)
        self.assertNotIn('elapsed', cancelled.lower())

    def test_ignored_regressions_require_successful_probe_results_and_cleanup(self):
        restore = self.tests.split('async fn slot_zero_restore_rotation_waits_for_admission_commit()', 1)[1].split(
            'async fn slot_zero_waits_for_legacy_lane', 1
        )[0]
        lane = self.tests.split('async fn slot_zero_waits_for_legacy_lane_before_scope_and_gate()', 1)[1].split(
            'fn sample_request()', 1
        )[0]
        for body in (restore, lane):
            self.assertIn('pg_blocking_pids', body)
            self.assertIn("wait_event_type='Lock'", body)
            self.assertIn('timeout(WAIT, pid_rx)', body)
            self.assertIn('timeout(WAIT, async {', body)
            self.assertIn('.context(', body)
            self.assertIn('??;', body)
            self.assertIn('if waiting', body)
            self.assertIn('break Ok::<(), anyhow::Error>(())', body)
            self.assertNotIn('is_finished', body)
            self.assertNotIn('elapsed', body.lower())
            self.assertIn('let outcome: anyhow::Result<()> = async {', body)
            self.assertIn('if let Err(mut error) = outcome', body)
            self.assertIn('append_cleanup(', body)
            self.assertIn('rollback_bounded(owned)', body)
            self.assertNotIn('observed', body)
        self.assertIn('UPDATE public.cluster_authority', restore)
        self.assertIn('assert_eq!(receipt.sequence, 1)', restore)
        self.assertIn('restore wait probe did not finish")??', restore)
        self.assertIn('restore worker never reported its backend pid")??', restore)
        self.assertIn('restore worker did not finish")?', restore)
        self.assertIn('restore result did not arrive")??', restore)
        self.assertIn('admission commit did not finish")??', restore)
        self.assertIn('restore_joined = true', restore)
        self.assertIn('if !restore_joined', restore)
        self.assertIn('abort_worker(&mut restore)', restore)
        self.assertIn('changed != 1', restore)
        self.assertIn('incarnation == fixture.restore', restore)
        self.assertLess(restore.index('owned.commit()'), restore.index('&mut restore'))

        self.assertIn('PgRefStore.begin', lane)
        self.assertIn('ref_store_issuer_lanes', lane)
        self.assertIn('pg_locks', lane)
        self.assertIn("l.mode <> 'AccessShareLock'", lane)
        self.assertIn('slot-zero lane wait probe did not finish")??', lane)
        self.assertIn('slot-zero worker never reported its backend pid")??', lane)
        self.assertIn('slot-zero admission did not finish")?', lane)
        self.assertIn('slot-zero admission result did not arrive")??', lane)
        self.assertIn('legacy lane commit did not finish")??', lane)
        self.assertIn('slot-zero took repository/gate locks before waiting for the legacy lane', lane)
        self.assertIn('admission_joined = true', lane)
        self.assertIn('if !admission_joined', lane)
        self.assertIn('abort_worker(&mut admission)', lane)
        self.assertIn('legacy transaction missing before commit', lane)
        self.assertIn('receipt.sequence != 2', lane)
        self.assertLess(lane.index('owned.commit()'), lane.index('&mut admission'))

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
        self.assertGreaterEqual(self.tests.count('#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]'), 8)

    def test_fixture_setup_cleanup_is_owned_bounded_and_observable(self):
        self.assertIn('struct FixtureSeed', self.tests)
        self.assertIn('async fn fixture_with_setup_check', self.tests)
        self.assertIn('fixture_with_setup_check(|_| Ok(()))', self.tests)

        setup = self.tests.split('async fn fixture_with_setup_check', 1)[1].split('async fn with_fixture', 1)[0]
        self.assertIn('CREATE is the ownership linearization point', setup)
        self.assertIn('cleanup must not touch it', setup)
        self.assertIn('CREATE DATABASE {database}', setup)
        self.assertIn('let setup: anyhow::Result<FixtureSeed> = async {', setup)
        self.assertLess(
            setup.index('CREATE DATABASE {database}'),
            setup.index('let setup: anyhow::Result<FixtureSeed>'),
        )
        self.assertNotIn('cleanup_owned_database(', setup.split('CREATE DATABASE {database}', 1)[0])
        self.assertIn('check(&database)?;', setup)
        self.assertIn('Err(original) => {', setup)
        self.assertIn('cleanup_owned_database(&admin, &database)', setup)
        self.assertIn('append_cleanup(original, "fixture setup database cleanup"', setup)

        cleanup = self.tests.split('async fn cleanup_owned_database', 1)[1].split('async fn fixture()', 1)[0]
        self.assertIn('timeout(WAIT, admin.get())', cleanup)
        self.assertIn('pg_terminate_backend(pid)', cleanup)
        self.assertIn('DROP DATABASE {database}', cleanup)
        self.assertIn('cleanup admin checkout did not finish', cleanup)
        self.assertIn('terminating backends of owned database {database}', cleanup)
        self.assertIn('dropping owned database {database}', cleanup)
        self.assertIn('leave it in place for inspection', self.tests)

        with_fixture = self.tests.split('async fn with_fixture', 1)[1].split('#[tokio::test]', 1)[0]
        self.assertIn('let outcome = tokio::spawn(body(fixture)).await;', with_fixture)
        self.assertIn('cleanup_owned_database(&admin, &database)', with_fixture)
        self.assertIn('(Ok(Err(error)), Ok(())) => Err(error)', with_fixture)
        self.assertIn('append_cleanup(error, "database cleanup"', with_fixture)
        self.assertIn('(Err(join_error), Ok(())) => Err(join_error.into())', with_fixture)

        self.assertIn(
            '#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]\n'
            'async fn slot_zero_fixture_setup_error_drops_only_its_owned_database()',
            self.tests,
        )
        test = self.tests.split('async fn slot_zero_fixture_setup_error_drops_only_its_owned_database()', 1)[1]
        self.assertIn('fixture_with_setup_check(move |database|', test)
        self.assertIn('injected setup failure after fixture seed', test)
        self.assertIn('setup cleanup replaced the original error', test)
        self.assertIn('setup cleanup failed', test)
        self.assertIn('SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1)', test)
        self.assertIn('owned setup database {database} survived cleanup', test)
        self.assertGreaterEqual(self.tests.count('#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]'), 8)

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
