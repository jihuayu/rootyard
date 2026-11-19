"""Offline checks for migration-152 legacy UUID collision refusal.

This pins the current paths against the later source: reserve, begin, cancel
and the receive probe take the migration-138 key before their mutation or
collision probe; the raw core get remains internal; the read-only HTTP status
route takes no such key and classifies the wrapper, private claim and eligible
legacy row in one atomic statement; pre-152 catalogs keep the legacy read and
partial catalogs fail closed. No database, Cargo or service is touched.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PG = ROOT / 'src/ref_store/pg.rs'
API = ROOT / 'src/blob_git_gateway/api.rs'
OPERATION = ROOT / 'src/blob_git_gateway/operation.rs'
CANCEL = ROOT / 'src/ref_store/core/pack_commit/authorized/cancel.rs'
PUBLISH = ROOT / 'src/blob_git_gateway/publish.rs'
ADAPTER = ROOT / 'src/blob_git_gateway/operation_read.rs'


def slice_between(source, start, end):
    return source.split(start, 1)[1].split(end, 1)[0]


class LegacyCollisionSourceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pg = PG.read_text()
        cls.api = API.read_text()
        cls.operation = OPERATION.read_text()
        cls.cancel = CANCEL.read_text()
        cls.publish = PUBLISH.read_text()
        cls.adapter = ADAPTER.read_text()

    def test_reserve_begin_and_cancel_refuse_after_the_operation_lock(self):
        for name in ('reserve_sequence_inner', 'begin_inner', 'cancel_inner'):
            body = slice_between(self.pg, f'async fn {name}(', '\n    }\n')
            lock = body.index('lock_operation_key(')
            probe = body.index('refuse_legacy_collision(')
            later = body.index('ensure_repository(')
            self.assertLess(lock, probe, name)
            self.assertLess(probe, later, name)

    def test_collision_probe_is_pre_152_safe_and_read_committed(self):
        probe = slice_between(self.pg, 'async fn refuse_legacy_collision(', '\npub(crate) async fn bound(')
        self.assertIn('schema_migrations WHERE version=152', probe)
        self.assertIn("current_setting('transaction_isolation') = 'read committed'", probe)
        self.assertIn('if !schema.get::<_, bool>(0) {', probe)
        self.assertIn('ref_store_public_operations', probe)
        self.assertIn('public_id=$2', probe)
        self.assertIn('ref_store_private_attempts', probe)
        self.assertIn('private_id=$2', probe)
        self.assertIn('RefStoreError::IdentityConflict', probe)
        self.assertLess(probe.index('public_operations'), probe.index('private_attempts'))

    def test_legacy_lookup_is_guarded_while_raw_core_get_remains(self):
        raw = slice_between(self.pg, 'pub async fn get(', 'pub(crate) async fn get_legacy_locked(')
        self.assertIn('self.get_inner(', raw)
        self.assertNotIn('refuse_legacy_collision', raw)
        guarded = slice_between(
            self.pg,
            'pub(crate) async fn get_legacy_locked(',
            'pub(crate) async fn get_legacy_status(',
        )
        self.assertLess(guarded.index('bound(tx, deadline)'), guarded.index('refuse_legacy_collision'))
        self.assertLess(guarded.index('refuse_legacy_collision'), guarded.index('self.get_inner('))

    def test_legacy_status_uses_one_snapshot_and_exact_pre152_catalog(self):
        status = slice_between(self.pg, 'pub(crate) async fn get_legacy_status(', 'async fn get_inner(')
        self.assertEqual(status.count('query_one(LEGACY_STATUS_SNAPSHOT'), 1)
        self.assertNotIn('refuse_legacy_collision(', status)
        self.assertNotIn('lock_operation', status)
        self.assertIn('LEGACY_STATUS_SCHEMA_PROBE', status)
        self.assertIn('if !version && !wrapper_relation && !attempt_relation && !binding_function', status)
        self.assertIn('if !version || !wrapper_relation || !attempt_relation || !binding_function', status)
        self.assertIn('RefStoreError::Unsupported(LEGACY_STATUS_SCHEMA_REQUIRED)', status)
        self.assertIn('OperationLookup::Known(record) => Ok(LegacyStatusLookup::Legacy(record))', status)
        self.assertIn('self.get_inner(tx, repository_id, operation_id, deadline)', status)
        self.assertIn('LegacyStatusLookup::PrivateIdentifier', status)
        self.assertIn('LegacyStatusLookup::PublicWrapper', status)
        self.assertIn('legacy_present || private_claimed || !selected_private', status)
        self.assertIn('record_from_row(&row, repository_id)', status)

        sql = slice_between(self.pg, 'const LEGACY_STATUS_SNAPSHOT: &str = "SELECT ', '";')
        for table in ('ref_store_operations', 'ref_store_public_operations', 'ref_store_private_attempts'):
            self.assertIn(table, sql)
        self.assertIn(
            'o.issuer_id, o.lane, o.sequence, o.request_digest, o.state, o.terminal_result, o.operation_id',
            sql,
        )
        for marker in ('public_wrapper', 'private_claimed', 'selected_private'):
            self.assertIn(marker, sql)
        self.assertEqual(sql.count('LEFT JOIN'), 4)
        probe = slice_between(self.pg, 'const LEGACY_STATUS_SCHEMA_PROBE: &str = "SELECT ', '";')
        self.assertIn('schema_migrations WHERE version=152', probe)
        self.assertIn("to_regclass('ref_store_public_operations')", probe)
        self.assertIn("to_regclass('ref_store_private_attempts')", probe)
        self.assertIn('rootyard_ref_store_attempt_has_binding', probe)

    def test_http_status_read_takes_no_key_and_legacy_fallthrough_is_atomic(self):
        api = slice_between(self.api, 'let loaded: Result<OperationRead', 'let _ = tokio::time::timeout_at')
        self.assertNotIn('lock_operation(', api)
        self.assertNotIn('get_legacy_locked(', api)
        self.assertLess(api.index('lookup_in_tx('), api.index('operation_read::resolve('))
        self.assertIn('fresh.cluster_incarnation != serving.cluster_incarnation', api)
        self.assertIn('authorization.ensure_same_realm(&fresh)?', api)
        self.assertNotIn('PgRefStore.get(&tx', api)

        resolve = slice_between(self.adapter, 'pub(super) async fn resolve(', 'async fn resolve_admin(')
        self.assertIn('lookup_public_operation_status', resolve)
        self.assertIn('Ok(PublicOperationStatusLookup::Found(status)) => Ok(OperationRead::Public(status))', resolve)
        self.assertIn(
            'Ok(PublicOperationStatusLookup::Unknown | PublicOperationStatusLookup::PrivateIdentifier)',
            resolve,
        )
        self.assertIn('Err(GatewayError::NotFound)', resolve)
        self.assertIn('PublicOperationStatusLookup::LegacyPath', resolve)
        self.assertIn('resolve_legacy_status(', resolve)
        self.assertNotIn('public_attempt_catalog_absent', resolve)
        self.assertNotIn('get_legacy_locked(', resolve)
        self.assertNotIn('private_conflict', resolve)

        status = slice_between(self.adapter, 'async fn resolve_legacy_status(', 'async fn effective_role(')
        self.assertEqual(status.count('get_legacy_status('), 1)
        self.assertNotIn('get_legacy_locked(', status)
        self.assertNotIn('get_inner(', status)
        self.assertIn('LegacyStatusLookup::Legacy(record) => record', status)
        self.assertIn(
            'LegacyStatusLookup::PublicWrapper => return Err(GatewayError::Conflict(OPERATION_CHANGED))',
            status,
        )
        self.assertIn(
            'LegacyStatusLookup::PrivateIdentifier | LegacyStatusLookup::Unknown',
            status,
        )
        self.assertIn('Err(GatewayError::NotFound)', status)
        self.assertLess(status.index('get_legacy_status('), status.index('effective_role('))

        lookup = slice_between(self.operation, 'pub(super) async fn lookup(', 'pub(super) async fn lookup_in_tx(')
        self.assertLess(lookup.index('lock_operation('), lookup.index('lookup_in_tx('))
        inner = slice_between(self.operation, 'pub(super) async fn lookup_in_tx(', '/// Query the immutable')
        self.assertIn('get_legacy_locked(', inner)
        self.assertNotIn('PgRefStore.get(tx', inner)

    def test_external_cancel_is_guarded_and_internal_reads_stay_raw(self):
        external = slice_between(self.cancel, 'async fn resolve_registered_operation(', '/// Public projection')
        self.assertIn('get_legacy_locked(', external)
        self.assertNotIn('PgRefStore.get(tx', external)
        final_read = slice_between(self.cancel, 'let final_record =',
                                   'if final_record.identity()')
        self.assertIn('PgRefStore.get(&tx', final_read)
        self.assertNotIn('get_legacy_locked', final_read)
        self.assertIn('legacy_identity_collision_keeps_the_fixed_conflict_refusal', self.publish)
        self.assertIn('operation identity conflicts with a durable record', self.publish)


if __name__ == '__main__':
    unittest.main()
