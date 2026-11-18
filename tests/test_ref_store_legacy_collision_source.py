"""Offline checks for migration-152 legacy UUID collision refusal.

This pins the five bff76bee paths against the current later source: reserve,
begin and cancel take the migration-138 key before probing migration 152;
external legacy get/replay probes use the guarded lookup; the raw core get
remains internal; pre-152 catalogs stay independent; and HTTP authorization
checks happen after the operation key is held. No database, Cargo or service
is touched.
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
        guarded = slice_between(self.pg, 'pub(crate) async fn get_legacy_locked(', 'async fn get_inner(')
        self.assertLess(guarded.index('bound(tx, deadline)'), guarded.index('refuse_legacy_collision'))
        self.assertLess(guarded.index('refuse_legacy_collision'), guarded.index('self.get_inner('))

    def test_http_get_and_receive_probe_take_the_operation_key_first(self):
        api = slice_between(self.api, 'let loaded: Result<OperationRead', 'let _ = tokio::time::timeout_at')
        self.assertLess(api.index('lock_operation('), api.index('lookup_in_tx('))
        self.assertLess(api.index('lock_operation('), api.index('operation_read::resolve('))
        self.assertNotIn('PgRefStore.get(&tx', api)
        self.assertIn('get_legacy_locked(', self.adapter)

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
