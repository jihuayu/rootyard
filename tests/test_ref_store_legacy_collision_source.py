"""Offline checks for migration-152 legacy UUID collision refusal.

This pins the five bff76bee paths against the current later source: reserve,
begin and cancel take the migration-138 key before probing migration 152;
external legacy get/replay probes use the guarded lookup; the raw core get
remains internal; pre-152 catalogs stay independent; the HTTP status read
keeps the collision guard without taking the operation key; and the receive
probe still takes that key before its HTTP authorization checks. No database,
Cargo or service is touched.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PG = ROOT / 'src/ref_store/pg.rs'
API = ROOT / 'src/blob_git_gateway/api.rs'
OPERATION = ROOT / 'src/blob_git_gateway/operation.rs'
CANCEL = ROOT / 'src/ref_store/core/pack_commit/authorized/cancel.rs'
PUBLISH = ROOT / 'src/blob_git_gateway/publish.rs'


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
            'pub(crate) async fn get_legacy_read(',
        )
        self.assertLess(guarded.index('bound(tx, deadline)'), guarded.index('refuse_legacy_collision'))
        self.assertLess(guarded.index('refuse_legacy_collision'), guarded.index('self.get_inner('))
        read = slice_between(self.pg, 'pub(crate) async fn get_legacy_read(', 'async fn get_inner(')
        self.assertLess(read.index('bound(tx, deadline)'), read.index('refuse_legacy_collision'))
        self.assertLess(read.index('refuse_legacy_collision'), read.index('self.get_inner('))
        self.assertNotIn('lock_operation', read)

    def test_http_status_read_is_unlocked_and_receive_probe_takes_the_operation_key(self):
        api = slice_between(self.api, 'let loaded: Result<(OperationLookup, Option<Role>)', 'let _ = tokio::time::timeout_at')
        self.assertNotIn('lock_operation(', api)
        self.assertNotIn('get_legacy_locked(', api)
        self.assertLess(api.index('lookup_in_tx('), api.index('get_legacy_read('))
        self.assertNotIn('PgRefStore.get(&tx', api)

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
