"""Offline source checks for the public UUID operation GET adapter.

Pins the gate-owned transaction order, live issuer/admin distinction, exact
legacy fallback probe and fixed refusals. No PostgreSQL, Cargo, service or
network is touched.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / 'src/blob_git_gateway/api.rs'
ADAPTER = ROOT / 'src/blob_git_gateway/operation_read.rs'
MOD = ROOT / 'src/blob_git_gateway/mod.rs'
PUBLIC = ROOT / 'src/ref_store/pg/public_attempt.rs'


def between(source, start, end):
    return source.split(start, 1)[1].split(end, 1)[0]


class PublicOperationReadSourceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api = API.read_text()
        cls.adapter = ADAPTER.read_text()
        cls.mod = MOD.read_text()
        cls.public = PUBLIC.read_text()

    def test_get_keeps_lock_then_fresh_lookup_then_capture_then_resolve(self):
        body = between(self.api, 'let loaded: Result<OperationRead, GatewayError> = async {',
                       'let _ = tokio::time::timeout_at(deadline, tx.rollback()).await;')
        markers = [
            'crate::ref_store::pg::lock_operation(&tx, repository_id, operation_id, deadline)',
            'crate::ref_store::serving::lookup_in_tx(',
            'fresh.cluster_incarnation != serving.cluster_incarnation',
            'authorization.ensure_same_realm(&fresh)?',
            'operation_read::resolve(&tx, &identity, repository_id, owner_id, operation_id, deadline)',
        ]
        positions = [body.index(marker) for marker in markers]
        self.assertEqual(positions, sorted(positions))
        self.assertIn('mod operation_read;', self.mod)
        self.assertIn('operation_read::resolve(', self.api)
        self.assertNotIn('PgRefStore.get(&tx', body)
        self.assertIn('[(header::CACHE_CONTROL, "no-store")]', self.api)
        handler = between(self.api, 'async fn get_operation_authorized(', 'let loaded:')
        self.assertEqual(handler.count('let backend = state.store().backend_identity();'), 1)
        self.assertEqual(handler.count('backend,'), 2)
        self.assertIn('backend,', body)

    def test_public_live_issuer_then_explicit_admin_in_same_transaction(self):
        body = between(self.adapter, 'pub(super) async fn resolve(', 'async fn resolve_admin(')
        self.assertIn('PublicOperationReadAuthorization::LiveIssuer', body)
        self.assertIn('issuer_id: identity.id', body)
        self.assertIn('PublicOperationStatusLookup::Found(status)', body)
        self.assertIn('PublicOperationStatusLookup::Unknown) => Err(GatewayError::NotFound)', body)
        self.assertIn('PublicOperationStatusLookup::PrivateIdentifier) => Err(private_conflict())', body)
        self.assertIn('PublicOperationStatusLookup::Forbidden)', body)
        self.assertIn('resolve_admin(', body)
        self.assertIn('resolve_legacy(', body)
        admin = between(self.adapter, 'async fn resolve_admin(', 'async fn resolve_legacy(')
        self.assertIn('effective_role(tx, repository_id, owner_id, identity.id, deadline)', admin)
        self.assertIn('PublicOperationReadAuthorization::RepositoryAdmin', admin)
        self.assertIn('lookup_public_operation_status(&**tx, &admin, deadline)', admin)

    def test_legacy_resolution_preserves_get_then_role_and_exact_message(self):
        legacy = between(self.adapter, 'async fn resolve_legacy(', 'async fn effective_role(')
        self.assertLess(legacy.index('get_legacy_locked('), legacy.index('effective_role('))
        self.assertIn('operation_visible(record.identity().issuer_id(), identity.id, role)', legacy)
        self.assertIn('operation is visible only to its issuer or a current repository admin', self.adapter)
        self.assertIn('operation identity conflicts with a durable record', self.adapter)

    def test_only_proven_missing_152_catalog_can_fall_back_to_legacy(self):
        body = between(self.adapter, 'pub(super) async fn resolve(', 'async fn resolve_admin(')
        self.assertIn('missing_public_schema(&error)', body)
        self.assertIn('public_attempt_catalog_absent(&**tx, deadline)', body)
        self.assertIn('if absent {', body)
        self.assertIn('Err(error.into())', body)
        self.assertIn('PUBLIC_ATTEMPT_SCHEMA_REQUIRED', self.adapter)
        self.assertIn('pack_commit::PackCommitError', self.adapter)
        self.assertNotIn('Unsupported(_)', body)

        probe = between(self.public, 'pub(crate) async fn public_attempt_catalog_absent(',
                        'fn validate_request(')
        self.assertIn("NOT EXISTS(SELECT 1 FROM schema_migrations WHERE version=152)", probe)
        self.assertIn("to_regclass('ref_store_public_operations') IS NULL", probe)
        self.assertIn("to_regclass('ref_store_private_attempts') IS NULL", probe)
        self.assertIn('rootyard_ref_store_attempt_has_binding', probe)
        self.assertIn("to_regprocedure(", probe)
        self.assertIn('pub(crate) const PUBLIC_ATTEMPT_SCHEMA_REQUIRED', self.public)
        self.assertIn('Unsupported(PUBLIC_ATTEMPT_SCHEMA_REQUIRED)', self.public)

    def test_read_adapter_has_no_write_or_retired_surface(self):
        for forbidden in ('INSERT', 'UPDATE', 'DELETE', 'synchronous_commit', 'cancel_known',
                          'begin_serving_pending', 'replay', 'declaration', 'commit()'):
            self.assertNotIn(forbidden, self.adapter)
        self.assertIn('enum OperationRead', self.adapter)
        self.assertIn('Public(PublicOperationStatus)', self.adapter)
        self.assertIn('Legacy(OperationRecord)', self.adapter)
        self.assertIn('private_conflict()', self.adapter)
        self.assertIn('operation_visibility_is_exact_issuer_or_current_admin', self.adapter)
        self.assertIn('only_the_exact_missing_schema_refusal_can_consider_legacy_fallback', self.adapter)


if __name__ == '__main__':
    unittest.main()
