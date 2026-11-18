"""Offline checks for the crate-private public operation status contract.

This pins the GET-side boundary only: repository plus public id, no guessed push
wire/mode/private identity, one shared bounded snapshot/schema/deadline, the
same current/retired/realm/terminal proof as the request-aware lookup, no raw
terminal JSON, and no new write path. No database, Cargo, rustc or service runs.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'src/ref_store/pg/public_attempt.rs'


def slice_between(source, start, end):
    return source.split(start, 1)[1].split(end, 1)[0]


class PublicOperationStatusSourceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_text()

    def test_status_request_carries_only_repository_public_id_and_auth(self):
        request = slice_between(
            self.source,
            'pub(crate) struct PublicOperationStatusRequest {',
            'impl PublicOperationStatusRequest {')
        self.assertIn('pub repository_id: Uuid', request)
        self.assertIn('pub public_id: Uuid', request)
        self.assertIn('pub authorization: PublicOperationReadAuthorization', request)
        for forbidden in ('wire_digest', 'request_mode', 'backend_identity', 'private_id',
                          'lane:', 'sequence:', 'terminal'):
            self.assertNotIn(forbidden, request)

    def test_status_result_never_exposes_private_ids_or_terminal_payload(self):
        status = slice_between(self.source, 'pub(crate) struct PublicOperationStatus {',
                               'impl fmt::Debug for PublicOperationStatus {')
        self.assertIn('pub public_id: Uuid', status)
        self.assertIn('pub state: OperationState', status)
        for forbidden in ('private_id', 'plan_digest', 'proof_digest', 'lane', 'sequence',
                          'terminal_result', 'terminal:'):
            self.assertNotIn(forbidden, status)
        lookup = slice_between(self.source, 'pub(crate) enum PublicOperationStatusLookup {',
                               'impl fmt::Debug for PublicOperationStatusLookup {')
        for marker in ('Unknown', 'PrivateIdentifier', 'LegacyPath', 'Forbidden', 'Found'):
            self.assertIn(marker, lookup)

    def test_status_and_request_lookup_share_one_bounded_snapshot(self):
        reader = slice_between(self.source, 'async fn read_public_snapshot(',
                               'fn validate_request(')
        self.assertEqual(reader.count('SCHEMA_PROBE'), 1)
        self.assertEqual(reader.count('SELECT_SNAPSHOT'), 1)
        self.assertGreaterEqual(reader.count('bound(tx, deadline)'), 2)
        self.assertIn('.query_one(SELECT_SNAPSHOT', reader)
        for forbidden in ('tx.execute', 'INSERT ', 'UPDATE ', 'DELETE ', 'COMMIT', 'BEGIN'):
            self.assertNotIn(forbidden, reader)

        attempt = slice_between(self.source, 'async fn lookup_public_attempt_checked(',
                                '/// Resolve only the current public operation state')
        self.assertIn('read_public_snapshot(tx, request.repository_id, request.public_id, deadline)', attempt)
        self.assertIn('evaluate(snapshot, request)', attempt)
        status = slice_between(self.source, 'async fn lookup_public_operation_status_checked(',
                               '/// Read the one bounded schema probe')
        self.assertIn('read_public_snapshot(tx, request.repository_id, request.public_id, deadline)', status)
        self.assertIn('evaluate_status(snapshot, request)', status)

    def test_request_aware_lookup_keeps_its_digest_and_mode_comparisons(self):
        wrapper = slice_between(self.source, 'pub(super) fn validate_wrapper(',
                                'fn validate_wrapper_shape(')
        self.assertIn('parse_wrapper_identity(wrapper)', wrapper)
        self.assertIn('stored.wire_digest != request.wire_digest', wrapper)
        self.assertIn('stored.request_mode != request.request_mode', wrapper)
        self.assertIn('stored.object_format != request.object_format', wrapper)
        self.assertIn('RefStoreError::DigestConflict', wrapper)
        self.assertIn('RefStoreError::IdentityConflict', wrapper)

    def test_status_reuses_shape_realm_and_current_retired_proofs(self):
        status = slice_between(self.source, 'fn evaluate_status(',
                               'fn evaluate(snapshot: RawSnapshot')
        self.assertIn('parse_wrapper_identity(&wrapper)', status)
        self.assertIn('validate_wrapper_shape(&wrapper, &stored)', status)
        self.assertIn('snapshot.realm_matches', status)
        self.assertIn('stale_realm()', status)
        self.assertIn('validate_current_attempts(&snapshot, &wrapper, state)', status)
        self.assertIn('PublicOperationStatusLookup::PrivateIdentifier', status)
        self.assertIn('PublicOperationStatusLookup::LegacyPath', status)
        self.assertIn('PublicOperationStatusLookup::Forbidden', status)
        self.assertIn('issuer_id != wrapper.issuer_id', status)
        self.assertIn('PublicOperationStatus { public_id: evidence.public_id, state }', status)

        proof = slice_between(self.source, 'fn validate_current_attempts(',
                              '/// The stored immutable identity')
        for shared in ('validate_attempt(', 'validate_current(', 'validate_retired(',
                       'retired_raw', 'private identifier'):
            self.assertIn(shared, proof)

    def test_status_has_no_handler_or_write_path(self):
        status = slice_between(self.source, 'pub(crate) async fn lookup_public_operation_status(',
                               'async fn lookup_public_operation_status_checked(')
        for forbidden in ('axum', 'Router', 'INSERT', 'UPDATE', 'DELETE', 'SET TRANSACTION',
                          'synchronous_commit', 'advisory', 'FOR UPDATE', 'commit()', 'rollback()'):
            self.assertNotIn(forbidden, status)
        self.assertIn('timeout_at(deadline', status)


if __name__ == '__main__':
    unittest.main()
