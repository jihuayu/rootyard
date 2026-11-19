"""Offline checks for the crate-private public operation status contract.

This pins the GET-side boundary only: repository plus public id, no guessed push
wire/mode/private identity, one shared bounded snapshot/schema/deadline, the
same current/retired/realm/terminal proof as the request-aware lookup, a
GET-only bounded typed terminal projection, and no new write path. No database,
Cargo, rustc or service runs.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'src/ref_store/pg/public_attempt.rs'
STATUS_TERMINAL = ROOT / 'src/ref_store/pg/public_attempt/status_terminal.rs'
STATUS_TESTS = ROOT / 'src/ref_store/pg/public_attempt/tests.rs'


def slice_between(source, start, end):
    return source.split(start, 1)[1].split(end, 1)[0]


class PublicOperationStatusSourceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_text()
        cls.status_terminal = STATUS_TERMINAL.read_text()
        cls.status_tests = STATUS_TESTS.read_text()

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
        self.assertIn('terminal: Option<Value>', status)
        self.assertIn('pub(crate) fn terminal(&self) -> Option<&Value>', status)
        for forbidden in ('private_id', 'plan_digest', 'proof_digest', 'lane', 'sequence',
                          'terminal_result', 'pub terminal'):
            self.assertNotIn(forbidden, status)
        lookup = slice_between(self.source, 'pub(crate) enum PublicOperationStatusLookup {',
                               'impl fmt::Debug for PublicOperationStatusLookup {')
        for marker in ('Unknown', 'PrivateIdentifier', 'LegacyPath', 'Forbidden', 'Found'):
            self.assertIn(marker, lookup)

    def test_status_and_request_lookup_share_one_bounded_snapshot(self):
        reader = slice_between(self.source, 'async fn read_public_snapshot_sql(',
                               'fn validate_request(')
        self.assertEqual(reader.count('SCHEMA_PROBE'), 1)
        self.assertGreaterEqual(reader.count('bound(tx, deadline)'), 2)
        self.assertIn('.query_one(sql,', reader)
        for forbidden in ('tx.execute', 'INSERT ', 'UPDATE ', 'DELETE ', 'COMMIT', 'BEGIN'):
            self.assertNotIn(forbidden, reader)

        attempt = slice_between(self.source, 'async fn lookup_public_attempt_checked(',
                                '/// Resolve only the current public operation state')
        self.assertIn('read_public_snapshot(tx, request.repository_id, request.public_id, deadline)', attempt)
        self.assertIn('evaluate(snapshot, request)', attempt)
        status = slice_between(self.source, 'async fn lookup_public_operation_status_checked(',
                               '/// Read the ordinary request-aware snapshot')
        self.assertIn('read_public_status_snapshot(tx, request.repository_id, request.public_id, deadline)', status)
        self.assertIn('evaluate_status(snapshot, request)', status)
        self.assertIn('read_public_snapshot_sql(tx, SELECT_SNAPSHOT', self.source)
        self.assertIn('SELECT_STATUS_SNAPSHOT', self.source)
        self.assertIn('&transport_bound', self.source)

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
        self.assertIn('parse_wrapper_identity(wrapper)', status)
        self.assertIn('validate_wrapper_shape(wrapper, &stored)', status)
        self.assertIn('snapshot.realm_matches', status)
        self.assertIn('stale_realm()', status)
        self.assertIn('validate_current_attempts(&snapshot, wrapper, state, false)', status)
        self.assertIn('project_terminal(', status)
        self.assertIn('snapshot.status_terminal.as_ref()', status)
        self.assertIn('state, terminal', status)
        self.assertIn('PublicOperationStatusLookup::PrivateIdentifier', status)
        self.assertIn('PublicOperationStatusLookup::LegacyPath', status)
        self.assertIn('PublicOperationStatusLookup::Forbidden', status)
        self.assertIn('issuer_id != wrapper.issuer_id', status)

        proof = slice_between(self.source, 'fn validate_current_attempts(',
                              '/// The stored immutable identity')
        for shared in ('validate_attempt(', 'validate_current(', 'validate_retired(',
                       'retired_raw', 'private identifier'):
            self.assertIn(shared, proof)

    def test_get_only_terminal_projection_is_typed_bounded_and_payload_free_on_push(self):
        request_sql = slice_between(self.source, 'const SELECT_SNAPSHOT: &str = r#"', '"#;')
        status_sql = slice_between(self.status_terminal,
                                   'pub(super) const SELECT_STATUS_SNAPSHOT: &str = r#"', '"#;')
        self.assertNotIn('status_terminal', request_sql)
        self.assertNotIn('to_jsonb(o.terminal_result)', request_sql)
        self.assertIn("'status_terminal'", status_sql)
        self.assertIn('a.slot=w.current_slot', status_sql)
        self.assertIn('o.terminal_result', status_sql)
        for forbidden in ('pg_column_size', 'char_length', 'jsonb_pretty'):
            self.assertNotIn(forbidden, status_sql)
        for forbidden in (';', ' insert ', ' update ', ' delete ', ' for update', ' for share', 'pg_advisory'):
            self.assertNotIn(forbidden, status_sql.lower())

        projection = slice_between(self.status_terminal, 'pub(super) fn project_terminal(', 'fn cancelled_terminal')
        self.assertIn('TerminalResult::json(value.clone())', projection)
        self.assertIn('PackCommitTerminal', projection)
        self.assertIn('canonical != result.value()', projection)
        self.assertIn('validate_typed(', projection)
        self.assertNotIn('private_id', projection)
        self.assertNotIn('plan_digest', projection)
        self.assertNotIn('wire_digest', projection)
        validation = slice_between(self.status_terminal, 'fn validate_typed(', 'fn validate_ref_result')
        for check in ('typed.repository_id != repository_id', 'event_revision != Some(typed.revision)',
                      'PackMode::parse', 'RefName::branch', 'MAX_PLAN_REFS',
                      'MAX_BATCH_NEW_PACKS', 'is_canonical_hex_64', 'validate_rejection'):
            self.assertIn(check, validation)
        rejection = slice_between(self.status_terminal, 'fn validate_rejection(', '#[cfg(test)]' if '#[cfg(test)]' in self.status_terminal else self.status_terminal[-200:])
        self.assertIn('DenialCode::ALL', rejection)
        self.assertIn('admitted base was superseded', rejection)
        self.assertIn('no ref accepted', rejection)

    def test_status_sql_transport_bound_is_distinct_generous_and_fail_closed(self):
        status_sql = slice_between(self.status_terminal,
                                   'pub(super) const SELECT_STATUS_SNAPSHOT: &str = r#"', '"#;')
        self.assertIn('octet_length(o.terminal_result::text) <= $3::integer', status_sql)
        self.assertIn('octet_length(o.terminal_result::text) > $3::integer', status_sql)
        self.assertIn('ELSE NULL', status_sql)
        self.assertIn("'status_terminal_over_bound'", status_sql)
        self.assertIn('a.slot=w.current_slot', status_sql)
        self.assertNotIn('pg_column_size', status_sql)

        self.assertIn('pub(super) const STATUS_TERMINAL_TRANSPORT_BOUND_BYTES: i32 = 256 * 1024;',
                      self.status_terminal)
        self.assertGreater(256 * 1024, 64 * 1024)
        self.assertIn('&[&repository_id, &public_id, &transport_bound]', self.source)
        self.assertIn('snapshot.status_terminal_over_bound', self.source)
        self.assertIn('public terminal exceeds the bounded transport projection', self.source)
        self.assertNotIn('$3', slice_between(self.source, 'const SELECT_SNAPSHOT: &str = r#"', '"#;'))

        self.assertIn('fn status_terminal_projection_uses_the_compact_64k_bound', self.status_tests)
        self.assertIn('let dense = terminal_value(&dense);', self.status_tests)
        self.assertIn('len() < 64 * 1024', self.status_tests)
        self.assertIn('status_terminal_over_the_sql_transport_bound_fails_closed', self.status_tests)

    def test_status_has_no_handler_or_write_path(self):
        status = slice_between(self.source, 'pub(crate) async fn lookup_public_operation_status(',
                               'async fn lookup_public_operation_status_checked(')
        for forbidden in ('axum', 'Router', 'INSERT', 'UPDATE', 'DELETE', 'SET TRANSACTION',
                          'synchronous_commit', 'advisory', 'FOR UPDATE', 'commit()', 'rollback()'):
            self.assertNotIn(forbidden, status)
        self.assertIn('timeout_at(deadline', status)


if __name__ == '__main__':
    unittest.main()
