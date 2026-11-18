"""Offline source checks for schema 152 slot-zero and late-cancellation evidence."""
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests/fixtures'
MIGRATION = ROOT / 'migrations/152_ref_store_public_attempts.sql'
if not MIGRATION.is_file():
    MIGRATION = FIXTURES / 'ref_store_public_attempts_migration_152.sql'


class LateCancellationSourceTest(unittest.TestCase):
    def test_slot_zero_fixture_reserves_after_mapping_and_requires_exact_binding(self):
        sql = (FIXTURES / 'ref_store_schema152_late_cancellation.sql').read_text()
        admission = sql.split('FOREACH scenario IN ARRAY', 1)[1].split('SET CONSTRAINTS ALL IMMEDIATE;', 1)[0]
        steps = [
            'rootyard_ref_store_lock_public_operation(repo, public_op, private_op)',
            "CASE WHEN scenario = 'pending' THEN 0 ELSE 2 END",
            'SELECT last_reserved_sequence + 1 INTO STRICT initial_sequence',
            'FOR UPDATE;',
            'INSERT INTO ref_store_public_operations',
            'INSERT INTO ref_store_private_attempts',
            'SET last_reserved_sequence = initial_sequence',
            'AND last_reserved_sequence = initial_sequence - 1',
            'VALUES (repo, issuer, scenario, initial_sequence, private_op, parent_digest,',
            'FOREACH wrong_wire IN ARRAY ARRAY[NULL::text, proof_digest]',
            'IF wrong_wire IS NOT NULL THEN',
            'VALUES (repo, private_op, issuer, wrong_wire, parent_digest)',
            'SET CONSTRAINTS ref_store_private_attempt_evidence IMMEDIATE;',
            'EXCEPTION WHEN check_violation THEN',
            "IF failed_constraint IS DISTINCT FROM 'ref_store_public_attempt_evidence' THEN RAISE; END IF;",
            'VALUES (repo, private_op, issuer, wire_digest, parent_digest)',
        ]
        positions = [admission.index(step) for step in steps]
        self.assertEqual(positions, sorted(positions))

    def test_wrapper_evidence_distinguishes_late_and_winning_tombstones(self):
        sql = MIGRATION.read_text()
        verifier = sql.split('CREATE FUNCTION rootyard_ref_store_verify_public_operation(', 1)[1].split('END $$;', 1)[0]
        self.assertIn('c.operation_id IS DISTINCT FROM k.operation_id AS tombstone_key_differs', verifier)
        self.assertIn('attempt.exact_tombstone IS NOT TRUE OR attempt.core_state = \'pending\'', verifier)
        self.assertIn('attempt.terminal_result IS DISTINCT FROM \'{"state":"cancelled","reason":"cancel_requested"}\'::jsonb', verifier)
        retired = verifier.split('OR (attempt.slot < wrapper.current_slot', 1)[1].split('OR (attempt.slot = wrapper.current_slot', 1)[0]
        self.assertIn('attempt.event_id IS DISTINCT FROM wrapper.retired_event_id', retired)
        self.assertNotIn('attempt.has_tombstone', retired)
        self.assertIn('attempt.event_id IS DISTINCT FROM wrapper.event_id', verifier)
        self.assertIn('attempt.payload IS DISTINCT FROM attempt.terminal_result', verifier)
        self.assertNotRegex(verifier, r'(?im)^\s*(UPDATE|INSERT INTO|DELETE FROM)\b')

    def test_legacy_cancel_trigger_resolves_both_keys_in_its_own_schema(self):
        sql = MIGRATION.read_text()
        trigger = sql.split('CREATE FUNCTION rootyard_ref_store_private_cancellation_evidence()', 1)[1]
        self.assertIn('SECURITY DEFINER SET search_path = pg_catalog, pg_temp', trigger)
        self.assertIn("format('pg_catalog, %I, pg_temp', TG_TABLE_SCHEMA)", trigger)
        self.assertIn('(NEW.repository_id, NEW.operation_id)', trigger)
        self.assertIn('(NEW.repository_id, NEW.issuer_id, NEW.lane, NEW.sequence)', trigger)
        self.assertIn('PERFORM rootyard_ref_store_verify_public_operation(NEW.repository_id, public_op)', trigger)
        self.assertIn('REVOKE EXECUTE ON FUNCTION rootyard_ref_store_private_cancellation_evidence() FROM PUBLIC;', trigger)
        self.assertRegex(trigger, r'AFTER INSERT OR UPDATE ON ref_store_cancellations\s+DEFERRABLE INITIALLY DEFERRED')

    def test_sql_fixture_flushes_the_tombstone_trigger_after_each_durable_winner(self):
        sql = (FIXTURES / 'ref_store_schema152_late_cancellation.sql').read_text()
        self.assertIn("ARRAY['committed', 'rejected', 'retired', 'cancelled', 'pending']", sql)
        self.assertIn("WHEN 'committed' THEN ARRAY['wrong_parent_digest', 'different_operation_at_lane']", sql)
        observed = re.findall(r'IS DISTINCT FROM (before_\w+)', sql)
        self.assertCountEqual(observed, ['before_operation', 'before_event', 'before_wrapper'])
        self.assertIn('SET CONSTRAINTS ref_store_private_cancellation_evidence IMMEDIATE;', sql)
        self.assertIn('SET LOCAL ROLE issue42_legacy_cancel_probe;', sql)
        self.assertTrue(sql.rstrip().endswith('ROLLBACK;'))


if __name__ == '__main__':
    unittest.main()
