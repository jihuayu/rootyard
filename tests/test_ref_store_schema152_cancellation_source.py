"""Offline source checks for the schema 152 late-cancellation contract."""
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests/fixtures'
MIGRATION = ROOT / 'migrations/152_ref_store_public_attempts.sql'
if not MIGRATION.is_file():
    MIGRATION = FIXTURES / 'ref_store_public_attempts_migration_152.sql'


class LateCancellationSourceTest(unittest.TestCase):
    def test_wrapper_evidence_distinguishes_late_and_winning_tombstones(self):
        sql = MIGRATION.read_text()
        verifier = sql.split('CREATE FUNCTION rootyard_ref_store_verify_public_operation(', 1)[1].split('END $$;', 1)[0]
        self.assertIn('c.operation_id IS DISTINCT FROM k.operation_id AS tombstone_key_differs', verifier)
        self.assertIn('attempt.exact_tombstone IS NOT TRUE OR attempt.core_state = \'pending\'', verifier)
        self.assertIn('attempt.terminal_result IS DISTINCT FROM \'{"state":"cancelled","reason":"cancel_requested"}\'::jsonb', verifier)
        retired = verifier.split('OR (attempt.slot < wrapper.current_slot', 1)[1].split('OR (attempt.slot = wrapper.current_slot', 1)[0]
        self.assertIn('attempt.event_id IS DISTINCT FROM attempt.retired_event_id', retired)
        self.assertIn('attempt.next_base IS DISTINCT FROM attempt.revision', retired)
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
