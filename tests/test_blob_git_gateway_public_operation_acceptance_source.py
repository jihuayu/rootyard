"""Offline source checks for the owned public-operation GET acceptance case.

Pins the ignored owned database/Blob HTTP proof to the real production route and
the real slot-zero admission path. No database, Blob store, Cargo, service or
network is touched.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
TEST = ROOT / 'src/blob_git_gateway/session_http_acceptance/public_operation_tests.rs'
MOD = ROOT / 'src/blob_git_gateway/session_http_acceptance.rs'
DB = ROOT / 'tests/blob_gateway_support/db.rs'


class PublicOperationAcceptanceSourceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.test = TEST.read_text()
        cls.mod = MOD.read_text()
        cls.db = DB.read_text()

    def test_case_is_ignored_owned_and_bounded(self):
        self.assertIn('#[tokio::test]', self.test)
        self.assertIn('#[ignore = "requires real PostgreSQL with CREATEDB, S3-compatible Blob and native Git"]',
                      self.test)
        self.assertIn('mod public_operation_tests;', self.mod)
        self.assertIn('Db::setup_public_owned().await?', self.test)
        self.assertIn('db.finish(outcome).await', self.test)
        self.assertIn('NATIVE_ACCEPTANCE_SERIAL.lock().await', self.test)

    def test_ready_repository_and_roles_use_existing_support(self):
        for helper in ('Gateway::start', 'actor::owner', 'create_repository',
                       'provision_decision_realm', 'open_store', 'test_tokens'):
            self.assertIn(helper, self.test)

    def test_public_private_pair_uses_real_slot_zero_admission(self):
        self.assertIn('SlotZeroAdmissionRequest', self.test)
        self.assertIn('PgRefStore', self.test)
        self.assertIn('.admit_slot_zero_in_tx(', self.test)
        self.assertIn('build_plan(&request, preview, facts)', self.test)
        self.assertIn('tx.commit().await?', self.test)
        for fabricated in ('INSERT INTO ref_store_public_operations', 'INSERT INTO ref_store_private_attempts',
                           'INSERT INTO ref_store_operations'):
            self.assertNotIn(fabricated, self.test)
        self.assertIn('SELECT current_slot,state,event_id,retired_event_id', self.test)

    def test_route_is_real_http_and_checks_absent_pending_and_private(self):
        self.assertIn('reqwest::Client::new()', self.test)
        self.assertIn('client.get(&public_path)', self.test)
        self.assertIn('StatusCode::OK', self.test)
        self.assertIn('header::CACHE_CONTROL', self.test)
        self.assertIn('Some("no-store")', self.test)
        self.assertIn('body["state"] == json!("pending")', self.test)
        self.assertIn('body["terminal"].is_null()', self.test)
        self.assertIn('private identifier GET was not a conflict', self.test)
        self.assertIn('absent public id GET was not 404', self.test)
        self.assertIn('admit_pending_public(db, &gateway, &owner, &serving, public_id, private_id)', self.test)
        self.assertNotIn('status == 200 && terminal', self.test)

    def test_owned_public_schema_database_has_independent_cleanup(self):
        self.assertIn('pub async fn setup_public_owned()', self.db)
        self.assertIn('CREATE DATABASE {database}', self.db)
        self.assertIn('search_path=public', self.db)
        self.assertIn('version=152', self.db)
        self.assertIn('DROP DATABASE {database}', self.db)
        self.assertIn('owned_database: Some(database)', self.db)
        self.assertIn("ensure!(installed", self.db)


if __name__ == '__main__':
    unittest.main()
