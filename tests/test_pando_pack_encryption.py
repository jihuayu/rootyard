from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent.parent


class PandoPackEncryptionContractTests(unittest.TestCase):
    def test_synthetic_mode_is_explicitly_labeled_and_authenticated_default(self):
        crypto = (ROOT / "src" / "pando_lab" / "lifecycle" / "crypto.rs").read_text(encoding="utf-8")
        self.assertIn('AUTHENTICATED_ENVELOPE_MODE: &str = "authenticated-envelope-v1"', crypto)
        self.assertIn('SYNTHETIC_METADATA_MODE: &str = "synthetic-metadata-lab-only"', crypto)

        envelopes = (ROOT / "src" / "pando_lab" / "lifecycle" / "envelopes.rs").read_text(encoding="utf-8")
        self.assertIn("synthetic metadata-only lab envelope", envelopes)

        obj_store = (ROOT / "src" / "pando_lab" / "object_store.rs").read_text(encoding="utf-8")
        self.assertIn("AUTHENTICATED_ENVELOPE_MODE", obj_store)

    def test_kms_schema_tables_and_lifecycle_submodules_bounded(self):
        schema_sql = (ROOT / "experimental" / "pando" / "schema.sql").read_text(encoding="utf-8")
        for table in (
            "CREATE TABLE IF NOT EXISTS pando_lab.kms_keys",
            "CREATE TABLE IF NOT EXISTS pando_lab.kms_key_policies",
            "CREATE TABLE IF NOT EXISTS pando_lab.kms_rotations",
        ):
            self.assertIn(table, schema_sql)
        self.assertNotIn("between", schema_sql.lower())
        self.assertNotIn("bigserial", schema_sql.lower())

        lifecycle_rs = ROOT / "src" / "pando_lab" / "lifecycle.rs"
        lifecycle_lines = len(lifecycle_rs.read_text(encoding="utf-8").splitlines())
        self.assertGreaterEqual(lifecycle_lines, 120)
        self.assertLess(lifecycle_lines, 450)

        for sub in (ROOT / "src" / "pando_lab" / "lifecycle").glob("*.rs"):
            sub_lines = len(sub.read_text(encoding="utf-8").splitlines())
            self.assertLess(sub_lines, 500, f"{sub} exceeds 500 lines ({sub_lines})")
            self.assertNotIn("unsafe ", sub.read_text(encoding="utf-8"))

    def test_cli_http_and_e2e_harness_wire_kms_operations(self):
        mod_rs = (ROOT / "src" / "pando_lab" / "mod.rs").read_text(encoding="utf-8")
        for cmd in (
            'Some("kms-rotate")',
            'Some("kms-status")',
            'Some("kms-verify")',
            'Some("kms-revoke-key")',
            'Some("kms-revoke-provider")',
            'Some("kms-grant-provider")',
            'Some("kms-policy")',
        ):
            self.assertIn(cmd, mod_rs)

        http_rs = (ROOT / "src" / "pando_lab" / "http.rs").read_text(encoding="utf-8")
        self.assertIn('tail == "kms"', http_rs)
        self.assertIn('tail == "kms/rotate"', http_rs)

        pando_lab_py = (ROOT / "tests" / "pando_lab.py").read_text(encoding="utf-8")
        self.assertIn("authenticated_pack_encryption_and_kms_rotation", pando_lab_py)
        self.assertIn("synthetic-metadata-lab-only", pando_lab_py)


if __name__ == "__main__":
    unittest.main()
