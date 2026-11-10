#!/usr/bin/env python3
"""Focused static tests for the genuine format4/schema007 restore relation set.

Static/unit only: no native binary, PostgreSQL or Cargo is required. The
genuine archive is produced by the pinned schema007 binary
(08b10e9976c012343c48e4fd6a5981e0266b8c53) and its manifest schema_versions are
`[1, 2, 3, 6, 7]`, so `repository_audit_log` (migration 050) and
`organization_audit_log` (migration 120) do not exist yet. Restore must still
accept the exact relations that archive declares and must not accept anything
else for any other format.
"""
import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
FORMAT4_SEQUENCES = ("organization_audit_log_id_seq", "repository_audit_log_id_seq")


def relations(fixture):
    value = json.loads((ROOT / "schema" / fixture).read_text())
    return sorted(item["name"] for item in value["tables"] if item["kind"] in "rpvmfS")


class Format4RestoreRelationsTest(unittest.TestCase):
    def test_format4_catalog_predates_the_audit_log_columns(self):
        # The genuine archive can never contain a table that these later
        # migrations create; this is why the leftover sequences must be
        # expected explicitly rather than discovered from the running binary.
        for version in (50, 110, 120):
            self.assertTrue((ROOT / "migrations").glob(f"{version:03d}_*.sql"), version)
        legacy = relations("007_catalog.json")
        self.assertNotIn("repository_audit_log", legacy)
        self.assertNotIn("organization_audit_log", legacy)
        self.assertFalse(set(FORMAT4_SEQUENCES) & set(legacy))

    def test_expected_format4_restore_relations_are_the_pinned_set(self):
        catalog_rs = (ROOT / "src/backup/catalog.rs").read_text()
        arm = re.search(r"\n\s*4\s*=>\s*\[(.*?)\n\s*\],", catalog_rs, re.S)
        self.assertIsNotNone(arm, "format4 catalog arm missing")
        fixtures = re.findall(r"schema/([A-Za-z0-9_]+\.json)", arm.group(1))
        self.assertEqual(fixtures, ["007_catalog.json", "007_restored_catalog.json", "007_upgraded_catalog.json"])
        for fixture in fixtures:
            restored = relations(fixture)
            expected = sorted(restored + list(FORMAT4_SEQUENCES))
            self.assertEqual(expected, sorted(set(expected)))
        backup_rs = (ROOT / "src/backup.rs").read_text()
        declared = re.search(r"const FORMAT4_RESTORE_SEQUENCES: &\[&str\] = &\[(.*?)\];", backup_rs)
        self.assertIsNotNone(declared, "FORMAT4_RESTORE_SEQUENCES missing in src/backup.rs")
        self.assertEqual(tuple(re.findall(r'"([a-z0-9_]+)"', declared.group(1))), FORMAT4_SEQUENCES)

    def test_relation_allowance_is_scoped_to_format4_opt_in(self):
        postgres_rs = (ROOT / "src/backup/postgres.rs").read_text()
        # Non-format4 expectations still have to equal the frozen catalog exactly.
        self.assertRegex(
            postgres_rs,
            r"let mut allowed = catalog::relations\(format, false\)\?;\s*if format == 4 \{\s*allowed\.extend\(FORMAT4_RESTORE_SEQUENCES",
            "only format 4 may extend the frozen relation set")
        self.assertRegex(postgres_rs, r"ensure!\(expected == allowed,")
        # The leftover declaration never relaxes the catalog projection.
        self.assertIn("schema_catalogs(format)?.contains(&actual)", postgres_rs)
        restore_rs = (ROOT / "src/backup/restore.rs").read_text()
        self.assertRegex(
            restore_rs,
            r"if allow_legacy_schema007 \{\s*//[^\n]*\n(?:\s*//[^\n]*\n)*\s*expected_relations\.extend\(FORMAT4_RESTORE_SEQUENCES",
            "the leftover sequences are expected only for the explicit schema007 opt-in")
        # Snapshot verification of a live format21 source stays exact.
        self.assertIn("catalog::relations(format, false)?).await?", (ROOT / "src/backup/snapshot.rs").read_text())

    def test_genuine_legacy_case_keeps_its_assertions(self):
        # The positive legacy test must still prove the restored schema007
        # version list before the reviewed upgrade; this fix does not skip,
        # remove or weaken it.
        checks = (ROOT / "tests/backup_ci_checkouts.py").read_text()
        self.assertIn("'--allow-legacy-schema007'", checks)
        self.assertIn("assert versions == '1,2,3,6,7'", checks)


if __name__ == "__main__":
    unittest.main()
