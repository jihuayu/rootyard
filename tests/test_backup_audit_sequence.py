#!/usr/bin/env python3
"""Focused #7 oracle for the legacy audit-sequence recovery drill.

Offline only: no binary, PostgreSQL, Git or Cargo runs here. These pin the
pure expectation model the native drill (``backup_audit_sequence_legacy.py``)
uses to judge restored audit IDs, and pin the wiring that keeps the drill on
the legacy format-21 stock-GitFS path with strict preflight. They cannot stand
in for the native run and never claim it passed.
"""
from pathlib import Path
import re
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import backup_audit_sequence_legacy as drill  # noqa: E402

def sql_literal(text):
    """A whole SQL string literal, so keywords inside literals never match."""
    return r"'(?:[^']|'')*'"


def sql_code(text):
    """Strip SQL comments and string literals, keeping structure and tokens."""
    text = re.sub(r"--[^\n]*", " ", text)
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(sql_literal(text), "''", text)


class NewAuditIdsModelTest(unittest.TestCase):
    def test_sequence_continues_above_every_pre_backup_id(self):
        self.assertEqual(drill.new_audit_ids([3, 9, 11], [3, 9, 11, 12], [12]), [12])

    def test_gaps_after_restore_are_allowed_but_returned_ids_must_exist(self):
        # A rolled-back write burns a sequence value: the gap is legal (#110).
        self.assertEqual(drill.new_audit_ids([1, 2], [1, 2, 4], [4]), [4])
        with self.assertRaisesRegex(AssertionError, "differ from API-returned"):
            drill.new_audit_ids([1, 2], [1, 2, 3, 4], [4])

    def test_rewound_id_is_rejected(self):
        with self.assertRaisesRegex(AssertionError, "rewound"):
            drill.new_audit_ids([1, 2, 10], [1, 2, 10, 3], [3])

    def test_reused_id_is_rejected(self):
        with self.assertRaisesRegex(AssertionError, "disappeared"):
            drill.new_audit_ids([1, 2, 3], [2, 3], [4])
        with self.assertRaisesRegex(AssertionError, "distinct"):
            drill.new_audit_ids([1], [1, 2, 3], [2, 2])

    def test_missing_pre_backup_row_is_rejected(self):
        with self.assertRaisesRegex(AssertionError, "disappeared"):
            drill.new_audit_ids([1, 2, 3], [1, 3, 4], [4])

    def test_empty_or_non_integer_evidence_is_rejected(self):
        with self.assertRaisesRegex(AssertionError, "before the backup"):
            drill.new_audit_ids([], [1], [1])
        with self.assertRaisesRegex(AssertionError, "integers"):
            drill.new_audit_ids([1], [1, "2"], ["2"])
        with self.assertRaisesRegex(AssertionError, "integers"):
            drill.new_audit_ids([1.0], [1.0, 2], [2])


class SettledOutcomesTest(unittest.TestCase):
    def test_unsettled_or_ambiguous_journal_is_never_a_pass(self):
        self.assertIsNone(drill.settled_outcomes([]))
        self.assertIsNone(drill.settled_outcomes(["recorded", "unknown"]))
        self.assertEqual(drill.settled_outcomes(["recorded", "no_ref_changes"]),
                         ["recorded", "no_ref_changes"])


class VersionGateTest(unittest.TestCase):
    def test_git_and_postgres_minimums(self):
        self.assertEqual(drill.numeric_version("git version 2.43.0"), (2, 43))
        self.assertEqual(drill.numeric_version("git version 2.54.0"), (2, 54))
        self.assertLess(drill.numeric_version("git version 2.42.1"), drill.MIN_GIT_VERSION)
        self.assertEqual(drill.numeric_version("psql (PostgreSQL) 17.11 (Homebrew)"), (17, 11))
        self.assertEqual(drill.numeric_version("") , None)
        self.assertEqual(drill.MIN_POSTGRES_VERSION, 17)


class DrillWiringTest(unittest.TestCase):
    def setUp(self):
        self.source = (Path(__file__).with_name("backup_audit_sequence_legacy.py")).read_text()

    def test_preflight_fails_instead_of_skipping(self):
        parser_error = re.compile(r"(pytest\.skip|self\.skipTest|unittest\.skip|raise SkipTest)")
        self.assertIsNone(parser_error.search(self.source))
        self.assertIn("raise SystemExit", self.source)
        self.assertIn('"ROOTYARD_TEST_DATABASE_URL"', self.source)
        self.assertIn('SHOW server_version_num', self.source)
        self.assertIn("build_record", self.source)

    def test_drill_stays_on_the_legacy_stock_gitfs_path(self):
        # No Blob serving service / object store: a paired format-22 archive
        # could never be produced or silently accepted by this drill.
        self.assertNotIn("serve-blob", self.source)
        self.assertNotIn("serve_blob", self.source)
        self.assertIn('== 21', self.source)
        self.assertIn("blob_closure", self.source)
        # The positive audit state is written through real HTTP, never SQL INSERT.
        code = sql_code(self.source)
        self.assertIsNone(re.search(r"INSERT\s+INTO\s+repository_audit_log", code, re.I))
        self.assertNotIn("\"worker-once\"", code)

    def test_control_only_touches_the_restored_run_owned_database(self):
        control = self.source[self.source.index("def legacy_replay_control_loses_sequence"):]
        body = control[:control.index("\n\n\ndef ")]
        self.assertIn("self.target_db", body)
        self.assertNotIn("self.source_db", body)
        self.assertNotIn("self.admin", body)
        self.assertIn("finally:", body)
        self.assertIn("MIGRATION_110.read_text()", body)

    def test_required_cases_stay_registered(self):
        self.assertEqual(drill.CASES, (
            "setup",
            "metadata_only_format_without_blob_service",
            "offline_backup_and_fresh_database_restore",
            "restored_http_audit_sequence_continues",
            "restored_concurrent_audit_sequence_continues",
            "restored_git_push_audit_sequence_continues",
            "legacy_replay_control_loses_sequence",
        ))
        for name in drill.CASES:
            self.assertTrue(callable(getattr(drill.AuditSequenceLegacyHarness, name, None)), name)

    def test_control_replays_the_real_migration_not_a_copy(self):
        migration = drill.MIGRATION_110.read_text()
        self.assertIn("repository_audit_log_id_seq", migration)
        self.assertIn("catalog::FORMAT", (ROOT / "src/backup/restore.rs").read_text())

    def test_preflight_rejects_missing_binary_before_any_dependency_probe(self):
        args = mock.Mock(binary=str(ROOT / "target" / "does-not-exist-rootyard"))
        with mock.patch.dict("os.environ", {"ROOTYARD_TEST_DATABASE_URL": "postgres://x/y"}), \
                mock.patch.object(drill.shutil, "which", return_value="/bin/true"), \
                mock.patch.object(drill, "subprocess_version", return_value="git version 9.9"):
            with self.assertRaises(SystemExit) as caught:
                drill.preflight(args)
        self.assertIn("no skip", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
