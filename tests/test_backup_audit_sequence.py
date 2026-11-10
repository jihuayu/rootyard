#!/usr/bin/env python3
"""Focused #7 oracle for the audit-sequence recovery drill.

Offline only: no binary, PostgreSQL, Git or Cargo runs here. These pin the pure
expectation model the native drill uses to judge restored audit IDs, and the
wiring that keeps the drill on real API audit writes, the ascending cursor, the
Git-vs-audit-log separation, the honestly labelled missing-default control,
and the source binding. They cannot stand in for the native run and never claim
it passed.
"""
import ast
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import backup_audit_sequence_legacy as drill  # noqa: E402
import source_bound_binary  # noqa: E402

DRILL = Path(__file__).with_name("backup_audit_sequence_legacy.py")


def sql_code(text):
    """Strip SQL comments and string literals, keeping structure and tokens."""
    text = re.sub(r"--[^\n]*", " ", text)
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"'(?:[^']|'')*'", "''", text)


def drill_method(name):
    tree = ast.parse(DRILL.read_text())
    klass = next(n for n in tree.body if isinstance(n, ast.ClassDef)
                 and n.name == "AuditSequenceLegacyHarness")
    return next(n for n in klass.body if isinstance(n, ast.FunctionDef) and n.name == name)


def method_source(name):
    return ast.get_source_segment(DRILL.read_text(), drill_method(name))


def executable(name):
    """The method without its docstring: only executable nodes remain."""
    method = drill_method(name)
    ast.fix_missing_locations(method)
    if ast.get_docstring(method) is not None:
        method.body = method.body[1:]
    return ast.unparse(method)


class NewAuditIdsModelTest(unittest.TestCase):
    def test_sequence_continues_above_every_pre_backup_id(self):
        self.assertEqual(drill.new_audit_ids([3, 9, 11], [3, 9, 11, 12], [12]), [12])

    def test_gaps_after_restore_are_allowed_but_walked_ids_must_exist(self):
        # A rolled-back write burns a sequence value: the gap is legal (#110).
        self.assertEqual(drill.new_audit_ids([1, 2], [1, 2, 4], [4]), [4])
        with self.assertRaisesRegex(AssertionError, "differ from the IDs walked"):
            drill.new_audit_ids([1, 2], [1, 2, 3, 4], [4])

    def test_unwalked_new_row_is_rejected(self):
        # A row added but never observed through the cursor is not evidence.
        with self.assertRaisesRegex(AssertionError, "differ from the IDs walked"):
            drill.new_audit_ids([1], [1, 2, 3], [2])

    def test_rewound_id_is_rejected(self):
        with self.assertRaisesRegex(AssertionError, "rewound"):
            drill.new_audit_ids([1, 2, 10], [1, 2, 10, 3], [3])

    def test_reused_or_missing_rows_are_rejected(self):
        with self.assertRaisesRegex(AssertionError, "disappeared"):
            drill.new_audit_ids([1, 2, 3], [2, 3], [4])
        with self.assertRaisesRegex(AssertionError, "distinct"):
            drill.new_audit_ids([1], [1, 2, 3], [2, 2])
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
        self.assertIsNone(drill.numeric_version(""))
        self.assertEqual(drill.MIN_POSTGRES_VERSION, 17)


class DrillWiringTest(unittest.TestCase):
    def setUp(self):
        self.source = DRILL.read_text()

    def test_cases_are_registered_and_ordered(self):
        self.assertEqual(drill.CASES, (
            "setup", "setup_repos", "source_audit_writes_advance_sequence",
            "metadata_only_format_without_blob_service",
            "offline_backup_and_fresh_database_restore",
            "restored_http_audit_sequence_continues",
            "restored_concurrent_audit_sequence_continues",
            "restored_git_push_and_audit_events_recovery",
            "missing_default_control_has_no_sequence",
        ))
        for name in drill.CASES:
            self.assertTrue(callable(getattr(drill.AuditSequenceLegacyHarness, name, None)), name)

    def test_http_audit_write_uses_real_update_semantics(self):
        body = method_source("restored_http_audit_sequence_continues")
        # Bob exists (inherited collaborator); the update must send its version
        # and expect 200 collaborator.updated, never a create with version 1.
        self.assertNotIn('"version": 1', body)
        self.assertIn('bob["version"]', body)
        self.assertIn("self.document(self.authors_path, 200", body)
        self.assertIn('["collaborator.updated"]', body)
        # The API only reports that action when a row actually changed.
        self.assertIn('(StatusCode::OK, "collaborator.updated")',
                      (ROOT / "src/members/rbac.rs").read_text())

    def test_audit_walk_is_ascending_from_the_known_floor(self):
        body = method_source("audit_page")
        self.assertIn('"?after="', body)
        walk = method_source("walk_audit")
        self.assertIn("more == sorted(more)", walk)
        self.assertIn("value > after", walk)
        # The REST list orders ascending (audit.rs): a DESC assumption would
        # silently read the oldest page and self-certify.
        am = (ROOT / "src/members/audit.rs").read_text()
        self.assertIn("AND id > $3", am)
        self.assertIn("ORDER BY id ASC", am)
        for name in ("restored_http_audit_sequence_continues",
                     "restored_concurrent_audit_sequence_continues"):
            body = method_source(name)
            self.assertIn("self.walk_audit(", body)
            self.assertNotIn("?limit=1", body)

    def test_git_push_is_not_claimed_as_an_audit_sequence_step(self):
        push = method_source("restored_git_push_and_audit_events_recovery")
        self.assertIn("audit_events", push)
        self.assertIn("repository_audit_log", push)
        self.assertIn('"the restored Git push wrote repository_audit_log"', push)
        # Only real API audit writes are allowed to create audit-log rows.
        code = sql_code(self.source)
        self.assertIsNone(re.search(r"INSERT\s+INTO\s+repository_audit_log", code, re.I))
        # worker-once only drains the outbox consumers; no other CLI command may
        # settle a push journal or act as the audit writer for this drill.
        cli_args = {ast.unparse(call.args[0]) for call in ast.walk(ast.parse(self.source))
                    if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                    and call.func.attr == "cli"}
        # backup-verify only re-checks the archive bytes; it settles nothing.
        self.assertEqual(cli_args, {"'worker-once'", "'backup-verify'"})

    def test_control_is_labelled_missing_default_not_the_legacy_algorithm(self):
        body = method_source("missing_default_control_has_no_sequence")
        self.assertIn("DROP DEFAULT", body)
        self.assertIn('"replays_legacy_max_id_algorithm": False', body)
        # The algorithm is named only as what the control does NOT reproduce;
        # no MAX(id)+1 computation may appear in executable code.
        self.assertIsNone(re.search(r"MAX\s*\(\s*id\s*\)\s*\+", executable(
            "missing_default_control_has_no_sequence"), re.I))
        self.assertIn("self.target_db", body)
        self.assertNotIn("self.source_db", body)
        self.assertNotIn("self.admin", body)
        self.assertIn("finally:", body)
        self.assertIn("MIGRATION_110.read_text()", body)

    def test_preflight_fails_instead_of_skipping(self):
        self.assertIsNone(re.search(r"skipTest|pytest\.skip|raise SkipTest", self.source))
        self.assertIn("raise SystemExit", self.source)
        self.assertIn("SHOW server_version_num", self.source)
        self.assertIn("source_bound_binary.bind(", self.source)

    def test_drill_stays_on_the_format21_gitfs_family(self):
        self.assertNotIn("serve-blob", self.source)
        self.assertIn("== 21", self.source)
        self.assertIn("blob_closure", self.source)


class SourceBindingTest(unittest.TestCase):
    def test_production_paths_are_the_build_digest_inputs(self):
        for path in ("Cargo.toml", "Cargo.lock", "src/main.rs", "migrations/110_audit_sequence.sql",
                     "schema/147_catalog.json", "vendor/x/y.rs", "build.rs"):
            self.assertTrue(source_bound_binary._production_path(path), path)
        for path in ("tests/backup_audit_sequence_legacy.py", "docs/x.md", "srcx/y.rs",
                     "tests/fixtures/x.c", "README.md"):
            self.assertFalse(source_bound_binary._production_path(path), path)

    def test_rename_reports_destination(self):
        self.assertTrue(source_bound_binary._production_path("tests/old.py -> src/new.rs"))
        self.assertFalse(source_bound_binary._production_path("src/old.rs -> tests/new.py"))

    def test_current_production_digest_matches_the_reviewed_builder(self):
        # The binding must use build_native.source_digest itself, not a copy.
        self.assertRegex(source_bound_binary.production_source_digest(), r"^[0-9a-f]{64}$")
        builder = (ROOT / "scripts/build_native.py").read_text()
        self.assertIn("for directory in ('src', 'migrations', 'schema', 'vendor')", builder)

    def test_missing_receipt_is_a_hard_binding_failure(self):
        with self.assertRaises(source_bound_binary.SourceBindingError):
            source_bound_binary.bind(ROOT / "target" / "does-not-exist-rootyard")


if __name__ == "__main__":
    unittest.main()
