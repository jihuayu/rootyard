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
import tempfile
import unittest
from unittest import mock

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


def source(text, name):
    tree = ast.parse(text)
    klass = next(n for n in tree.body if isinstance(n, ast.ClassDef)
                 and n.name == "AuditSequenceLegacyHarness")
    node = next(n for n in klass.body if isinstance(n, ast.FunctionDef) and n.name == name)
    return ast.get_source_segment(text, node)


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


def audit_row(**overrides):
    row = {"id": 7, "tenant_id": "t-1", "repository_id": "r-1", "actor_id": "u-1",
           "actor_name": "alice", "action": "collaborator.added", "target_type": "collaborator",
           "target_name": "bob", "details": {"role": "triage", "version": 1},
           "created_unix": 1700000000, "created_at": "2026-11-10 06:00:00.123456+00"}
    row.update(overrides)
    return row


class AuditRowsByIdTest(unittest.TestCase):
    def test_identical_rows_pass_and_extra_rows_are_checked_too(self):
        rows = [audit_row(), audit_row(id=8, target_name="carol")]
        self.assertEqual(sorted(drill.audit_rows_by_id(rows, [dict(r) for r in rows])), [7, 8])
        after = rows + [audit_row(id=9, action="collaborator.updated")]
        # Added rows belong to new_audit_ids (the walked window): this
        # comparison only proves the captured rows are still there unchanged.
        with self.assertRaisesRegex(AssertionError, "appeared"):
            drill.audit_rows_by_id(rows, after)
        with self.assertRaisesRegex(AssertionError, "disappeared"):
            drill.audit_rows_by_id(after, rows)

    def test_re_attributed_or_rewritten_rows_fail(self):
        rows = [audit_row()]
        for field, value in (("tenant_id", "t-2"), ("repository_id", "r-2"), ("actor_id", "u-2"),
                             ("actor_name", "bob"), ("created_at", "2026-11-10 06:00:00.123457+00"),
                             ("details", {"role": "admin", "version": 1}), ("created_unix", 1)):
            with self.assertRaisesRegex(AssertionError, "changed \\[\\'" + field + "'"):
                drill.audit_rows_by_id(rows, [audit_row(**{field: value})])

    def test_lost_or_duplicate_ids_fail(self):
        rows = [audit_row(), audit_row(id=8)]
        with self.assertRaisesRegex(AssertionError, "disappeared"):
            drill.audit_rows_by_id(rows, [rows[0]])
        with self.assertRaisesRegex(AssertionError, "duplicate audit id"):
            drill.audit_rows_by_id(rows, [rows[0], dict(rows[0])])

    def test_columns_cover_every_identity_field(self):
        columns = drill.AUDIT_COLUMNS.split(",")
        self.assertEqual(columns, ["id", "tenant_id", "repository_id", "actor_id", "actor_name",
                                   "action", "target_type", "target_name", "details",
                                   "created_unix", "created_at"])
        # The model must be the table's own column list, not a subset.
        ddl = (ROOT / "migrations/050_members_rbac.sql").read_text()
        table = ddl[ddl.index("CREATE TABLE repository_audit_log ("):]
        table = table[:table.index(");")]
        declared = re.findall(r"^\s{4}(\w+)\s+(?:BIGINT|UUID|TEXT|JSONB|TIMESTAMPTZ)", table, re.M)
        self.assertEqual(sorted(declared), sorted(columns))

    def test_restore_uses_the_full_row_comparison(self):
        body = method_source("offline_backup_and_fresh_database_restore")
        self.assertIn("audit_rows_by_id(self.snapshot_rows, self.restored_rows)", body)
        self.assertIn("self.restored_tenants == [alice_tenant]", body)
        self.assertIn('self.restored_actors == ["alice"]', body)
        # Writes after the restore add rows legally, so a full-set comparison
        # would fail for the wrong reason: original ids are compared as exact
        # rows and the added ids are returned to be bound to the walked window.
        for name in ("restored_http_audit_sequence_continues",
                     "restored_concurrent_audit_sequence_continues"):
            body = method_source(name)
            self.assertIn("audit_subrows_by_id(", body)
            self.assertNotIn("audit_rows_by_id(self.restored_rows, after)", body)


class AuditSubrowsByIdTest(unittest.TestCase):
    def test_added_rows_are_returned_and_originals_are_compared_in_full(self):
        rows = [audit_row(), audit_row(id=8, target_name="carol")]
        after = [dict(row) for row in rows] + [audit_row(id=9, action="collaborator.updated")]
        self.assertEqual(drill.audit_subrows_by_id(rows, after), [9])
        self.assertEqual(drill.audit_subrows_by_id(rows, rows), [])
        # The original ids keep the full-row check even when new rows exist.
        rewritten = [dict(rows[0], actor_name="bob"), rows[1], after[2]]
        with self.assertRaisesRegex(AssertionError, "changed \\['actor_name'\\]"):
            drill.audit_subrows_by_id(rows, rewritten)
        with self.assertRaisesRegex(AssertionError, "disappeared"):
            drill.audit_subrows_by_id(rows, [rows[0], after[2]])
        with self.assertRaisesRegex(AssertionError, "duplicate audit id"):
            drill.audit_subrows_by_id(rows, after + [dict(after[2])])


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
        # Bob's triage grant is a real source POST; restore must see it, and the
        # update goes through the PUT helper with the live version and 200.
        self.assertIn('for name in ("bob", "carol", "dave")', source(self.source, "setup"))
        self.assertIn('self.collaborator("bob")["role"] == "triage"', body)
        self.assertIn("self.triage_negative(", body)
        self.assertIn('self.update_collaborator("bob", "maintain")', body)
        self.assertNotIn('"version": 1', body)
        self.assertNotIn("kept", body)
        helper = method_source("update_collaborator")
        self.assertIn('self.document(self.authors_path + "/" + name, 200', helper)
        self.assertIn('"expected_version": current["version"]', helper)
        # The API only reports that action when a row actually changed.
        self.assertIn('(StatusCode::OK, "collaborator.updated")',
                      (ROOT / "src/members/rbac.rs").read_text())

    def test_triage_negatives_use_distinct_valid_refs_and_real_writes(self):
        helper = method_source("triage_negative")
        # Same-branch pulls are refused as 400 before the role gate: the
        # negative must use two distinct, valid branch names to be a 403.
        self.assertIn('"head_ref": "refs/heads/main"', helper)
        self.assertIn('"base_ref": "refs/heads/triage-base"', helper)
        models = (ROOT / "src/pulls/models.rs").read_text()
        self.assertIn('!s.contains("..")', models)
        self.assertIn('(12..=1024).contains(&s.len())', models)
        handlers = (ROOT / "src/pulls/handlers.rs").read_text()
        self.assertLess(handlers.index("if head_ref == base_ref {"),
                        handlers.index("auth::authorize_repo_with_role(&tx, &actor, &owner, &name,"
                                       " auth::Role::Write"))
        # Bob holds a triage grant on demo only: both writes use demo, never
        # the planned "ahead" repository where Bob has no grant.
        self.assertIn('self.document(self.repo_path("/issues"), 201, token=self.bob', helper)
        self.assertIn('self.document(self.repo_path("/pulls"), 403, token=self.bob', helper)
        self.assertNotIn('"ahead"', helper)
        self.assertIn("self.triage_negative(", source(self.source, "setup_repos"))
        # The REST create_issue handler records no audit row (only the web form
        # handler does), so the drill never expects issue.created from REST.
        forge = (ROOT / "src/forge/handlers.rs").read_text()
        rest = forge[forge.index("pub async fn create_issue("):]
        rest = rest[:rest.index("pub async fn list_issues(")]
        self.assertNotIn("record_audit_event", rest)
        self.assertIn("record_audit_event", (ROOT / "src/web/handlers.rs").read_text())
        restored = method_source("restored_http_audit_sequence_continues")
        self.assertIn('["collaborator.updated"]', restored)
        self.assertIn('["alice"]', restored)
        self.assertIn("rest_triage_issue_audited", restored)
        source_case = method_source("setup_repos")
        self.assertIn("before_triage = self.audit_rows(self.db)", source_case)
        self.assertIn("self.pre_push_rows == before_triage", source_case)
        self.assertIn('"collaborator.added"] * 3', source_case)

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

    def test_concurrent_writes_use_unique_creates_and_the_saved_sequence(self):
        body = method_source("restored_concurrent_audit_sequence_continues")
        # One unique, previously absent branch per request: a shared main (or a
        # reused rule) would make every request after the first a 409.
        self.assertIn('"refs/heads/audit-race-" + os.urandom(4).hex()', body)
        self.assertIn("len(set(branches))", body)
        self.assertNotIn('"refs/heads/main"', body)
        self.assertIn('"branch_ref": branch_ref', body)
        # The known prefix is the source collaborator rows plus the restored
        # PUT (also collaborator.updated), not the source sequence alone, and
        # it is re-read and compared byte-identically after the race.
        self.assertIn("known == expected_prefix", body)
        self.assertIn("self.source_sequence + self.after_http_rows[len(self.restored_rows):]", body)
        self.assertNotIn("known == self.source_sequence", body)
        self.assertIn("self.action_sequence(self.target_db, self.saved_actions) == "
                      "self.prefix_sequence", body)
        self.assertNotIn("known + window == self.prefix_sequence", body)
        self.assertIn("self.walk_audit(self.http_floor, limit=7)", body)
        self.assertIn("audit_subrows_by_id(before_rows, after)", body)
        self.assertNotIn("audit_rows_by_id(self.restored_rows, after)", body)
        # The cursor is per repository, so its window equals demo's SQL rows.
        self.assertIn("walked == [value for value in demo_rows if value > self.http_floor]", body)
        self.assertIn("[row[\"id\"] for row in rows] == list(new)", body)
        self.assertIn(">= self.race_floor", body)
        # The saved prefix is captured on the source before any restore write.
        self.assertIn("self.source_sequence = self.action_sequence(self.db, self.saved_actions)",
                      method_source("source_audit_writes_advance_sequence"))
        # The restored PUT is a collaborator.updated too, so it must be part of
        # the saved action set the race prefix is selected with.
        self.assertIn('["collaborator.added", "collaborator.updated"]',
                      method_source("source_audit_writes_advance_sequence"))
        self.assertEqual(drill.new_audit_ids([1, 2], [1, 2, 4], [4], expected=1), [4])
        with self.assertRaisesRegex(AssertionError, "expected 1"):
            drill.new_audit_ids([1], [1, 2, 3], [2, 3], expected=1)

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


class PartialConstructionCleanupTest(unittest.TestCase):
    """A failed construction must drop only the databases it created.

    Exercises the real ``BackupHarness.__init__`` on the drill's own subclass
    with a stubbed query layer: no PostgreSQL is touched here.
    """

    class _Args:
        def __init__(self, root):
            self.binary = "/nonexistent/rootyard"
            self.keep = True
            self.root = Path(root)

    def build(self, root, databases_by_admin, failing_admin):
        import backup

        args = self._Args(root)
        calls = []
        harness = object.__new__(drill.AuditSequenceLegacyHarness)

        def fake_init(self, _args):
            import tempfile
            self.args = _args
            self.root = Path(tempfile.mkdtemp(prefix="rootyard-e2e-"))
            self.schema = "rootyard_e2e_probe"
            self.base_db = "postgres://admin/a"
            self.env = {"DATABASE_URL": "unchanged", "ROOTYARD_DATA_DIR": str(self.root / "data")}
            self.secrets, self.results, self.limits = [], [], []
            self.proc = None

        def fake_query(self, admin, sql):
            calls.append((admin, sql))
            if sql.startswith("CREATE"):
                name = sql.split('"')[1]
                if admin == failing_admin:
                    raise AssertionError("simulated CREATE failure on the restore server")
                databases_by_admin.setdefault(admin, set()).add(name)
                return ""
            for name in sql.split('"')[1:2]:
                databases_by_admin.get(admin, set()).discard(name)
            return ""

        with mock.patch.object(backup.Harness, "__init__", fake_init), \
                mock.patch.object(backup.BackupHarness, "query", fake_query), \
                mock.patch.dict("os.environ", {"ROOTYARD_RESTORE_TEST_DATABASE_URL": failing_admin}):
            try:
                drill.AuditSequenceLegacyHarness(args)
            except AssertionError as error:
                self.assertIn("simulated CREATE failure", str(error))
            else:
                self.fail("construction must surface the second CREATE failure")
        return harness, calls

    def test_first_database_is_dropped_and_the_foreign_one_is_never_touched(self):
        with tempfile.TemporaryDirectory() as root:
            owned, calls = self.build(root, {"postgres://admin/a": {"other_developer_db"}},
                                      "postgres://admin/b")
            # The first (owned) database was created on admin/a and dropped there.
            created = [sql for _, sql in calls if sql.startswith("CREATE")]
            dropped = [sql for _, sql in calls if sql.startswith("DROP")]
            self.assertEqual(len(created), 2)
            self.assertEqual(len(dropped), 1, calls)
            self.assertIn(created[0].split('"')[1], dropped[0])
            self.assertTrue(all("other_developer_db" not in sql for _, sql in calls), calls)
            # Only the restore server's CREATE failed; nothing else was dropped.
            self.assertFalse([sql for admin, sql in calls if admin == "postgres://admin/b"
                              and sql.startswith("DROP")])


if __name__ == "__main__":
    unittest.main()
