#!/usr/bin/env python3
"""Offline unit and contract tests for Track 1 (Pull Requests, Reviews, Check Runs, Branch Rules, Atomic Merge)."""
import ast
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import backup_pulls  # noqa: E402
import pulls  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]


class PullsTrack1ContractTest(unittest.TestCase):
    def test_pulls_module_layout_and_no_monolith(self):
        pulls_rs = ROOT / "src/pulls.rs"
        self.assertTrue(pulls_rs.is_file(), "src/pulls.rs must be a regular file")
        pulls_src = pulls_rs.read_text()
        pulls_lines = pulls_src.splitlines()
        self.assertLess(
            len(pulls_lines),
            100,
            f"src/pulls.rs should remain < 100 lines, got {len(pulls_lines)}",
        )
        self.assertIn("pub fn routes() -> Router<Arc<AppState>>", pulls_src)

        submodules = ("models", "handlers", "checks", "rules", "merge")
        for sub in submodules:
            self.assertIn(f"pub mod {sub};", pulls_src)
            sub_path = ROOT / "src/pulls" / f"{sub}.rs"
            self.assertTrue(sub_path.is_file(), f"Missing submodule {sub_path}")
            sub_lines = sub_path.read_text().splitlines()
            self.assertGreater(len(sub_lines), 50, f"{sub}.rs is unexpectedly small")
            self.assertLess(
                len(sub_lines),
                600,
                f"{sub}.rs exceeds modular size limit ({len(sub_lines)} lines)",
            )

        expected_routes = (
            "/api/repos/{owner}/{name}/pulls",
            "/api/repos/{owner}/{name}/pulls/{number}",
            "/api/repos/{owner}/{name}/pulls/{number}/diff",
            "/api/repos/{owner}/{name}/pulls/{number}/reviews",
            "/api/repos/{owner}/{name}/pulls/{number}/checks",
            "/api/repos/{owner}/{name}/pulls/{number}/merge",
            "/api/repos/{owner}/{name}/checks",
            "/api/repos/{owner}/{name}/commits/{oid}/checks",
            "/api/repos/{owner}/{name}/commits/{oid}/check-runs",
            "/api/repos/{owner}/{name}/branch-rules",
            "/api/repos/{owner}/{name}/branch-rules/{*branch}",
        )
        for route in expected_routes:
            self.assertIn(route, pulls_src, f"Route {route} missing from src/pulls.rs")

    def test_migration_009_sql_contract_and_no_between_variance(self):
        sql_path = pulls.migration_009_path()
        self.assertTrue(sql_path.is_file(), f"Missing SQL migration at {sql_path}")
        sql = sql_path.read_text()

        # Verify zero occurrences of BETWEEN to preserve pg_dump catalog invariance.
        self.assertIsNone(
            re.search(r"\bBETWEEN\b", sql, flags=re.IGNORECASE),
            "009_forge_pulls.sql must not use BETWEEN (use >= and <= for pg_dump invariance)",
        )

        tables = (
            "forge_pull_counters",
            "forge_pulls",
            "forge_pull_reviews",
            "forge_check_runs",
            "forge_branch_rules",
        )
        positions = {}
        for table in tables:
            match = re.search(rf"CREATE\s+TABLE\s+{table}\s*\(", sql)
            self.assertIsNotNone(match, f"Missing CREATE TABLE {table}")
            positions[table] = match.start()

        self.assertLess(
            positions["forge_pulls"],
            positions["forge_pull_reviews"],
            "forge_pulls must be created before forge_pull_reviews",
        )

        # Composite tenant foreign keys to repositories(id, owner_id).
        repo_fks = re.findall(
            r"FOREIGN KEY\s*\(\s*repository_id\s*,\s*tenant_id\s*\)\s*REFERENCES\s+repositories\s*\(\s*id\s*,\s*owner_id\s*\)",
            sql,
        )
        self.assertEqual(
            len(repo_fks),
            4,
            "Expected 4 composite repository FKs (counters, pulls, check_runs, branch_rules)",
        )
        self.assertIn(
            "FOREIGN KEY (tenant_id, repository_id, pull_number) REFERENCES forge_pulls(tenant_id, repository_id, number)",
            sql,
        )
        self.assertEqual(sql.count("CHECK (author_id = tenant_id)"), 2)
        self.assertIn("state IN ('open', 'closed', 'merged')", sql)
        self.assertIn("state IN ('approved', 'changes_requested', 'commented')", sql)
        self.assertIn("status IN ('queued', 'in_progress', 'completed')", sql)
        self.assertIn(
            "conclusion IN ('success', 'failure', 'neutral', 'cancelled', 'timed_out', 'skipped')",
            sql,
        )
        self.assertTrue(
            sql.strip().endswith(
                "INSERT INTO schema_migrations (version) VALUES (9);"
            ),
            "009_forge_pulls.sql must end with schema_migrations version 9 insert",
        )

    def test_shared_auth_and_git_reliability_invariants_in_rust_sources(self):
        models_src = (ROOT / "src/pulls/models.rs").read_text()
        handlers_src = (ROOT / "src/pulls/handlers.rs").read_text()
        checks_src = (ROOT / "src/pulls/checks.rs").read_text()
        rules_src = (ROOT / "src/pulls/rules.rs").read_text()
        merge_src = (ROOT / "src/pulls/merge.rs").read_text()

        self.assertGreaterEqual(models_src.count("#[serde(deny_unknown_fields)]"), 8)
        self.assertIn("#[cfg(test)]", models_src)

        for name, src in (
            ("handlers.rs", handlers_src),
            ("checks.rs", checks_src),
            ("rules.rs", rules_src),
            ("merge.rs", merge_src),
        ):
            self.assertIn("auth::authenticate", src, f"{name} must authenticate via auth::authenticate")
            self.assertIn("authorize(", src, f"{name} must authorize via auth::authorize_repo")
            self.assertIn("finish(", src, f"{name} must commit via auth::finish_tx")

        for required_merge_token in (
            "git_slots",
            "storage::ref_publication::acquire(",
            "publication.enter_window(",
            "storage::admission::acquire(",
            "publication.ensure_active()?",
            "reliability::before_gitfs_push(",
            "auth::verify_token(&tx, &actor, true)",
            "core.hooksPath=/dev/null",
            "update-ref",
            "--no-deref",
            "journal::begin(",
            "journal::finish(",
            "events::publish(",
            "state.dispatch.committed()",
            "journal::retire(",
        ):
            self.assertIn(
                required_merge_token,
                merge_src,
                f"merge.rs missing required reliability/Git token: {required_merge_token}",
            )

        self.assertRegex(
            rules_src,
            r"number\s*>\s*COALESCE\s*\(\s*\(\s*SELECT\s+max\(number\)\s+FROM\s+forge_pull_reviews\b[^;]*state\s*=\s*'changes_requested'",
            "rules.rs must only count approved reviews with number > max(number) of changes_requested on the same commit_oid",
        )
        self.assertIn(
            "drop(tx);",
            merge_src,
            "merge.rs must explicitly drop(tx) on the update-ref failure path before events::publish",
        )
        self.assertGreaterEqual(
            merge_src.count("drop(client);"),
            2,
            "merge.rs must drop(client) before events::publish on both error and success paths",
        )
        err_drop_idx = merge_src.index("drop(tx);")
        err_client_drop_idx = merge_src.index("drop(client);", err_drop_idx)
        first_publish_idx = merge_src.index("events::publish(")
        self.assertLess(err_drop_idx, first_publish_idx)
        self.assertLess(err_client_drop_idx, first_publish_idx)

    def test_e2e_and_backup_scripts_structure_and_harness_methods(self):
        pulls_py = ROOT / "tests/pulls.py"
        backup_pulls_py = ROOT / "tests/backup_pulls.py"
        pulls_src = pulls_py.read_text()
        backup_src = backup_pulls_py.read_text()
        ast.parse(pulls_src)
        ast.parse(backup_src)

        expected_pull_cases = (
            "setup",
            "migration",
            "lifecycle_and_diff",
            "reviews_and_head_binding",
            "checks_and_monotonic_ordering",
            "branch_rules_and_stale_invalidation",
            "atomic_merge_and_idempotency",
            "access_and_boundaries",
            "concurrency_and_pagination",
            "database_boundaries_and_rollback",
            "restart",
        )
        for method_name in expected_pull_cases:
            self.assertTrue(
                callable(getattr(pulls.PullsHarness, method_name, None)),
                f"PullsHarness missing method {method_name}",
            )

        expected_backup_cases = (
            "populated_pulls_source",
            "post_backup_mutations_not_in_snapshot",
            "restore_pulls_exact",
            "restored_pulls_access_and_post_restore_merge",
        )
        for method_name in expected_backup_cases:
            self.assertTrue(
                callable(getattr(backup_pulls.BackupPullsHarness, method_name, None)),
                f"BackupPullsHarness missing method {method_name}",
            )

        for script_name, script_src in (
            ("tests/pulls.py", pulls_src),
            ("tests/backup_pulls.py", backup_src),
        ):
            self.assertNotIn(
                'ops["items"]',
                script_src,
                f"{script_name} must not index /operations list response with ['items']",
            )
            self.assertIsNone(
                re.search(r'operations"\)\s*\[\s*"items"\s*\]', script_src),
                f"{script_name} must not index document('.../operations') with ['items']",
            )

        self.assertIn(
            'self.backup = self.root / "pulls-backup"',
            backup_src,
            "backup_pulls.py must assign a fresh self.backup path before calling self.backup_command()",
        )
        backup_assign_idx = backup_src.index('self.backup = self.root / "pulls-backup"')
        backup_cmd_idx = backup_src.index("self.backup_command()")
        self.assertLess(
            backup_assign_idx,
            backup_cmd_idx,
            "self.backup = self.root / 'pulls-backup' must precede self.backup_command() in populated_pulls_source",
        )

    def test_native_git_plumbing_for_pulls_diff_and_merge(self):
        env = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "LC_ALL": "C",
            "GIT_AUTHOR_NAME": "alice",
            "GIT_AUTHOR_EMAIL": "alice@rootyard.local",
            "GIT_COMMITTER_NAME": "alice",
            "GIT_COMMITTER_EMAIL": "alice@rootyard.local",
        }

        def run_git(*args, cwd=None, check=True):
            return subprocess.run(
                ["git", *args],
                cwd=cwd,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=check,
            )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bare = root / "repo.git"
            work = root / "work"
            run_git("init", "--bare", "--initial-branch=main", str(bare))
            run_git("clone", str(bare), str(work))

            (work / "README.md").write_text("rootyard\n")
            run_git("add", "README.md", cwd=work)
            run_git("commit", "-m", "base", cwd=work)
            base_oid = run_git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
            run_git("push", "origin", "HEAD:refs/heads/main", cwd=work)

            (work / "feature.txt").write_text("feature line\n")
            run_git("add", "feature.txt", cwd=work)
            run_git("commit", "-m", "feature", cwd=work)
            feat_oid = run_git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
            run_git("push", "origin", "HEAD:refs/heads/feature", cwd=work)

            # 1. Verify for-each-ref format used by resolve_ref_oid.
            ref_info = (
                run_git(
                    "--no-replace-objects",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "--git-dir",
                    str(bare),
                    "for-each-ref",
                    "--count=1",
                    "--format=%(objectname)%00%(objecttype)%00%(symref)",
                    "refs/heads/main",
                )
                .stdout.decode()
                .rstrip("\n")
            )
            self.assertEqual(ref_info.split("\0"), [base_oid, "commit", ""])

            missing_ref = run_git(
                "--no-replace-objects",
                "-c",
                "core.hooksPath=/dev/null",
                "--git-dir",
                str(bare),
                "for-each-ref",
                "--count=1",
                "--format=%(objectname)%00%(objecttype)%00%(symref)",
                "refs/heads/nonexistent",
            ).stdout
            self.assertEqual(missing_ref, b"")

            # 2. Verify cat-file -t, merge-base, and diff.
            obj_type = run_git(
                "--git-dir", str(bare), "cat-file", "-t", feat_oid
            ).stdout
            self.assertEqual(obj_type, b"commit\n")

            mb = (
                run_git(
                    "--git-dir", str(bare), "merge-base", base_oid, feat_oid
                )
                .stdout.decode()
                .strip()
            )
            self.assertEqual(mb, base_oid)

            diff_out = run_git(
                "--git-dir",
                str(bare),
                "diff",
                "--no-color",
                "--no-ext-diff",
                base_oid,
                feat_oid,
            ).stdout.decode()
            self.assertIn("+feature line", diff_out)

            # 3. Verify atomic CAS update-ref --no-deref rejects wrong old_oid and succeeds on exact old_oid.
            wrong_cas = run_git(
                "-c",
                "core.hooksPath=/dev/null",
                "--no-replace-objects",
                "--git-dir",
                str(bare),
                "update-ref",
                "--no-deref",
                "refs/heads/main",
                feat_oid,
                feat_oid,
                check=False,
            )
            self.assertNotEqual(wrong_cas.returncode, 0)

            good_cas = run_git(
                "-c",
                "core.hooksPath=/dev/null",
                "--no-replace-objects",
                "--git-dir",
                str(bare),
                "update-ref",
                "--no-deref",
                "refs/heads/main",
                feat_oid,
                base_oid,
            )
            self.assertEqual(good_cas.returncode, 0)

            # 4. Verify non-fast-forward merge-tree --write-tree and commit-tree.
            run_git("checkout", "--detach", base_oid, cwd=work)
            (work / "other.txt").write_text("other branch\n")
            run_git("add", "other.txt", cwd=work)
            run_git("commit", "-m", "other", cwd=work)
            other_oid = run_git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
            run_git("push", "origin", "HEAD:refs/heads/other", cwd=work)

            ff_check = run_git(
                "--git-dir",
                str(bare),
                "merge-base",
                "--is-ancestor",
                other_oid,
                feat_oid,
                check=False,
            )
            self.assertNotEqual(ff_check.returncode, 0)

            tree_oid = (
                run_git(
                    "--git-dir",
                    str(bare),
                    "merge-tree",
                    "--write-tree",
                    other_oid,
                    feat_oid,
                )
                .stdout.decode()
                .splitlines()[0]
                .strip()
            )
            self.assertEqual(len(tree_oid), 40)

            merge_commit_oid = (
                run_git(
                    "--git-dir",
                    str(bare),
                    "commit-tree",
                    tree_oid,
                    "-p",
                    other_oid,
                    "-p",
                    feat_oid,
                    "-m",
                    "Merge pull request #2",
                )
                .stdout.decode()
                .strip()
            )
            self.assertEqual(len(merge_commit_oid), 40)


if __name__ == "__main__":
    unittest.main()
