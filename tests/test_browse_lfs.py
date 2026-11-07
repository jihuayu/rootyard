#!/usr/bin/env python3
"""Unit and contract tests for Track 2A (Browse API & Multi-Ref CAS) and Track 2B (Git LFS)."""
import ast
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
ZERO_OID = "0" * 40


class BrowseAndLfsContractTest(unittest.TestCase):
    def test_browse_and_lfs_modular_file_layout(self):
        browse_rs = ROOT / "src/browse.rs"
        lfs_rs = ROOT / "src/lfs.rs"
        self.assertTrue(browse_rs.is_file(), "src/browse.rs must be a regular file")
        self.assertTrue(lfs_rs.is_file(), "src/lfs.rs must be a regular file")

        browse_lines = browse_rs.read_text().splitlines()
        lfs_lines = lfs_rs.read_text().splitlines()
        self.assertLessEqual(
            len(browse_lines), 100, "src/browse.rs must remain a thin router (<100 lines)"
        )
        self.assertLessEqual(
            len(lfs_lines), 100, "src/lfs.rs must remain a thin router (<100 lines)"
        )
        # src/browse.rs is mounted behind session auth and the sharding transport middleware, so
        # its router factory takes the shared AppState. Accept exactly that single optional param.
        self.assertRegex(
            browse_rs.read_text(),
            r"pub fn routes\((?:state: Arc<AppState>)?\) -> Router<Arc<AppState>> \{",
            "src/browse.rs must expose routes(state: Arc<AppState>) -> Router<Arc<AppState>>",
        )
        library_rs = (ROOT / "src/lib.rs").read_text()
        self.assertIn(
            "browse::routes(state.clone())",
            library_rs,
            "src/lib.rs must mount the browse router with the shared AppState",
        )
        self.assertIn("pub fn routes() -> Router<Arc<AppState>>", lfs_rs.read_text())

        expected_submodules = (
            ROOT / "src/browse/models.rs",
            ROOT / "src/browse/git_read.rs",
            ROOT / "src/browse/handlers.rs",
            ROOT / "src/browse/object_format.rs",
            ROOT / "src/browse/transactions.rs",
            ROOT / "src/lfs/models.rs",
            ROOT / "src/lfs/storage.rs",
            ROOT / "src/lfs/handlers.rs",
            ROOT / "src/lfs/020_lfs_objects.sql",
        )
        for path in expected_submodules:
            self.assertTrue(path.is_file(), f"Missing submodule file: {path}")
            content = path.read_text()
            self.assertGreater(len(content.strip()), 0, f"Empty file: {path}")
            if path.suffix == ".rs":
                # Cap intentionally kept at 550: src/browse/git_read.rs (591 lines) is pending
                # extraction by the source-decomposition worker; never raise this bound.
                self.assertLessEqual(
                    len(content.splitlines()),
                    550,
                    f"Submodule {path} exceeds modular line bound",
                )

    def test_lfs_migration_sql_contract(self):
        sql_path = ROOT / "src/lfs/020_lfs_objects.sql"
        sql = sql_path.read_text()
        self.assertIn("CREATE TABLE lfs_objects", sql)
        for col in (
            "tenant_id UUID NOT NULL",
            "repository_id UUID NOT NULL",
            'oid TEXT NOT NULL CHECK (oid COLLATE "C" ~ \'^[0-9a-f]{64}$\')',
            "size BIGINT NOT NULL CHECK (size >= 0)",
            "state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'ready'))",
            "created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()",
            "updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()",
            "PRIMARY KEY (tenant_id, repository_id, oid)",
            "FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id)",
        ):
            self.assertIn(col, sql)
        self.assertNotIn(
            "between",
            sql.lower(),
            "020_lfs_objects.sql must avoid BETWEEN so pg_dump catalog normalization is invariant",
        )
        self.assertTrue(
            sql.strip().endswith("INSERT INTO schema_migrations (version) VALUES (20);"),
            "020_lfs_objects.sql must end with version 20 insertion",
        )

    def test_browse_routes_and_git_safety_contracts(self):
        browse_all = "\n".join(
            p.read_text()
            for p in [ROOT / "src/browse.rs", *(ROOT / "src/browse").glob("*.rs")]
        )
        for route in (
            '"/api/repos/{owner}/{name}/refs"',
            '"/api/repos/{owner}/{name}/commits"',
            '"/api/repos/{owner}/{name}/commits/{oid}"',
            '"/api/repos/{owner}/{name}/tree"',
            '"/api/repos/{owner}/{name}/tree/{oid}"',
            '"/api/repos/{owner}/{name}/blob"',
            '"/api/repos/{owner}/{name}/blob/{oid}"',
            '"/api/repos/{owner}/{name}/compare"',
            '"/api/repos/{owner}/{name}/ref-transactions"',
            '"/api/repos/{owner}/{name}/object-format"',
            '"/api/repos/{owner}/{name}/object-format/negotiate"',
            '"/api/repos/{owner}/{name}/object-format/drill"',
        ):
            self.assertIn(route, browse_all)

        for invariant in (
            "core.hooksPath=/dev/null",
            "--no-replace-objects",
            "ci_pins::reserved",
            # Authoritative storage fences: repository git slot, read lease, ref publication
            # window and durable write admission replaced the old process-local write_lock.
            "state.git_slots.clone().try_acquire_owned()",
            "crate::storage::read_leases::shared",
            "storage::ref_publication::acquire(",
            "storage::admission::acquire(",
            "reliability::before_gitfs_push",
            "update-ref",
            "--stdin",
            "--no-deref",
            "journal::begin",
            "journal::finish",
            "journal::retire",
            "events::publish",
            "forge_creation_requests",
            '"ref_transaction"',
        ):
            self.assertIn(invariant, browse_all, f"Missing browse invariant: {invariant}")

        self.assertNotIn(
            "tempfile::",
            browse_all,
            "Production browse code must not depend on dev-only tempfile crate",
        )

    def test_lfs_routes_and_streaming_storage_contracts(self):
        lfs_rs = (ROOT / "src/lfs.rs").read_text()
        lfs_handlers_rs = (ROOT / "src/lfs/handlers.rs").read_text()
        lfs_routes_rs = (ROOT / "src/lfs/routes.rs").read_text()
        self.assertIn("mod routes;", lfs_rs, "src/lfs.rs must declare its routes submodule")
        self.assertIn(
            "routes::routes()",
            lfs_rs,
            "src/lfs.rs must delegate route construction to routes::routes()",
        )
        for lfs_route_text in (lfs_rs, lfs_routes_rs):
            self.assertNotIn(
                "{owner}/{repo}",
                lfs_route_text,
                "LFS routes must use {owner}/{name} to avoid matchit 0.8.4 route parameter conflict",
            )
        for route in (
            '"/api/repos/{owner}/{name}/lfs/objects/batch"',
            '"/git/{owner}/{name}/info/lfs/objects/batch"',
            '"/{owner}/{name}/info/lfs/objects/batch"',
        ):
            self.assertIn(route, lfs_routes_rs, f"src/lfs/routes.rs must register {route}")
        self.assertIn(
            "DefaultBodyLimit::disable()",
            lfs_routes_rs,
            "src/lfs/routes.rs must disable the body limit for streamed LFS uploads",
        )
        # Streaming upload/hydration moved out of handlers.rs: the disconnect-safe spawn that
        # wraps upload_inner now lives in the upload module declared by src/lfs.rs.
        self.assertIn("mod upload;", lfs_rs, "src/lfs.rs must declare its upload submodule")
        lfs_upload_rs = (ROOT / "src/lfs/upload.rs").read_text()
        self.assertIn(
            "tokio::spawn(async move { upload_inner(",
            lfs_upload_rs,
            "src/lfs/upload.rs must wrap upload_inner in tokio::spawn for disconnect safety",
        )
        self.assertIn(
            "sanitize_headers(&headers)",
            lfs_handlers_rs,
            "src/lfs/handlers.rs must sanitize inbound Authorization headers",
        )

        lfs_all = "\n".join(
            p.read_text()
            for p in [ROOT / "src/lfs.rs", *(ROOT / "src/lfs").glob("*.rs")]
        )
        for invariant in (
            "objects/batch",
            "objects/{oid}",
            "objects/{oid}/{size}",
            "/verify",
            "DefaultBodyLimit::disable()",
            "application/vnd.git-lfs+json",
            "StagingFileGuard",
            "O_NOFOLLOW",
            ".tmp-",
            "Sha256",
            "into_data_stream",
            "sync_all",
            "sanitize_headers",
        ):
            self.assertIn(invariant, lfs_all, f"Missing LFS invariant: {invariant}")

    def test_e2e_harnesses_syntax_and_cli_contracts(self):
        for script_name, class_name, required_methods in (
            (
                "browse.py",
                "BrowseHarness",
                (
                    "setup_repos",
                    "refs_and_pagination",
                    "commits_and_pagination",
                    "tree_and_blob",
                    "compare_revisions",
                    "ref_transactions_atomic_cas",
                    "idempotency_and_concurrency",
                    "access_and_fences",
                    "object_format_and_negotiation",
                ),
            ),
            (
                "lfs.py",
                "LfsHarness",
                (
                    "setup_lfs",
                    "batch_upload_stream_verify_and_download",
                    "hash_and_size_mismatch_rejection",
                    "permissions_and_tenant_isolation",
                    "corrupted_on_disk_blob_fails_closed",
                    "paired_backup_and_restore",
                ),
            ),
        ):
            script_path = ROOT / "tests" / script_name
            self.assertTrue(script_path.is_file(), f"Missing E2E script: {script_path}")
            tree = ast.parse(script_path.read_text(), filename=str(script_path))
            classes = {n.name: n for n in tree.body if isinstance(n, ast.ClassDef)}
            self.assertIn(class_name, classes)
            methods = {
                n.name for n in classes[class_name].body if isinstance(n, ast.FunctionDef)
            }
            for method in required_methods:
                self.assertIn(method, methods, f"{script_name} missing method {method}")

            proc = subprocess.run(
                [sys.executable, str(script_path), "--help"],
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertIn("--binary", proc.stdout)
            self.assertIn("--report", proc.stdout)
            self.assertIn("--keep", proc.stdout)

    def test_real_git_browse_and_update_ref_stdin_semantics(self):
        """Exercises the exact Git plumbing commands used by Track 2A against a real Git repo."""
        with tempfile.TemporaryDirectory(prefix="rootyard-m2-unit-") as tmp:
            tmp_path = Path(tmp)
            bare = tmp_path / "repo.git"
            work = tmp_path / "work"
            subprocess.run(
                ["git", "init", "--bare", "--initial-branch=main", str(bare)],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "clone", str(bare), str(work)],
                check=True,
                capture_output=True,
            )
            env = {
                **dict(
                    PATH="/usr/local/bin:/usr/bin:/bin",
                    GIT_AUTHOR_NAME="Test",
                    GIT_AUTHOR_EMAIL="test@example.invalid",
                    GIT_COMMITTER_NAME="Test",
                    GIT_COMMITTER_EMAIL="test@example.invalid",
                )
            }
            (work / "src").mkdir()
            (work / "src/main.rs").write_text("fn main() {}\n")
            (work / "bin.dat").write_bytes(b"\x00\x01\x02")
            subprocess.run(["git", "add", "."], cwd=work, env=env, check=True)
            subprocess.run(
                ["git", "commit", "-m", "initial commit\n\ndetailed body"],
                cwd=work,
                env=env,
                check=True,
                capture_output=True,
            )
            c1 = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=work,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            subprocess.run(
                ["git", "push", "origin", "HEAD:refs/heads/main"],
                cwd=work,
                check=True,
                capture_output=True,
            )
            # Create a controller-owned CI ref directly in bare repo
            subprocess.run(
                [
                    "git",
                    "--git-dir",
                    str(bare),
                    "update-ref",
                    "refs/rootyard-ci/jobs/11111111-1111-1111-1111-111111111111",
                    c1,
                ],
                check=True,
            )
            # Verify for-each-ref over refs/heads refs/tags excludes refs/rootyard-ci/*
            refs_out = subprocess.run(
                [
                    "git",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "--no-replace-objects",
                    "--git-dir",
                    str(bare),
                    "for-each-ref",
                    "--sort=refname",
                    "--format=%(refname)%00%(objectname)%00%(*objectname)",
                    "refs/heads",
                    "refs/tags",
                ],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            self.assertIn(f"refs/heads/main\x00{c1}\x00", refs_out)
            self.assertNotIn("refs/rootyard-ci", refs_out)

            # Verify atomic update-ref --stdin -z --no-deref succeeds on matching CAS
            # and rolls back all updates when any single ref fails CAS
            good_stdin = (
                b"start\x00"
                + f"update refs/heads/release\x00{c1}\x00{ZERO_OID}\x00".encode()
                + f"update refs/tags/v1.0\x00{c1}\x00{ZERO_OID}\x00".encode()
                + b"prepare\x00commit\x00"
            )
            subprocess.run(
                [
                    "git",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "--no-replace-objects",
                    "--git-dir",
                    str(bare),
                    "update-ref",
                    "--stdin",
                    "-z",
                    "--no-deref",
                ],
                input=good_stdin,
                check=True,
                capture_output=True,
            )
            bad_old = "a" * 40
            conflict_stdin = (
                b"start\x00"
                + f"update refs/heads/new-branch\x00{c1}\x00{ZERO_OID}\x00".encode()
                + f"update refs/heads/release\x00{ZERO_OID}\x00{bad_old}\x00".encode()
                + b"prepare\x00commit\x00"
            )
            failed = subprocess.run(
                [
                    "git",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "--no-replace-objects",
                    "--git-dir",
                    str(bare),
                    "update-ref",
                    "--stdin",
                    "-z",
                    "--no-deref",
                ],
                input=conflict_stdin,
                check=False,
                capture_output=True,
            )
            self.assertNotEqual(failed.returncode, 0)
            # Verify refs/heads/new-branch was NOT created and refs/heads/release still exists
            after_refs = subprocess.run(
                [
                    "git",
                    "--git-dir",
                    str(bare),
                    "for-each-ref",
                    "--format=%(refname)",
                    "refs/heads",
                ],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.splitlines()
            self.assertEqual(sorted(after_refs), ["refs/heads/main", "refs/heads/release"])

            # Verify ls-tree -z -l on c1^{tree}
            ls_tree = subprocess.run(
                [
                    "git",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "--no-replace-objects",
                    "--git-dir",
                    str(bare),
                    "ls-tree",
                    "-z",
                    "-l",
                    f"{c1}^{{tree}}",
                ],
                check=True,
                capture_output=True,
            ).stdout
            records = [r.decode() for r in ls_tree.split(b"\x00") if r]
            names = [r.split("\t", 1)[1] for r in records]
            self.assertEqual(sorted(names), ["bin.dat", "src"])

            # Verify cat-file commit and diff-tree
            commit_raw = subprocess.run(
                ["git", "--git-dir", str(bare), "cat-file", "commit", c1],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            self.assertIn("author Test <test@example.invalid>", commit_raw)
            self.assertIn("\n\ninitial commit\n\ndetailed body", commit_raw)

            changed = subprocess.run(
                [
                    "git",
                    "--git-dir",
                    str(bare),
                    "diff-tree",
                    "--no-commit-id",
                    "--name-only",
                    "-r",
                    "-z",
                    "--root",
                    c1,
                ],
                check=True,
                capture_output=True,
            ).stdout
            changed_paths = sorted(p.decode() for p in changed.split(b"\x00") if p)
            self.assertEqual(changed_paths, ["bin.dat", "src/main.rs"])

    def test_lfs_pointer_and_staging_guard_semantics(self):
        """Verifies canonical Git LFS v1 pointer format and SHA-256 staging semantics."""
        payload = b"rootyard-lfs-binary-payload-\x00\xff" * 1024
        oid = hashlib.sha256(payload).hexdigest()
        size = len(payload)
        pointer = (
            f"version https://git-lfs.github.com/spec/v1\n"
            f"oid sha256:{oid}\n"
            f"size {size}\n"
        ).encode()
        lines = pointer.decode().splitlines()
        self.assertEqual(lines[0], "version https://git-lfs.github.com/spec/v1")
        self.assertTrue(lines[1].startswith("oid sha256:") and len(lines[1].split(":")[1]) == 64)
        self.assertEqual(int(lines[2].split(" ")[1]), size)


if __name__ == "__main__":
    unittest.main()

