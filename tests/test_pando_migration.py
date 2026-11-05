import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tests.pando_lab import Lab
from tests.test_track4_labs import _verify_git_pack, _walk_git_graph

ROOT = Path(__file__).resolve().parent.parent


def _extract_gitfs_hook_script() -> str:
    mig_text = (ROOT / "src" / "pando_lab" / "migration.rs").read_text(encoding="utf-8")
    start = mig_text.index('const GITFS_PRE_RECEIVE_HOOK: &str = r#"') + len(
        'const GITFS_PRE_RECEIVE_HOOK: &str = r#"'
    )
    end = mig_text.index('"#;', start)
    return mig_text[start:end]


def _configure_gitfs_fence_py(
    gitfs_path: Path, write_paused: bool, backend: str, storage_gen: int
) -> None:
    hooks_dir = gitfs_path / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_file = hooks_dir / "pre-receive"
    hook_file.write_text(_extract_gitfs_hook_script(), encoding="utf-8")
    hook_file.chmod(0o755)
    receive_pack = "true" if (not write_paused and backend == "gitfs") else "false"
    for k, v in (
        ("rootyard.writePaused", "true" if write_paused else "false"),
        ("rootyard.storageBackend", backend),
        ("rootyard.storageGeneration", str(storage_gen)),
        ("http.receivepack", receive_pack),
    ):
        subprocess.run(
            ["git", f"--git-dir={gitfs_path}", "config", k, v],
            check=True,
            capture_output=True,
        )


def _read_git_refs_py(git_dir: Path) -> dict[str, str]:
    out = subprocess.check_output(
        [
            "git",
            f"--git-dir={git_dir}",
            "for-each-ref",
            "--format=%(refname) %(objectname)",
            "refs/heads",
            "refs/tags",
        ],
        text=True,
    )
    refs = {}
    for line in out.splitlines():
        if line.strip():
            name, oid = line.strip().split(" ", 1)
            refs[name] = oid
    return refs


class PandoMigrationModuleAndSchemaContractTests(unittest.TestCase):
    def test_pando_submodules_exist_and_respect_line_bounds(self):
        pando_dir = ROOT / "src" / "pando_lab"
        for name in (
            "mod.rs",
            "delta.rs",
            "graph.rs",
            "export.rs",
            "store.rs",
            "http.rs",
            "hook.rs",
            "migration.rs",
            "rollback.rs",
        ):
            path = pando_dir / name
            self.assertTrue(path.is_file(), f"Missing src/pando_lab/{name}")
            text = path.read_text(encoding="utf-8")
            lines = len(text.splitlines())
            self.assertGreaterEqual(lines, 35, f"src/pando_lab/{name} too short ({lines} lines)")
            self.assertLess(lines, 850, f"src/pando_lab/{name} exceeds 850 lines ({lines} lines)")
            self.assertNotIn("unsafe ", text, f"Unexpected unsafe block in src/pando_lab/{name}")

    def test_mod_rs_preserves_config_load_first_and_wires_migration_cli(self):
        mod_text = (ROOT / "src" / "pando_lab" / "mod.rs").read_text(encoding="utf-8")
        for mod_decl in (
            "pub mod delta;",
            "pub mod export;",
            "pub mod graph;",
            "pub mod migration;",
            "pub mod rollback;",
        ):
            self.assertIn(mod_decl, mod_text)
        run_section = mod_text.split("pub async fn run() -> Result<()> {", 1)[1]
        first_stmt = run_section.strip().splitlines()[0].strip()
        self.assertEqual(first_stmt, "let config = Config::load()?;")
        for subcmd in (
            'Some("migrate")',
            'Some("migrate-step")',
            'Some("rollback")',
            'Some("migration-status")',
            'Some("verify-delta")',
            'Some("walk-graph")',
            'Some("diff-export")',
            'Some("gc")',
        ):
            self.assertIn(subcmd, mod_text)

    def test_schema_sql_defines_migration_columns_and_table_without_between(self):
        schema_text = (ROOT / "experimental" / "pando" / "schema.sql").read_text(encoding="utf-8")
        self.assertNotIn("BETWEEN", schema_text.upper())
        for col in (
            "storage_backend",
            "migration_state",
            "write_paused",
            "gitfs_path",
            "CREATE TABLE IF NOT EXISTS pando_lab.migrations",
            "gitfs_to_pando",
            "pando_to_gitfs",
            "post_switchover_commits",
            "immutable_manifest",
            "immutable_object",
        ):
            self.assertIn(col, schema_text)

    def test_http_and_hook_enforce_migration_fences_and_expose_status(self):
        http_text = (ROOT / "src" / "pando_lab" / "http.rs").read_text(encoding="utf-8")
        self.assertIn('tail == "refs"', http_text)
        self.assertIn('tail.strip_prefix("operations/")', http_text)
        self.assertIn('tail == "migration"', http_text)
        self.assertIn("migration::status", http_text)
        self.assertIn('write_paused || storage_backend != "pando"', http_text)

        hook_text = (ROOT / "src" / "pando_lab" / "hook.rs").read_text(encoding="utf-8")
        self.assertIn(
            "SELECT generation,storage_generation,write_paused,storage_backend FROM pando_lab.repositories WHERE id=$1 FOR UPDATE",
            hook_text,
        )
        self.assertIn("stale storage generation", hook_text)
        self.assertIn("repository writes paused", hook_text)
        self.assertIn("repository storage backend is not pando", hook_text)

    def test_migration_and_rollback_modules_use_store_and_export_contracts(self):
        mig_text = (ROOT / "src" / "pando_lab" / "migration.rs").read_text(encoding="utf-8")
        for sym in (
            "pub struct MigrationReport",
            "pub struct MigrationStatusReport",
            "store::publish_pack",
            "export::diff_export",
            "configure_gitfs_fence",
            "step_copy",
            "step_verify",
            "step_drain",
            "step_fence",
            "step_switchover",
            "migrate_full",
        ):
            self.assertIn(sym, mig_text)

        rb_text = (ROOT / "src" / "pando_lab" / "rollback.rs").read_text(encoding="utf-8")
        for sym in (
            "pub struct RollbackReport",
            "pub(super) async fn rollback",
            "index-pack",
            "update-ref",
            "verify_parity_against_gitfs",
            "post_switchover_commits",
            "deleted_refs_reconciled",
        ):
            self.assertIn(sym, rb_text)


class PandoMigrationAndRollbackGitEngineTests(unittest.TestCase):
    def test_five_step_migration_incremental_drain_fence_and_rollback_with_new_commits(self):
        with tempfile.TemporaryDirectory(prefix="pando-mig-engine-") as tmp:
            root = Path(tmp)
            gitfs_bare = root / "gitfs-origin.git"
            gitfs_work = root / "gitfs-work"
            pando_staging = root / "pando-staging.git"

            subprocess.run(
                ["git", "init", "--bare", "--initial-branch=main", str(gitfs_bare)],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "init", "--initial-branch=main", str(gitfs_work)],
                check=True,
                capture_output=True,
            )

            def make_commit(work_dir: Path, name: str, content: str, msg: str) -> str:
                (work_dir / name).write_text(content, encoding="utf-8")
                subprocess.run(["git", "-C", str(work_dir), "add", "."], check=True, capture_output=True)
                subprocess.run(
                    [
                        "git",
                        "-C",
                        str(work_dir),
                        "-c",
                        "user.name=T",
                        "-c",
                        "user.email=t@e.c",
                        "commit",
                        "-m",
                        msg,
                    ],
                    check=True,
                    capture_output=True,
                )
                return subprocess.check_output(
                    ["git", "-C", str(work_dir), "rev-parse", "HEAD"], text=True
                ).strip()

            c1 = make_commit(gitfs_work, "app.txt", "v1\n", "commit 1")
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(gitfs_work),
                    "push",
                    str(gitfs_bare),
                    "HEAD:refs/heads/main",
                    "HEAD:refs/heads/feature",
                ],
                check=True,
                capture_output=True,
            )
            c2 = make_commit(gitfs_work, "app.txt", "v2\n", "commit 2")
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(gitfs_work),
                    "-c",
                    "user.name=T",
                    "-c",
                    "user.email=t@e.c",
                    "tag",
                    "-a",
                    "v1.0",
                    "-m",
                    "release v1.0",
                ],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(gitfs_work),
                    "push",
                    str(gitfs_bare),
                    "HEAD:refs/heads/main",
                    "refs/tags/v1.0",
                ],
                check=True,
                capture_output=True,
            )

            # Step 1 (copy): package all reachable objects into Pando pack 1
            _configure_gitfs_fence_py(gitfs_bare, write_paused=False, backend="gitfs", storage_gen=1)
            copy_refs = _read_git_refs_py(gitfs_bare)
            self.assertEqual(len(copy_refs), 3)
            roots_1 = sorted(set(copy_refs.values()))
            pack1 = subprocess.run(
                ["git", f"--git-dir={gitfs_bare}", "pack-objects", "--stdout", "--revs"],
                input=("\n".join(roots_1) + "\n").encode(),
                check=True,
                capture_output=True,
            ).stdout
            resolved_1 = _verify_git_pack(pack1)
            obj_store = {o["oid"]: (o["type"], o["data"]) for o in resolved_1}

            # Step 2 (verify): dual-operator walk matches git rev-list and cat-file bit-for-bit
            visited_1, _ = _walk_git_graph(obj_store, roots_1, [])
            git_oids_1 = set(
                subprocess.check_output(
                    ["git", f"--git-dir={gitfs_bare}", "rev-list", "--objects", "--no-object-names", *roots_1],
                    text=True,
                ).splitlines()
            )
            self.assertEqual(set(visited_1.keys()), git_oids_1)

            # Incremental commit c3 pushed to GitFS before drain
            c3 = make_commit(gitfs_work, "drain.txt", "incremental before drain\n", "commit 3")
            subprocess.run(
                ["git", "-C", str(gitfs_work), "push", str(gitfs_bare), "HEAD:refs/heads/main"],
                check=True,
                capture_output=True,
            )

            # Step 3 (drain): pause GitFS writes via pre-receive hook and capture incremental delta pack
            _configure_gitfs_fence_py(gitfs_bare, write_paused=True, backend="gitfs", storage_gen=1)
            c_blocked = make_commit(gitfs_work, "blocked.txt", "blocked\n", "blocked commit")
            blocked_push = subprocess.run(
                ["git", "-C", str(gitfs_work), "push", str(gitfs_bare), "HEAD:refs/heads/blocked"],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(blocked_push.returncode, 0)
            self.assertIn("writes are paused on GitFS", blocked_push.stderr)
            subprocess.run(
                ["git", "-C", str(gitfs_work), "reset", "--hard", c3],
                check=True,
                capture_output=True,
            )

            drain_refs = _read_git_refs_py(gitfs_bare)
            roots_2 = sorted(set(drain_refs.values()))
            rev_input = "\n".join(roots_2) + "\n" + "\n".join(f"^{r}" for r in roots_1) + "\n"
            pack2 = subprocess.run(
                ["git", f"--git-dir={gitfs_bare}", "pack-objects", "--stdout", "--revs"],
                input=rev_input.encode(),
                check=True,
                capture_output=True,
            ).stdout
            resolved_2 = _verify_git_pack(pack2)
            self.assertGreater(len(resolved_2), 0)
            for o in resolved_2:
                obj_store[o["oid"]] = (o["type"], o["data"])
            visited_2, _ = _walk_git_graph(obj_store, roots_2, [])
            self.assertIn(c3, visited_2)

            # Step 4 (fence) & Step 5 (switchover): bump storage_generation to 2, set backend=pando
            _configure_gitfs_fence_py(gitfs_bare, write_paused=True, backend="pando", storage_gen=2)
            subprocess.run(
                ["git", "init", "--bare", "--initial-branch=main", str(pando_staging)],
                check=True,
                capture_output=True,
            )
            for p_bytes in (pack1, pack2):
                subprocess.run(
                    ["git", f"--git-dir={pando_staging}", "index-pack", "--stdin", "--strict"],
                    input=p_bytes,
                    check=True,
                    capture_output=True,
                )
            for ref_name, ref_oid in drain_refs.items():
                subprocess.run(
                    ["git", f"--git-dir={pando_staging}", "update-ref", ref_name, ref_oid],
                    check=True,
                )

            # Post-switchover writes on Pando: commits c4, c5, new branch, delete feature branch
            pando_work = root / "pando-work"
            subprocess.run(
                ["git", "clone", str(pando_staging), str(pando_work)],
                check=True,
                capture_output=True,
            )
            c4 = make_commit(pando_work, "pando.txt", "post-switchover 4\n", "commit 4")
            c5 = make_commit(pando_work, "pando.txt", "post-switchover 5\n", "commit 5")
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(pando_work),
                    "push",
                    str(pando_staging),
                    "HEAD:refs/heads/main",
                    "HEAD:refs/heads/post-switchover",
                    ":refs/heads/feature",
                ],
                check=True,
                capture_output=True,
            )
            pando_refs = _read_git_refs_py(pando_staging)
            roots_3 = sorted(set(pando_refs.values()))
            rev_input_3 = "\n".join(roots_3) + "\n" + "\n".join(f"^{r}" for r in roots_2) + "\n"
            pack3 = subprocess.run(
                ["git", f"--git-dir={pando_staging}", "pack-objects", "--stdout", "--revs"],
                input=rev_input_3.encode(),
                check=True,
                capture_output=True,
            ).stdout
            resolved_3 = _verify_git_pack(pack3)
            for o in resolved_3:
                obj_store[o["oid"]] = (o["type"], o["data"])

            # Rollback (F27): reverse-sync pack3 to gitfs_bare, reconcile refs, verify fsck & parity
            inc_post_switch, _ = _walk_git_graph(obj_store, roots_3, roots_2)
            post_commits = sum(1 for t, _ in inc_post_switch.values() if t == "commit")
            self.assertEqual(post_commits, 2)

            subprocess.run(
                ["git", f"--git-dir={gitfs_bare}", "index-pack", "--stdin", "--strict"],
                input=pack3,
                check=True,
                capture_output=True,
            )
            gitfs_before = _read_git_refs_py(gitfs_bare)
            for name, oid in pando_refs.items():
                subprocess.run(
                    [
                        "git",
                        f"--git-dir={gitfs_bare}",
                        "-c",
                        "core.hooksPath=/dev/null",
                        "update-ref",
                        name,
                        oid,
                    ],
                    check=True,
                )
            deleted = 0
            for old_name in gitfs_before:
                if old_name not in pando_refs:
                    subprocess.run(
                        [
                            "git",
                            f"--git-dir={gitfs_bare}",
                            "-c",
                            "core.hooksPath=/dev/null",
                            "update-ref",
                            "-d",
                            old_name,
                        ],
                        check=True,
                    )
                    deleted += 1
            self.assertEqual(deleted, 1)
            self.assertEqual(_read_git_refs_py(gitfs_bare), pando_refs)
            subprocess.run(
                ["git", f"--git-dir={gitfs_bare}", "fsck", "--full", "--strict", "--no-reflogs"],
                check=True,
                capture_output=True,
            )

            # Unfence GitFS at storage_generation = 3
            _configure_gitfs_fence_py(gitfs_bare, write_paused=False, backend="gitfs", storage_gen=3)
            c6 = make_commit(pando_work, "restored.txt", "back on gitfs\n", "commit 6")
            stale_env = os.environ.copy()
            stale_env["ROOTYARD_EXPECTED_STORAGE_GENERATION"] = "2"
            stale_push = subprocess.run(
                ["git", "-C", str(pando_work), "push", str(gitfs_bare), "HEAD:refs/heads/main"],
                env=stale_env,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(stale_push.returncode, 0)
            self.assertIn("stale storage_generation", stale_push.stderr)

            valid_env = os.environ.copy()
            valid_env["ROOTYARD_EXPECTED_STORAGE_GENERATION"] = "3"
            subprocess.run(
                ["git", "-C", str(pando_work), "push", str(gitfs_bare), "HEAD:refs/heads/main"],
                env=valid_env,
                check=True,
                capture_output=True,
            )
            self.assertEqual(_read_git_refs_py(gitfs_bare)["refs/heads/main"], c6)


class PandoLabHarnessMigrationMethodsOfflineTests(unittest.TestCase):
    def test_pando_lab_harness_migration_and_rollback_methods_offline(self):
        args = argparse.Namespace(binary="target/debug/rootyard-pando-lab", pg_share=None)
        lab = Lab(args)
        try:
            lab.base = "http://127.0.0.1:59999"
            pando_repos: dict[str, dict] = {}
            sql_queries: list[str] = []

            def ensure_repo_state(repo_id: str) -> dict:
                if repo_id not in pando_repos:
                    bare_dir = lab.root / f"pando-sim-{repo_id}.git"
                    subprocess.run(
                        ["git", "init", "--bare", "--initial-branch=main", str(bare_dir)],
                        check=True,
                        capture_output=True,
                    )
                    pando_repos[repo_id] = {
                        "bare": bare_dir,
                        "storage_backend": "pando",
                        "migration_state": "idle",
                        "write_paused": False,
                        "generation": 0,
                        "storage_generation": 1,
                        "gitfs_path": None,
                        "latest_migration": None,
                        "packs": [],
                    }
                return pando_repos[repo_id]

            def sync_gitfs_to_pando(st: dict, gitfs_dir: Path) -> int:
                before_refs = _read_git_refs_py(st["bare"])
                gitfs_refs = _read_git_refs_py(gitfs_dir)
                wants = sorted(set(gitfs_refs.values()))
                haves = sorted(set(before_refs.values()))
                rev_in = "\n".join(wants) + "\n" + ("\n".join(f"^{h}" for h in haves) + "\n" if haves else "")
                inc_oids = subprocess.check_output(
                    ["git", f"--git-dir={gitfs_dir}", "rev-list", "--objects", "--no-object-names", "--stdin"],
                    input=rev_in,
                    text=True,
                ).splitlines()
                if inc_oids:
                    pack_bytes = subprocess.run(
                        ["git", f"--git-dir={gitfs_dir}", "pack-objects", "--stdout", "--revs"],
                        input=rev_in.encode(),
                        check=True,
                        capture_output=True,
                    ).stdout
                    _verify_git_pack(pack_bytes)
                    subprocess.run(
                        ["git", f"--git-dir={st['bare']}", "index-pack", "--stdin", "--strict"],
                        input=pack_bytes,
                        check=True,
                        capture_output=True,
                    )
                    st["packs"].append(pack_bytes)
                for rname in list(before_refs):
                    if rname not in gitfs_refs:
                        subprocess.run(
                            ["git", f"--git-dir={st['bare']}", "update-ref", "-d", rname],
                            check=True,
                        )
                for rname, roid in gitfs_refs.items():
                    subprocess.run(
                        ["git", f"--git-dir={st['bare']}", "update-ref", rname, roid],
                        check=True,
                    )
                return len(inc_oids)

            def make_diff_report(repo_id: str, st: dict) -> dict:
                refs = _read_git_refs_py(st["bare"])
                return {
                    "repo": repo_id,
                    "generation": st["generation"],
                    "storage_generation": st["storage_generation"],
                    "ref_count": len(refs),
                    "pack_count": len(st["packs"]),
                    "total_pack_objects": 6,
                    "reachable_objects": 6,
                    "excluded_objects": 0,
                    "commits": 2,
                    "trees": 2,
                    "blobs": 1,
                    "tags": 1,
                    "max_delta_depth": 0,
                    "matched": True,
                    "bit_for_bit_match": True,
                }

            def fake_sql(query: str) -> str:
                sql_queries.append(query)
                return "1"

            def fake_cli(*cli_args) -> str:
                cmd = cli_args[0]
                if cmd == "create-repo":
                    ensure_repo_state(cli_args[1])
                    return ""
                if cmd == "migrate-step":
                    repo_id, gitfs_str, step = cli_args[1], cli_args[2], cli_args[3]
                    st = ensure_repo_state(repo_id)
                    gitfs_dir = Path(gitfs_str)
                    st["gitfs_path"] = gitfs_str
                    old_sgen = st["storage_generation"]
                    inc = 0
                    state_map = {
                        "copy": ("COPYING", "gitfs", "copying", False, False),
                        "verify": ("VERIFIED", "gitfs", "verified", False, False),
                        "drain": ("DRAINED", "gitfs", "draining", True, True),
                        "fence": ("FENCED", "gitfs", "fenced", True, True),
                        "switchover": ("SWITCHED_OVER", "pando", "switched_over", False, True),
                    }
                    m_state, backend, repo_mstate, wpaused, fenced_ro = state_map[step]
                    if step in ("copy", "drain"):
                        inc = sync_gitfs_to_pando(st, gitfs_dir)
                    if step == "fence":
                        st["storage_generation"] += 1
                    st["storage_backend"] = backend
                    st["migration_state"] = repo_mstate
                    st["write_paused"] = wpaused
                    st["generation"] += 1
                    _configure_gitfs_fence_py(
                        gitfs_dir,
                        write_paused=(step in ("drain", "fence", "switchover")),
                        backend=backend,
                        storage_gen=st["storage_generation"],
                    )
                    diff_rep = make_diff_report(repo_id, st)
                    rep = {
                        "migration_id": "11111111-1111-4111-8111-111111111111",
                        "repo": repo_id,
                        "direction": "gitfs_to_pando",
                        "step": step,
                        "state": m_state,
                        "storage_backend": backend,
                        "migration_state": repo_mstate,
                        "write_paused": wpaused,
                        "gitfs_path": gitfs_str,
                        "generation": st["generation"],
                        "old_storage_generation": 1,
                        "new_storage_generation": st["storage_generation"],
                        "copied_packs": len(st["packs"]),
                        "copied_objects": 6,
                        "ref_count": len(_read_git_refs_py(st["bare"])),
                        "drained_operations": 0,
                        "incremental_objects_synced": inc,
                        "gitfs_fenced_readonly": fenced_ro,
                        "diff_report": diff_rep,
                    }
                    st["latest_migration"] = rep
                    return json.dumps(rep)
                if cmd == "migrate":
                    repo_id, gitfs_str = cli_args[1], cli_args[2]
                    for s in ("copy", "verify", "drain", "fence", "switchover"):
                        last = json.loads(fake_cli("migrate-step", repo_id, gitfs_str, s))
                    last["step"] = "full"
                    return json.dumps(last)
                if cmd == "migration-status":
                    repo_id = cli_args[1]
                    st = ensure_repo_state(repo_id)
                    return json.dumps(
                        {
                            "repo": repo_id,
                            "generation": st["generation"],
                            "storage_generation": st["storage_generation"],
                            "storage_backend": st["storage_backend"],
                            "migration_state": st["migration_state"],
                            "write_paused": st["write_paused"],
                            "gitfs_path": st["gitfs_path"],
                            "inflight_operations": 0,
                            "latest_migration": st["latest_migration"],
                        }
                    )
                if cmd == "rollback":
                    repo_id, gitfs_str = cli_args[1], cli_args[2]
                    st = ensure_repo_state(repo_id)
                    gitfs_dir = Path(gitfs_str)
                    before_gitfs = _read_git_refs_py(gitfs_dir)
                    pando_refs = _read_git_refs_py(st["bare"])
                    wants = sorted(set(pando_refs.values()))
                    haves = sorted(set(before_gitfs.values()))
                    rev_in = "\n".join(wants) + "\n" + "\n".join(f"^{h}" for h in haves) + "\n"
                    post_commits = int(
                        subprocess.check_output(
                            ["git", f"--git-dir={st['bare']}", "rev-list", "--count", "--stdin"],
                            input=rev_in,
                            text=True,
                        ).strip()
                    )
                    pack_bytes = subprocess.run(
                        ["git", f"--git-dir={st['bare']}", "pack-objects", "--stdout", "--revs"],
                        input=rev_in.encode(),
                        check=True,
                        capture_output=True,
                    ).stdout
                    subprocess.run(
                        ["git", f"--git-dir={gitfs_dir}", "index-pack", "--stdin", "--strict"],
                        input=pack_bytes,
                        check=True,
                        capture_output=True,
                    )
                    for rname, roid in pando_refs.items():
                        subprocess.run(
                            [
                                "git",
                                f"--git-dir={gitfs_dir}",
                                "-c",
                                "core.hooksPath=/dev/null",
                                "update-ref",
                                rname,
                                roid,
                            ],
                            check=True,
                        )
                    deleted = 0
                    for old_r in before_gitfs:
                        if old_r not in pando_refs:
                            subprocess.run(
                                [
                                    "git",
                                    f"--git-dir={gitfs_dir}",
                                    "-c",
                                    "core.hooksPath=/dev/null",
                                    "update-ref",
                                    "-d",
                                    old_r,
                                ],
                                check=True,
                            )
                            deleted += 1
                    old_sgen = st["storage_generation"]
                    st["storage_generation"] += 1
                    st["generation"] += 1
                    st["storage_backend"] = "gitfs"
                    st["migration_state"] = "rolled_back"
                    st["write_paused"] = True
                    _configure_gitfs_fence_py(
                        gitfs_dir,
                        write_paused=False,
                        backend="gitfs",
                        storage_gen=st["storage_generation"],
                    )
                    return json.dumps(
                        {
                            "migration_id": "22222222-2222-4222-8222-222222222222",
                            "repo": repo_id,
                            "direction": "pando_to_gitfs",
                            "state": "ROLLED_BACK",
                            "storage_backend": "gitfs",
                            "migration_state": "rolled_back",
                            "write_paused": True,
                            "gitfs_write_paused": False,
                            "gitfs_path": gitfs_str,
                            "generation": st["generation"],
                            "old_storage_generation": old_sgen,
                            "new_storage_generation": st["storage_generation"],
                            "packs_synced": len(st["packs"]) + 1,
                            "objects_verified": 10,
                            "ref_count": len(pando_refs),
                            "post_switchover_commits": post_commits,
                            "deleted_refs_reconciled": deleted,
                            "gitfs_fsck_ok": True,
                            "diff_report": make_diff_report(repo_id, st),
                        }
                    )
                raise AssertionError(f"Unexpected CLI call: {cli_args}")

            def fake_http(path: str, principal: str = "reader", method: str = "GET", body=None, redirects: bool = True):
                if path.endswith("/migration"):
                    if principal == "bob":
                        return 403, {}, b"repository access denied"
                    repo_id = path.split("/repos/")[1].split(".git")[0]
                    return 200, {}, fake_cli("migration-status", repo_id).encode()
                if "service=git-receive-pack" in path:
                    repo_id = path.split("/repos/")[1].split(".git")[0]
                    st = ensure_repo_state(repo_id)
                    if st["write_paused"] or st["storage_backend"] != "pando":
                        return 409, {}, b"repository writes paused or routed to gitfs"
                return 200, {}, b""

            orig_git = lab.git

            def fake_git(*g_args, principal="alice", protocol=2, check=True, cwd=None):
                mapped = list(g_args)
                for idx, arg in enumerate(mapped):
                    if isinstance(arg, str) and arg.startswith(lab.base + "/repos/"):
                        repo_id = arg.split("/repos/")[1].split(".git")[0]
                        st = ensure_repo_state(repo_id)
                        if mapped[0] == "push" and (st["write_paused"] or st["storage_backend"] != "pando"):
                            if check:
                                raise AssertionError("Pando push rejected by write fence")
                            return subprocess.CompletedProcess(mapped, 1, "", "repository writes paused")
                        mapped[idx] = str(st["bare"])
                res = orig_git(*mapped, principal=principal, protocol=protocol, check=check, cwd=cwd)
                if mapped[0] == "clone" and protocol == 2:
                    res.packet_trace = "version 2\n" + getattr(res, "packet_trace", "")
                return res

            lab.sql = fake_sql
            lab.cli = fake_cli
            lab.http = fake_http
            lab.git = fake_git

            res_f26 = lab.online_migration_state_machine()
            self.assertTrue(res_f26["one_shot_migrated"])
            self.assertGreaterEqual(res_f26["incremental_objects_synced"], 1)
            self.assertEqual(res_f26["new_storage_generation"], 2)

            res_f27 = lab.post_switchover_rollback_with_new_commits()
            self.assertTrue(res_f27["gitfs_restored_and_writable"])
            self.assertGreaterEqual(res_f27["post_switchover_commits"], 2)
            self.assertGreaterEqual(res_f27["deleted_refs_reconciled"], 1)
            self.assertEqual(res_f27["new_storage_generation"], 3)
        finally:
            shutil.rmtree(lab.root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
