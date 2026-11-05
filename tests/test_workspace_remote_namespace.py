#!/usr/bin/env python3
"""Unit, integration, and adversarial tests for Track D (Features F28 & F29):
Workspace Remote CAS Checkpoint Sync & Multi-Repo BaseVector Namespace Views.
"""

import hashlib
import json
import os
from pathlib import Path
import unittest

from tests.workspace import WorkspaceHarness

ROOT = Path(__file__).resolve().parent.parent


class WorkspaceRemoteNamespaceContractTests(unittest.TestCase):
    """Verify structural modularity, line-count limits, and schema contracts for Track D."""

    def test_workspace_lab_facade_and_submodules_stay_under_line_limits(self):
        facade = ROOT / "src" / "workspace_lab.rs"
        self.assertTrue(facade.is_file(), "src/workspace_lab.rs must be a regular file")
        self.assertFalse(
            (ROOT / "src" / "workspace_lab" / "mod.rs").exists(),
            "src/workspace_lab/mod.rs must not exist",
        )
        facade_text = facade.read_text(encoding="utf-8")
        facade_lines = facade_text.splitlines()
        self.assertLess(
            len(facade_lines),
            150,
            f"src/workspace_lab.rs has {len(facade_lines)} lines (limit < 150)",
        )
        for mod_decl in (
            '#[path = "workspace_lab/remote.rs"]',
            '#[path = "workspace_lab/namespace.rs"]',
        ):
            self.assertIn(mod_decl, facade_text)
        for subcmd in (
            '"push-remote"',
            '"pull-remote"',
            '"namespace-mount"',
            '"verify-namespace"',
            '"namespace-git-view"',
        ):
            self.assertIn(subcmd, facade_text)

        core_rs = ROOT / "src" / "workspace_lab" / "core.rs"
        core_text = core_rs.read_text(encoding="utf-8")
        core_lines = core_text.splitlines()
        self.assertLess(
            len(core_lines),
            1100,
            f"src/workspace_lab/core.rs has {len(core_lines)} lines (limit < 1100)",
        )
        self.assertIn('"namespaces"', core_text)

        for sub_name in ("remote.rs", "namespace.rs"):
            sub_path = ROOT / "src" / "workspace_lab" / sub_name
            self.assertTrue(sub_path.is_file(), f"Missing {sub_path}")
            sub_text = sub_path.read_text(encoding="utf-8")
            sub_lines = sub_text.splitlines()
            self.assertGreaterEqual(len(sub_lines), 35)
            self.assertLess(
                len(sub_lines),
                600,
                f"{sub_name} has {len(sub_lines)} lines (limit < 600)",
            )
            self.assertIn("#[serde(deny_unknown_fields)]", sub_text)

    def test_remote_and_namespace_types_and_docs_are_present(self):
        remote_text = (ROOT / "src" / "workspace_lab" / "remote.rs").read_text(encoding="utf-8")
        for item in (
            "pub struct RemoteDirtyManifest",
            "pub struct RemoteCheckpointManifest",
            "pub struct RemotePushReport",
            "pub struct RemotePullReport",
            "pub fn cmd_push_remote",
            "pub fn cmd_pull_remote",
            "O_NOFOLLOW",
            "remote_cas_committed",
        ):
            self.assertIn(item, remote_text)

        ns_text = (ROOT / "src" / "workspace_lab" / "namespace.rs").read_text(encoding="utf-8")
        for item in (
            "pub struct BaseVectorEntry",
            "pub struct NamespaceManifest",
            "pub struct NamespaceViewReport",
            "pub struct NamespaceGitViewReport",
            "pub fn cmd_namespace_mount",
            "pub fn cmd_verify_namespace",
            "pub fn cmd_namespace_git_view",
            "task_snapshot",
            ".rootyard-namespace.json",
        ):
            self.assertIn(item, ns_text)

        doc_text = (ROOT / "docs" / "workspace-foundation.md").read_text(encoding="utf-8")
        for cmd in (
            "push-remote",
            "pull-remote",
            "namespace-mount",
            "verify-namespace",
            "namespace-git-view",
        ):
            self.assertIn(cmd, doc_text)


class WorkspaceRemoteCasTests(unittest.TestCase):
    """End-to-end and adversarial tests for F28 (Remote CAS Checkpoint & Cross-Node Restore)."""

    def test_remote_cas_deduplication_and_cross_node_fidelity(self):
        harness = WorkspaceHarness()
        try:
            root, source, store1, _ = harness.fixture(
                "f28-fidelity",
                {
                    ".gitignore": b"*.tmp\nbuild_out/\n",
                    ".rootyardignore": b"scratch/*\n!scratch/pinned.txt\n",
                    "app.txt": b"v1\n",
                    "bin/tool.sh": b"#!/bin/sh\necho tool\n",
                },
            )
            (source / "bin/tool.sh").chmod(0o755)
            (source / "app-link").symlink_to("app.txt")
            harness.git("add", "--all", cwd=source)
            harness.git("commit", "--amend", "-m", "initial commit", cwd=source)
            base = harness.oid(source)

            ws1, repo1 = harness.init(store1, source, base, "agent-alpha")
            remote_cas = root / "remote-cas"

            # 1. Push initial clean checkpoint
            cp1 = harness.checkpoint(store1, ws1)
            push1 = harness.data("push-remote", store1, cp1["checkpoint_id"], remote_cas)
            self.assertEqual(push1["state"], "COMMITTED")
            self.assertEqual(push1["durability"], "remote_cas_committed")
            self.assertEqual(push1["dirty_entries_count"], 0)
            self.assertEqual(
                push1["blobs_uploaded"] + push1["blobs_reused"], push1["total_entries"]
            )

            # 2. Create a local commit moving HEAD, plus partial staging, untracked, and ignored files
            harness.write(repo1, "committed_later.txt", b"committed on branch\n")
            harness.git("add", "committed_later.txt", cwd=repo1)
            harness.git("commit", "-m", "second commit", cwd=repo1)
            moved_head = harness.oid(repo1)
            self.assertNotEqual(moved_head, base)

            harness.write(repo1, "app.txt", b"staged app v2\n")
            harness.git("add", "app.txt", cwd=repo1)
            harness.write(repo1, "app.txt", b"unstaged app v3\n")
            harness.write(repo1, "untracked_note.md", b"hello cross node\n")
            harness.write(repo1, "scratch/pinned.txt", b"kept by negation\n")
            harness.write(repo1, "scratch/ignored.txt", b"excluded by rootyardignore\n")
            harness.write(repo1, "cache.tmp", b"excluded by gitignore\n")

            # Live workspace push without --quiescent must fail closed
            res_no_q = harness.lab(
                "push-remote", store1, ws1["workspace_id"], remote_cas, check=False
            )
            self.assertNotEqual(res_no_q.returncode, 0)

            # Live workspace push with --quiescent captures and commits to remote CAS
            push2 = harness.data(
                "push-remote", store1, ws1["workspace_id"], remote_cas, "--quiescent"
            )
            self.assertEqual(push2["state"], "COMMITTED")
            self.assertGreater(push2["blobs_reused"], 10)
            self.assertEqual(push2["excluded_ignored_entries"], 2)
            self.assertEqual(push2["dirty_entries_count"], 3)

            # Verify remote CAS layout on disk
            cp2_id = push2["checkpoint_id"]
            remote_cp_dir = remote_cas / "checkpoints" / cp2_id
            self.assertTrue((remote_cp_dir / "manifest.json").is_file())
            self.assertTrue((remote_cp_dir / "manifest.sha256").is_file())
            self.assertTrue((remote_cp_dir / "dirty_manifest.json").is_file())
            self.assertTrue((remote_cp_dir / "dirty_manifest.sha256").is_file())

            # 3. Pull into a brand-new node store and verify full state restoration
            store2 = root / "store-node2"
            pull = harness.data("pull-remote", store2, remote_cas, cp2_id, "agent-beta")
            self.assertEqual(pull["state"], "restored_from_remote")
            self.assertEqual(pull["durability"], "remote_cas_committed")
            self.assertEqual(pull["base_oid"], base)
            self.assertEqual(pull["entries_restored"], push2["total_entries"])
            self.assertEqual(pull["blobs_verified"], push2["total_entries"])

            repo2 = Path(pull["repo_path"])
            self.assertEqual(harness.oid(repo2), moved_head)
            self.assertEqual((repo2 / "committed_later.txt").read_bytes(), b"committed on branch\n")
            self.assertEqual((repo2 / "app.txt").read_bytes(), b"unstaged app v3\n")
            self.assertEqual(
                harness.git("show", ":app.txt", cwd=repo2).stdout, b"staged app v2\n"
            )
            self.assertEqual((repo2 / "untracked_note.md").read_bytes(), b"hello cross node\n")
            self.assertEqual((repo2 / "scratch/pinned.txt").read_bytes(), b"kept by negation\n")
            self.assertFalse((repo2 / "scratch/ignored.txt").exists())
            self.assertFalse((repo2 / "cache.tmp").exists())
            self.assertNotEqual((repo2 / "bin/tool.sh").stat().st_mode & 0o111, 0)
            self.assertTrue((repo2 / "app-link").is_symlink())
            self.assertEqual(os.readlink(repo2 / "app-link"), "app.txt")

            # Verify local checkpoint was also registered in store2 so status works
            st2 = harness.data("status", store2, pull["workspace_id"])
            self.assertEqual(st2["parent_checkpoint_id"], cp2_id)
            self.assertEqual(st2["head_oid"], moved_head)
        finally:
            harness.cleanup()

    def test_remote_cas_merge_conflict_stages_and_corruption_rejection(self):
        harness = WorkspaceHarness()
        try:
            root, source, store1, base = harness.fixture(
                "f28-conflict-and-corrupt",
                {"conflict.txt": b"base line\n", "other.txt": b"untouched\n"},
            )
            ws1, repo1 = harness.init(store1, source, base, "agent-conflict")

            # Create a real merge conflict in repo1 (stages 1, 2, 3 + MERGE_HEAD)
            harness.git("checkout", "-b", "side", cwd=repo1)
            harness.write(repo1, "conflict.txt", b"side branch change\n")
            harness.git("commit", "-am", "side edit", cwd=repo1)
            harness.git("checkout", "main", cwd=repo1)
            harness.write(repo1, "conflict.txt", b"main branch change\n")
            harness.git("commit", "-am", "main edit", cwd=repo1)
            merge_res = harness.git("merge", "side", cwd=repo1, check=False)
            self.assertNotEqual(merge_res.returncode, 0)

            remote_cas = root / "remote-cas"
            push = harness.data(
                "push-remote", store1, ws1["workspace_id"], remote_cas, "--quiescent"
            )
            cp_id = push["checkpoint_id"]

            # Pull into store2 and verify unmerged index stages 1, 2, 3 are preserved
            store2 = root / "store2"
            pull = harness.data("pull-remote", store2, remote_cas, cp_id, "agent-resolver")
            repo2 = Path(pull["repo_path"])
            unmerged = harness.git("ls-files", "--unmerged", cwd=repo2).stdout.decode()
            self.assertIn("\tconflict.txt", unmerged)
            stages = [line.split()[2] for line in unmerged.strip().splitlines()]
            self.assertEqual(sorted(stages), ["1", "2", "3"])
            self.assertTrue((repo2 / ".git" / "MERGE_HEAD").is_file())

            # Adversarial 1: Tamper dirty_manifest.json and verify pull-remote fails closed
            dirty_path = remote_cas / "checkpoints" / cp_id / "dirty_manifest.json"
            orig_dirty = dirty_path.read_bytes()
            dirty_path.chmod(0o600)
            dirty_path.write_bytes(orig_dirty + b"\n")
            store3 = root / "store3"
            res_dirty = harness.lab(
                "pull-remote", store3, remote_cas, cp_id, "agent-3", check=False
            )
            self.assertNotEqual(res_dirty.returncode, 0)
            dirty_path.write_bytes(orig_dirty)

            # Adversarial 2: Missing CAS blob fails closed without leaving partial workspace
            other_sha = hashlib.sha256(b"untouched\n").hexdigest()
            blob_path = remote_cas / "blobs" / other_sha[:2] / other_sha
            saved_blob = blob_path.read_bytes()
            blob_path.unlink()
            res_missing = harness.lab(
                "pull-remote", store3, remote_cas, cp_id, "agent-3", check=False
            )
            self.assertNotEqual(res_missing.returncode, 0)
            self.assertEqual(list((store3 / "workspaces").iterdir()), [])
            self.assertEqual(list((store3 / "checkpoints").iterdir()), [])

            # Restore blob and verify pull-remote succeeds again
            blob_path.write_bytes(saved_blob)
            blob_path.chmod(0o600)
            pull_ok = harness.data("pull-remote", store3, remote_cas, cp_id, "agent-3")
            self.assertEqual(pull_ok["state"], "restored_from_remote")
        finally:
            harness.cleanup()


class WorkspaceNamespaceViewTests(unittest.TestCase):
    """End-to-end and adversarial tests for F29 (Multi-Repo BaseVector Namespace & Git View)."""

    def test_namespace_mount_verify_tamper_and_deterministic_git_view(self):
        harness = WorkspaceHarness()
        try:
            root, src_a, store, base_a = harness.fixture(
                "f29-namespace",
                {
                    "README.md": b"# Service A\n",
                    "scripts/deploy.sh": b"#!/bin/sh\necho deploy\n",
                },
            )
            (src_a / "scripts/deploy.sh").chmod(0o755)
            (src_a / "doc-link.md").symlink_to("README.md")
            harness.git("add", "--all", cwd=src_a)
            harness.git("commit", "--amend", "-m", "service-a init", cwd=src_a)
            base_a = harness.oid(src_a)

            src_b = root / "source-b"
            harness.git("init", "-b", "main", src_b)
            harness.write(src_b, "pkg/core.rs", b"pub fn version() -> u32 { 1 }\n")
            harness.git("add", "--all", cwd=src_b)
            harness.git("commit", "-m", "lib-b init", cwd=src_b)
            base_b = harness.oid(src_b)

            ws_a, repo_a = harness.init(store, src_a, base_a, "agent-a")
            ws_b, _ = harness.init(store, src_b, base_b, "agent-b")
            # Add an uncommitted dirty file in ws_a before checkpointing
            harness.write(repo_a, "dirty_config.json", b'{"env":"staging"}\n')
            cp_a = harness.checkpoint(store, ws_a)
            cp_b = harness.checkpoint(store, ws_b)

            # 1. Verify overlap and invalid mount path rejections
            for invalid_mounts in (
                [f"services/api={cp_a['checkpoint_id']}", f"services/api={cp_b['checkpoint_id']}"],
                [f"services={cp_a['checkpoint_id']}", f"services/api={cp_b['checkpoint_id']}"],
                [f"services/api/v1={cp_a['checkpoint_id']}", f"services/api={cp_b['checkpoint_id']}"],
                [f"../outside={cp_a['checkpoint_id']}"],
                [f"/abs/path={cp_a['checkpoint_id']}"],
                [f".git={cp_a['checkpoint_id']}"],
                [f"services/.git/sub={cp_a['checkpoint_id']}"],
                [f".rootyard-namespace.json={cp_a['checkpoint_id']}"],
            ):
                res = harness.lab(
                    "namespace-mount", store, "invalid-ns", *invalid_mounts, check=False
                )
                self.assertNotEqual(
                    res.returncode, 0, f"Mount should have failed: {invalid_mounts}"
                )

            # 2. Mount valid multi-repo namespace
            ns1 = harness.data(
                "namespace-mount",
                store,
                "platform-ns",
                f"services/api={cp_a['checkpoint_id']}",
                f"libs/core={cp_b['checkpoint_id']}",
            )
            self.assertEqual(ns1["state"], "mounted")
            self.assertEqual(ns1["mount_count"], 2)
            self.assertEqual(ns1["total_entries"], 5)
            self.assertEqual(
                [bv["mount_path"] for bv in ns1["base_vector"]],
                ["libs/core", "services/api"],
            )

            view_root = Path(ns1["view_path"])
            self.assertFalse((view_root / ".git").exists())
            self.assertFalse((view_root / "services" / ".git").exists())
            self.assertFalse((view_root / "services" / "api" / ".git").exists())
            self.assertEqual(
                (view_root / "services/api/dirty_config.json").read_bytes(),
                b'{"env":"staging"}\n',
            )
            self.assertEqual(
                (view_root / "libs/core/pkg/core.rs").read_bytes(),
                b"pub fn version() -> u32 { 1 }\n",
            )

            # 3. Verify namespace and test tamper detection
            ver = harness.data("verify-namespace", store, ns1["namespace_id"])
            self.assertTrue(ver["verified"])
            self.assertTrue(ver["readonly"])

            # Tamper A: Inject an upper .git directory above mounts
            (view_root / ".git").mkdir()
            self.assertNotEqual(
                harness.lab("verify-namespace", store, ns1["namespace_id"], check=False).returncode,
                0,
            )
            (view_root / ".git").rmdir()

            # Tamper B: Make a mounted file writable
            target_file = view_root / "libs/core/pkg/core.rs"
            target_file.chmod(0o644)
            self.assertNotEqual(
                harness.lab("verify-namespace", store, ns1["namespace_id"], check=False).returncode,
                0,
            )
            target_file.chmod(0o444)

            # Tamper C: Add an unlisted file outside mounts
            unlisted = view_root / "stray.txt"
            unlisted.write_bytes(b"stray\n")
            unlisted.chmod(0o444)
            self.assertNotEqual(
                harness.lab("verify-namespace", store, ns1["namespace_id"], check=False).returncode,
                0,
            )
            unlisted.chmod(0o644)
            unlisted.unlink()

            # Re-verify clean state passes
            ver_clean = harness.data("verify-namespace", store, ns1["namespace_id"])
            self.assertTrue(ver_clean["verified"])

            # 4. Deterministic Git View projection
            gv1 = harness.data("namespace-git-view", store, ns1["namespace_id"])
            self.assertEqual(gv1["state"], "projected")
            self.assertEqual(gv1["history_strategy"], "task_snapshot")
            self.assertTrue(gv1["fsck_passed"])
            self.assertTrue(gv1["readonly"])
            self.assertEqual(gv1["projected_files"], 6)

            # Mount a second namespace with identical name + BaseVector (in reverse CLI order)
            ns2 = harness.data(
                "namespace-mount",
                store,
                "platform-ns",
                f"libs/core={cp_b['checkpoint_id']}",
                f"services/api={cp_a['checkpoint_id']}",
            )
            custom_gv_dir = root / "custom-git-view"
            gv2 = harness.data("namespace-git-view", store, ns2["namespace_id"], custom_gv_dir)
            self.assertEqual(gv1["projected_commit_oid"], gv2["projected_commit_oid"])
            self.assertEqual(gv1["projected_tree_oid"], gv2["projected_tree_oid"])

            # Verify standard git clone and git fsck --full --strict on projected Git View
            cloned = root / "cloned-namespace"
            harness.git("clone", gv2["view_repo_path"], cloned)
            harness.git("fsck", "--full", "--strict", cwd=cloned)
            self.assertEqual(harness.oid(cloned), gv1["projected_commit_oid"])
            prov = json.loads((cloned / ".rootyard-namespace.json").read_bytes())
            self.assertEqual(prov["name"], "platform-ns")
            self.assertEqual(prov["history_strategy"], "task_snapshot")
            self.assertEqual(len(prov["base_vector"]), 2)
        finally:
            harness.cleanup()


if __name__ == "__main__":
    unittest.main()
