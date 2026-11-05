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
            148,
            f"src/workspace_lab.rs has {len(facade_lines)} lines (limit < 148)",
        )
        for mod_decl in (
            '#[path = "workspace_lab/remote.rs"]',
            '#[path = "workspace_lab/namespace.rs"]',
            '#[path = "workspace_lab/writable_view.rs"]',
        ):
            self.assertIn(mod_decl, facade_text)
        for subcmd in (
            '"push-remote"',
            '"pull-remote"',
            '"namespace-mount"',
            '"verify-namespace"',
            '"namespace-git-view"',
            '"agent-lease"',
            '"namespace-write"',
            '"namespace-commit-back"',
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

        wv_path = ROOT / "src" / "workspace_lab" / "writable_view.rs"
        self.assertTrue(wv_path.is_file(), f"Missing {wv_path}")
        wv_text = wv_path.read_text(encoding="utf-8")
        wv_lines = wv_text.splitlines()
        self.assertGreaterEqual(
            len(wv_lines),
            150,
            f"writable_view.rs has {len(wv_lines)} lines (minimum >= 150)",
        )
        self.assertLess(
            len(wv_lines),
            500,
            f"writable_view.rs has {len(wv_lines)} lines (limit < 500)",
        )
        struct_count = wv_text.count("pub struct ")
        deny_count = wv_text.count("#[serde(deny_unknown_fields)]")
        self.assertGreaterEqual(struct_count, 6)
        self.assertEqual(
            struct_count,
            deny_count,
            "Every struct in writable_view.rs must have #[serde(deny_unknown_fields)]",
        )

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

        wv_text = (ROOT / "src" / "workspace_lab" / "writable_view.rs").read_text(encoding="utf-8")
        for item in (
            "pub struct AgentLeaseEntry",
            "pub struct AgentLeaseTable",
            "pub struct NamespaceWriteReport",
            "pub struct CrossRepoCommitReceipt",
            "pub fn cmd_agent_lease",
            "pub fn cmd_namespace_write",
            "pub fn cmd_namespace_commit_back",
        ):
            self.assertIn(item, wv_text)

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


class WorkspaceWritableNamespaceAndLeaseTests(unittest.TestCase):
    """Unit, integration, and adversarial tests for Milestone M20:
    Workspace Writable Namespace Reverse Mapping & Multi-Agent Lease Locks.
    """

    def test_deterministic_reverse_path_mapping_and_unmapped_or_traversal_rejection(self):
        harness = WorkspaceHarness()
        try:
            root, src_auth, store, base_auth = harness.fixture(
                "m20-reverse-map",
                {
                    "src/main.rs": b"fn main() {}\n",
                    "legacy.txt": b"remove me\n",
                },
            )
            src_billing = root / "source-billing"
            harness.git("init", "-b", "main", src_billing)
            harness.write(src_billing, "invoice.py", b"RATE = 10\n")
            harness.git("add", "--all", cwd=src_billing)
            harness.git("commit", "-m", "billing init", cwd=src_billing)
            base_billing = harness.oid(src_billing)

            src_shared = root / "source-shared"
            harness.git("init", "-b", "main", src_shared)
            harness.write(src_shared, "util.h", b"#pragma once\n")
            harness.git("add", "--all", cwd=src_shared)
            harness.git("commit", "-m", "shared init", cwd=src_shared)
            base_shared = harness.oid(src_shared)

            ws_auth, _ = harness.init(store, src_auth, base_auth, "agent-auth")
            ws_billing, _ = harness.init(store, src_billing, base_billing, "agent-billing")
            ws_shared, _ = harness.init(store, src_shared, base_shared, "agent-shared")
            cp_auth = harness.checkpoint(store, ws_auth)
            cp_billing = harness.checkpoint(store, ws_billing)
            cp_shared = harness.checkpoint(store, ws_shared)

            ns = harness.data(
                "namespace-mount",
                store,
                "tri-repo-ns",
                f"services/auth={cp_auth['checkpoint_id']}",
                f"services/billing={cp_billing['checkpoint_id']}",
                f"libs/shared={cp_shared['checkpoint_id']}",
            )
            ns_id = ns["namespace_id"]

            # Reject unmapped root paths, unmapped intermediate paths, leading '/', '..', and .git
            for bad_path in (
                "root_level.txt",
                "services/unmapped_file.txt",
                "services/auth",
                "../escape.txt",
                "services/auth/../../outside.txt",
                "/services/auth/src/main.rs",
                "services/auth/.git/HEAD",
                ".rootyard-namespace.json",
            ):
                res = harness.lab(
                    "namespace-write",
                    store,
                    ns_id,
                    "agent-writer",
                    bad_path,
                    "payload\n",
                    check=False,
                )
                self.assertNotEqual(
                    res.returncode, 0, f"Expected bad/unmapped path {bad_path} to fail"
                )

            # Segment normalization ('services//auth/./src/main.rs') maps deterministically
            w_auth = harness.data(
                "namespace-write",
                store,
                ns_id,
                "agent-writer",
                "services//auth/./src/main.rs",
                "fn main() { println!(\"v2\"); }\n",
            )
            self.assertEqual(w_auth["path"], "services/auth/src/main.rs")
            self.assertEqual(w_auth["mount_path"], "services/auth")
            self.assertEqual(w_auth["repo_rel_path"], "src/main.rs")
            self.assertEqual(w_auth["base_checkpoint_id"], cp_auth["checkpoint_id"])
            self.assertEqual(w_auth["workspace_id"], ws_auth["workspace_id"])
            self.assertEqual(w_auth["change"], "modified")

            w_del = harness.data(
                "namespace-write",
                store,
                ns_id,
                "agent-writer",
                "services/auth/legacy.txt",
                "DELETE",
            )
            self.assertEqual(w_del["mount_path"], "services/auth")
            self.assertEqual(w_del["repo_rel_path"], "legacy.txt")
            self.assertEqual(w_del["operation"], "delete")
            self.assertEqual(w_del["change"], "deleted")

            w_shared = harness.data(
                "namespace-write",
                store,
                ns_id,
                "agent-writer",
                "libs/shared/new_header.h",
                "#define VERSION 2\n",
            )
            self.assertEqual(w_shared["mount_path"], "libs/shared")
            self.assertEqual(w_shared["repo_rel_path"], "new_header.h")
            self.assertEqual(w_shared["base_checkpoint_id"], cp_shared["checkpoint_id"])
            self.assertEqual(w_shared["change"], "added")
            self.assertEqual(w_shared["pending_writes_count"], 3)
        finally:
            harness.cleanup()

    def test_multi_agent_overlapping_prefix_lease_conflict_and_expired_takeover(self):
        harness = WorkspaceHarness()
        try:
            _, src_a, store, base_a = harness.fixture(
                "m20-leases",
                {"src/lib.rs": b"pub fn a() {}\n"},
            )
            ws_a, _ = harness.init(store, src_a, base_a, "agent-alpha")
            cp_a = harness.checkpoint(store, ws_a)
            ns = harness.data(
                "namespace-mount",
                store,
                "lease-ns",
                f"services/auth={cp_a['checkpoint_id']}",
                f"libs/core={cp_a['checkpoint_id']}",
            )
            ns_id = ns["namespace_id"]

            # Agent-alpha acquires lease on services/auth (epoch 1)
            l1 = harness.data(
                "agent-lease",
                store,
                ns_id,
                "agent-alpha",
                "acquire",
                "--prefix",
                "services/auth",
                "--ttl-secs",
                "300",
            )
            self.assertEqual(l1["lease_epoch"], 1)
            self.assertEqual(l1["state"], "acquired")
            self.assertTrue((store / "leases" / f"{ns_id}.json").is_file())

            # Agent-beta can acquire non-overlapping prefix libs/core concurrently (epoch 2)
            l2 = harness.data(
                "agent-lease",
                store,
                ns_id,
                "agent-beta",
                "acquire",
                "--prefix",
                "libs/core",
                "--ttl-secs",
                "300",
            )
            self.assertEqual(l2["lease_epoch"], 2)
            self.assertEqual(l2["active_leases"], 2)

            # Agent-beta cannot acquire overlapping prefix (exact, child, parent, or root)
            for conflict_prefix in ("services/auth", "services/auth/src", "services", ""):
                res_c = harness.lab(
                    "agent-lease",
                    store,
                    ns_id,
                    "agent-beta",
                    "acquire",
                    "--prefix",
                    conflict_prefix,
                    check=False,
                )
                self.assertNotEqual(
                    res_c.returncode,
                    0,
                    f"Overlapping prefix '{conflict_prefix}' must be rejected",
                )

            # Agent-beta cannot write under services/auth while agent-alpha holds lease
            res_w = harness.lab(
                "namespace-write",
                store,
                ns_id,
                "agent-beta",
                "services/auth/src/lib.rs",
                "unauthorized\n",
                check=False,
            )
            self.assertNotEqual(res_w.returncode, 0)

            # Release agent-alpha's lease, then re-acquire with --ttl-secs 0 so it expires immediately
            rel = harness.data(
                "agent-lease",
                store,
                ns_id,
                "agent-alpha",
                "release",
                "--prefix",
                "services/auth",
                "--epoch",
                "1",
            )
            self.assertEqual(rel["state"], "released")

            l3 = harness.data(
                "agent-lease",
                store,
                ns_id,
                "agent-alpha",
                "acquire",
                "--prefix",
                "services/auth",
                "--ttl-secs",
                "0",
            )
            self.assertEqual(l3["lease_epoch"], 3)

            # Agent-beta takes over expired prefix -> bumps lease_epoch to 4
            l4 = harness.data(
                "agent-lease",
                store,
                ns_id,
                "agent-beta",
                "acquire",
                "--prefix",
                "services/auth/src",
                "--ttl-secs",
                "300",
            )
            self.assertEqual(l4["lease_epoch"], 4)
            self.assertEqual(l4["state"], "acquired")

            # Stale epoch renewal and stale epoch write by agent-alpha (epoch 3) must fail
            self.assertNotEqual(
                harness.lab(
                    "agent-lease",
                    store,
                    ns_id,
                    "agent-alpha",
                    "renew",
                    "--prefix",
                    "services/auth",
                    "--epoch",
                    "3",
                    check=False,
                ).returncode,
                0,
            )
            self.assertNotEqual(
                harness.lab(
                    "namespace-write",
                    store,
                    ns_id,
                    "agent-alpha",
                    "services/auth/src/lib.rs",
                    "stale write\n",
                    "--lease-epoch",
                    "3",
                    check=False,
                ).returncode,
                0,
            )

            # Agent-beta succeeds with current epoch 4
            w_ok = harness.data(
                "namespace-write",
                store,
                ns_id,
                "agent-beta",
                "services/auth/src/lib.rs",
                "pub fn a() { /* epoch 4 */ }\n",
                "--lease-epoch",
                "4",
            )
            self.assertEqual(w_ok["lease_epoch"], 4)
            self.assertEqual(w_ok["state"], "staged")
        finally:
            harness.cleanup()

    def test_atomic_two_phase_cross_repo_commit_back_and_base_drift_rollback(self):
        harness = WorkspaceHarness()
        try:
            root, src_a, store, base_a = harness.fixture(
                "m20-commit-back",
                {
                    "api.rs": b"pub fn api() -> u32 { 1 }\n",
                    "drop.txt": b"temporary\n",
                },
            )
            src_b = root / "source-b"
            harness.git("init", "-b", "main", src_b)
            harness.write(src_b, "lib.rs", b"pub fn lib() -> u32 { 10 }\n")
            harness.git("add", "--all", cwd=src_b)
            harness.git("commit", "-m", "b base", cwd=src_b)
            base_b = harness.oid(src_b)

            src_c = root / "source-c"
            harness.git("init", "-b", "main", src_c)
            harness.write(src_c, "readme.txt", b"untouched mount\n")
            harness.git("add", "--all", cwd=src_c)
            harness.git("commit", "-m", "c base", cwd=src_c)
            base_c = harness.oid(src_c)

            ws_a, repo_a = harness.init(store, src_a, base_a, "agent-a")
            ws_b, repo_b = harness.init(store, src_b, base_b, "agent-b")
            ws_c, _ = harness.init(store, src_c, base_c, "agent-c")
            cp_a = harness.checkpoint(store, ws_a)
            cp_b = harness.checkpoint(store, ws_b)
            cp_c = harness.checkpoint(store, ws_c)

            ns = harness.data(
                "namespace-mount",
                store,
                "commit-back-ns",
                f"services/api={cp_a['checkpoint_id']}",
                f"libs/core={cp_b['checkpoint_id']}",
                f"docs/guide={cp_c['checkpoint_id']}",
            )
            ns_id = ns["namespace_id"]

            lease = harness.data(
                "agent-lease",
                store,
                ns_id,
                "agent-coord",
                "acquire",
                "--ttl-secs",
                "300",
            )
            ep = str(lease["lease_epoch"])

            # Stage cross-repo writes across services/api and libs/core (docs/guide untouched)
            harness.data(
                "namespace-write",
                store,
                ns_id,
                "agent-coord",
                "services/api/api.rs",
                "pub fn api() -> u32 { 2 }\n",
                "--lease-epoch",
                ep,
            )
            harness.data(
                "namespace-write",
                store,
                ns_id,
                "agent-coord",
                "services/api/drop.txt",
                "DELETE",
                "--lease-epoch",
                ep,
            )
            harness.data(
                "namespace-write",
                store,
                ns_id,
                "agent-coord",
                "libs/core/added.rs",
                "pub const EXTRA: u32 = 5;\n",
                "--lease-epoch",
                ep,
            )

            receipt = harness.data(
                "namespace-commit-back",
                store,
                ns_id,
                "agent-coord",
                "--quiescent",
                "--lease-epoch",
                ep,
            )
            self.assertEqual(receipt["state"], "committed")
            self.assertEqual(receipt["phase"], "committed")
            self.assertEqual(receipt["previous_revision"], 1)
            self.assertEqual(receipt["namespace_revision"], 2)
            self.assertEqual(receipt["touched_mounts_count"], 2)
            self.assertEqual(receipt["total_writes_committed"], 3)
            self.assertTrue(Path(receipt["receipt_path"]).is_file())

            # Verify derived checkpoints and changesets were persisted, and docs/guide was untouched
            by_mount = {mc["mount_path"]: mc for mc in receipt["mount_commits"]}
            self.assertEqual(sorted(by_mount.keys()), ["libs/core", "services/api"])
            self.assertEqual(by_mount["services/api"]["modified"], 1)
            self.assertEqual(by_mount["services/api"]["deleted"], 1)
            self.assertEqual(by_mount["libs/core"]["added"], 1)
            for mc in receipt["mount_commits"]:
                self.assertNotEqual(mc["new_checkpoint_id"], mc["previous_checkpoint_id"])
                self.assertTrue((store / "checkpoints" / mc["new_checkpoint_id"] / "manifest.json").is_file())
                self.assertTrue((store / "changesets" / mc["changeset_id"] / "changeset.json").is_file())

            bv_by_mount = {bv["mount_path"]: bv for bv in receipt["base_vector"]}
            self.assertEqual(bv_by_mount["docs/guide"]["checkpoint_id"], cp_c["checkpoint_id"])
            self.assertEqual(
                bv_by_mount["services/api"]["checkpoint_id"],
                by_mount["services/api"]["new_checkpoint_id"],
            )

            # Verify constituent workspaces and namespace verification at revision 2
            self.assertEqual((repo_a / "api.rs").read_bytes(), b"pub fn api() -> u32 { 2 }\n")
            self.assertFalse((repo_a / "drop.txt").exists())
            self.assertEqual((repo_b / "added.rs").read_bytes(), b"pub const EXTRA: u32 = 5;\n")
            ver2 = harness.data("verify-namespace", store, ns_id)
            self.assertTrue(ver2["verified"])
            self.assertEqual(ver2["namespace_revision"], 2)

            # Phase 1 Prepare conflict rollback: stage writes, then drift constituent workspace repo_b
            harness.data(
                "namespace-write",
                store,
                ns_id,
                "agent-coord",
                "services/api/api.rs",
                "pub fn api() -> u32 { 3 }\n",
                "--lease-epoch",
                ep,
            )
            harness.data(
                "namespace-write",
                store,
                ns_id,
                "agent-coord",
                "libs/core/lib.rs",
                "pub fn lib() -> u32 { 20 }\n",
                "--lease-epoch",
                ep,
            )
            # Induce base drift in repo_b
            harness.write(repo_b, "lib.rs", b"pub fn lib() -> u32 { 999 /* drift */ }\n")

            commits_before = set((store / "namespaces" / ns_id / "commits").iterdir())
            res_drift = harness.lab(
                "namespace-commit-back",
                store,
                ns_id,
                "agent-coord",
                "--quiescent",
                "--lease-epoch",
                ep,
                check=False,
            )
            self.assertNotEqual(res_drift.returncode, 0)
            commits_after = set((store / "namespaces" / ns_id / "commits").iterdir())
            self.assertEqual(commits_before, commits_after)
            # Verify repo_a was NOT mutated by partial commit and namespace view rolled back cleanly to rev 2
            self.assertEqual((repo_a / "api.rs").read_bytes(), b"pub fn api() -> u32 { 2 }\n")
            ver_rollback = harness.data("verify-namespace", store, ns_id)
            self.assertTrue(ver_rollback["verified"])
            self.assertEqual(ver_rollback["namespace_revision"], 2)
        finally:
            harness.cleanup()


if __name__ == "__main__":
    unittest.main()

