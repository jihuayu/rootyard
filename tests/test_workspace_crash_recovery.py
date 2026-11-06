#!/usr/bin/env python3
"""Verification suite for Phase 5 Track 4 CoW Overlay Sandbox & Power-Loss Crash Recovery (F50 & F51)."""

import json
import os
from pathlib import Path
import stat
import unittest

from tests.workspace import WorkspaceHarness

REPO_ROOT = Path(__file__).resolve().parent.parent


class WorkspaceCrashRecoveryTestSuite(unittest.TestCase):
    def test_overlay_write_rejects_parent_symlinks_in_native_cli(self):
        harness = WorkspaceHarness()
        try:
            self.assertTrue(harness.requested_binary.is_file(), "native Rust CLI required")
            root, source, store, base = harness.fixture(
                "overlay-parent-symlink", {"sub/data.txt": b"checkpoint original\n"}
            )
            workspace, _ = harness.init(store, source, base)
            checkpoint = harness.checkpoint(store, workspace)
            overlay = harness.data("overlay-mount", store, checkpoint["checkpoint_id"], "agent-one")
            lower = Path(overlay["lower_path"])
            upper = Path(overlay["upper_path"])
            merged = Path(overlay["merged_path"])
            external = root / "external"
            external.mkdir()
            (external / "sub").mkdir()
            outside_file = external / "sub/data.txt"
            outside_file.write_bytes(b"outside original\n")
            outside_file.chmod(0o640)
            lower_file = lower / "sub/data.txt"
            original = [(p.read_bytes(), stat.S_IMODE(p.lstat().st_mode)) for p in (lower_file, outside_file)]

            (merged / "alias").symlink_to("../lower")
            (merged / "outside").symlink_to(external)
            for alias in ("alias", "outside"):
                result = harness.lab("overlay-write", store, overlay["overlay_id"],
                                     f"{alias}/sub/data.txt", "attacker bytes", check=False)
                self.assertNotEqual(result.returncode, 0, result.stdout.decode())
                self.assertFalse((upper / alias).exists())
            self.assertEqual(
                [(p.read_bytes(), stat.S_IMODE(p.lstat().st_mode)) for p in (lower_file, outside_file)],
                original,
            )
        finally:
            harness.cleanup()

    def test_source_tree_line_caps_and_serde_deny_unknown_fields(self):
        facade = REPO_ROOT / "src/workspace_lab.rs"
        mod_rs = REPO_ROOT / "src/workspace_lab/mod.rs"
        crash_rs = REPO_ROOT / "src/workspace_lab/crash_recovery.rs"
        doc_md = REPO_ROOT / "docs/workspace-foundation.md"

        self.assertTrue(facade.is_file(), "Missing src/workspace_lab.rs")
        self.assertFalse(mod_rs.exists(), "Forbidden src/workspace_lab/mod.rs must not exist")
        self.assertTrue(crash_rs.is_file(), "Missing src/workspace_lab/crash_recovery.rs")
        self.assertTrue(doc_md.is_file(), "Missing docs/workspace-foundation.md")

        facade_lines = len(facade.read_text(encoding="utf-8").splitlines())
        crash_lines = len(crash_rs.read_text(encoding="utf-8").splitlines())
        self.assertLess(facade_lines, 150, f"src/workspace_lab.rs={facade_lines} lines >= 150 cap")
        self.assertGreaterEqual(crash_lines, 50, f"src/workspace_lab/crash_recovery.rs={crash_lines} lines < 50")
        self.assertLess(crash_lines, 500, f"src/workspace_lab/crash_recovery.rs={crash_lines} lines >= 500 cap")

        facade_src = facade.read_text(encoding="utf-8")
        self.assertIn('#[path = "workspace_lab/crash_recovery.rs"]', facade_src)
        self.assertIn("pub mod crash_recovery;", facade_src)
        for cmd in (
            "overlay-mount",
            "overlay-op",
            "overlay-write",
            "overlay-delete",
            "overlay-rename",
            "overlay-chmod",
            "overlay-git-add-f",
            "overlay-status",
            "crash-drill",
            "crash-recover",
        ):
            self.assertIn(f'"{cmd}"', facade_src, f"Command {cmd} not wired in src/workspace_lab.rs")

        crash_src = crash_rs.read_text(encoding="utf-8")
        for struct_name in (
            "OverlayMountManifest",
            "OverlayOpReport",
            "OverlayStatusReport",
            "CrashJournalEntry",
            "CrashJournal",
            "CrashDrillReport",
            "CrashRecoveryReport",
        ):
            idx = crash_src.find(f"pub struct {struct_name}")
            self.assertNotEqual(idx, -1, f"Missing struct {struct_name} in src/workspace_lab/crash_recovery.rs")
            preceding = crash_src[max(0, idx - 160) : idx]
            self.assertIn(
                "#[serde(deny_unknown_fields)]",
                preceding,
                f"{struct_name} missing #[serde(deny_unknown_fields)]",
            )

        doc_text = doc_md.read_text(encoding="utf-8")
        for token in (
            "overlay-mount",
            "overlay-op",
            "overlay-write",
            "overlay-delete",
            "overlay-rename",
            "overlay-chmod",
            "overlay-git-add-f",
            "overlay-status",
            "crash-drill",
            "crash-recover",
            "overlays/<uuid>/overlay.json",
            "crash_journal.json",
        ):
            self.assertIn(token, doc_text, f"docs/workspace-foundation.md missing {token}")

    def test_f50_overlay_cow_sandbox_rename_whiteout_chmod_and_git_add_f(self):
        harness = WorkspaceHarness()
        try:
            root, source, store, _ = harness.fixture(
                "f50-overlay-sandbox",
                {
                    ".gitignore": b"*.log\nbuild/\n",
                    ".rootyardignore": b"scratch/*\n!scratch/keep.txt\n",
                    "README.md": b"# Base Readme\n",
                    "src/lib.rs": b"pub fn val() -> u32 { 10 }\n",
                    "src/obsolete.rs": b"pub fn drop_me() {}\n",
                    "pkg/mod_a.rs": b"pub const A: u32 = 1;\n",
                    "pkg/sub/mod_b.rs": b"pub const B: u32 = 2;\n",
                    "bin/tool.sh": b"#!/bin/sh\necho tool\n",
                },
            )
            (source / "bin/tool.sh").chmod(0o644)
            (source / "bin/alias.sh").symlink_to("tool.sh")
            harness.git("add", "--all", cwd=source)
            harness.git("commit", "--amend", "-m", "f50 fixture base", cwd=source)
            base = harness.oid(source)

            ws, _ = harness.init(store, source, base, "agent-base")
            cp = harness.checkpoint(store, ws)
            remote_cas = root / "remote-cas"
            harness.data("push-remote", store, cp["checkpoint_id"], remote_cas)

            # Mount two concurrent agent overlays (one local, one via --remote-cas into a fresh store)
            ov1 = harness.data("overlay-mount", store, cp["checkpoint_id"], "agent-one")
            ov2 = harness.data("overlay-mount", store, cp["checkpoint_id"], "agent-two")

            store_remote = root / "store-remote-node"
            ov_remote = harness.data(
                "overlay-mount",
                store_remote,
                cp["checkpoint_id"],
                "agent-remote",
                "--remote-cas",
                remote_cas,
            )
            self.assertEqual(ov_remote["state"], "mounted")
            self.assertTrue((Path(ov_remote["merged_path"]) / "README.md").is_file())

            lower1 = Path(ov1["lower_path"])
            upper1 = Path(ov1["upper_path"])
            merged1 = Path(ov1["merged_path"])
            merged2 = Path(ov2["merged_path"])
            cp_repo = store / "checkpoints" / cp["checkpoint_id"] / "repo"

            # Verify lower layer is strictly read-only and all inodes are isolated
            for rel in ("README.md", "src/lib.rs", "bin/tool.sh"):
                st_cp = (cp_repo / rel).stat()
                st_l1 = (lower1 / rel).stat()
                st_m1 = (merged1 / rel).stat()
                st_m2 = (merged2 / rel).stat()
                self.assertEqual(st_l1.st_mode & 0o222, 0, f"Lower file {rel} must have no write bits")
                self.assertNotEqual((st_cp.st_dev, st_cp.st_ino), (st_l1.st_dev, st_l1.st_ino))
                self.assertNotEqual((st_l1.st_dev, st_l1.st_ino), (st_m1.st_dev, st_m1.st_ino))
                self.assertNotEqual((st_m1.st_dev, st_m1.st_ino), (st_m2.st_dev, st_m2.st_ino))

            # Reject unsafe overlay paths
            for bad_path in ("../escape.txt", "/abs/path.txt", ".git/config", "cross-repo:other/file.txt"):
                res_bad = harness.lab("overlay-write", store, ov1["overlay_id"], bad_path, "bad", check=False)
                self.assertNotEqual(res_bad.returncode, 0, f"Unsafe path {bad_path} must be rejected")

            # 1. CoW write in ov1 does not mutate lower1 or sibling ov2
            w_rep = harness.data("overlay-write", store, ov1["overlay_id"], "src/lib.rs", "pub fn val() -> u32 { 42 }\n")
            self.assertTrue(w_rep["copied_up"])
            self.assertEqual((merged1 / "src/lib.rs").read_bytes(), b"pub fn val() -> u32 { 42 }\n")
            self.assertEqual((upper1 / "src/lib.rs").read_bytes(), b"pub fn val() -> u32 { 42 }\n")
            self.assertEqual((lower1 / "src/lib.rs").read_bytes(), b"pub fn val() -> u32 { 10 }\n")
            self.assertEqual((merged2 / "src/lib.rs").read_bytes(), b"pub fn val() -> u32 { 10 }\n")

            # 2. CoW chmod on lower-backed file
            chmod_rep = harness.data("overlay-chmod", store, ov1["overlay_id"], "bin/tool.sh", "0755")
            self.assertTrue(chmod_rep["copied_up"])
            self.assertEqual(chmod_rep["mode"], 0o755)
            self.assertEqual((merged1 / "bin/tool.sh").stat().st_mode & 0o777, 0o755)
            self.assertEqual((lower1 / "bin/tool.sh").stat().st_mode & 0o777, 0o444)

            # 3. Whiteout deletion of lower-backed file
            del_rep = harness.data("overlay-delete", store, ov1["overlay_id"], "src/obsolete.rs")
            self.assertTrue(del_rep["whiteout_recorded"])
            self.assertFalse((merged1 / "src/obsolete.rs").exists())
            self.assertTrue((lower1 / "src/obsolete.rs").is_file())
            self.assertTrue((merged2 / "src/obsolete.rs").is_file())

            # 4. Cross-layer file rename & directory rename with whiteouts
            ren_file = harness.data("overlay-rename", store, ov1["overlay_id"], "README.md", " docs_readme.md".strip())
            self.assertTrue(ren_file["copied_up"])
            self.assertTrue(ren_file["whiteout_recorded"])
            self.assertFalse((merged1 / "README.md").exists())
            self.assertEqual((merged1 / "docs_readme.md").read_bytes(), b"# Base Readme\n")

            ren_dir = harness.data("overlay-rename", store, ov1["overlay_id"], "pkg", "crates/pkg_v2")
            self.assertTrue(ren_dir["copied_up"])
            self.assertTrue(ren_dir["whiteout_recorded"])
            self.assertFalse((merged1 / "pkg").exists())
            self.assertEqual((merged1 / "crates/pkg_v2/mod_a.rs").read_bytes(), b"pub const A: u32 = 1;\n")
            self.assertEqual((merged1 / "crates/pkg_v2/sub/mod_b.rs").read_bytes(), b"pub const B: u32 = 2;\n")

            # 5. Synchronous git add -f ignore override for both .gitignore and .rootyardignore paths
            harness.data("overlay-write", store, ov1["overlay_id"], "build/artifact.bin", "binary payload\n")
            harness.data("overlay-write", store, ov1["overlay_id"], "scratch/secret.tmp", "forced scratch\n")
            harness.data("overlay-write", store, ov1["overlay_id"], "debug.log", "still ignored log\n")

            st_before = harness.data("overlay-status", store, ov1["overlay_id"])
            self.assertIn("build/artifact.bin", st_before["ignored_paths"])
            self.assertIn("scratch/secret.tmp", st_before["ignored_paths"])
            self.assertIn("debug.log", st_before["ignored_paths"])

            add_f1 = harness.data("overlay-git-add-f", store, ov1["overlay_id"], "build/artifact.bin")
            add_f2 = harness.data("overlay-op", store, ov1["overlay_id"], "git-add-f", "scratch/secret.tmp")
            self.assertTrue(add_f1["forced_managed"])
            self.assertTrue(add_f2["forced_managed"])

            st_after = harness.data("overlay-status", store, ov1["overlay_id"])
            self.assertTrue(st_after["is_dirty"])
            self.assertIn("build/artifact.bin", st_after["managed_paths"])
            self.assertIn("build/artifact.bin", st_after["staged_paths"])
            self.assertNotIn("build/artifact.bin", st_after["ignored_paths"])
            self.assertIn("scratch/secret.tmp", st_after["managed_paths"])
            self.assertIn("scratch/secret.tmp", st_after["staged_paths"])
            self.assertNotIn("scratch/secret.tmp", st_after["ignored_paths"])
            self.assertIn("debug.log", st_after["ignored_paths"])
            for w_expected in ("src/obsolete.rs", "README.md", "pkg", "pkg/mod_a.rs", "pkg/sub/mod_b.rs"):
                self.assertIn(w_expected, st_after["whiteouts"])

            # 6. Tamper detection on overlay.json
            ov_json_p = store / "overlays" / ov1["overlay_id"] / "overlay.json"
            orig_bytes = ov_json_p.read_bytes()
            tampered = json.loads(orig_bytes)
            tampered["agent_id"] = "tampered"
            ov_json_p.chmod(0o600)
            ov_json_p.write_bytes(json.dumps(tampered, indent=2).encode())
            self.assertNotEqual(harness.lab("overlay-status", store, ov1["overlay_id"], check=False).returncode, 0)
            ov_json_p.write_bytes(orig_bytes)
            self.assertEqual(harness.data("overlay-status", store, ov1["overlay_id"])["state"], "mounted")
        finally:
            harness.cleanup()

    def test_f51_power_loss_crash_drills_and_wal_recovery_windows(self):
        harness = WorkspaceHarness()
        try:
            _, source, store, base = harness.fixture(
                "f51-crash-recovery",
                {
                    ".gitignore": b"*.log\n",
                    "README.md": b"initial\n",
                    "src/app.rs": b"pub fn app() -> u32 { 1 }\n",
                },
            )
            ws, ws_repo = harness.init(store, source, base, "agent-crash-ws")
            cp = harness.checkpoint(store, ws)
            ov = harness.data("overlay-mount", store, cp["checkpoint_id"], "agent-crash-ov")
            ov_id = ov["overlay_id"]
            merged_dir = Path(ov["merged_path"])

            # Mutate overlay before Window 1 (before_wal_fsync)
            harness.data("overlay-write", store, ov_id, "src/app.rs", "pub fn app() -> u32 { 2 }\n")
            harness.data("overlay-write", store, ov_id, "src/unsynced.rs", "pub const UNSYNCED: bool = true;\n")

            d1 = harness.data("crash-drill", store, ov_id, "before_wal_fsync", "--quiescent")
            self.assertEqual(d1["window"], "before_wal_fsync")
            self.assertEqual(d1["simulated_kill_code"], 137)
            self.assertFalse(d1["wal_persisted"])
            self.assertGreaterEqual(d1["tmp_files_created"], 2)
            self.assertIn("src/app.rs", d1["unsynced_paths"])
            self.assertIn("src/unsynced.rs", d1["unsynced_paths"])

            r1 = harness.data("crash-recover", store, ov_id)
            self.assertEqual(r1["state"], "recovered")
            self.assertEqual(r1["window_recovered"], "before_wal_fsync")
            self.assertEqual(r1["action_taken"], "truncated_corrupt_wal_tail")
            self.assertEqual(r1["truncated_corrupt_wal_entries"], 1)
            self.assertGreaterEqual(r1["purged_tmp_files"], 2)
            self.assertIn("src/app.rs", r1["unsynced_paths"])
            self.assertTrue(r1["git_status_clean_or_consistent"])
            self.assertTrue(r1["fsck_passed"])

            # Window 2: after_wal_before_publish (WAL committed & fsynced, checkpoint staged but not published)
            d2 = harness.data("crash-drill", store, ov_id, "after_wal_before_publish", "--quiescent")
            self.assertTrue(d2["wal_persisted"])
            self.assertFalse(d2["publish_completed"])
            staged_cp_2 = d2["staged_checkpoint_id"]
            self.assertIsNotNone(staged_cp_2)
            self.assertFalse((store / "checkpoints" / staged_cp_2).exists())

            r2 = harness.data("crash-recover", store, ov_id)
            self.assertEqual(r2["window_recovered"], "after_wal_before_publish")
            self.assertEqual(r2["action_taken"], "replayed_wal_and_published_checkpoint")
            self.assertEqual(r2["replayed_wal_entries"], 1)
            self.assertEqual(r2["committed_checkpoint_id"], staged_cp_2)
            self.assertTrue((store / "checkpoints" / staged_cp_2 / "manifest.json").is_file())
            self.assertEqual(r2["unsynced_paths"], [])

            # Window 3: after_publish_before_ack (published + stale .git/index.lock left behind)
            harness.data("overlay-write", store, ov_id, "README.md", "updated before window 3\n")
            d3 = harness.data("crash-drill", store, ov_id, "after_publish_before_ack", "--quiescent")
            self.assertTrue(d3["wal_persisted"])
            self.assertTrue(d3["publish_completed"])
            self.assertTrue(d3["index_lock_left"])
            self.assertTrue((merged_dir / ".git/index.lock").is_file())

            r3 = harness.data("crash-recover", store, ov_id)
            self.assertEqual(r3["window_recovered"], "after_publish_before_ack")
            self.assertEqual(r3["action_taken"], "reconciled_lock_and_acked_wal")
            self.assertTrue(r3["removed_index_lock"])
            self.assertFalse((merged_dir / ".git/index.lock").exists())
            self.assertEqual(r3["committed_checkpoint_id"], d3["staged_checkpoint_id"])
            self.assertTrue(r3["fsck_passed"])

            # Window 4: index_update_interrupted on standard workspace target + idempotent re-recovery
            harness.write(ws_repo, "src/app.rs", b"pub fn app() -> u32 { 99 }\n")
            d4 = harness.data("crash-drill", store, ws["workspace_id"], "index_update_interrupted", "--quiescent")
            self.assertEqual(d4["target_kind"], "workspace")
            self.assertTrue(d4["index_lock_left"])
            self.assertTrue((ws_repo / ".git/index.lock").is_file())

            r4 = harness.data("crash-recover", store, ws["workspace_id"])
            self.assertEqual(r4["target_kind"], "workspace")
            self.assertEqual(r4["window_recovered"], "index_update_interrupted")
            self.assertTrue(r4["removed_index_lock"])
            self.assertFalse((ws_repo / ".git/index.lock").exists())
            self.assertIn("src/app.rs", r4["unsynced_paths"])
            self.assertTrue(r4["git_status_clean_or_consistent"])
            self.assertTrue(r4["fsck_passed"])

            # Verify git status and git fsck work directly on both recovered repositories
            harness.git("status", "--porcelain=v2", cwd=merged_dir)
            harness.git("fsck", "--full", "--strict", cwd=merged_dir)
            harness.git("status", "--porcelain=v2", cwd=ws_repo)
            harness.git("fsck", "--full", "--strict", cwd=ws_repo)

            # Second crash-recover call is a clean idempotent no-op
            r4_idem = harness.data("crash-recover", store, ws["workspace_id"])
            self.assertEqual(r4_idem["window_recovered"], "none_idempotent")
            self.assertEqual(r4_idem["action_taken"], "noop_already_recovered")
            self.assertEqual(r4_idem["replayed_wal_entries"], 0)
            self.assertEqual(r4_idem["truncated_corrupt_wal_entries"], 0)
        finally:
            harness.cleanup()


if __name__ == "__main__":
    unittest.main()
