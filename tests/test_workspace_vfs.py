#!/usr/bin/env python3
"""Verification suite for Phase 5 Track 3 On-Demand VFS Mounts (F37 & F38)."""

import hashlib
import json
import os
from pathlib import Path
import unittest

from tests.workspace import WorkspaceHarness, require

REPO_ROOT = Path(__file__).resolve().parent.parent


class WorkspaceVfsTestSuite(unittest.TestCase):
    def test_source_tree_line_caps_and_vfs_wiring(self):
        facade = REPO_ROOT / "src/workspace_lab.rs"
        vfs_rs = REPO_ROOT / "src/workspace_lab/vfs.rs"
        doc_md = REPO_ROOT / "docs/workspace-foundation.md"

        self.assertTrue(facade.is_file(), "Missing src/workspace_lab.rs")
        self.assertTrue(vfs_rs.is_file(), "Missing src/workspace_lab/vfs.rs")
        self.assertTrue(doc_md.is_file(), "Missing docs/workspace-foundation.md")

        facade_lines = len(facade.read_text(encoding="utf-8").splitlines())
        vfs_lines = len(vfs_rs.read_text(encoding="utf-8").splitlines())
        self.assertLess(facade_lines, 150, f"src/workspace_lab.rs={facade_lines} lines >= 150 cap")
        self.assertGreaterEqual(vfs_lines, 50, f"src/workspace_lab/vfs.rs={vfs_lines} lines < 50")
        self.assertLess(vfs_lines, 600, f"src/workspace_lab/vfs.rs={vfs_lines} lines >= 600 cap")

        facade_src = facade.read_text(encoding="utf-8")
        self.assertIn("pub mod vfs;", facade_src)
        for cmd in ("vfs-mount", "vfs-hydrate", "vfs-status", "vfs-evict"):
            self.assertIn(f'"{cmd}"', facade_src, f"Command {cmd} not wired in src/workspace_lab.rs")

        vfs_src = vfs_rs.read_text(encoding="utf-8")
        for struct_name in (
            "VfsCatalogEntry",
            "VfsMountManifest",
            "VfsHydrateReport",
            "VfsDirtyEntry",
            "VfsStatusReport",
            "VfsEvictReport",
        ):
            idx = vfs_src.find(f"pub struct {struct_name}")
            self.assertNotEqual(idx, -1, f"Missing struct {struct_name} in src/workspace_lab/vfs.rs")
            preceding = vfs_src[max(0, idx - 160):idx]
            self.assertIn("#[serde(deny_unknown_fields)]", preceding, f"{struct_name} missing #[serde(deny_unknown_fields)]")

        doc_text = doc_md.read_text(encoding="utf-8")
        for token in ("vfs-mount", "vfs-hydrate", "vfs-status", "vfs-evict", "vfs/<uuid>/vfs.json"):
            self.assertIn(token, doc_text, f"docs/workspace-foundation.md missing {token}")

    def test_vfs_mount_lazy_catalog_and_inline_threshold(self):
        harness = WorkspaceHarness()
        try:
            model_a = b"A" * 4096
            model_b = b"B" * 6144
            root, source, store_a, _ = harness.fixture("vfs-mount-lazy", {
                "README.md": b"# Lazy VFS\n",
                "bin/run.sh": b"#!/bin/sh\necho vfs\n",
                "assets/model-a.bin": model_a,
                "assets/model-b.bin": model_b,
            })
            (source / "bin/run.sh").chmod(0o755)
            (source / "bin/latest.sh").symlink_to("run.sh")
            harness.git("add", "--all", cwd=source)
            harness.git("commit", "--amend", "-m", "vfs fixture base", cwd=source)
            base = harness.oid(source)

            ws, _ = harness.init(store_a, source, base, "agent-node-a")
            cp = harness.checkpoint(store_a, ws)
            remote_cas = root / "remote-cas"
            harness.data("push-remote", store_a, cp["checkpoint_id"], remote_cas)

            store_b = root / "store-node-b"
            vfs = harness.data(
                "vfs-mount",
                store_b,
                cp["checkpoint_id"],
                "agent-node-b",
                "--remote-cas",
                remote_cas,
                "--inline-threshold",
                "128",
                "--hydrate-pattern",
                "bin/*",
            )
            self.assertEqual(vfs["state"], "mounted")
            self.assertEqual(vfs["total_entries"], 5)
            self.assertEqual(vfs["hydrated_entries"], 3)
            self.assertEqual(vfs["dehydrated_entries"], 2)
            self.assertEqual(vfs["unhydrated_bytes"], 4096 + 6144)
            self.assertEqual(vfs["total_bytes"], vfs["hydrated_bytes"] + vfs["unhydrated_bytes"])

            mount_dir = Path(vfs["mount_path"])
            self.assertTrue((mount_dir / ".git").is_dir())
            self.assertTrue((mount_dir / "README.md").is_file())
            self.assertEqual((mount_dir / "bin/run.sh").stat().st_mode & 0o777, 0o755)
            self.assertTrue((mount_dir / "bin/latest.sh").is_symlink())
            self.assertEqual(os.readlink(mount_dir / "bin/latest.sh"), "run.sh")
            self.assertFalse((mount_dir / "assets/model-a.bin").exists())
            self.assertFalse((mount_dir / "assets/model-b.bin").exists())

            # Local checkpoint vfs-mount must not share hard-link inodes with checkpoint repo
            vfs_local = harness.data("vfs-mount", store_a, cp["checkpoint_id"], "agent-local", "--inline-threshold", "128")
            local_mount = Path(vfs_local["mount_path"])
            cp_readme = store_a / "checkpoints" / cp["checkpoint_id"] / "repo/README.md"
            st_mount = (local_mount / "README.md").stat()
            st_cp = cp_readme.stat()
            self.assertNotEqual((st_mount.st_dev, st_mount.st_ino), (st_cp.st_dev, st_cp.st_ino))
        finally:
            harness.cleanup()

    def test_vfs_on_demand_hydrate_prewarm_and_cas_verification(self):
        harness = WorkspaceHarness()
        try:
            blob_a = b"M" * 4096
            blob_b = b"N" * 8192
            root, source, store, base = harness.fixture("vfs-hydrate", {
                "README.md": b"small\n",
                "assets/blob-a.bin": blob_a,
                "assets/blob-b.bin": blob_b,
            })
            ws, _ = harness.init(store, source, base, "agent-hyd")
            cp = harness.checkpoint(store, ws)
            remote_cas = root / "remote-cas"
            harness.data("push-remote", store, cp["checkpoint_id"], remote_cas)

            vfs = harness.data(
                "vfs-mount",
                store,
                cp["checkpoint_id"],
                "agent-hyd-mount",
                "--remote-cas",
                remote_cas,
                "--inline-threshold",
                "32",
            )
            mount_dir = Path(vfs["mount_path"])
            self.assertEqual(vfs["unhydrated_bytes"], 4096 + 8192)

            # Reject unsafe patterns
            for bad_pat in ("../escape", ".git/config", "/abs/path"):
                res_bad = harness.lab("vfs-hydrate", store, vfs["vfs_id"], bad_pat, check=False)
                self.assertNotEqual(res_bad.returncode, 0, f"Unsafe pattern {bad_pat} must fail closed")

            # On-demand hydrate of assets/blob-a.bin
            h1 = harness.data("vfs-hydrate", store, vfs["vfs_id"], "assets/blob-a.bin")
            self.assertEqual(h1["newly_hydrated"], 1)
            self.assertEqual(h1["already_hydrated"], 0)
            self.assertEqual(h1["bytes_hydrated"], 4096)
            self.assertEqual(h1["unhydrated_bytes"], 8192)
            self.assertEqual((mount_dir / "assets/blob-a.bin").read_bytes(), blob_a)

            # Re-hydrating an already hydrated file is idempotent
            h2 = harness.data("vfs-hydrate", store, vfs["vfs_id"], "assets/blob-a.bin")
            self.assertEqual(h2["newly_hydrated"], 0)
            self.assertEqual(h2["already_hydrated"], 1)

            # Corrupt blob-b in remote CAS -> vfs-hydrate must fail closed without leaving partial files
            sha_b = hashlib.sha256(blob_b).hexdigest()
            cas_blob_b = remote_cas / "blobs" / sha_b[:2] / sha_b
            cas_blob_b.chmod(0o600)
            cas_blob_b.write_bytes(b"corrupted" + blob_b[9:])
            res_corrupt = harness.lab("vfs-hydrate", store, vfs["vfs_id"], "assets/blob-b.bin", check=False)
            self.assertNotEqual(res_corrupt.returncode, 0, "Corrupt CAS blob must fail closed on vfs-hydrate")
            self.assertFalse((mount_dir / "assets/blob-b.bin").exists())

            # Restore valid CAS blob and run batch --prewarm
            cas_blob_b.write_bytes(blob_b)
            h_prewarm = harness.data("vfs-hydrate", store, vfs["vfs_id"], "--prewarm")
            self.assertTrue(h_prewarm["prewarm"])
            self.assertEqual(h_prewarm["newly_hydrated"], 1)
            self.assertEqual(h_prewarm["dehydrated_entries"], 0)
            self.assertEqual(h_prewarm["unhydrated_bytes"], 0)
            self.assertEqual((mount_dir / "assets/blob-b.bin").read_bytes(), blob_b)
        finally:
            harness.cleanup()

    def test_vfs_cow_write_and_dirty_state_classification(self):
        harness = WorkspaceHarness()
        try:
            root, source, store, _ = harness.fixture("vfs-status-cow", {
                ".gitignore": b"*.log\nbuild/\n",
                ".rootyardignore": b"scratch/*\n!scratch/keep.txt\n",
                "README.md": b"base readme\n",
                "src/main.rs": b"fn main() {}\n",
                "src/drop.rs": b"pub fn drop_me() {}\n",
                "assets/weights.bin": b"W" * 2048,
                "assets/clean.bin": b"C" * 2048,
            })
            base = harness.oid(source)
            ws, _ = harness.init(store, source, base, "agent-status")
            cp = harness.checkpoint(store, ws)

            # Mount with inline-threshold 0 and only src/* hydrated so .gitignore and .rootyardignore stay dehydrated!
            vfs = harness.data(
                "vfs-mount",
                store,
                cp["checkpoint_id"],
                "agent-status-mount",
                "--inline-threshold",
                "0",
                "--hydrate-pattern",
                "src/*",
            )
            mount_dir = Path(vfs["mount_path"])
            self.assertFalse((mount_dir / ".gitignore").exists(), ".gitignore should be dehydrated on disk")
            self.assertFalse((mount_dir / ".rootyardignore").exists(), ".rootyardignore should be dehydrated on disk")

            # Copy-on-Write hydrate on dehydrated assets/weights.bin
            cow_rep = harness.data(
                "vfs-hydrate",
                store,
                vfs["vfs_id"],
                "assets/weights.bin",
                "--cow-write",
                "cow-updated-weights\n",
            )
            self.assertTrue(cow_rep["cow_write"])
            self.assertEqual((mount_dir / "assets/weights.bin").read_bytes(), b"cow-updated-weights\n")

            # Mode change on hydrated src/main.rs, delete hydrated src/drop.rs, add untracked + ignored files
            (mount_dir / "src/main.rs").chmod(0o755)
            (mount_dir / "src/drop.rs").unlink()
            harness.write(mount_dir, "src/added.rs", b"pub fn added() {}\n")
            harness.write(mount_dir, "debug.log", b"ignored by gitignore\n")
            harness.write(mount_dir, "build/out.o", b"ignored build artifact\n")
            harness.write(mount_dir, "scratch/temp.dat", b"ignored by rootyardignore\n")
            harness.write(mount_dir, "scratch/keep.txt", b"unignored by !scratch/keep.txt\n")

            st = harness.data("vfs-status", store, vfs["vfs_id"])
            self.assertTrue(st["is_dirty"])
            self.assertFalse(st["clean"])
            self.assertIn("assets/clean.bin", st["dehydrated_paths"])
            self.assertIn(".gitignore", st["dehydrated_paths"])
            self.assertIn(".rootyardignore", st["dehydrated_paths"])
            self.assertEqual(
                set(st["ignored_paths"]),
                {"build/out.o", "debug.log", "scratch/temp.dat"},
            )
            dirty_by_path = {d["path"]: d["change"] for d in st["dirty_details"]}
            self.assertEqual(dirty_by_path, {
                "assets/weights.bin": "modified",
                "scratch/keep.txt": "added",
                "src/added.rs": "added",
                "src/drop.rs": "deleted",
                "src/main.rs": "mode_changed",
            })
            self.assertEqual(st["total_bytes"], st["hydrated_bytes"] + st["unhydrated_bytes"])
        finally:
            harness.cleanup()

    def test_vfs_evict_reclaims_clean_and_protects_dirty_cow(self):
        harness = WorkspaceHarness()
        try:
            blob_clean = b"C" * 6144
            blob_dirty = b"D" * 4096
            root, source, store, base = harness.fixture("vfs-evict", {
                "README.md": b"readme\n",
                "assets/clean.bin": blob_clean,
                "assets/dirty.bin": blob_dirty,
            })
            ws, _ = harness.init(store, source, base, "agent-evict")
            cp = harness.checkpoint(store, ws)
            remote_cas = root / "remote-cas"
            harness.data("push-remote", store, cp["checkpoint_id"], remote_cas)

            vfs = harness.data(
                "vfs-mount",
                store,
                cp["checkpoint_id"],
                "agent-evict-mount",
                "--remote-cas",
                remote_cas,
                "--inline-threshold",
                "16384",
            )
            mount_dir = Path(vfs["mount_path"])
            self.assertEqual(vfs["dehydrated_entries"], 0)

            # Mutate assets/dirty.bin via CoW and add an untracked file
            harness.data("vfs-hydrate", store, vfs["vfs_id"], "assets/dirty.bin", "--cow-write", "dirty-cow-data\n")
            harness.write(mount_dir, "src/untracked.rs", b"pub const X: u32 = 1;\n")

            # 1. Evicting dirty file directly without --skip-dirty must fail closed
            r1 = harness.lab("vfs-evict", store, vfs["vfs_id"], "assets/dirty.bin", "--quiescent", check=False)
            self.assertNotEqual(r1.returncode, 0)
            self.assertEqual((mount_dir / "assets/dirty.bin").read_bytes(), b"dirty-cow-data\n")

            # 2. Evicting "*" without --skip-dirty must fail closed atomically without evicting clean files
            r2 = harness.lab("vfs-evict", store, vfs["vfs_id"], "*", "--quiescent", check=False)
            self.assertNotEqual(r2.returncode, 0)
            self.assertTrue((mount_dir / "assets/clean.bin").is_file(), "Atomic pre-flight must not unlink clean files on conflict")
            self.assertTrue((mount_dir / "README.md").is_file())

            # 3. Evicting "*" with --skip-dirty evicts clean files and preserves all dirty files
            ev = harness.data("vfs-evict", store, vfs["vfs_id"], "*", "--skip-dirty", "--quiescent")
            self.assertEqual(ev["state"], "evicted")
            self.assertEqual(ev["evicted_entries"], 2)
            self.assertEqual(set(ev["evicted_paths"]), {"README.md", "assets/clean.bin"})
            self.assertEqual(ev["reclaimed_bytes"], len(b"readme\n") + 6144)
            self.assertEqual(set(ev["skipped_dirty_paths"]), {"assets/dirty.bin", "src/untracked.rs"})
            self.assertFalse((mount_dir / "assets/clean.bin").exists())
            self.assertFalse((mount_dir / "README.md").exists())
            self.assertEqual((mount_dir / "assets/dirty.bin").read_bytes(), b"dirty-cow-data\n")
            self.assertEqual((mount_dir / "src/untracked.rs").read_bytes(), b"pub const X: u32 = 1;\n")

            # 4. Re-hydrating evicted assets/clean.bin restores exact bytes from CAS
            rehyd = harness.data("vfs-hydrate", store, vfs["vfs_id"], "assets/clean.bin")
            self.assertEqual(rehyd["newly_hydrated"], 1)
            self.assertEqual((mount_dir / "assets/clean.bin").read_bytes(), blob_clean)
        finally:
            harness.cleanup()

    def test_vfs_manifest_tamper_detection(self):
        harness = WorkspaceHarness()
        try:
            _, source, store, base = harness.fixture("vfs-tamper", {
                "README.md": b"hello\n",
            })
            ws, _ = harness.init(store, source, base, "agent-tamper")
            cp = harness.checkpoint(store, ws)
            vfs = harness.data("vfs-mount", store, cp["checkpoint_id"], "agent-tamper-mount")

            vfs_json_path = store / "vfs" / vfs["vfs_id"] / "vfs.json"
            original = vfs_json_path.read_bytes()
            tampered = json.loads(original)
            tampered["agent_id"] = "tampered-agent"
            vfs_json_path.chmod(0o600)
            vfs_json_path.write_bytes(json.dumps(tampered, indent=2).encode())

            self.assertNotEqual(harness.lab("vfs-status", store, vfs["vfs_id"], check=False).returncode, 0)
            self.assertNotEqual(harness.lab("vfs-hydrate", store, vfs["vfs_id"], "README.md", check=False).returncode, 0)
            self.assertNotEqual(harness.lab("vfs-evict", store, vfs["vfs_id"], "README.md", check=False).returncode, 0)

            # Restore valid manifest and verify vfs-status succeeds
            vfs_json_path.write_bytes(original)
            st = harness.data("vfs-status", store, vfs["vfs_id"])
            self.assertEqual(st["state"], "mounted")
        finally:
            harness.cleanup()


if __name__ == "__main__":
    unittest.main()
