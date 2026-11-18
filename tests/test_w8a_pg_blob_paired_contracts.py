#!/usr/bin/env python3
"""Offline contracts for the W8-A paired PostgreSQL + Blob restore slice."""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

LIMITS = {
    "src/backup/authority.rs": 160,
    "src/backup/w8a_paired.rs": 95,
    "src/backup/w8a_paired/manifest_key_ref.rs": 360,
    "src/backup/w8a_paired/create.rs": 400,
    "src/backup/w8a_paired/restore.rs": 460,
    "src/backup/w8a_paired/deleter_fence.rs": 220,
    "src/backup/w8a_paired/tests.rs": 380,
    "src/bin/rootyard-w8a-backup.rs": 95,
    "tests/w8a_pg_blob_paired_restore.rs": 460,
    "tests/w8a_pg_blob_support/s3.rs": 280,
    "tests/w8a_pg_blob_support/seed.rs": 420,
    "tests/test_w8a_pg_blob_paired_contracts.py": 260,
    "docs/w8a-pg-blob-paired-restore.md": 300,
    ".github/workflows/w8a-pg-blob-restore.yml": 150,
}


def read(relative: str) -> str:
    path = ROOT / relative
    assert path.is_file(), f"missing {relative}"
    data = path.read_bytes()
    assert b"\r\n" not in data and b"\r" not in data, f"non-LF line ending in {relative}"
    return data.decode("utf-8")


class W8aPgBlobPairedContractsTest(unittest.TestCase):
    def test_w8a_contracts(self) -> None:
        files = {relative: read(relative) for relative in LIMITS}
        for relative, maximum in LIMITS.items():
            count = len(files[relative].splitlines())
            self.assertLessEqual(count, maximum, f"{relative} has {count} lines, limit {maximum}")
            self.assertNotIn("\t", files[relative], f"tab in {relative}")

        self.assertIn("pub mod w8a_paired;", read("src/backup.rs"))
        for relative, text in files.items():
            if not relative.startswith("src/"):
                continue
            self.assertNotIn("#[allow(", text, f"broad allow in {relative}")
            self.assertNotIn("#![allow(", text, f"broad allow in {relative}")
            self.assertNotIn("unsafe", text, f"unsafe in authored src file {relative}")

        for relative in ["tests/w8a_pg_blob_paired_restore.rs", "tests/w8a_pg_blob_support/seed.rs"]:
            self.assertNotIn("#[allow(", files[relative])
            self.assertNotIn("unsafe", files[relative])
        s3 = files["tests/w8a_pg_blob_support/s3.rs"]
        self.assertIn("unsafe { std::env::", s3)
        self.assertIn("static ENV_LOCK: Mutex<()>", s3)
        self.assertIn("struct EnvGuard", s3)
        self.assertEqual(s3.count("unsafe"), 6)
        self.assertFalse((ROOT / "src/backup/w8a_paired/mod.rs").exists())
        self.assertFalse((ROOT / "tests/w8a_pg_blob_support/mod.rs").exists())

        manifest = files["src/backup/w8a_paired/manifest_key_ref.rs"]
        self.assertIn('MANIFEST_SEAL_DOMAIN: &[u8] = b"rootyard-w8a-manifest-v1\\0"', manifest)
        self.assertIn('KEY_CANARY_DOMAIN: &[u8] = b"rootyard-w8a-key-canary-v1\\0"', manifest)
        self.assertIn('KEY_DIGEST_DOMAIN: &[u8] = b"rootyard-w8a-keyring-public-v1\\0"', manifest)
        self.assertIn('ENV_KMS_KEY_REF: &str = "ROOTYARD_BLOB_KMS_KEY_REF"', manifest)
        self.assertIn('ENV_PAIRED_RAFT_CLUSTER: &str = "ROOTYARD_PAIRED_RAFT_CLUSTER_JSON"', manifest)
        sidecar = re.search(r"pub struct W8aPairedSidecarManifest \{(.*?)\n\}", manifest, re.S)
        self.assertIsNotNone(sidecar, "sidecar struct missing")
        fields = set(re.findall(r"pub (\w+):", sidecar.group(1)))
        required = {
            "w8a_backup_id", "format", "schema_head", "schema_contract_sha256",
            "metadata_dump_sha256", "inner_manifest_sha256", "inner_complete_sha256",
            "inner_backup_id", "inner_volume_id", "blob_repository_count",
            "blob_artifact_count", "blob_total_bytes", "blob_closure_digest",
            "blob_backend_identity", "blob_provider", "source_cluster_incarnation",
            "source_storage_authority_id", "source_storage_authority_epoch",
            "key_reference", "single_node_w8a", "raft_cut_supported",
            "paired_restore_trusted", "manifest_seal_sha256",
        }
        self.assertEqual(fields, required, sorted(required ^ fields))

        errors = files["src/backup/w8a_paired.rs"]
        for variant in [
            "RaftCutForbiddenInSingleNodeW8a", "DestructiveGcForbidden",
            "UnsupportedRepositoryBackend", "KeyReferenceMismatch", "MixedPointInTime",
            "MissingOrCorruptBlobArtifact", "StaleDeleterFenced", "GitFsckFailed",
            "BackupFailed", "RestoreFailed",
        ]:
            self.assertIn(variant, errors, f"missing W8aError::{variant}")
        restore = files["src/backup/w8a_paired/restore.rs"]
        for token in [
            "restored_incarnation", "verify_key_reference", "fence_w8a_fresh_incarnation",
            "repositories_fscked", "ArchiveTransfer::for_export", "ref_store_core_refs",
            "ref_store_serving_repositories",
        ]:
            self.assertIn(token, restore, f"restore.rs missing {token}")
        create = files["src/backup/w8a_paired/create.rs"]
        self.assertIn("W8A_COMPLETE", create)
        self.assertIn("w8a-paired.json", create)
        self.assertIn("capture_key_reference", create)
        self.assertIn("ensure_clean_source", create)
        authority = files["src/backup/authority.rs"]
        for token in [
            "w8a-paired-restore-fenced", "remote_delete_fenced = true",
            "restored_incarnation", "release_reason='operator_request'",
            "event_deliveries", "ci_checkout_jobs", "ref_store_core_pins",
        ]:
            self.assertIn(token, authority, f"authority.rs missing {token}")
        self.assertIn("pull_remote_merge_attempts", authority)

        integration = files["tests/w8a_pg_blob_paired_restore.rs"]
        for token in [
            '"sha1"', '"sha256"', "KeyReferenceMismatch", "MixedPointInTime",
            "MissingOrCorruptBlobArtifact", "RaftCutForbiddenInSingleNodeW8a",
            "DestructiveGcForbidden", "StaleDeleterFenced", "admit_deleter_epoch",
            "auth::authenticate", "worker_once", "ref_store_core_pins",
            "ref_store_core_root_heads", "ci_checkout_jobs", "repositories_fscked",
        ]:
            self.assertIn(token, integration, f"integration missing {token}")
        seed = files["tests/w8a_pg_blob_support/seed.rs"]
        for token in [
            "provision(", "producer_snapshot", "create_actor_owned", "ci_checkout_jobs",
            "workspaces", "write_volume", "write_keyring", "with_database",
            "GitObjectFormat::Sha1", "GitObjectFormat::Sha256",
        ]:
            self.assertIn(token, seed, f"seed missing {token}")
        for token in ["LoopbackS3", "IF_NONE_MATCH", "RANGE", "Method::PUT", "Method::HEAD", "Method::GET", "Method::DELETE"]:
            self.assertIn(token, s3, f"s3 support missing {token}")

        docs = files["docs/w8a-pg-blob-paired-restore.md"]
        fences = sum(1 for line in docs.splitlines() if line.strip().startswith("```"))
        self.assertGreater(fences, 0)
        self.assertEqual(fences % 2, 0, "unbalanced Markdown fences")
        links = re.findall(r"\]\((?!https?://|#)([^)]+)\)", docs)
        self.assertTrue(links, "docs must link to implementation files")
        for link in links:
            target = (ROOT / "docs" / link.split("#", 1)[0]).resolve()
            self.assertTrue(target.exists(), f"broken relative link {link}")
        for token in [
            "format30", "W8A_COMPLETE", "w8a-paired.json", "rootyard-w8a-manifest-v1",
            "rootyard-w8a-key-canary-v1", "rootyard-w8a-keyring-public-v1", "w8a-paired-restore-fenced",
        ]:
            self.assertIn(token, docs, f"docs missing {token}")

        workflow = files[".github/workflows/w8a-pg-blob-restore.yml"]
        for token in [
            "name: W8-A PG+Blob Paired Restore", "w8a-pg-blob-restore:", "runs-on: ubuntu-24.04",
            "timeout-minutes: 35", "image: postgres:17", "127.0.0.1:55432:5432",
            "pg_isready -U rootyard", "rustup toolchain install 1.99.1",
            "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b", "1.101.0",
            "rootyard-cargo-fork-${{ runner.os }}-${{ runner.arch }}-${{ github.job }}-64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b-1.99.1-v1",
            "install_ci_cargo_fork.sh install", "install_ci_cargo_fork.sh verify",
            "--record test-results/w8a-pg-blob-restore/cargo-fork.json",
            "cargo fmt --all -- --check",
            "cargo clippy --locked --no-default-features --lib --bin rootyard-w8a-backup",
            "cargo test --locked --no-default-features --lib backup::w8a_paired",
            "cargo test --locked --no-default-features --test w8a_pg_blob_paired_restore",
            "tests/test_w8a_pg_blob_paired_contracts.py", "tee -a", "w8a-pg-blob-restore-evidence",
        ]:
            self.assertIn(token, workflow, f"workflow missing {token}")
        self.assertTrue("  on:" in workflow or "\non:" in workflow)
        self.assertIn("permissions:", workflow)
        self.assertIn("contents: read", workflow)


if __name__ == "__main__":
    unittest.main()
