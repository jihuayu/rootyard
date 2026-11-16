#!/usr/bin/env python3
"""Offline structural and security contract tests for #150 tenant-scoped mTLS Raft RPC and #149 doc fix."""

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
REFCAS = ROOT / "crates" / "refcas-log"


class RefcasTenantRpcContractsTest(unittest.TestCase):
    def test_module_modularity_line_caps_and_zero_mod_rs(self):
        self.assertEqual(list(REFCAS.rglob("mod.rs")), [], "mod.rs is forbidden under crates/refcas-log")
        bounded_files = [
            "src/mtls.rs",
            "src/mtls/tenant_san.rs",
            "src/cluster.rs",
            "src/streaming.rs",
            "src/tenant_rpc.rs",
            "src/tenant_rpc/types.rs",
            "src/tenant_rpc/realm.rs",
            "src/tenant_rpc/server.rs",
            "src/tenant_rpc/client.rs",
            "tests/helpers/tenant_cluster.rs",
            "tests/tenant_mtls_rpc.rs",
        ]
        for rel in bounded_files:
            path = REFCAS / rel
            self.assertTrue(path.is_file(), f"missing expected file {rel}")
            text = path.read_text(encoding="utf-8")
            lines = text.splitlines()
            self.assertLess(len(lines), 500, f"{rel} has {len(lines)} lines (limit < 500)")
            self.assertNotIn("#[allow(", text, f"{rel} must not suppress lints with #[allow(")

    def test_every_deserialize_type_uses_deny_unknown_fields(self):
        checked_files = [
            "src/mtls.rs",
            "src/mtls/tenant_san.rs",
            "src/cluster.rs",
            "src/streaming.rs",
            "src/tenant_rpc/types.rs",
        ]
        derive_re = re.compile(r"#\[derive\([^\]]*\bDeserialize\b[^\]]*\)\]")
        for rel in checked_files:
            lines = (REFCAS / rel).read_text(encoding="utf-8").splitlines()
            for idx, line in enumerate(lines):
                if derive_re.search(line):
                    window = "\n".join(lines[max(0, idx - 2) : min(len(lines), idx + 4)])
                    self.assertIn(
                        "deny_unknown_fields",
                        window,
                        f"{rel}:{idx + 1} derives Deserialize without #[serde(deny_unknown_fields)]",
                    )

    def test_san_token_epoch_and_streaming_invariants_present(self):
        tenant_san = (REFCAS / "src/mtls/tenant_san.rs").read_text(encoding="utf-8")
        self.assertIn("raft-client-tenant-", tenant_san)
        self.assertIn(".raft.internal", tenant_san)
        self.assertIn("urn:rootyard:refcas:tenant:", tenant_san)
        self.assertIn("extract_tenant_client_scope", tenant_san)
        self.assertIn("extract_verified_peer", tenant_san)

        rpc_types = (REFCAS / "src/tenant_rpc/types.rs").read_text(encoding="utf-8")
        for token in (
            "WideTokenRejected",
            "CrossTenantDenied",
            "WrongGroup",
            "StaleAuthority",
            "StaleHistory",
            "StaleGroupEpoch",
            "StaleStorageGeneration",
            "PayloadTooLarge",
            "QuorumUnavailable",
            "DeadlineExceeded",
            "BackpressureCancelled",
            "LeaderRedirect",
            "raft_term",
            "storage_generation",
        ):
            self.assertIn(token, rpc_types)

        streaming = (REFCAS / "src/streaming.rs").read_text(encoding="utf-8")
        server = (REFCAS / "src/tenant_rpc/server.rs").read_text(encoding="utf-8")
        self.assertIn("mpsc::channel", server)
        for sym in (
            "mpsc::Receiver",
            "BufferedByteTracker",
            "TrackedChunk",
            "validate_raft_proposal_payload",
            "MAX_RAFT_PROPOSAL_BYTES",
            "MAX_STREAM_FRAME_BYTES",
            "MAX_STREAM_TOTAL_BYTES",
        ):
            self.assertIn(sym, streaming)

    def test_standalone_crate_isolation_from_root_pg_redis_blob(self):
        cargo_toml = (REFCAS / "Cargo.toml").read_text(encoding="utf-8").lower()
        for forbidden in ("opendal", "sqlx", "tokio-postgres", "redis", "deadpool"):
            self.assertNotIn(forbidden, cargo_toml, f"standalone crate must not depend on {forbidden}")

    def test_readme_149_rollback_clarification_and_docs_and_lf_workflow(self):
        readme = (REFCAS / "README.md").read_text(encoding="utf-8")
        self.assertIn("Pre-commit failures", readme)
        self.assertIn("Commit and post-commit uncertain errors", readme)
        self.assertIn("SnapshotInstallPostCommitSync", readme)
        self.assertIn("does not promise rollback", readme)

        doc_path = ROOT / "docs" / "refcas-tenant-rpc.md"
        self.assertTrue(doc_path.is_file(), "missing docs/refcas-tenant-rpc.md")
        doc_text = doc_path.read_text(encoding="utf-8")
        self.assertIn("remain `OPEN`", doc_text)
        self.assertIn("LeaderRedirect", doc_text)
        self.assertIn("ReadIndex", doc_text)

        wf_path = ROOT / ".github" / "workflows" / "refcas-tenant-rpc.yml"
        wf_bytes = wf_path.read_bytes()
        self.assertNotIn(b"\r", wf_bytes, "workflow YAML must use pure LF")
        wf_text = wf_bytes.decode("utf-8")
        for expected in (
            "cargo fmt --manifest-path crates/refcas-log/Cargo.toml --all -- --check",
            "cargo clippy --locked --manifest-path crates/refcas-log/Cargo.toml --all-targets -- -D warnings",
            "cargo test --locked --manifest-path crates/refcas-log/Cargo.toml --all-targets",
            "python3 -m unittest tests.test_refcas_tenant_rpc_contracts",
        ):
            self.assertIn(expected, wf_text)


if __name__ == "__main__":
    unittest.main()
