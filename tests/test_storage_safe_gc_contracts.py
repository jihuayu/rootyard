#!/usr/bin/env python3
"""Offline structural, policy, eval, and CI workflow contracts for Issue #122."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import unittest

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

ROOT = Path(__file__).resolve().parents[1]
RUST_FILES = [
    ROOT / "src" / "storage_lifecycle" / "fence.rs",
    ROOT / "src" / "storage_lifecycle" / "scheduler.rs",
    ROOT / "src" / "storage_lifecycle" / "worker.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "anti_aba.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "codec.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "compaction.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "dist_auth.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "dist_evidence.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "dist_journal_migration.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "dist_keyring.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "dist_trust_migration.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "domain.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "error.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "executor.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "git_ops.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "model.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "pg_maintenance.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "pg_maintenance_dist.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "pg_reconcile.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "proof.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "proof_digest.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "provider_delete.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "quiescence.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "refcas_cut.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "refcas_publisher.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "retention_bridge.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "store.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "store_barrier.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "store_reconcile.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "store_verify.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "tests.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "tests_concurrency.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "tests_dist_auth.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "tests_dist_migration.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "tests_dist_migration_fixtures.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "tests_reconcile.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "voter_service.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "voter_tls.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "voter_writer.rs",
    ROOT / "src" / "bin" / "rootyard-safe-gc-voter.rs",
    ROOT / "tests" / "storage_safe_gc.rs",
    ROOT / "tests" / "storage_safe_gc_maintenance.rs",
    ROOT / "tests" / "storage_safe_gc_support" / "dist_auth_harness.rs",
    ROOT / "tests" / "storage_safe_gc_support" / "pg_child_worker.rs",
    ROOT / "tests" / "storage_safe_gc_support" / "pg_refcas_cases.rs",
    ROOT / "tests" / "storage_safe_gc_support" / "pg_refcas_merge_fixture.rs",
    ROOT / "tests" / "storage_safe_gc_support" / "pg_refcas_migration_cases.rs",
    ROOT / "tests" / "storage_safe_gc_support" / "pg_refcas_restart_cases.rs",
    ROOT / "tests" / "storage_safe_gc_support" / "pg_refcas_voter_auth_cases.rs",
    ROOT / "tests" / "storage_safe_gc_support" / "pg_refcas_lifecycle_cases.rs",
    ROOT / "tests" / "storage_safe_gc_support" / "raft_voter_cluster.rs",
    ROOT / "tests" / "storage_safe_gc_support" / "raft_merge_backend.rs",
    ROOT / "tests" / "storage_safe_gc_support" / "s3_harness.rs",
    ROOT / "src" / "pulls" / "remote_merge_finalizer" / "coordinator_outcome.rs",
]
WORKFLOW = ROOT / ".github" / "workflows" / "storage-safe-gc.yml"
DOC = ROOT / "docs" / "storage-safe-gc.md"
EVAL_SCRIPT = ROOT / "scripts" / "eval_storage_safe_gc.py"


class StorageSafeGcContractsTest(unittest.TestCase):
    def test_rust_hygiene_default_off_and_serde_guards(self) -> None:
        facade = (ROOT / "src" / "storage_lifecycle.rs").read_text(encoding="utf-8")
        self.assertIn("pub mod safe_gc;", facade)
        self.assertLess(len(facade.splitlines()), 110)
        safe_gc_facade = (ROOT / "src" / "storage_lifecycle" / "safe_gc.rs").read_text(encoding="utf-8")
        self.assertLess(len(safe_gc_facade.splitlines()), 100)
        self.assertFalse(list((ROOT / "src" / "storage_lifecycle").rglob("mod.rs")))

        for path in RUST_FILES:
            with self.subTest(file=path.relative_to(ROOT).as_posix()):
                raw = path.read_bytes()
                self.assertNotIn(b"\r\n", raw, "CRLF detected")
                text = raw.decode("utf-8")
                lines = text.splitlines()
                self.assertLess(len(lines), 500, f"{path.name} has {len(lines)} lines (>= 500)")
                self.assertNotIn("#[allow(", text, f"lint suppression forbidden in {path.name}")

        for name in (
            "model.rs",
            "proof.rs",
            "anti_aba.rs",
            "store.rs",
            "domain.rs",
            "quiescence.rs",
            "refcas_cut.rs",
            "pg_maintenance_dist.rs",
            "dist_auth.rs",
            "dist_evidence.rs",
            "dist_journal_migration.rs",
            "dist_keyring.rs",
            "dist_trust_migration.rs",
            "voter_service.rs",
            "voter_tls.rs",
            "voter_writer.rs",
        ):
            src = (ROOT / "src" / "storage_lifecycle" / "safe_gc" / name).read_text(encoding="utf-8")
            for m in re.finditer(r"#\[derive\([^)]*Deserialize[^)]*\)\]\s*(?:#\[[^\]]+\]\s*)*pub struct (\w+)", src):
                self.assertIn("deny_unknown_fields", m.group(0), f"{name}:{m.group(1)} missing deny_unknown_fields")

        model = (ROOT / "src" / "storage_lifecycle" / "safe_gc" / "model.rs").read_text(encoding="utf-8")
        self.assertIn("pub const SAFE_GC_DESTRUCTIVE_ENABLED_BY_DEFAULT: bool = false;", model)
        bridge = (ROOT / "src" / "storage_lifecycle" / "safe_gc" / "retention_bridge.rs").read_text(encoding="utf-8")
        self.assertIn("PackRetentionState::GcEligible", bridge)
        provider = (ROOT / "src" / "storage_lifecycle" / "safe_gc" / "provider_delete.rs").read_text(encoding="utf-8")
        for outcome in ("ConfirmedDeleted", "AlreadyAbsent", "OutcomeUnknown"):
            self.assertIn(outcome, provider)
        maintenance = (ROOT / "src" / "storage_lifecycle" / "safe_gc" / "pg_maintenance.rs").read_text(
            encoding="utf-8"
        )
        self.assertIn("reconcile_worker_refcas_cut_if_needed", maintenance)
        dist = (ROOT / "src" / "storage_lifecycle" / "safe_gc" / "pg_maintenance_dist.rs").read_text(
            encoding="utf-8"
        )
        self.assertIn("reconcile_refcas_cut_with_pg", dist)
        self.assertNotIn("lookup_production_refcas_source", dist)

        coordinator = (
            ROOT / "src" / "pulls" / "remote_merge_finalizer" / "coordinator.rs"
        ).read_text(encoding="utf-8")
        self.assertIn("with_safe_gc_cutpoint_publisher", coordinator)
        self.assertIn("publish_committed_state", coordinator)
        self.assertIn("abort_after_install_once", coordinator)
        self.assertIn("publish_cutpoint", coordinator)
        self.assertIn("register_safe_gc_repo", coordinator)
        self.assertIn("arm_signature_hex", model)
        self.assertNotIn("quorum_verified: bool", model)
        worker = (ROOT / "src" / "storage_lifecycle" / "worker.rs").read_text(encoding="utf-8")
        self.assertIn("ProductionRefCasAuthoritySource", worker)
        child = (
            ROOT / "tests" / "storage_safe_gc_support" / "pg_child_worker.rs"
        ).read_text(encoding="utf-8")
        self.assertIn("storage_lifecycle::run", child)
        self.assertNotIn("UPDATE storage_maintenance_repo_state", child)
        self.assertIn("Command::new", child)
        cases = (ROOT / "tests" / "storage_safe_gc_support" / "pg_refcas_cases.rs").read_text(
            encoding="utf-8"
        )
        merge_fixture = (
            ROOT / "tests" / "storage_safe_gc_support" / "pg_refcas_merge_fixture.rs"
        ).read_text(encoding="utf-8")
        restart = (
            ROOT / "tests" / "storage_safe_gc_support" / "pg_refcas_restart_cases.rs"
        ).read_text(encoding="utf-8")
        lifecycle = (
            ROOT / "tests" / "storage_safe_gc_support" / "pg_refcas_lifecycle_cases.rs"
        ).read_text(encoding="utf-8")
        self.assertIn("set_abort_after_install_once", lifecycle)
        self.assertIn("isolated_pg_pool_with_schema", lifecycle)
        self.assertIn("LiveRaft3MergeBackend", merge_fixture)
        self.assertIn("LiveRaftVoterCluster", merge_fixture)
        self.assertIn("build_refcas_merge_rig", merge_fixture)
        self.assertNotIn("with_safe_gc_cutpoint_publisher", merge_fixture)
        self.assertIn("production_refcas_pr_merge", cases)
        self.assertIn("production_refcas_pr_merge", restart)
        self.assertIn("run_claimed_safe_gc_once_with_fault", restart)
        self.assertIn("reconcile_pending_delete_after_restart_fenced", restart)
        self.assertIn("SIGKILL", restart)
        self.assertIn("PauseAfterDeletesForExternalKill", restart)
        self.assertIn("spawn_pass1_sigkill_child", restart)
        for support in (merge_fixture, restart):
            self.assertNotIn("persist_refcas_cutpoint_snapshot", support)
        self.assertIn("persist_refcas_cutpoint_snapshot", cases)

        voter_service = (
            ROOT / "src" / "storage_lifecycle" / "safe_gc" / "voter_service.rs"
        ).read_text(encoding="utf-8")
        self.assertIn("pub struct SafeGcVoterServiceConfig", voter_service)
        self.assertIn("pub async fn serve_safe_gc_voter", voter_service)
        voter_bin = (ROOT / "src" / "bin" / "rootyard-safe-gc-voter.rs").read_text(encoding="utf-8")
        self.assertIn("serve_safe_gc_voter", voter_bin)
        live_voters = (
            ROOT / "tests" / "storage_safe_gc_support" / "raft_voter_cluster.rs"
        ).read_text(encoding="utf-8")
        self.assertIn("ROOTYARD_SAFE_GC_VOTER_BIN", live_voters)
        self.assertNotIn("axum::Router", live_voters)
        journal_migration = (
            ROOT / "src" / "storage_lifecycle" / "safe_gc" / "dist_journal_migration.rs"
        ).read_text(encoding="utf-8")
        self.assertIn("migrate_legacy_trust_and_journal", journal_migration)
        self.assertIn("rearm_distributed_from_voters", journal_migration)

        keyring = (ROOT / "src" / "storage_lifecycle" / "safe_gc" / "dist_keyring.rs").read_text(
            encoding="utf-8"
        )
        evidence = (ROOT / "src" / "storage_lifecycle" / "safe_gc" / "dist_evidence.rs").read_text(
            encoding="utf-8"
        )
        auth = (ROOT / "src" / "storage_lifecycle" / "safe_gc" / "dist_auth.rs").read_text(
            encoding="utf-8"
        )
        migration = (
            ROOT / "src" / "storage_lifecycle" / "safe_gc" / "dist_trust_migration.rs"
        ).read_text(encoding="utf-8")
        self.assertIn("migrate_legacy_trust_file", migration)
        executor = (ROOT / "src" / "storage_lifecycle" / "safe_gc" / "executor.rs").read_text(
            encoding="utf-8"
        )
        maintenance = (ROOT / "src" / "storage_lifecycle" / "safe_gc" / "pg_maintenance.rs").read_text(
            encoding="utf-8"
        )
        worker = (ROOT / "src" / "storage_lifecycle" / "worker.rs").read_text(encoding="utf-8")
        for text in (auth, dist):
            self.assertNotIn("mint_cutpoint_attestation", text)
            self.assertNotIn("sign_snapshot_with_keyring_dir", text)
            self.assertNotIn(".quorum.seed", text)
            self.assertNotIn(".bridge.seed", text)
            self.assertNotIn(".backup.seed", text)
        self.assertIn("VOTER_CUTPOINT_DOMAIN", keyring)
        self.assertIn("voter_cutpoint_transcript", evidence)
        self.assertIn("PauseAfterDeletesForExternalKill", executor)
        self.assertIn("reap_expired_pg_refstore_jobs", maintenance)
        self.assertIn("reap_expired_pg_refstore_jobs", worker)
        capture = dist.split("pub(super) async fn capture_verified_dist_cutpoint", 1)[1].split(
            "pub(super) async fn reconcile_worker_refcas_cut_if_needed", 1
        )[0]
        self.assertNotIn("FsSealedRefCasCutpointSource", capture)
        self.assertIn("fetch_quorum_cutpoint_from_voters", capture)

        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn(
            "COPY --from=build /build/target/release/rootyard-safe-gc-voter "
            "/usr/local/bin/rootyard-safe-gc-voter",
            dockerfile,
        )
        writer = (
            ROOT / "src" / "storage_lifecycle" / "safe_gc" / "voter_writer.rs"
        ).read_text(encoding="utf-8")
        self.assertIn("pub struct SafeGcRaftCommitWriter", writer)
        self.assertIn("KvGet", writer)
        self.assertIn("SafeGcRaftCommitWriter", live_voters)
        self.assertNotIn("async fn kv_put", live_voters)
        transport = (
            ROOT / "src" / "storage_lifecycle" / "safe_gc" / "voter_tls.rs"
        ).read_text(encoding="utf-8")
        self.assertIn("WebPkiClientVerifier", transport)
        self.assertIn("constant_time_bearer_eq", transport)
        self.assertIn("voter_client_auth", auth)
        self.assertIn('starts_with("https://")', keyring)
        self.assertIn("parse_slot_log_id", voter_service)
        self.assertNotIn(".unwrap_or(slot)", voter_service)
        self.assertNotIn(".unwrap_or(1)", voter_service)
        self.assertIn("reconcile_pending_delete_after_restart_fenced_with_fault", maintenance)
        self.assertIn("spawn_cold_runtime_no_delete_child", child)
        migration_cases = (
            ROOT / "tests" / "storage_safe_gc_support" / "pg_refcas_migration_cases.rs"
        ).read_text(encoding="utf-8")
        self.assertIn("spawn_pass1_sigkill_child", migration_cases)
        self.assertIn("spawn_pass2_scheduled_runtime_child", migration_cases)
        self.assertIn("migrate_legacy_trust_and_journal", migration_cases)
        voter_auth_cases = (
            ROOT / "tests" / "storage_safe_gc_support" / "pg_refcas_voter_auth_cases.rs"
        ).read_text(encoding="utf-8")
        self.assertIn("request_voter_https", voter_auth_cases)
        self.assertIn("foreign_voter_client_auth", voter_auth_cases)

    def test_workflow_and_doc_contracts(self) -> None:
        wf_raw = WORKFLOW.read_bytes()
        self.assertNotIn(b"\r\n", wf_raw)
        wf_text = wf_raw.decode("utf-8")
        self.assertTrue(wf_text.startswith("name: "))
        self.assertNotIn("\t", wf_text)
        if yaml is not None:
            doc = yaml.safe_load(wf_text)
            on_cfg = doc.get("on") if "on" in doc else doc.get(True)
            self.assertIn("pull_request", on_cfg)
            self.assertIn("workflow_dispatch", on_cfg)
            self.assertNotIn("push", on_cfg)
            paths = on_cfg["pull_request"]["paths"]
            for req in (
                "src/storage_lifecycle.rs",
                "src/storage_lifecycle/safe_gc.rs",
                "src/storage_lifecycle/safe_gc/**",
                "src/bin/rootyard-safe-gc-voter.rs",
                "tests/storage_safe_gc.rs",
                "tests/storage_safe_gc_maintenance.rs",
                "scripts/eval_storage_safe_gc.py",
                "docs/storage-safe-gc.md",
                "Dockerfile",
            ):
                self.assertIn(req, paths)

        for token in (
            "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b",
            "postgres:17",
            "scripts/install_ci_cargo_fork.sh install",
            "scripts/install_ci_cargo_fork.sh verify",
            "cargo test --locked --no-default-features --lib storage_lifecycle::safe_gc",
            "cargo test --locked --no-default-features --test storage_safe_gc",
            "cargo test --locked --no-default-features --test storage_safe_gc_maintenance",
            "ROOTYARD_REFCAS_NODE_BIN",
            "ROOTYARD_SAFE_GC_VOTER_BIN",
            "crates/refcas-log/Cargo.toml",
            "--bin raft-node",
            "--bin rootyard-safe-gc-voter",
            "scripts/eval_storage_safe_gc.py",
        ):
            self.assertIn(token, wf_text)

        doc_text = DOC.read_text(encoding="utf-8")
        self.assertIn("SAFE_GC_DESTRUCTIVE_ENABLED_BY_DEFAULT = false", doc_text)
        self.assertIn("#151", doc_text)
        self.assertIn("#153", doc_text)
        for target in re.findall(r"\[[^\]]*\]\(([^)]+)\)", doc_text):
            clean = target.split("#", 1)[0]
            if not clean or "://" in clean:
                continue
            self.assertTrue((DOC.parent / clean).resolve().exists(), f"missing doc link: {target}")

    def test_eval_script_smoke_sha1_and_sha256(self) -> None:
        spec = importlib.util.spec_from_file_location("eval_storage_safe_gc", EVAL_SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        report = module.run_benchmark(["small"], ["sha1", "sha256"])
        self.assertEqual(report["issue"], 122)
        self.assertTrue(report["delete_disabled_by_default"])
        self.assertEqual(len(report["runs"]), 2)
        for run in report["runs"]:
            self.assertEqual(run["git_fsck_parity"], "pass")
            self.assertEqual(run["aba_key_collisions"], 0)
            self.assertEqual(run["false_deletions"], 0)
            self.assertGreater(run["reclaimed_orphan_bytes"], 0)


if __name__ == "__main__":
    unittest.main()
