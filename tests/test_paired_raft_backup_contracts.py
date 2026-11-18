#!/usr/bin/env python3
"""Offline structural, protocol, evaluator, and CI workflow contracts for Issue #153."""
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
MOD_DIR = ROOT / "src" / "maintenance" / "paired_raft_backup"
RUST_FILES = [
    ROOT / "src" / "standalone.rs",
    ROOT / "src" / "maintenance" / "paired_raft_backup.rs",
    *sorted(MOD_DIR.glob("*.rs")),
    ROOT / "tests" / "paired_raft_backup_restore.rs",
    *sorted((ROOT / "tests" / "paired_raft_backup_support").glob("*.rs")),
]
WORKFLOW = ROOT / ".github" / "workflows" / "paired-raft-backup.yml"
DOC = ROOT / "docs" / "paired-raft-backup-restore.md"
EVAL_SCRIPT = ROOT / "scripts" / "eval_paired_raft_backup.py"


class PairedRaftBackupContractsTest(unittest.TestCase):
    def test_rust_modules_respect_line_budget_mod_rs_allow_and_serde_guards(self) -> None:
        facade = ROOT / "src" / "maintenance.rs"
        facade_raw = facade.read_bytes()
        self.assertNotIn(b"\r\n", facade_raw)
        facade_text = facade_raw.decode("utf-8")
        self.assertLess(len(facade_text.splitlines()), 500)
        self.assertIn("pub mod paired_raft_backup;", facade_text)
        self.assertNotIn('#[path = "maintenance/paired_raft_backup.rs"]', facade_text)
        self.assertFalse(list((ROOT / "src" / "maintenance").rglob("mod.rs")))
        self.assertFalse(list((ROOT / "tests" / "paired_raft_backup_support").rglob("mod.rs")))

        mod_facade_lines = (ROOT / "src" / "maintenance" / "paired_raft_backup.rs").read_text(encoding="utf-8").splitlines()
        self.assertLess(len(mod_facade_lines), 100)

        for path in RUST_FILES:
            with self.subTest(file=path.relative_to(ROOT).as_posix()):
                raw = path.read_bytes()
                self.assertNotIn(b"\r\n", raw, "CRLF detected")
                text = raw.decode("utf-8")
                lines = text.splitlines()
                self.assertLess(len(lines), 500, f"{path.name} has {len(lines)} lines (must stay < 500)")
                self.assertNotIn("#[allow(", text, f"lint suppression forbidden in {path.name}")
                for match in re.finditer(
                    r"#\[derive\([^)]*Deserialize[^)]*\)\]\s*(?:#\[[^\]]+\]\s*)*(?:pub\s+)?struct (\w+)",
                    text,
                ):
                    self.assertIn("deny_unknown_fields", match.group(0), f"{match.group(1)} missing deny_unknown_fields")

    def test_paired_protocol_enforces_freeze_close_closure_bind_incarnation_and_s3_close(self) -> None:
        types_src = (MOD_DIR / "types.rs").read_text(encoding="utf-8")
        for token in (
            "IncompleteCut",
            "FreezeNotHeld",
            "ScopeNotClosed",
            "UnknownInFlightOperations",
            "DeleterNotFenced",
            "CutpointSkew",
            "TenantOrRepoMismatch",
            "BlobClosureIncomplete",
            "CorruptBlobOrDigest",
            "BackendIdentityMismatch",
            "StaleIncarnation",
            "StaleGrantRefused",
            "StaleDecisionRefused",
            "StaleDeleterRefused",
            "ExpectedPackPairSpec",
            "max_decision_scope_version",
        ):
            self.assertIn(token, types_src)

        barrier_src = (MOD_DIR / "raft_barrier.rs").read_text(encoding="utf-8") + (
            MOD_DIR / "quorum_wal.rs"
        ).read_text(encoding="utf-8")
        for token in (
            "DurableRaftBackend",
            "WalSyncedRaftBackend",
            "QuorumCommitReceipt",
            "LocalWalApplyReceipt",
            "VoterWalAck",
            "DurableFreezeBarrierProof",
            "SealedArchiveReceipt",
            "sync_data",
        ):
            self.assertIn(token, barrier_src)

        bind_src = (MOD_DIR / "closure_bind.rs").read_text(encoding="utf-8") + (
            MOD_DIR / "peer_groups.rs"
        ).read_text(encoding="utf-8")
        for token in (
            "compute_canonical_pack_set_digest",
            "PeerRaftCutpointProof",
            "verify_archived_peer_groups",
            "verify_all_group_cursors",
            "verify_blob_closure_against_durable_raft",
            "verify_registration_spec_completeness",
        ):
            self.assertIn(token, bind_src)

        freeze_src = (MOD_DIR / "freeze_drain.rs").read_text(encoding="utf-8")
        for token in (
            "CloseAuthScope",
            "CreateSnapshotPin",
            "AcquireHoldBatch",
            "RegisterRoot",
            "unfreeze_after_backup",
            "SealedArchiveReceipt",
            "verify_backup_archive",
        ):
            self.assertIn(token, freeze_src)

        backup_src = (MOD_DIR / "backup.rs").read_text(encoding="utf-8")
        self.assertIn("IsolationLevel::RepeatableRead", backup_src)
        self.assertIn("verify_blob_closure_against_durable_raft", backup_src)
        self.assertIn("verify_all_group_cursors", backup_src)

        pg_src = (MOD_DIR / "pg_cutpoint.rs").read_text(encoding="utf-8") + (
            MOD_DIR / "pg_restore_admission.rs"
        ).read_text(encoding="utf-8")
        for token in (
            "capture_pg_cutpoint_in_tx",
            "pando_storage_authorities",
            "pando_retention_roots",
            "ref_cas_projection_cursors",
            "ref_store_serving_repositories",
            "ref_store_decision_scopes",
            "verify_pg_restored_cursors",
        ):
            self.assertIn(token, pg_src)

        mtls_and_fmt30_src = (
            (MOD_DIR / "mtls_raft.rs").read_text(encoding="utf-8")
            + (MOD_DIR / "mtls_wire.rs").read_text(encoding="utf-8")
            + (MOD_DIR / "durable_freeze_gate.rs").read_text(encoding="utf-8")
            + (MOD_DIR / "durable_guarded_ops.rs").read_text(encoding="utf-8")
            + (MOD_DIR / "format30_paired.rs").read_text(encoding="utf-8")
            + (MOD_DIR / "format30_boot.rs").read_text(encoding="utf-8")
        )
        for token in (
            "MtlsLiveRaftBackend",
            "raft-node-",
            "peer_certificates",
            "PG_FREEZE_SETTING",
            "repo_access",
            "upsert_repo_access_collaborator_guarded",
            "create_format30_paired_raft_backup",
            "restore_and_boot_format30_new_incarnation",
            "STANDARD_PAIRED_PG_FORMAT",
            "STANDARD_SCHEMA_HEAD",
            "crate::backup::create",
            "crate::backup::restore",
        ):
            self.assertIn(token, mtls_and_fmt30_src)

        it_src = (ROOT / "tests" / "paired_raft_backup_restore.rs").read_text(encoding="utf-8") + (
            ROOT / "tests" / "paired_raft_backup_support" / "fixture.rs"
        ).read_text(encoding="utf-8")
        self.assertIn("RETRY_MAX_TIMES=3", it_src)
        self.assertIn("header::CONNECTION", it_src)
        self.assertIn('"close"', it_src)
        self.assertIn("missing_whole_pack_pair_and_single_side_closure_regressions", it_src)
        self.assertIn("durable_wal_barrier_and_sealing_receipt_freeze_thaw_regressions", it_src)
        self.assertIn("production_mtls_quorum_durable_freeze_format30_and_new_incarnation_boot", it_src)

    def test_freeze_reset_attestation_pristine_and_production_guards(self) -> None:
        pg_src = (MOD_DIR / "pg_freeze_settings.rs").read_text(encoding="utf-8")
        for token in (
            "terminate_and_await_other_pg_sessions",
            "pg_terminate_backend",
            "verify_no_active_pg_writers",
            "enforce_maintenance_pg_write_guard",
            "pg_stat_activity",
            "read_pg_database_read_only",
        ):
            self.assertIn(token, pg_src, f"missing PG freeze/writer-exit contract: {token}")

        gate_src = (MOD_DIR / "durable_freeze_gate.rs").read_text(encoding="utf-8")
        self.assertIn("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY", gate_src)
        self.assertIn("terminate_and_await_other_pg_sessions", gate_src)
        self.assertIn("verify_no_active_pg_writers", gate_src)

        fmt30_src = (MOD_DIR / "format30_paired.rs").read_text(encoding="utf-8")
        self.assertIn("verify_no_active_pg_writers_except_fence", fmt30_src)
        self.assertIn("cutpoint_attestations", fmt30_src)

        attest_src = (
            (MOD_DIR / "peer_attestation.rs").read_text(encoding="utf-8")
            + (MOD_DIR / "peer_attestation_rpc.rs").read_text(encoding="utf-8")
            + (MOD_DIR / "wal_voters.rs").read_text(encoding="utf-8")
        )
        for token in (
            "PeerDurableAttestationClaims",
            "PeerDurableAttestation",
            "derive_voter_uuid_bound",
            "load_or_create_ed25519_keypair",
            "PeerAttestationDaemon",
            "AttestCommit",
            "AttestCutpoint",
            "rootyard-peer-durable-attestation-v1",
            "voter{slot}.pk8",
            "0o600",
        ):
            self.assertIn(token, attest_src, f"missing Ed25519 attestation contract: {token}")

        barrier_src = (MOD_DIR / "raft_barrier.rs").read_text(encoding="utf-8")
        self.assertIn("peer_attestation", barrier_src)
        self.assertIn("verify_cutpoint_attestations", barrier_src)

        for name in ("backup.rs", "format30_paired.rs", "peer_groups.rs", "restore.rs"):
            self.assertIn(
                "cutpoint_attestations",
                (MOD_DIR / name).read_text(encoding="utf-8"),
                f"{name} must populate/verify cutpoint attestations",
            )

        mtls_src = (MOD_DIR / "mtls_raft.rs").read_text(encoding="utf-8")
        self.assertIn("verify_pristine_new_incarnation_target", mtls_src)
        self.assertIn("voter_bindings", mtls_src)
        boot_src = (MOD_DIR / "format30_boot.rs").read_text(encoding="utf-8")
        for token in ("verify_pristine_new_incarnation_target", "forbidden_incarnations"):
            self.assertIn(token, boot_src, f"missing pristine-incarnation contract: {token}")

        runtime_src = (MOD_DIR / "production_runtime.rs").read_text(encoding="utf-8")
        for token in (
            "PairedProductionRuntimeGuard",
            "WorkerProjectionTicket",
            "commit_ref_write",
            "run_projection_worker_step",
            "execute_fenced_pack_delete",
        ):
            self.assertIn(token, runtime_src, f"missing production guard contract: {token}")

        facade_src = (ROOT / "src" / "maintenance.rs").read_text(encoding="utf-8")
        self.assertIn("enforce_maintenance_pg_write_guard", facade_src)
        self.assertIn("pub use paired_raft_backup::{PairedProductionRuntimeGuard, WorkerProjectionTicket};", facade_src)

        for token, rel in (
            ("fsync_and_hash_voter_durable_wal", "src/maintenance/paired_raft_backup/wal_file_digest.rs"),
            ("PAIRED_FREEZE_JOURNAL_LOCK_KEY", "src/maintenance/paired_raft_backup/pg_freeze_settings.rs"),
            ("install_production_serving_guard", "src/maintenance/paired_raft_backup/startup_wiring.rs"),
            ("ensure_serving_database_unfrozen", "src/maintenance/paired_raft_backup/startup_wiring.rs"),
            ("expected_peer_ids", "src/maintenance/paired_raft_backup/format30_boot.rs"),
        ):
            self.assertIn(token, (ROOT / rel).read_text(encoding="utf-8"), token)

        admission_src = (MOD_DIR / "admission_guard.rs").read_text(encoding="utf-8")
        for token in ("admit_writer_grant", "admit_decision_execution", "admit_deleter_lease"):
            self.assertIn(token, admission_src)

        cluster_src = (ROOT / "tests" / "paired_raft_backup_support" / "mtls_cluster.rs").read_text(encoding="utf-8")
        for token in ("attestor_endpoints", "peer_attestor_bin", "AttestorProc", "ROOTYARD_PEER_ATTESTOR_BIN"):
            self.assertIn(token, cluster_src, f"mTLS harness must run real per-voter attestors: {token}")
        gates_src = (ROOT / "tests" / "paired_raft_backup_support" / "format30_luna_gates.rs").read_text(
            encoding="utf-8"
        )
        for token in (
            "gate1_pooled_pg_session_read_only_reset_and_verified_writer_exit",
            "gate2_forged_voter_acks_and_minority_cutpoint_attestations_are_rejected",
            "gate3_pristine_target_rejects_reused_source_incarnation",
            "gate4_production_guards_refuse_frozen_stale_and_superseded_paths",
        ):
            self.assertIn(token, gates_src)

    def test_kernel_write_fence_peer_attestor_sidecar_and_group_epoch_contracts(self) -> None:
        fence_path = MOD_DIR / "pg_write_fence.rs"
        fence_raw = fence_path.read_bytes()
        self.assertNotIn(b"\r\n", fence_raw)
        fence_text = fence_raw.decode("utf-8")
        self.assertLess(len(fence_text.splitlines()), 175)
        self.assertNotIn("#[allow(", fence_text)
        for token in ("PgTableShareFence", "LOCK TABLE", "IN SHARE MODE", "pg_backend_pid", "backend_xid"):
            self.assertIn(token, fence_text, f"missing kernel PostgreSQL write-fence contract: {token}")

        sidecar = ROOT / "src" / "bin" / "rootyard-peer-attestor.rs"
        sidecar_raw = sidecar.read_bytes()
        self.assertNotIn(b"\r\n", sidecar_raw)
        sidecar_text = sidecar_raw.decode("utf-8")
        self.assertLess(len(sidecar_text.splitlines()), 95)
        self.assertNotIn("#[allow(", sidecar_text)
        for token in ("READY", "ed25519_pubkey_hex", "--raft-node-addr", "--rpc-timeout-ms", "ctrl_c"):
            self.assertIn(token, sidecar_text, f"missing peer-attestor sidecar contract: {token}")

        wiring = (MOD_DIR / "startup_wiring.rs").read_text(encoding="utf-8")
        for token in (
            "ROOTYARD_PAIRED_RAFT_ATTESTOR_JSON",
            "installed_peer_attestation_daemon_addr",
            "shutdown_installed_peer_attestation_daemon",
        ):
            self.assertIn(token, wiring, f"missing co-located attestor startup contract: {token}")
        self.assertIn(
            "shutdown_installed_peer_attestation_daemon",
            (ROOT / "src" / "standalone.rs").read_text(encoding="utf-8"),
            "standalone serving must shut down the co-located attestor",
        )

        rpc = (MOD_DIR / "peer_attestation_rpc.rs").read_text(encoding="utf-8")
        for token in ("verify_local_group_epoch", "GROUP_EPOCH_KV_KEY", "StaleIncarnation", "CutpointSkew"):
            self.assertIn(token, rpc, f"missing signed local group_epoch verification: {token}")
        self.assertIn(
            "refcas/group_epoch",
            (MOD_DIR / "mtls_raft.rs").read_text(encoding="utf-8"),
            "missing group epoch key literal in mtls_raft",
        )
        self.assertLess(len(rpc.splitlines()), 495)
        self.assertLess(len((ROOT / "tests" / "paired_raft_backup_support" / "format30_e2e.rs").read_text(encoding="utf-8").splitlines()), 475)
        self.assertLess(
            len((ROOT / "tests" / "paired_raft_backup_support" / "format30_luna_startup_gates.rs").read_text(encoding="utf-8").splitlines()),
            240,
        )

    def test_workflow_contract_and_doc_links(self) -> None:
        raw_wf = WORKFLOW.read_bytes()
        self.assertNotIn(b"\r\n", raw_wf)
        wf_text = raw_wf.decode("utf-8")
        self.assertTrue(wf_text.startswith("name: "))
        self.assertNotIn("\t", wf_text)
        if yaml is not None:
            doc = yaml.safe_load(wf_text)
            on_cfg = doc.get("on") if "on" in doc else doc.get(True)
            self.assertIsInstance(on_cfg, dict)
            self.assertIn("pull_request", on_cfg)
            self.assertIn("workflow_dispatch", on_cfg)
            self.assertNotIn("push", on_cfg)
            paths = on_cfg["pull_request"]["paths"]
            for required in (
                "src/maintenance.rs",
                "src/maintenance/paired_raft_backup.rs",
                "src/maintenance/paired_raft_backup/**",
                "src/bin/rootyard-peer-attestor.rs",
                "tests/paired_raft_backup_restore.rs",
                "tests/paired_raft_backup_support/**",
                "scripts/eval_paired_raft_backup.py",
                "docs/paired-raft-backup-restore.md",
            ):
                self.assertIn(required, paths)

        for token in (
            "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b",
            "scripts/install_ci_cargo_fork.sh install",
            "scripts/install_ci_cargo_fork.sh verify",
            "postgres:17",
            "cargo build --locked --no-default-features --bin rootyard-peer-attestor",
            "ROOTYARD_PEER_ATTESTOR_BIN=",
            "--bin rootyard-peer-attestor",
            "cargo test --locked --no-default-features --lib maintenance::paired_raft_backup",
            "cargo test --locked --no-default-features --test paired_raft_backup_restore",
            "--ignored",
            "scripts/eval_paired_raft_backup.py",
        ):
            self.assertIn(token, wf_text)

        raw_doc = DOC.read_bytes()
        self.assertNotIn(b"\r\n", raw_doc)
        doc_text = raw_doc.decode("utf-8")
        self.assertLess(len(doc_text.splitlines()), 130)
        for token in (
            "#153",
            "CurrentCodeFact",
            "EnforcedRestoreProtocol",
            "MeasuredEvalBaseline",
            "pg_write_fence.rs",
            "verify_local_group_epoch",
            "rootyard-peer-attestor.rs",
        ):
            self.assertIn(token, doc_text)
        for target in re.findall(r"\[[^\]]*\]\(([^)]+)\)", doc_text):
            clean = target.split("#", 1)[0]
            if not clean or "://" in clean:
                continue
            self.assertTrue((DOC.parent / clean).resolve().exists(), f"missing doc link: {target}")

    def test_eval_script_smoke_execution(self) -> None:
        eval_raw = EVAL_SCRIPT.read_bytes()
        self.assertNotIn(b"\r\n", eval_raw)
        eval_text = eval_raw.decode("utf-8")
        self.assertLess(len(eval_text.splitlines()), 500)
        self.assertIn("validate_receipt", eval_text)
        self.assertNotIn("verify_receipt", eval_text)

        spec = importlib.util.spec_from_file_location("eval_paired_raft_backup", EVAL_SCRIPT)
        self.assertIsNotNone(spec)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        report = module.run_evaluation([4], ["sha1"])
        self.assertEqual(report["issue"], 153)
        self.assertEqual(len(report["results"]), 1)
        row = report["results"][0]
        self.assertEqual(row["pack_count"], 4)
        self.assertEqual(row["closure_artifacts"], 8)
        self.assertEqual(row["negative_faults_rejected"], 1)
        self.assertEqual(row["git_verified_refs"], 1)
        self.assertTrue(row["new_incarnation_minted"])


if __name__ == "__main__":
    unittest.main()
