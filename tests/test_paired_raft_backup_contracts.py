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
    ROOT / "src" / "blob_git_gateway" / "receive.rs",
    ROOT / "src" / "blob_git_gateway" / "receive" / "response.rs",
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
                for match in re.finditer(r"#\[derive\([^)]*Deserialize[^)]*\)\]\s*(?:#\[[^\]]+\]\s*)*(?:pub\s+)?struct (\w+)", text):
                    self.assertIn("deny_unknown_fields", match.group(0), f"{match.group(1)} missing deny_unknown_fields")

    def test_paired_protocol_enforces_freeze_close_closure_bind_incarnation_and_s3_close(self) -> None:
        types_src = (MOD_DIR / "types.rs").read_text(encoding="utf-8")
        for token in (
            "IncompleteCut", "FreezeNotHeld", "ScopeNotClosed", "UnknownInFlightOperations", "DeleterNotFenced",
            "CutpointSkew", "TenantOrRepoMismatch", "BlobClosureIncomplete", "CorruptBlobOrDigest",
            "BackendIdentityMismatch", "StaleIncarnation", "StaleGrantRefused", "StaleDecisionRefused",
            "StaleDeleterRefused", "ExpectedPackPairSpec", "max_decision_scope_version",
            "RepositoryClosureExceedsVerifierBudget",
        ):
            self.assertIn(token, types_src)

        barrier_src = (MOD_DIR / "raft_barrier.rs").read_text(encoding="utf-8") + (
            MOD_DIR / "quorum_wal.rs"
        ).read_text(encoding="utf-8")
        for token in (
            "DurableRaftBackend", "WalSyncedRaftBackend", "QuorumCommitReceipt", "LocalWalApplyReceipt", "VoterWalAck",
            "DurableFreezeBarrierProof", "SealedArchiveReceipt", "sync_data",
        ):
            self.assertIn(token, barrier_src)

        bind_src = (MOD_DIR / "closure_bind.rs").read_text(encoding="utf-8") + (
            MOD_DIR / "peer_groups.rs"
        ).read_text(encoding="utf-8")
        for token in (
            "compute_canonical_pack_set_digest", "PeerRaftCutpointProof", "verify_archived_peer_groups",
            "verify_all_group_cursors", "verify_blob_closure_against_durable_raft", "verify_registration_spec_completeness",
        ):
            self.assertIn(token, bind_src)

        freeze_src = (MOD_DIR / "freeze_drain.rs").read_text(encoding="utf-8")
        for token in ("CloseAuthScope", "CreateSnapshotPin", "AcquireHoldBatch", "RegisterRoot", "unfreeze_after_backup", "SealedArchiveReceipt", "verify_backup_archive"):
            self.assertIn(token, freeze_src)

        backup_src = (MOD_DIR / "backup.rs").read_text(encoding="utf-8")
        self.assertIn("IsolationLevel::RepeatableRead", backup_src)
        self.assertIn("verify_blob_closure_against_durable_raft", backup_src)
        self.assertIn("verify_all_group_cursors", backup_src)

        pg_src = (MOD_DIR / "pg_cutpoint.rs").read_text(encoding="utf-8") + (
            MOD_DIR / "pg_restore_admission.rs"
        ).read_text(encoding="utf-8")
        for token in (
            "capture_pg_cutpoint_in_tx", "pando_storage_authorities", "pando_retention_roots",
            "ref_cas_projection_cursors", "ref_store_serving_repositories", "ref_store_decision_scopes",
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
            "MtlsLiveRaftBackend", "raft-node-", "peer_certificates", "PG_FREEZE_SETTING", "repo_access",
            "upsert_repo_access_collaborator_guarded", "create_format30_paired_raft_backup",
            "restore_and_boot_format30_new_incarnation", "STANDARD_PAIRED_PG_FORMAT", "STANDARD_SCHEMA_HEAD",
            "crate::backup::create", "crate::backup::restore",
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
            "terminate_and_await_other_pg_sessions", "pg_terminate_backend", "verify_no_active_pg_writers",
            "enforce_maintenance_pg_write_guard", "pg_stat_activity", "read_pg_database_read_only",
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
            "PeerDurableAttestationClaims", "PeerDurableAttestation", "derive_voter_uuid_bound",
            "load_or_create_ed25519_keypair", "PeerAttestationDaemon", "AttestCommit", "AttestCutpoint", "rootyard-peer-durable-attestation-v1", "voter{slot}.pk8", "0o600",
        ):
            self.assertIn(token, attest_src, f"missing Ed25519 attestation contract: {token}")

        barrier_src = (MOD_DIR / "raft_barrier.rs").read_text(encoding="utf-8")
        self.assertIn("peer_attestation", barrier_src)
        self.assertIn("verify_cutpoint_attestations", barrier_src)

        for name in ("backup.rs", "format30_paired.rs", "peer_groups.rs", "restore.rs"):
            self.assertIn("cutpoint_attestations", (MOD_DIR / name).read_text(encoding="utf-8"), f"{name} must populate/verify cutpoint attestations")

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
        self.assertLess(len((ROOT / "tests" / "paired_raft_backup_support" / "format30_luna_startup_gates.rs").read_text(encoding="utf-8").splitlines()), 240)

    def test_fence_hold_caller_auth_cutpoint_reach_and_realm_rehome_contracts(self) -> None:
        def read(name: str) -> str:
            return (MOD_DIR / name).read_text(encoding="utf-8")

        def require(source: str, tokens: tuple[str, ...], detail: str) -> None:
            for token in tokens:
                self.assertIn(token, source, f"missing {detail}: {token}")

        require(read("pg_write_fence.rs"), ("granted_count", "total_public_tables", "current_pid", "backend_pid", "no_xid", "granted"), "single round-trip SHARE-fence proof")
        require(read("durable_guarded_ops.rs"), ("verify_fence_intact_for_publication", "verify_write_fence_held", "remote_delete_fenced", "verify_freeze_barrier_active", "fault_drop_fence_stage", "maybe_inject_fence_fault"), "publication fence continuity contract")
        fmt30 = read("format30_paired.rs")
        self.assertGreaterEqual(fmt30.count("verify_fence_intact_for_publication"), 4, "every publication boundary must re-prove the fence")
        self.assertEqual(fmt30.count("maybe_inject_fence_fault"), 3, "gate-7 needs three publication-boundary seams")
        for name in ("quorum_wal.rs", "mtls_raft.rs"):
            self.assertIn("verify_freeze_barrier_active", read(name), f"{name} must prove the Raft freeze barrier")
        require(read("peer_attestation.rs"), ("durable_sqlite_sha256", "allowed_caller_cert_sha256s", "authorize_caller_peer_certs", "build_allowed_caller_digests"), "attestation/caller-auth contract")
        require(read("peer_caller_auth.rs"), ("AUTHORIZED_ATTESTOR_CLIENT_DNS", "authorize_caller_peer_certs", "OID_SUBJECT_ALT_NAME"), "X.509 caller authorization contract")
        require(read("peer_attestation_rpc.rs"), ("min_committed_index", "durable_sqlite_sha256", "reached the attested cutpoint"), "quorum-reached cutpoint contract")
        require(read("raft_barrier.rs"), ("durable_sqlite_sha256", "claims.raft_committed_index < applied_log_id.index"), "cutpoint reach verification")
        rehome = MOD_DIR / "format30_realm_rehome.rs"
        self.assertTrue(rehome.exists(), "restored A3/A4 realm re-home module is missing")
        rehome_src = rehome.read_text(encoding="utf-8")
        self.assertLess(len(rehome_src.splitlines()), 480)
        rehome_all = rehome_src + "\n" + read("format30_rebind_plans.rs")
        require(rehome_src, ("rehome_restored_repositories_realm", "rebind_restored_repositories_in_new_realm", "PgPackCommit", "PgArtifactHoldStore", "ProtectedUploader", "PackVerifier", "PackRegistrationRequest", "commit_verified_pending"), "restored realm re-home contract")
        for statement in ("UPDATE public.artifact_hold_requests", "UPDATE public.artifact_hold_consume_receipts", "UPDATE public.ref_store_core_pack_publications", "UPDATE public.ref_store_core_pack_history"):
            self.assertNotIn(statement, rehome_all, "historical A3/A4 ledger rows must stay immutable")
        self.assertIn("rehome_restored_repositories_realm", read("format30_boot.rs"), "boot must re-home the realm")
        consolidate = MOD_DIR / "format30_pack_consolidate.rs"
        self.assertTrue(consolidate.exists(), "restored ref-less pack consolidation module is missing")
        consolidate_src = consolidate.read_text(encoding="utf-8")
        require(consolidate_src, ("RebindTempDir", "consolidate_packs_with_git", "pick_any_object_oid_from_pack", "consolidate_more_than_eight_identical_filename_pairs_preserves_all_objects", "pack-{index:06}-", "--batch-all-objects"), "ref-less restore pack consolidation contract")
        require(rehome_all, ("rootyard-rebind-", "RefTarget::Delete", "delete_ephemeral_rebind_tag", "old_packs()"), "ref-less active-pack rebind contract")
        require(read("mtls_consensus.rs"), ("HEAD_RAFT_INDEX_KV_KEY", "linearizable_consensus_index", "EnsureReadIndex", "forward_to_leader_id"), "real Raft consensus index contract")
        require(read("mtls_raft.rs"), ("refcas/head_raft_index", "linearizable_consensus_index", "commit_raft_idx"), "durable head_raft_index persistence contract")
        require(read("peer_attestation_rpc.rs"), ("HEAD_RAFT_INDEX_KV_KEY", "read_replica_u64"), "local head_raft_index attestation floor")
        self.assertIn("min_consensus_index", read("types.rs"), "cutpoint proofs must carry the consensus floor")
        self.assertIn("min_consensus_index", read("peer_groups.rs"))
        require(read("format30_boot.rs"), ("staging_root", "restore_guard_path", "restore_in_progress"), "staged restore publication contract")
        boot_src = read("format30_boot.rs")
        require(
            boot_src,
            ("publish_staged_dir_noreplace", "RENAME_NOREPLACE", "boot_thaw", "tag_thaw_group"),
            "atomic no-replace staged publication contract",
        )
        order = ("boot_thaw", "publish_staged_dir_noreplace(&staged_data", "clear_restored_pg_freeze(&dst_client)")
        order += ("remove_file(&guard_path)",)
        self.assertEqual(order, tuple(sorted(order, key=boot_src.index)), "PG unfreeze after publish; guard last")
        self.assertIn("BootThawRefused", read("types.rs"), "boot thaw must be a typed refusal")
        self.assertIn("BootThawRefused", boot_src, "boot thaw refusal must be raised in format30_boot")
        self.assertIn("VERIFIER_MAX_OBJECTS", consolidate_src, "consolidation must bound the verifier object count")
        self.assertIn("RepositoryClosureExceedsVerifierBudget", read("format30_paired.rs"), "archive pairs must be bounded")
        self.assertNotIn("wait_with_output", consolidate_src, "the consolidated pack must never be buffered in heap RAM")
        mtls_cluster_src = (ROOT / "tests" / "paired_raft_backup_support" / "mtls_cluster.rs").read_text(encoding="utf-8")
        self.assertIn("partition_all_nodes", mtls_cluster_src, "gate 8 must be able to partition every voter")
        self.assertNotIn("let _ = n.rpc", mtls_cluster_src, "partition RPC results must never be discarded")
        self.assertIn("kill_hard_checked", mtls_cluster_src, "gate 10 must check kill/reap outcomes")
        require(
            read("format30_pg_raft_sync.rs"),
            ("ensure_raft_commit_refs_committed", "TerminalKind::Committed"),
            "a rejected Raft terminal must never be mirrored or replayed as success",
        )
        self.assertIn("ensure_raft_commit_refs_committed", read("format30_boot_raft.rs"))
        self.assertIn("replicate_pg_repo_to_raft_guarded", read("durable_guarded_ops.rs"))
        delta8 = ROOT / "tests" / "paired_raft_backup_support" / "format30_delta8_gates.rs"
        self.assertTrue(delta8.exists(), "gate-8 delta module is missing")
        require(delta8.read_text(encoding="utf-8"), ("gate8_refless_active_packs_rebind_and_failed_restore_stays_unpublished", "rootyard-restoring", "partition_all_nodes"), "gate-8 ref-less rebind and unpublished-restore coverage")
        self.assertIn("format30_delta8_gates", (ROOT / "tests" / "paired_raft_backup_restore.rs").read_text(encoding="utf-8"), "gate-8 module must be wired into the integration test target")
        luna = (ROOT / "tests" / "paired_raft_backup_support" / "format30_luna_startup_gates.rs")
        require(luna.read_text(encoding="utf-8"), ("min_committed_index", "durable_sqlite_sha256", "wrong_san_cert", "rogue_client_cert", "unpinned_client_cert"), "gate-6")
        ledger = ROOT / "tests" / "paired_raft_backup_support" / "format30_ledger_gates.rs"
        self.assertTrue(ledger.exists(), "A3/A4 ledger gate module is missing")
        ledger_src = ledger.read_text(encoding="utf-8")
        self.assertLess(len(ledger_src.splitlines()), 300)
        self.assertIn("format30_ledger_gates", (ROOT / "tests" / "paired_raft_backup_restore.rs").read_text(encoding="utf-8"), "A3/A4 ledger gate module must be wired")
        require(ledger_src, ("capture_pre_backup_ledger_proof", "verify_post_restore_ledger_immutability_and_denials", "verify_post_push_new_realm_ledger", "HistoryIncarnationMismatch", "RegistrationConflict"), "A3/A4 ledger immutability and denial contract")
        hold = ROOT / "tests" / "paired_raft_backup_support" / "format30_luna_fence_hold_gates.rs"
        self.assertTrue(hold.exists(), "gate-7 fence-hold test module is missing")
        hold_src = hold.read_text(encoding="utf-8")
        self.assertLess(len(hold_src.splitlines()), 260)
        require(hold_src, ("gate7_fence_drop_at_each_publication_boundary_fails_closed", "set_fault_drop_fence_stage_for_test", "durable_attestation_without_wal_digest_is_refused"), "gate-7 fence-drop boundary coverage")
        self.assertIn("format30_luna_fence_hold_gates", (ROOT / "tests" / "paired_raft_backup_restore.rs").read_text(encoding="utf-8"), "gate-7 module must be wired into the integration test target")
        require((ROOT / "src" / "bin" / "rootyard-peer-attestor.rs").read_text(encoding="utf-8"), ("--allow-caller-sha256",), "attestor caller allowlist flag")
        require(read("startup_wiring.rs"), ("allowed_caller_cert_sha256s",), "attestor startup allowlist wiring")
        delta10 = ROOT / "tests" / "paired_raft_backup_support" / "format30_delta10_gates.rs"
        self.assertTrue(delta10.exists(), "gate-10 delta module is missing")
        delta10_src = delta10.read_text(encoding="utf-8")
        self.assertLess(len(delta10_src.splitlines()), 450)
        require(
            delta10_src,
            (
                "gate10_multi_plan_135_refs_rebind_and_thaw_failure_blocks_publish", "restore_and_boot_format30_with_pre_thaw_hook",
                "kill_hard_checked", "paired-restore-rebind", "BootThawRefused", "pre_thaw_hook_ran",
                "restore_and_boot_format30_with_pre_publish_hook",
            ),
            "gate-10 multi-plan rebind, thaw-failure and pre-publish collision coverage",
        )
        self.assertIn("format30_delta10_gates", (ROOT / "tests" / "paired_raft_backup_restore.rs").read_text(encoding="utf-8"),
                      "gate-10 module must be wired into the integration test target")
        require(
            read("format30_pack_consolidate.rs"),
            ("chunk_refs_for_plans", "select_packs_for_rebind_with_limit", "MAX_REBIND_REF_ACK_BYTES", "RepositoryClosureExceedsVerifierBudget"),
            "multi-plan rebind ref/ACK and verifier byte chunking contract",
        )
        require(read("format30_pg_raft_sync.rs"), ("apply_pg_repo_state_to_raft", "RefPrecondition::Present", "RefTarget::Delete", "MAX_PLAN_REFS"),
                "delta-exact PG -> Raft replication contract")
        require(
            read("mtls_raft.rs"),
            ("sync_cached_state_machine", "resolve_group_epoch(&cmd, &before_sm)", "post-commit snapshot failed"),
            "multi-handle Raft cache sync and per-commit group-epoch resolution contract",
        )
        require(read("startup_wiring.rs") + read("startup_wiring_tests.rs"), ("PairedWriteRaftScopeGuard", "install_paired_write_raft_binding", "mirror_gateway_push_to_paired_raft", "run_serialized_pg_to_raft_step",
                "tokio::sync::Mutex", "lock_owned", "cancelled_caller_keeps_serialization_lock_until_blocking_raft_apply_finishes"), "database-keyed paired write binding contract")
        receive_src = (ROOT / "src" / "blob_git_gateway" / "receive.rs").read_text(encoding="utf-8")
        self.assertIn("paired_write_raft_gate(&state, repository_id, false).await?", receive_src)
        response_src = (ROOT / "src" / "blob_git_gateway" / "receive" / "response.rs").read_text(encoding="utf-8")
        require(
            response_src,
            ("check_paired_write_unfrozen", "mirror_gateway_push_to_paired_raft", "GatewayError::OutcomeUnknown",
             "paired_write_raft_gate(self.state, self.serving.gate.repository_id(), terminal.is_committed()).await?"),
            "normal paired Smart-HTTP write-path mirror contract",
        )
        for gate in (
            "format30_delta8_gates.rs", "format30_delta10_gates.rs", "format30_delta15_gates.rs",
            "format30_luna_fence_hold_gates.rs",
        ):
            gate_src = (ROOT / "tests" / "paired_raft_backup_support" / gate).read_text(encoding="utf-8")
            self.assertNotIn("replicate_pg_repo_to_raft_guarded", gate_src, f"{gate} must use the normal paired write path")
            self.assertIn('flavor = "multi_thread"', gate_src, f"{gate} must drive the mirrored write path on a multi-thread runtime")
        self.assertNotIn(
            "replicate_pg_repo_to_raft_guarded",
            (ROOT / "tests" / "paired_raft_backup_support" / "format30_e2e.rs").read_text(encoding="utf-8"),
            "the live E2E must prove the normal push path owns the Raft floor",
        )
        delta15 = ROOT / "tests" / "paired_raft_backup_support" / "format30_delta15_gates.rs"
        self.assertLess(len(delta15.read_text(encoding="utf-8").splitlines()), 450)
        require(delta15.read_text(encoding="utf-8"), ("gate15_admitted_over_eight_pairs_restores_and_verifies_end_to_end", "gate15_over_budget_backup_refused_before_publishing_destination"), "gate-15 over-eight-pair and over-budget gates")
        self.assertIn("format30_delta15_gates", (ROOT / "tests" / "paired_raft_backup_restore.rs").read_text(encoding="utf-8"))
        budget = fmt30.index("enforce_blob_closure_verifier_budget(&blob_closure.entries)")
        self.assertTrue(budget < fmt30.index("write_synced(&work_dir.join(COMPLETE_MARKER)") < fmt30.index("fs::rename(&work_dir, req.destination)") and "PartialDirGuard" in fmt30)
        self.assertLess(read("backup.rs").index("enforce_blob_closure_verifier_budget(&entries)"), read("backup.rs").index("write_synced_file(&work_dir.join(COMPLETE_MARKER)"))

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
                "src/blob_git_gateway/receive.rs",
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
            "RepositoryClosureExceedsVerifierBudget",
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
