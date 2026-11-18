# Coordinated PG Cutpoint + Raft Index + Blob Closure Paired Backup & New-Incarnation Restore (`#153`)

This document specifies the paired backup and clean-room new-incarnation restore engine implemented under [`src/maintenance/paired_raft_backup.rs`](../src/maintenance/paired_raft_backup.rs) for Blob-only Pando (`PostgreSQL 17 + RefCasStateMachine + OpenDAL BlobStore + stock Git`).

Classification tags used below:
- **CurrentCodeFact**: schema triggers, tables, and Raft state-machine commands enforced in `origin/main` ([`migrations/144_ref_store_core_roots_decisions.sql`](../migrations/144_ref_store_core_roots_decisions.sql), [`migrations/145_ref_store_serving.sql`](../migrations/145_ref_store_serving.sql), [`migrations/148_pando_pitr_authority_fence.sql`](../migrations/148_pando_pitr_authority_fence.sql), [`migrations/149_ref_cas_event_projection.sql`](../migrations/149_ref_cas_event_projection.sql), [`src/ref_store/core/state_machine.rs`](../src/ref_store/core/state_machine.rs)).
- **EnforcedRestoreProtocol**: paired durable WAL freeze/drain/seal, complete hold/root/pin Blob closure binding, cursor `group_epoch` reconciliation, and clean-room `authz_floor` restore checks implemented in [`raft_barrier.rs`](../src/maintenance/paired_raft_backup/raft_barrier.rs), [`closure_bind.rs`](../src/maintenance/paired_raft_backup/closure_bind.rs), [`freeze_drain.rs`](../src/maintenance/paired_raft_backup/freeze_drain.rs), [`pg_cutpoint.rs`](../src/maintenance/paired_raft_backup/pg_cutpoint.rs), [`pg_restore_admission.rs`](../src/maintenance/paired_raft_backup/pg_restore_admission.rs), [`backup.rs`](../src/maintenance/paired_raft_backup/backup.rs), [`restore.rs`](../src/maintenance/paired_raft_backup/restore.rs), and [`git_verify.rs`](../src/maintenance/paired_raft_backup/git_verify.rs).
- **MeasuredEvalBaseline**: reproducible SHA-1 & SHA-256 stock-Git archive/restore/tamper timings and closure byte counts from [`scripts/eval_paired_raft_backup.py`](../scripts/eval_paired_raft_backup.py).

---

## 1. Coordinated Paired Cutpoint & Durable Raft Freeze/Thaw Barrier (`EnforcedRestoreProtocol`)

1. **Durable Raft WAL + Quorum Freeze Barrier (Consensus Preserved)**:
   - [`TriPartyBackupCoordinator::freeze_drain_and_register`](../src/maintenance/paired_raft_backup/freeze_drain.rs) commits every barrier command (`Cancel`, `CreateSnapshotPin`, `AcquireHoldBatch`, `RegisterRoot`, `CloseAuthScope`) through [`DurableRaftBackend`](../src/maintenance/paired_raft_backup/raft_barrier.rs) ([`WalSyncedRaftBackend`](../src/maintenance/paired_raft_backup/raft_barrier.rs) fsynced WAL + quorum commit witness) and verifies the reopened durable Raft snapshot before transitioning into `DurableFreezeBarrierProof` (`app_paused`, `worker_paused`, `deleter_fenced`, while keeping `consensus_replication_active = true` and `leader_election_active = true`). Local volatile-only apply or missing quorum fails closed (`FreezeNotHeld`).
   - [`unfreeze_after_backup`](../src/maintenance/paired_raft_backup/freeze_drain.rs) refuses to thaw unless [`SealedArchiveReceipt`](../src/maintenance/paired_raft_backup/raft_barrier.rs) matches the active `DurableFreezeBarrierProof`, on-disk [`verify_backup_archive`](../src/maintenance/paired_raft_backup/restore.rs) (`COMPLETE` + `manifest.json` + Blob SHA-256s) passes, and the durable Raft WAL preserves active backup retention roots/holds and `Closed` auth scopes at `>= barrier_log_id`.
2. **PG 17 Repeatable-Read <-> Raft `group_epoch` & Index Reconciliation**:
   - [`capture_pg_cutpoint_in_tx`](../src/maintenance/paired_raft_backup/pg_cutpoint.rs) runs inside a `READ ONLY REPEATABLE READ` PG 17 transaction, capturing `max_decision_scope_version` from `ref_store_decision_scopes` and verifying `remote_delete_fenced = true`, zero `'OPEN'` `ref_store_publication_decisions`, zero `'unknown'` `git_operations` / outbox / projection jobs, **`group_epoch` equality across all Raft groups** in `ref_cas_projection_cursors` ([`verify_cursor_group_epochs`](../src/maintenance/paired_raft_backup/closure_bind.rs)), and exact `(history_incarnation, group_epoch, applied_event_seq, applied_log_index, applied_log_term)` + `ref_store_core_refs` alignment.
3. **Complete Durable Hold/Root/Pin Blob Closure Binding**:
   - [`verify_registration_spec_completeness`](../src/maintenance/paired_raft_backup/closure_bind.rs) and [`verify_blob_closure_against_durable_raft`](../src/maintenance/paired_raft_backup/closure_bind.rs) bind both `.pack` and `.idx` of every pack pair into durable Raft holds, snapshot pins, and active retention roots (`compute_canonical_pack_set_digest`), failing closed (`BlobClosureIncomplete`) whether a single `.pack`/`.idx` side or an **entire `(pack, idx)` pair** is omitted from storage or from a re-sealed archive manifest.

---

## 2. Clean-Room New-Incarnation Restore & Restored `authz_epoch` Floor (`EnforcedRestoreProtocol`)

1. **Pre-Exposure Verification**: [`verify_backup_archive`](../src/maintenance/paired_raft_backup/restore.rs) validates `COMPLETE`, `#[serde(deny_unknown_fields)]`, `paired_cut_digest`, `PgCutpointProof`, `RaftCutpointProof`, `verify_cursor_group_epochs` across all Raft groups, `verify_blob_closure_against_durable_raft`, `backend_identity`, and full SHA-256 + byte length on every `.pack`/`.idx` member **before** exposing state.
2. **Fresh Incarnation & Authority Rotation**: [`restore_new_incarnation`](../src/maintenance/paired_raft_backup/restore.rs) mints fresh `new_cluster_incarnation`, `new_storage_authority_id`, `new_history_incarnation`, and strictly bumped `new_storage_generation`, `new_authority_epoch`, `new_group_epoch`, `new_authz_floor` (`max(close_receipts, pg.max_decision_scope_version) + 10`), and `new_deleter_epoch`; uploads paired blobs into `target_store` via `upload_pack_pair`; runs stock-Git `git index-pack --strict`, `git verify-pack -v`, `git fsck --full --strict`, and `git clone --no-hardlinks` for both `SHA-1` and `SHA-256`; and commits restored gates/refs/holds via `WalSyncedRaftBackend`.
3. **Clean-Room PG 17 Installation & Restored `authz_epoch` Floor Admission**:
   - [`install_restored_pg_incarnation`](../src/maintenance/paired_raft_backup/pg_restore_admission.rs) fences the pre-backup authority in `ref_store_decision_scopes` (`state = 'CLOSING'`), installs `'OPEN'` `ref_store_decision_scopes` rows (`authority`, `repo_lifecycle`, `repo_access`) at `version = new_authz_floor`, installs rotated `cluster_authority`, `pando_storage_authorities`, `repositories`, `ref_store_core_gates`, `ref_store_serving_repositories`, `'backup_snapshot'` `pando_retention_roots`, and `ref_cas_projection_cursors` (`verify_pg_restored_cursors`).
   - [`verify_pg_live_incarnation`](../src/maintenance/paired_raft_backup/pg_restore_admission.rs) and [`IncarnationAdmissionGuard`](../src/maintenance/paired_raft_backup/restore.rs) enforce the restored `ref_store_decision_scopes` `authz_epoch` floor against `WriterGrantTicket` (`StaleGrantRefused`), `DecisionExecutionTicket` (`StaleDecisionRefused`), and `DeleterLeaseTicket` (`StaleDeleterRefused`).

---

## 3. Verification Commands

```bash
cargo fmt --all -- --check
python3 scripts/check_design_docs.py
python3 -m unittest tests/test_ci_workflow_triggers.py tests/test_ci_cargo_fork_workflows.py tests/test_paired_raft_backup_contracts.py tests.test_workspace_remote_namespace.WorkspaceRemoteNamespaceContractTests
cargo clippy --locked --no-default-features --lib --test paired_raft_backup_restore -- -D warnings
RUSTFLAGS="-D warnings" cargo test --locked --no-default-features --lib maintenance::paired_raft_backup
RUSTFLAGS="-D warnings" cargo test --locked --no-default-features --test paired_raft_backup_restore
ROOTYARD_TEST_DATABASE_URL="postgres://postgres:password@localhost:5432/rootyard_test" RUSTFLAGS="-D warnings" cargo test --locked --no-default-features --test paired_raft_backup_restore -- --ignored --test-threads=1
python3 scripts/eval_paired_raft_backup.py --pack-counts 4,8 --formats sha1,sha256
```
