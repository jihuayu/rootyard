# Coordinated PG Cutpoint + Raft Index + Blob Closure Paired Backup & New-Incarnation Restore (`#153`)

This document specifies the paired backup and clean-room new-incarnation restore engine implemented under [`src/maintenance/paired_raft_backup.rs`](../src/maintenance/paired_raft_backup.rs) for Blob-only Pando (`PostgreSQL 17 + RefCasStateMachine + OpenDAL BlobStore + stock Git`).

Classification tags used below:
- **CurrentCodeFact**: schema triggers, tables, and Raft state-machine commands enforced in `origin/main` ([`migrations/145_ref_store_serving.sql`](../migrations/145_ref_store_serving.sql), [`migrations/148_pando_pitr_authority_fence.sql`](../migrations/148_pando_pitr_authority_fence.sql), [`migrations/149_ref_cas_event_projection.sql`](../migrations/149_ref_cas_event_projection.sql), [`src/ref_store/core/state_machine.rs`](../src/ref_store/core/state_machine.rs)).
- **EnforcedRestoreProtocol**: paired freeze/drain/seal and clean-room incarnation restore checks implemented in [`freeze_drain.rs`](../src/maintenance/paired_raft_backup/freeze_drain.rs), [`pg_cutpoint.rs`](../src/maintenance/paired_raft_backup/pg_cutpoint.rs), [`backup.rs`](../src/maintenance/paired_raft_backup/backup.rs), [`restore.rs`](../src/maintenance/paired_raft_backup/restore.rs), and [`git_verify.rs`](../src/maintenance/paired_raft_backup/git_verify.rs).
- **MeasuredEvalBaseline**: reproducible SHA-1 & SHA-256 stock-Git archive/restore/tamper timings and closure byte counts from [`scripts/eval_paired_raft_backup.py`](../scripts/eval_paired_raft_backup.py).

---

## 1. Coordinated Paired Cutpoint & Tri-Party Write Freeze (`EnforcedRestoreProtocol`)

1. **Three-Party Write Freeze (Consensus Preserved)**: [`TriPartyBackupCoordinator`](../src/maintenance/paired_raft_backup/freeze_drain.rs) freezes `app_paused`, `worker_paused`, and `deleter_fenced` (both in coordinator state and in PostgreSQL via [`freeze_pg_deleter`](../src/maintenance/paired_raft_backup/pg_cutpoint.rs) updating `pando_storage_authorities.remote_delete_fenced = true`) **without** stopping Raft consensus replication or leader elections (`consensus_replication_active = true`, `leader_election_active = true`).
2. **Unknown Operation Drain & Backup Hold Registration Before `CloseAuthScope`**:
   - Any unsettled in-flight write operations must either settle before cutpoint or be deterministically cancelled via `RefCasCommand::Cancel` (creating replay-safe cancel tombstones); unfreezing refuses (`IncompleteCut`) until durable backup holds are registered.
   - Because `CreateSnapshotPin(Backup)`, `AcquireHoldBatch("ref_publication")`, and `RegisterRoot("backup", "snapshot")` require `gate.lifecycle == ScopeLifecycle::Open` (`CurrentCodeFact`), the coordinator registers all backup pins, holds, and retention roots **first**, then applies `RefCasCommand::CloseAuthScope(Closed)` on `("repo_lifecycle", repository_id)` and `("authority", authority_id)` and rejects non-empty `open_decision_ids` / `pending_operation_ids` (`CloseScopeBarrierReceipt`).
3. **PG 17 Repeatable-Read <-> Raft Reconciliation**: [`capture_pg_cutpoint_in_tx`](../src/maintenance/paired_raft_backup/pg_cutpoint.rs) runs inside a `READ ONLY REPEATABLE READ` PG 17 transaction, verifying `remote_delete_fenced = true`, zero `'OPEN'` `ref_store_publication_decisions`, zero `'unknown'` `git_operations`, zero undelivered `event_deliveries`, zero active `ref_cas_projection_jobs`, exact `(group_id, history_incarnation, applied_event_seq, applied_log_index, applied_log_term)` equality between `ref_cas_projection_cursors` and the Raft `RefCasSnapshot`, and exact `ref_store_core_refs` / gate realm equality.
4. **Verified OpenDAL Blob Closure Seal**: [`create_paired_backup`](../src/maintenance/paired_raft_backup/backup.rs) verifies every `(repository_id, pack_id)` carries a paired `.pack` + `.idx` artifact, streams & SHA-256-verifies each object from `BlobStore` (`verify` + `get_to_file`), binds `backend_identity`, stages inside an atomic `.partial` workspace (cleaned on error), and seals `manifest.json` + SHA-256 `COMPLETE`.

---

## 2. Clean-Room New-Incarnation Restore & Fail-Closed Fencing (`EnforcedRestoreProtocol`)

1. **Pre-Exposure Verification**: [`verify_backup_archive`](../src/maintenance/paired_raft_backup/restore.rs) validates `COMPLETE`, `#[serde(deny_unknown_fields)]`, `paired_cut_digest`, frozen write barrier, `PgCutpointProof`, `RaftCutpointProof`, `CloseScopeBarrierReceipt`s, backup holds, exact PG-vs-Raft cursor alignment, `backend_identity`, and full SHA-256 + length on every `.pack`/`.idx` member **before** exposing state.
2. **Fresh Incarnation & Authority Rotation**: [`restore_new_incarnation`](../src/maintenance/paired_raft_backup/restore.rs) mints fresh `new_cluster_incarnation`, `new_storage_authority_id`, `new_history_incarnation`, and strictly bumped `new_storage_generation`, `new_authority_epoch`, `new_group_epoch`, `new_authz_floor`, and `new_deleter_epoch`; uploads paired blobs into `target_store` via `upload_pack_pair` under the new authority coordinate; runs stock-Git `git index-pack --strict`, `git verify-pack -v`, `git update-ref --stdin`, `git fsck --full --strict`, and `git clone --no-hardlinks` (`verify_bare_repo_from_blobs`) for both `SHA-1` and `SHA-256`; and initializes a fresh `RefCasStateMachine` with backup holds bound.
3. **Clean-Room PG 17 Installation**: [`restore_new_incarnation_with_pg`](../src/maintenance/paired_raft_backup/restore.rs) installs the rotated `cluster_authority`, `pando_storage_authorities`, `repositories` (`provisioning` -> `ready`), `ref_store_core_gates`, `ref_store_core_protocol_repos`, `ref_store_serving_repositories` (`pending` -> `ready`), `ref_store_core_refs`, `'backup_snapshot'` `pando_retention_roots`, and `ref_cas_projection_cursors` while fencing `cluster_transport_nonces`, sessions, and stale job leases.
4. **Fail-Closed Stale Credential Rejection**: [`IncarnationAdmissionGuard`](../src/maintenance/paired_raft_backup/restore.rs) and [`verify_pg_live_incarnation`](../src/maintenance/paired_raft_backup/pg_cutpoint.rs) reject pre-restore `WriterGrantTicket` (`StaleIncarnation` / `StaleGrantRefused`), pre-backup `DecisionExecutionTicket` (`StaleDecisionRefused`), pre-restore `DeleterLeaseTicket` (`StaleDeleterRefused`), and cross-tenant/repo/backend targets (`TenantOrRepoMismatch`, `BackendIdentityMismatch`).

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
