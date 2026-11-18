# Coordinated PG Cutpoint + Raft Index + Blob Closure Paired Backup & New-Incarnation Restore (`#153`)

This document specifies the paired backup and clean-room new-incarnation restore engine implemented under [`src/maintenance/paired_raft_backup.rs`](../src/maintenance/paired_raft_backup.rs) for Blob-only Pando (`PostgreSQL 17 + RefCasStateMachine + OpenDAL BlobStore + stock Git`).

Classification tags used below:
- **CurrentCodeFact**: schema triggers, tables, and Raft state-machine commands enforced in `origin/main` ([`migrations/144_ref_store_core_roots_decisions.sql`](../migrations/144_ref_store_core_roots_decisions.sql), [`migrations/145_ref_store_serving.sql`](../migrations/145_ref_store_serving.sql), [`migrations/148_pando_pitr_authority_fence.sql`](../migrations/148_pando_pitr_authority_fence.sql), [`migrations/149_ref_cas_event_projection.sql`](../migrations/149_ref_cas_event_projection.sql), [`src/ref_store/core/state_machine.rs`](../src/ref_store/core/state_machine.rs)).
- **EnforcedRestoreProtocol**: separated multi-voter `QuorumCommitReceipt` vs `LocalWalApplyReceipt` freeze/thaw barriers, durable peer-group Raft cutpoint proofs (`PeerRaftCutpointProof`), complete hold/root/pin Blob closure binding, and clean-room `authz_floor` + `deleter_epoch` restore checks implemented in [`quorum_wal.rs`](../src/maintenance/paired_raft_backup/quorum_wal.rs), [`raft_barrier.rs`](../src/maintenance/paired_raft_backup/raft_barrier.rs), [`peer_groups.rs`](../src/maintenance/paired_raft_backup/peer_groups.rs), [`closure_bind.rs`](../src/maintenance/paired_raft_backup/closure_bind.rs), [`freeze_drain.rs`](../src/maintenance/paired_raft_backup/freeze_drain.rs), [`pg_cutpoint.rs`](../src/maintenance/paired_raft_backup/pg_cutpoint.rs), [`pg_restore_admission.rs`](../src/maintenance/paired_raft_backup/pg_restore_admission.rs), [`backup.rs`](../src/maintenance/paired_raft_backup/backup.rs), [`restore.rs`](../src/maintenance/paired_raft_backup/restore.rs), and [`git_verify.rs`](../src/maintenance/paired_raft_backup/git_verify.rs).
- **MeasuredEvalBaseline**: reproducible SHA-1 & SHA-256 stock-Git archive/restore/tamper timings and closure byte counts from [`scripts/eval_paired_raft_backup.py`](../scripts/eval_paired_raft_backup.py).

---

## 1. Coordinated Paired Cutpoint & Separated Quorum/Local Raft Freeze/Thaw Barrier (`EnforcedRestoreProtocol`)

1. **Separated `QuorumCommitReceipt` vs `LocalWalApplyReceipt` Barrier (Consensus Preserved)**:
   - [`WalSyncedRaftBackend`](../src/maintenance/paired_raft_backup/quorum_wal.rs) models a `>= 3`-voter Raft group bound to `group_membership_digest` (`compute_group_membership_digest`), persisting per-voter fsynced WALs and advancing the durable `quorum_commit_index` marker **only** after [`QuorumCommitReceipt::verify`](../src/maintenance/paired_raft_backup/raft_barrier.rs) proves strict majority (`voter_acks.len() > voter_ids.len() / 2`) across unique authorized voters. Uncommitted local WAL tail entries (`index > quorum_commit_index`) are never applied on reopen.
   - [`LocalWalApplyReceipt`](../src/maintenance/paired_raft_backup/raft_barrier.rs) independently binds local node WAL fsync + committed state-machine apply. Both [`freeze_drain_and_register`](../src/maintenance/paired_raft_backup/freeze_drain.rs) and [`unfreeze_after_backup`](../src/maintenance/paired_raft_backup/freeze_drain.rs) verify `QuorumCommitReceipt`s, `LocalWalApplyReceipt`s, [`SealedArchiveReceipt`](../src/maintenance/paired_raft_backup/raft_barrier.rs), and reopened durable state.
2. **PG 17 Repeatable-Read <-> Active & Peer Durable Raft Proof Reconciliation**:
   - [`PeerRaftCutpointProof`](../src/maintenance/paired_raft_backup/peer_groups.rs) binds every peer Raft group in `ref_cas_projection_cursors` to its verified `RefCasSnapshot`, `snapshot_checksum`, `state_digest`, and `DurableFreezeBarrierProof` (`extract_peer_expected_cuts`, `verify_archived_peer_groups`, `verify_all_group_cursors`) — never trusting raw caller epoch maps.
3. **Complete Durable Hold/Root/Pin Blob Closure Binding**:
   - [`verify_registration_spec_completeness`](../src/maintenance/paired_raft_backup/closure_bind.rs) and [`verify_blob_closure_against_durable_raft`](../src/maintenance/paired_raft_backup/closure_bind.rs) bind both `.pack` and `.idx` of every pack pair into durable Raft holds, snapshot pins, and active retention roots, failing closed (`BlobClosureIncomplete`) whether a single side or an **entire `(pack, idx)` pair** is omitted.

---

## 2. Clean-Room Multi-Group New-Incarnation Restore & Floor Admission (`EnforcedRestoreProtocol`)

1. **Pre-Exposure Verification**: [`verify_backup_archive`](../src/maintenance/paired_raft_backup/restore.rs) validates `COMPLETE`, `#[serde(deny_unknown_fields)]`, `paired_cut_digest`, active + peer durable Raft snapshots (`verify_archived_peer_groups`), `verify_all_group_cursors`, `verify_blob_closure_against_durable_raft`, `backend_identity`, and full SHA-256 + byte length on every `.pack`/`.idx` member **before** exposing state.
2. **Fresh Incarnation & Multi-Group Raft Restoration**: [`restore_new_incarnation`](../src/maintenance/paired_raft_backup/restore.rs) and [`restore_peer_groups_state`](../src/maintenance/paired_raft_backup/peer_groups.rs) mint fresh `new_cluster_incarnation`, `new_storage_authority_id`, `new_history_incarnation`, and strictly bumped `new_storage_generation`, `new_authority_epoch`, `new_group_epoch`, `new_authz_floor`, and `new_deleter_epoch`; upload paired blobs via `upload_pack_pair`; verify stock-Git (`SHA-1` & `SHA-256`) `verify-pack -v`, cross-pack `index-pack --strict`, `fsck --full --strict`, and `clone --no-hardlinks`; and restore both active and peer Raft groups via 3-voter fsynced WALs.
3. **Clean-Room PG 17 Installation & Restored `authz_epoch` + `deleter_epoch` Floor Admission**:
   - [`install_restored_pg_incarnation`](../src/maintenance/paired_raft_backup/pg_restore_admission.rs) persists `'OPEN'` `ref_store_decision_scopes` rows at `version = new_authz_floor`, persists the `new_deleter_epoch` floor on `pando_storage_authorities`, and writes actual restored `(applied_event_seq, applied_log_index, applied_log_term)` cursors for every active and peer Raft group (`verify_pg_restored_cursors`).
   - [`verify_pg_live_incarnation`](../src/maintenance/paired_raft_backup/pg_restore_admission.rs) enforces the restored `authz_epoch` and `deleter_epoch` floors against `WriterGrantTicket` (`StaleGrantRefused`), `DecisionExecutionTicket` (`StaleDecisionRefused`), and `DeleterLeaseTicket` (`StaleDeleterRefused`).

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
