# Coordinated PG Cutpoint + Raft Index + Blob Closure Paired Backup & New-Incarnation Restore (`#153`)

This document specifies the paired backup and clean-room new-incarnation restore engine implemented under [`src/maintenance/paired_raft_backup.rs`](../src/maintenance/paired_raft_backup.rs) for Blob-only Pando (`PostgreSQL 17 schema 151 / format 30 + live 3-voter mTLS raft-node + OpenDAL BlobStore + stock Git`).

Classification tags used below:
- **CurrentCodeFact**: schema-151 / format-30 backup & catalog contracts, triggers, and Raft runtime in `origin/main` ([`src/backup/catalog.rs`](../src/backup/catalog.rs), [`migrations/144_ref_store_core_roots_decisions.sql`](../migrations/144_ref_store_core_roots_decisions.sql), [`migrations/145_ref_store_serving.sql`](../migrations/145_ref_store_serving.sql), [`migrations/149_ref_cas_event_projection.sql`](../migrations/149_ref_cas_event_projection.sql), [`migrations/151_repository_lifecycle.sql`](../migrations/151_repository_lifecycle.sql), [`crates/refcas-log/src/bin/raft-node.rs`](../crates/refcas-log/src/bin/raft-node.rs)).
- **EnforcedRestoreProtocol**: live 3-voter mTLS Raft quorum + `EnsureReadIndex` backend ([`mtls_raft.rs`](../src/maintenance/paired_raft_backup/mtls_raft.rs), [`mtls_wire.rs`](../src/maintenance/paired_raft_backup/mtls_wire.rs)), durable PostgreSQL + Raft `freeze`/`thaw` fence covering `repo_access`, holds, Ref-CAS writes, and deleters ([`durable_freeze_gate.rs`](../src/maintenance/paired_raft_backup/durable_freeze_gate.rs), [`durable_guarded_ops.rs`](../src/maintenance/paired_raft_backup/durable_guarded_ops.rs)), standard `schema 151` / `format 30` (`pg_dump`/`pg_restore`) paired backup & clean-room new-incarnation installation + boot ([`format30_paired.rs`](../src/maintenance/paired_raft_backup/format30_paired.rs), [`format30_boot.rs`](../src/maintenance/paired_raft_backup/format30_boot.rs)), and separated quorum vs local WAL proofs ([`quorum_wal.rs`](../src/maintenance/paired_raft_backup/quorum_wal.rs), [`raft_barrier.rs`](../src/maintenance/paired_raft_backup/raft_barrier.rs), [`peer_groups.rs`](../src/maintenance/paired_raft_backup/peer_groups.rs)).
- **MeasuredEvalBaseline**: reproducible SHA-1 & SHA-256 stock-Git archive/restore/tamper timings and closure byte counts from [`scripts/eval_paired_raft_backup.py`](../scripts/eval_paired_raft_backup.py).

---

## 1. Production 3-Voter mTLS Quorum, Durable `repo_access` Freeze/Thaw & `format 30` Cutpoint (`EnforcedRestoreProtocol`)

1. **Authenticated Live 3-Voter mTLS Raft Quorum (`MtlsLiveRaftBackend`)**:
   - [`MtlsLiveRaftBackend`](../src/maintenance/paired_raft_backup/mtls_raft.rs) connects over TLS 1.3 mutual-TLS (`rustls::ClientConnection`, verifying CA + `raft-node-{id}.refcas.internal` SANs and binding each voter's X.509 leaf SHA-256 into `group_membership_digest` and [`VoterWalAck`](../src/maintenance/paired_raft_backup/raft_barrier.rs)).
   - Commits execute real `openraft` majority `ClientWrite` + `EnsureReadIndex` + `TriggerSnapshot`, minting [`QuorumCommitReceipt`](../src/maintenance/paired_raft_backup/raft_barrier.rs) across `> N/2` authenticated live voters while independently verifying `local_node_id` replica catch-up ([`LocalWalApplyReceipt`](../src/maintenance/paired_raft_backup/raft_barrier.rs)).
2. **Durable PostgreSQL + Raft `freeze`/`thaw` Covering `repo_access`, Holds, Ref-CAS Writes & Deleters**:
   - [`enter_durable_pg_raft_freeze`](../src/maintenance/paired_raft_backup/durable_freeze_gate.rs) persists `ALTER DATABASE ... SET rootyard.paired_backup_freeze`, `pando_storage_authorities.remote_delete_fenced = true`, bumped `ref_store_decision_scopes` versions across `repo_access`, `repo_lifecycle`, and `authority`, and `DurableRaftFreezeRecord::Frozen` across active + peer 3-voter mTLS Raft clusters (surviving connection drops and `raft-node` restarts).
   - Guarded mutators ([`upsert_repo_access_collaborator_guarded`](../src/maintenance/paired_raft_backup/durable_guarded_ops.rs), [`propose_raft_hold_guarded`](../src/maintenance/paired_raft_backup/durable_guarded_ops.rs), [`propose_raft_ref_write_guarded`](../src/maintenance/paired_raft_backup/durable_guarded_ops.rs), [`execute_deleter_guarded`](../src/maintenance/paired_raft_backup/durable_guarded_ops.rs)) deterministically reject concurrent writes while frozen and resume only after [`thaw_durable_pg_raft_freeze`](../src/maintenance/paired_raft_backup/durable_freeze_gate.rs) verifies [`SealedArchiveReceipt`](../src/maintenance/paired_raft_backup/raft_barrier.rs) and the `format 30` archive.
3. **Standard `schema 151` / `format 30` Full PG + Blob + Multi-Group Raft Archive**:
   - [`create_format30_paired_raft_backup`](../src/maintenance/paired_raft_backup/format30_paired.rs) delegates the PostgreSQL (`pg_dump --format=custom --schema=public --snapshot`) and OpenDAL Blob closure archive to [`crate::backup::create`](../src/backup/snapshot.rs) (`format == 30`, `schema_versions == 1..=151`), binding `metadata.dump`, `blob/...`, `PgCutpointProof`, and active + peer [`PeerRaftCutpointProof`](../src/maintenance/paired_raft_backup/peer_groups.rs)s into [`Format30PairedManifest`](../src/maintenance/paired_raft_backup/format30_paired.rs).

---

## 2. Clean-Room `format 30` Restore & New-Incarnation Installation + Boot (`EnforcedRestoreProtocol`)

1. **Full `schema 151` / `format 30` Restore**: [`restore_and_boot_format30_new_incarnation`](../src/maintenance/paired_raft_backup/format30_boot.rs) verifies outer + inner `COMPLETE` seals via [`verify_format30_paired_archive`](../src/maintenance/paired_raft_backup/format30_paired.rs) and [`crate::backup::check`](../src/backup/restore.rs), then runs [`crate::backup::restore`](../src/backup/restore.rs) (`pg_restore` verified against `151_restored_catalog.json` + `OfflineRestorePermit` Blob rebuild).
2. **Actual Installation & Boot of the New Incarnation**:
   - Rotates `cluster_authority.incarnation` (`new_cluster_incarnation`) and `pando_storage_authorities` (`new_storage_authority_id`, bumped `generation`, `restore_generation >= new_deleter_epoch`, bumped `authority_epoch`), revokes all pre-restore `public.tokens`, cancels `OPEN` `ref_store_publication_decisions`, and advances `ref_store_decision_scopes` (`repo_access`, `repo_lifecycle`, `authority`) to `new_authz_floor`.
   - Boots fresh 3-voter mTLS `raft-node` clusters (active + peer groups) with the restored gates/refs/holds, `NewIncarnationAuthority`, and `new_authz_floor`, aligning `public.ref_cas_projection_cursors` (`verify_pg_restored_cursors`) and enforcing post-restore `repo_access`, Smart-HTTP Blob reads/pushes, and Ref-CAS quorum writes.

---

## 3. Verification Commands

```bash
cargo fmt --all -- --check
python3 scripts/check_design_docs.py
python3 -m unittest tests/test_ci_workflow_triggers.py tests/test_ci_cargo_fork_workflows.py tests/test_paired_raft_backup_contracts.py tests.test_workspace_remote_namespace.WorkspaceRemoteNamespaceContractTests
cargo build --locked --manifest-path crates/refcas-log/Cargo.toml --bin raft-node
cargo clippy --locked --no-default-features --lib --test paired_raft_backup_restore -- -D warnings
RUSTFLAGS="-D warnings" cargo test --locked --no-default-features --lib maintenance::paired_raft_backup
RUSTFLAGS="-D warnings" cargo test --locked --no-default-features --test paired_raft_backup_restore
ROOTYARD_TEST_DATABASE_URL="postgres://postgres:password@127.0.0.1:5432/rootyard_test" RUSTFLAGS="-D warnings" cargo test --locked --no-default-features --test paired_raft_backup_restore -- --ignored --test-threads=1
python3 scripts/eval_paired_raft_backup.py --pack-counts 4,8 --formats sha1,sha256
```
