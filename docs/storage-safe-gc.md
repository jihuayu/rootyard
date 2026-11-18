# Blob Compaction & Default-Off Safe Destructive GC (`Refs #122`)

This module ([`safe_gc.rs`](../src/storage_lifecycle/safe_gc.rs)) delivers safe physical deletion fencing, unified retention-root reconciliation, `#184` pack-cover `GcEligible` gating, live reader quiescence, monotonic anti-ABA physical key management, and two-phase read-back Blob compaction wired into Rootyard's real storage maintenance scheduler/worker for Issue `#122`.

## Invariants & Safety Model

1. **Default-Off Destructive GC (`SAFE_GC_DESTRUCTIVE_ENABLED_BY_DEFAULT = false`)**:
   - [`GcMode::DisabledByDefault`](../src/storage_lifecycle/safe_gc/model.rs) and `ROOTYARD_BLOB_SAFE_GC_DESTRUCTIVE=false` reject physical deletion by default, while [`BlobStore::delete`](../src/blob_store/readback.rs) stays `DeleteDisabled`.
   - Arming requires a sealed [`SafeGcArmReceipt`](../src/storage_lifecycle/safe_gc/model.rs) with `operator_opt_in = true`, non-TTL/non-cache origin, matching live `incarnation_id`/`incarnation_epoch`, and explicit lane prerequisites:
     - `AuthorityLane::SingleNodePg`: live PostgreSQL tx sequence, `repositories.gc_epoch` fence, and exclusive reader barrier epoch.
     - `AuthorityLane::DistributedRefCas`: verified Ref-CAS quorum/commit index, `#151` global hold bridge, and `#153` remote backup root (never async PG projection alone).
2. **Authoritative `DeletionProof`, `#184` `GcEligible` Bridge & Live Reader Quiescence**:
   - [`build_and_verify_deletion_proof`](../src/storage_lifecycle/safe_gc/proof.rs) and [`store_verify.rs`](../src/storage_lifecycle/safe_gc/store_verify.rs) bind `incarnation`, exact `membership_generation` + `membership_digest`, live Git refs, all 6 retention producers (`pull_request`, `ci_pin`, `workspace`, `namespace`, `lfs`, `backup`), global holds, in-flight decisions, paired PG/Ref-CAS cursors, verified [`GroupClosureReceipt`](../src/storage_lifecycle/safe_gc/model.rs) chains, and both `.pack`/`.idx` candidate keys.
   - [`retention_bridge.rs`](../src/storage_lifecycle/safe_gc/retention_bridge.rs) evaluates `#184` [`RetentionClassificationIndex`](../src/ref_store/core/ref_version/pack_cover/retention_class.rs) requiring `PackRetentionState::GcEligible` while ignoring TTL/cache/projection hints; [`quiescence.rs`](../src/storage_lifecycle/safe_gc/quiescence.rs) and `ref_store_core_serving_reads` enforce live reader drain watermarks without constant flags.
3. **Two-Phase Read-Back Compaction & Remote Staging Cleanup**:
   - [`execute_two_phase_compaction`](../src/storage_lifecycle/safe_gc/compaction.rs) keeps `Arc<TempViewLease>` alive across `BlobStore::get_to_file_with_owner`, excludes pack-pinned active packs, verifies self-contained `git verify-pack -v` + repository-wide `git fsck --full --strict` (`SHA-1` & `SHA-256`) before CAS publish, and cleans abandoned staging uploads via [`reclaim_abandoned_compaction_staging`](../src/storage_lifecycle/safe_gc/executor.rs).
4. **Continuous Provider Fence, Terminal Outcomes & Production Maintenance Entry**:
   - [`OpenDalS3GcProvider`](../src/storage_lifecycle/safe_gc/provider_delete.rs) executes real OpenDAL S3 wire `PUT`/`HEAD`/`DELETE` under [`ActiveDeleteFence`](../src/storage_lifecycle/safe_gc/domain.rs), distinguishing `ConfirmedDeleted`, `AlreadyAbsent`, and `OutcomeUnknown`, and [`pg_maintenance.rs`](../src/storage_lifecycle/safe_gc/pg_maintenance.rs) integrates with [`scheduler.rs`](../src/storage_lifecycle/scheduler.rs), [`worker.rs`](../src/storage_lifecycle/worker.rs), and [`fence.rs`](../src/storage_lifecycle/fence.rs).

## Verification

- Unit + Concurrency Suites: `cargo test --locked --no-default-features --lib storage_lifecycle::safe_gc`
- Real OpenDAL S3 + Stock Git (`SHA-1` & `SHA-256`) Suite: `cargo test --locked --no-default-features --test storage_safe_gc`
- Real PG17 + `storage_lifecycle` Scheduler/Worker + Ref-CAS + OpenDAL S3 Suite: `cargo test --locked --no-default-features --test storage_safe_gc_maintenance`
- Reproducible Benchmark: `python3 scripts/eval_storage_safe_gc.py --profiles small,sustained --formats sha1,sha256 --json-out test-results/storage-safe-gc/eval.json`
- CI Workflow: [`.github/workflows/storage-safe-gc.yml`](../.github/workflows/storage-safe-gc.yml)
