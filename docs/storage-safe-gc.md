# Blob Compaction & Default-Off Safe Destructive GC (`Refs #122`)

This module (`src/storage_lifecycle/safe_gc.rs`) delivers safe physical deletion fencing, unified retention-root reconciliation, monotonic anti-ABA physical key management, and two-phase read-back Blob compaction for Issue `#122`.

## Invariants & Safety Model

1. **Default-Off Destructive GC (`SAFE_GC_DESTRUCTIVE_ENABLED_BY_DEFAULT = false`)**:
   - [`GcMode::DisabledByDefault`](../src/storage_lifecycle/safe_gc/model.rs) is the default state and rejects any physical unlink (`SafeGcError::DestructiveGcDisabledByDefault`), while [`BlobStore::delete`](../src/blob_store/readback.rs) stays disabled in the Blob layer.
   - Arming destructive deletion requires a sealed [`SafeGcArmReceipt`](../src/storage_lifecycle/safe_gc/model.rs) with `operator_opt_in = true`, non-TTL/non-cache origin, matching live `incarnation_id`/`incarnation_epoch`, and explicit lane prerequisites:
     - `AuthorityLane::SingleNodePg`: standalone PostgreSQL tx sequence and quiesced local lock.
     - `AuthorityLane::DistributedRefCas`: verified Ref-CAS quorum/commit index, `#151` global hold bridge, and `#153` remote backup root (never async PG projection alone).
2. **Unified `DeletionProof` Reconciliation**:
   - [`build_and_verify_deletion_proof`](../src/storage_lifecycle/safe_gc/proof.rs) binds live Git refs, all 6 retention producers (`pull_request`, `ci_pin`, `workspace`, `namespace`, `lfs`, `backup`), global holds, in-flight decisions, paired PG/Ref-CAS cursors, and quiesced `GroupClosureReceipt` digests into one SHA-256-sealed proof. Any missing, unknown, stale, or lagging source fails closed.
3. **Two-Phase Read-Back Compaction**:
   - [`execute_two_phase_compaction`](../src/storage_lifecycle/safe_gc/compaction.rs) materializes self-contained replacement packs in a `0o700` `DisposableViewRoot`, uploads new immutable anti-ABA keys, reads back and checks SHA-256/length via [`BlobStore`](../src/blob_store/opendal.rs), runs `git verify-pack -v` and `git fsck --full --strict`, and CAS-publishes membership only after full verification. Failures keep prior closures untouched; old packs enter `RetiredPendingProof`.
4. **Anti-ABA Key Non-Reuse & Concurrency Barriers**:
   - [`AntiAbaKeyRegistry`](../src/storage_lifecycle/safe_gc/anti_aba.rs) derives monotonic `(incarnation_epoch, allocation_seq, nonce, sha256)` paths and retains deletion tombstones so identical-content `A -> delete -> A` re-uploads never collide.
   - [`DurableSafeGcAuthority`](../src/storage_lifecycle/safe_gc/store.rs) and [`reconcile_pending_delete_after_restart`](../src/storage_lifecycle/safe_gc/executor.rs) abort on concurrent new refs, holds, release-before-register cursor gaps, stale deleters, or incarnation rotation, and recover partial failures cleanly from disk journals.

## Verification

- Unit + Concurrency Suites: `cargo test --locked --no-default-features --lib storage_lifecycle::safe_gc`
- Real OpenDAL S3 + Stock Git (`SHA-1` & `SHA-256`) Integration Suite: `cargo test --locked --no-default-features --test storage_safe_gc`
- Reproducible Benchmark & Audit: `python3 scripts/eval_storage_safe_gc.py --profiles small,sustained --formats sha1,sha256 --json-out test-results/storage-safe-gc/eval.json`
- CI Workflow: [`.github/workflows/storage-safe-gc.yml`](../.github/workflows/storage-safe-gc.yml)
