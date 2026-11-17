# Rubicon No-Delete Sharded Blob Compaction (`#162`)

This document describes Rootyard's independent, no-delete Rubicon Blob compaction subsystem under [`src/storage_lifecycle/rubicon_compaction.rs`](../src/storage_lifecycle/rubicon_compaction.rs).

## 1. Architecture & Non-Deletion Contract

- **`DELETE_OLD_PACKS_BY_DEFAULT = false` (`delete_disabled = true`)**: Compaction retires old packs **only from active serving membership** (`serving_packs -> retained_old_packs`). Physical Blob deletion remains strictly forbidden until `#122` / `#151` / `#153` GC gates are delivered; any attempt to enable `delete_old_packs` returns `CompactionError::DeleteForbidden`, and `BlobStore::delete` returns `BlobError::DeleteDisabled`.
- **Separated physical byte accounting (`CompactionByteAccounting`)**:
  - `serving_pack_bytes`: active serving `.pack` + `.idx` footprint after compaction.
  - `newly_written_bytes`: cumulative newly uploaded compacted `.pack` + `.idx` bytes.
  - `retained_old_pack_bytes`: permanently retained retired input `.pack` + `.idx` bytes.
  - `total_physical_blob_bytes`: `serving_pack_bytes + retained_old_pack_bytes` (`physical_bytes_deleted == 0`, `claims_physical_savings == false`).
- **Causal pack & cover planner boundaries (`#180` / `#183` / `#184`)**: Replacing serving membership keeps physical `.pack` / `.idx` inputs intact for active `PackRetentionGuard` readers and older causal/pin snapshots, separating **physical presence**, **serving membership**, and **safe GC**. Replacing serving membership does **not** claim to implement `#184`'s hierarchical cover planner.

## 2. Pack-Hash Sharding, `open -> sealed` Segments & Tiered Merging

- **Deterministic sharding ([`sharding.rs`](../src/storage_lifecycle/rubicon_compaction/sharding.rs))**: Each pack is deterministically mapped to `0..shard_count` via `SHA-256("rubicon-compaction-shard-v1\0" || pack_sha256)`. Multiple maintenance workers handle disjoint `worker_shards(worker_idx, worker_total)` concurrently.
- **Log-structured `open -> sealed` segments ([`segment.rs`](../src/storage_lifecycle/rubicon_compaction/segment.rs))**:
  - Newly pushed packs append to the shard's current `Open` segment without blocking on background merges.
  - A segment seals (`Open -> Sealed`) when `max_segment_packs`, `max_segment_bytes`, or `max_segment_age_ms` triggers.
  - `plan_tiered_merge` selects `Sealed` segments **one tier at a time** (`L0Ingest -> L1Merged -> L2Base`) within `max_packs_per_batch` and `max_rewrite_bytes_per_run`, preventing small `L0` pushes from triggering full-repository `L2Base` repacks.

## 3. Isolated Budgets, Equivalence Proof & Fenced CAS Publication

- **Dedicated maintenance bulkhead ([`budget.rs`](../src/storage_lifecycle/rubicon_compaction/budget.rs))**: `CompactionResourceBudget` bounds `max_concurrent_jobs`, `max_concurrent_git_processes`, `max_scratch_bytes`, `max_rewrite_bytes_per_run`, and `max_packs_per_batch` independently from online serving Git concurrency (`#176` / `#177`).
- **Default Git compatibility**: Candidate packs are produced with stock `git pack-objects -q` (default Git delta/zlib parameters — no `--aggressive` or outer compression, leaving `#178` tuning unassumed).
- **Pre-publish equivalence & readback proof ([`executor.rs`](../src/storage_lifecycle/rubicon_compaction/executor.rs))**:
  - Verifies candidate `.pack` / `.idx` in isolation for self-contained delta bases (`verify_pack_self_contained`).
  - Verifies exact sorted `cat-file --batch-check --batch-all-objects` OID inventory, all `retention_roots` (`rev-list --objects`), `git fsck --full --strict`, and stock `git clone --no-local --bare` + `fsck` across `SHA-1` & `SHA-256`.
  - Streams full remote readback (`BlobStore::verify` + `BlobStore::get_to_file`) before CAS publication.
- **Durable lease/fence & CAS retry ([`lease.rs`](../src/storage_lifecycle/rubicon_compaction/lease.rs), [`store.rs`](../src/storage_lifecycle/rubicon_compaction/store.rs))**: Publishes atomically under `(tenant_id, repo_id, history_id, authority_epoch, expected_membership_generation, expected_pack_set_digest, expected_refs_digest, expected_retention_roots_digest)` and `(lease_id, fence_epoch)`. Concurrent pushes trigger safe CAS retry/recompute (`execute_shard_compaction_with_retry`); dropped ACKs and crashes replay idempotently by `op_id` with zero double retirement or closure loss.

## 4. Verification & Benchmark

```bash
cargo fmt --all -- --check
python3 scripts/check_design_docs.py
python3 -m unittest tests/test_ci_workflow_triggers.py tests/test_ci_cargo_fork_workflows.py tests/test_rubicon_compaction_contracts.py
cargo clippy --locked --no-default-features --lib --test rubicon_compaction -- -D warnings
cargo test --locked --no-default-features --lib storage_lifecycle::rubicon_compaction
cargo test --locked --no-default-features --test rubicon_compaction
python3 scripts/eval_rubicon_compaction.py --profiles small,sustained --formats sha1,sha256 --workers 1,2
```
