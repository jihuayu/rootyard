# Rubicon Version-Aware Disposable Compute Replica Cache & Bounded Routing (`#163`)

This document describes Rootyard's two-layer disposable compute replica cache and bounded scheduling router implemented under [`src/cache_wake/replica_cache.rs`](../src/cache_wake/replica_cache.rs) for Issue `#163`.

## 1. Two-Layer Disposable Cache Architecture

Replicas never hold canonical repository authority. All durable state remains in `RefStore` (`history_id`, `authority_epoch`, `gate_revision`, refs) and immutable `.pack` / `.idx` objects in OpenDAL Blob (`#164`), alongside optional rebuildable sidecars (`#165`).

1. **Layer 1 — Immutable Verified Pack Cache ([`pack_cache.rs`](../src/cache_wake/replica_cache/pack_cache.rs))**:
   - Stores verified immutable `.pack` / `.idx` files keyed by `(tenant_id, repo_id, backend_identity, pack_stem, pack_sha256, pack_len, idx_sha256, idx_len)` with read-only `0o444` file modes.
   - Across `v1 -> v2` updates or history rewinds (`history_id` changes), still-valid packs present in the new authoritative snapshot are reused after SHA-256 and byte-length re-verification without re-fetching from OpenDAL Blob.
   - Enforces atomic `max_pack_bytes` / `max_pack_entries` LRU eviction that strictly skips actively pinned packs (`PackCachePin`).
2. **Layer 2 — Version-Aware Read-Only Compute Views ([`catalog.rs`](../src/cache_wake/replica_cache/catalog.rs), [`materializer.rs`](../src/cache_wake/replica_cache/materializer.rs))**:
   - Materialized via `DisposableViewRoot::open(&replica_root.join("views"), ...)` on clean `0o700` sub-directories (never directly on a shared `TempDir::path()`), binding every cache key in [`types.rs`](../src/cache_wake/replica_cache/types.rs) to `(tenant_id, repo_id, history_id, cluster_incarnation, backend_identity, authority_epoch, gate_revision, membership_digest)`.
   - Materialized view files are `0o444` while view directories remain `0o700` so `TempViewLease::drop` can cleanly unlink expired or evicted directories.
   - Any missing or tampered pack/ref in a cached view increments `corrupt_rebuilds`, drops the broken entry, and rebuilds cleanly from Layer 1 or OpenDAL Blob.
3. **Push Scratch Isolation (`PushScratchGuard`)**:
   - Write/push scratch directories are allocated exclusively under `<replica_root>/scratch/` with strict `repo_id` / `tenant_id` binding and RAII cleanup on drop, ensuring mutable refs (`refs/heads/scratch-*`) never leak into shared read-only `views/`.

## 2. Security, Live Authority, `#174` Bounds & Non-Claims

- **Live per-request authorization ([`lease_pin.rs`](../src/cache_wake/replica_cache/lease_pin.rs))**: Cache keys, cached hits, and advisory `ServingCache` entries are **never** permission, version authority, or durable hold proofs. Every `ReplicaCacheNode::serve_view(...)` / `ReplicaScheduler::route_and_serve(...)` call evaluates `LiveAuthorizer::authorize_and_check_version` first, rejects cross-tenant mismatches, and enforces `#174` `SessionLowerBound` monotonicity (`authority_epoch`, `gate_revision`, `history_id`) when provided.
- **Reader Ref-Guard & Durable Pin/Hold Preservation**: `ReplicaViewGuard` binds a view lease to an active reader counter and a `DurablePinHold` (`DurablePinRegistry`) across the full lifetime of `git-upload-pack` / clone / read operations. LRU eviction, explicit `clear_cache()`, or task cancellation **never** deletes an actively held directory or revokes its `DurablePinHold` early; physical cleanup waits until the final guard drops.
- **Advisory Redis / Memory Cache Tolerance ([`scheduler.rs`](../src/cache_wake/replica_cache/scheduler.rs))**: Hot-replica `RouteDirectoryHint` values (`#[serde(deny_unknown_fields)]`) stored under `CacheKind::RouteDirectory` in `ServingCache` (`#163` adapter) are strictly best-effort hints. Stale, missing, corrupted, or disabled hints degrade safely to Rendezvous Hashing (`HRW`) over live cluster members without affecting correctness.

## 3. Single-Flight, Fair Admission & Hot-Kill Failover

- **Bounded Single-Flight ([`singleflight.rs`](../src/cache_wake/replica_cache/singleflight.rs))**: Concurrent cold/update misses on the same `ComputeViewKey` coalesce onto one leader download/materialization while waiters sit in a bounded queue (`max_waiters_per_key`, `max_total_waiters`) and fail fast with `WaiterQueueFull` / `DeadlineExceeded`. Dropping a cancelled waiter/leader immediately releases its slot via RAII guards.
- **Deficit Round-Robin Tenant Fair-Share ([`fair_admission.rs`](../src/cache_wake/replica_cache/fair_admission.rs))**: `TenantFairShareGate` protects compute slots and bounded per-tenant admission queues (`FairAdmissionPermit`) so a bursty noisy tenant hits per-tenant rejection (`FairShareShed`) instead of starving steady tenants.
- **Affinity & Drain / Failover ([`scheduler.rs`](../src/cache_wake/replica_cache/scheduler.rs))**: `ReplicaScheduler` routes warm reads toward the preferred HRW/hinted hot node and automatically marks unhealthy nodes or overloads (`Overloaded` / retryable transport failures) and fails over to a healthy cold node rebuilding independently from OpenDAL Blob (`tests/rubicon_replica_cache.rs`).

## 4. Reproducible Benchmark & Verified Baseline

[`scripts/eval_rubicon_replica_cache.py`](../scripts/eval_rubicon_replica_cache.py) seeds two-epoch multi-pack Git fixtures (`SHA-1` and `SHA-256`) backed by stock `git`, isolates Layer 1 `.pack`/`.idx` cache vs Layer 2 disposable `views/` and isolated `scratch/`, runs independent hot/cold worker subprocesses across two replica directories with `git clone` + `git fsck --full --strict` parity verification, executes a threaded DRR noisy-tenant flood test, and captures OS peak RSS (`K32GetProcessMemoryInfo` on Windows / `resource.getrusage` on POSIX).

Observed baseline on local host (`Windows-11-10.0.26100-SP0`, `Python 3.12.3`, `git version 2.45.1.windows.1`, process peak RSS `27,328,512` B):

| Profile | Format | Cold GETs / B (Mat ms) | Incremental GETs / B (Base Packs Reused) | Warm GETs (P50 / P95 / P99 ms) | Two-Process Failover GETs / B (E2E ms / Cold RSS B) | Push Scratch Residual B | Parity |
|---|---|---:|---:|---:|---:|---:|---|
| `small` | `sha1` | 2 / 4,372 (70.354) | 2 / 2,439 (1) | 0 (45.384 / 48.934 / 51.322) | 4 / 6,811 (598.832 / 21,528,576) | 0 (`view_isolated=true`) | PASS |
| `small` | `sha256` | 2 / 5,261 (78.398) | 2 / 2,841 (1) | 0 (47.510 / 55.128 / 60.098) | 4 / 8,102 (618.026 / 21,504,000) | 0 (`view_isolated=true`) | PASS |
| `medium` | `sha1` | 2 / 10,527 (77.232) | 2 / 4,241 (1) | 0 (52.640 / 64.349 / 70.160) | 4 / 14,768 (596.765 / 21,524,480) | 0 (`view_isolated=true`) | PASS |
| `medium` | `sha256` | 2 / 13,158 (82.129) | 2 / 5,124 (1) | 0 (49.795 / 51.314 / 51.339) | 4 / 18,282 (667.597 / 21,659,648) | 0 (`view_isolated=true`) | PASS |

Concurrent DRR fair admission benchmark (2 compute slots, 24 noisy-tenant burst requests vs 6 steady normal-tenant requests, per-tenant queue cap 6):
- **Normal tenant**: `6` admitted, `0` rejected (`P50 = 13.233 ms`, `P95 = 18.291 ms`).
- **Noisy tenant**: `8` admitted, `16` shed cleanly (`P95 = 21.077 ms`).

## 5. Verification Commands

```bash
cargo fmt --all -- --check
python3 scripts/check_design_docs.py
python3 -m unittest tests/test_ci_workflow_triggers.py tests/test_ci_cargo_fork_workflows.py tests/test_rubicon_replica_cache_contracts.py
cargo clippy --locked --no-default-features --lib --test rubicon_replica_cache -- -D warnings
RUSTFLAGS="-D warnings" cargo test --locked --no-default-features --lib cache_wake::replica_cache
RUSTFLAGS="-D warnings" cargo test --locked --no-default-features --test rubicon_replica_cache
python3 scripts/eval_rubicon_replica_cache.py --profiles small,medium --formats sha1,sha256
```
