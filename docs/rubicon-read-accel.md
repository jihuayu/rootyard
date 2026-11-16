# Rubicon Rebuildable Blob Read-Acceleration Sidecars (`#165`)

This document describes Rootyard's optional, non-authoritative Git read-acceleration sidecar layer (`MIDX`, multi-pack `.bitmap`, and `commit-graph`) under [`src/blob_store/read_accel.rs`](../src/blob_store/read_accel.rs).

## 1. Non-Authoritative & Default-Disabled Contract

- **`ENABLE_BY_DEFAULT = false`**: `ReadAccelConfig::default().enabled` is `false`. Read replicas materialize authoritative `.pack` / `.idx` closures without fetching sidecars unless an explicit opt-in configuration enables them.
- **No authoritative state in sidecars**: Durable repository truth lives solely in `RefStore` (refs, `history_id`, `membership_generation`) and immutable `.pack` / `.idx` Blob objects (`#163` / `#164`). Any sidecar artifact in Blob or local scratch caches may be truncated, corrupted, evicted, or discarded without affecting correctness or losing objects.
- **Strict identity & generation binding (`ReadAccelManifest`)**: Every sidecar bundle binds immutable metadata via [`manifest.rs`](../src/blob_store/read_accel/manifest.rs):
  - `(tenant_id, repo_id, history_id)`
  - `object_format` (`sha1` or `sha256`)
  - `membership_generation` (`>= 1`)
  - `sorted_pack_digests` (strictly sorted `(pack_stem, pack_sha256, pack_length, idx_sha256, idx_length, pack_locator, idx_locator)`)
  - Per-sidecar `ReadAccelArtifact` entries (`Midx`, `Bitmap`, `CommitGraph`), exact `relative_path`, read-only `BlobLocator`, plaintext SHA-256, byte length, and optional `EnvelopeMetadata`.
  - Every `Deserialize` struct enforces `#[serde(deny_unknown_fields)]`.

## 2. Fail-Closed Fallback, Quarantine & Pack Retention Binding

1. **Authoritative pack materialization first ([`reader.rs`](../src/blob_store/read_accel/reader.rs))**:
   - Read-replica materialization always creates a bounded disposable `TempViewLease` via `DisposableViewRoot` and populates authoritative `.pack` / `.idx` files first.
2. **Pre-download binding gate**:
   - Before fetching any `MIDX`, `.bitmap`, or `commit-graph` Blob object, the reader validates the fetched `ReadAccelManifest` against `(tenant_id, repo_id, history_id, object_format, expected_membership_generation, sorted_pack_digests)`. Any mismatch short-circuits to `ReadAccelSidecarStatus::FallbackToAuthoritativePackOnly(...)` with zero sidecar artifact GETs.
3. **Download, Git verification & sidecar quarantine**:
   - Selected sidecars are downloaded to private staging files, checked against expected SHA-256 and byte length, moved into `objects/pack/` and `objects/info/`, and verified via stock `git multi-pack-index verify`, bitmap header/`rev-list --use-bitmap-index`, and `git commit-graph verify`.
   - Any missing Blob (`404`), digest/length mismatch, truncation, or Git verification failure triggers `scrub_sidecars_in_repo(...)` to remove every placed or partial sidecar file and records a typed `ReadAccelFallbackReason` alongside `quarantined_sidecar_paths`, leaving a clean pack-only bare repository for stock Git.
4. **Retention pinning & compaction rebuild ([`builder.rs`](../src/blob_store/read_accel/builder.rs))**:
   - Active materialized views hold a `PackRetentionGuard` in `PackRetentionRegistry` over all referenced `.pack` and `.idx` locator paths so background compaction cannot retire those packs until active readers release their leases.
   - `build_and_upload_sidecars(...)` reconstructs `multi-pack-index`, `multi-pack-index-<oid>.bitmap`, and `commit-graph` cleanly in an isolated scratch bare repository populated exclusively from remaining authoritative packs, enabling seamless sidecar rebuilds after compaction increments `membership_generation`.

## 3. Explicit Scope Boundaries & Non-Claims

- **Distinct from `#163` / `#164`**: Sidecars never replace or eliminate full authoritative `.pack` / `.idx` Blob materialization; downstream runtime serving (`#144`) and compaction scheduling (`#162`) remain separate integration work.
- **Distinct from `#179`**: `MIDX`, `.bitmap`, and `commit-graph` do **not** eliminate cold full-pack downloads from Blob; shallow/partial/chunked pack range caching belongs to `#179`.

## 4. Benchmark Methodology & Baseline Decision

[`scripts/eval_blob_read_accel.py`](../scripts/eval_blob_read_accel.py) isolates maintenance build cost, Blob GET count/bytes, cold pack materialization vs sidecar apply/verify overhead, and warm Git query latency (`rev-list --count`, `rev-list --objects`, `rev-list --topo-order -n 100`, `merge-base`) across `small`, `medium`, and `history` multi-pack fixtures in both `sha1` and `sha256`.

Baseline measurement on local Windows host (`git version 2.45.1.windows.1`, loopback local disk + Git CLI only, non-network):

| Profile | Format | Objects | Auth Packs (Bytes / GETs) | Sidecar Bytes (Overhead % / GETs) | Build Wall (ms) | Pack Mat (ms) | Sidecar Apply+Verify (ms) | Cold Dis / En (ms) | Cold Speedup | Warm Speedup | Parity |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| `small` | `sha1` | 147 | 14,995 B / 4 | 11,230 B (74.89% / 4) | 451.5 | 391.2 | 188.8 | 752.0 / 913.6 | 0.823x | 0.975x | PASS |
| `small` | `sha256` | 147 | 18,824 B / 4 | 13,724 B (72.91% / 4) | 469.6 | 345.7 | 225.3 | 696.7 / 987.3 | 0.706x | 0.922x | PASS |
| `medium` | `sha1` | 963 | 84,284 B / 4 | 52,782 B (62.62% / 4) | 522.8 | 569.0 | 319.2 | 965.2 / 1,396.7 | 0.691x | 0.895x | PASS |
| `medium` | `sha256` | 963 | 108,773 B / 4 | 67,365 B (61.93% / 4) | 524.1 | 658.0 | 273.4 | 1,106.3 / 1,299.3 | 0.851x | 1.105x | PASS |
| `history` | `sha1` | 1,443 | 128,750 B / 4 | 78,277 B (60.80% / 4) | 431.0 | 551.9 | 238.4 | 951.2 / 1,228.2 | 0.774x | 0.950x | PASS |
| `history` | `sha256` | 1,443 | 165,554 B / 4 | 101,531 B (61.33% / 4) | 499.1 | 625.9 | 282.4 | 1,090.8 / 1,506.0 | 0.724x | 0.912x | PASS |

- **Default policy decision (`ENABLE_BY_DEFAULT = false`)**: On 147-to-1,443-object multi-pack repositories, generating, fetching (+4 Blob GETs), and verifying sidecars adds `60.8%–74.9%` byte overhead and `188–319 ms` of materialization latency without beating cold pack-only reads (`0.691x–0.851x`). Therefore sidecars remain **off by default** and should only be enabled per workload where warm traversal/bitmap wins on large histories clearly exceed build and Blob GET cost.

## 5. Verification Commands

```bash
cargo fmt --all -- --check
python3 scripts/check_design_docs.py
python3 -m unittest tests/test_ci_workflow_triggers.py tests/test_ci_cargo_fork_workflows.py tests/test_blob_read_accel_contracts.py
cargo clippy --locked --no-default-features --lib --test blob_read_accel -- -D warnings
cargo test --locked --no-default-features --lib blob_store::read_accel
cargo test --locked --no-default-features --test blob_read_accel
python3 scripts/eval_blob_read_accel.py --profiles small,medium,history --formats sha1,sha256
```
