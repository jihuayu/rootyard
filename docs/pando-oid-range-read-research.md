# Pando OID Localization & Blob Range-Read Feasibility Study (`#179`)

Status: **Research evaluation & fail-closed harness delivered (`Refs #179`).** No production serving handler, Git wire change, deletion path, or partial-clone/`promisor` protocol is enabled by this study.

## 1. Purpose & Non-Claims

Issue `#179` evaluates whether Rootyard should implement `OID -> (pack, byte_offset, span)` localization via `.idx` / `MIDX` combined with object-store HTTP `Range: bytes=start-end` (`206 Partial Content`) reads to reduce cold download amplification on large repositories **after** pack compaction (`#162`) and version-aware compute-replica caching (`#163`) are in place.

Explicit non-claims:
1. This study does **not** treat raw `Range GET` bytes as valid Git objects; full verification (CRC32, zlib, delta reconstruction, digest identity, and bounded closure checks) is mandatory.
2. This study does **not** introduce a proprietary Git transport protocol, partial clone/`promisor` support, or distributed multi-region serving claims.
3. No production `src/` route or deletion rule is altered; all retention, compaction, backup, and safe-reclaim semantics follow `#122`, `#151`, and `#153`.

## 2. Candidate Architecture & Verification Boundaries

| Layer | Design Contract | Failure / Drift Handling |
| --- | --- | --- |
| **Index Binding** | Stock Git `.idx` v2 (CRC32 + 32/64-bit offsets; SHA-1 `20B` & SHA-256 `32B`) and `MIDX` v1 bound to immutable `(tenant_id, repository_id, history_incarnation, authority_epoch, membership_version)` + verified SHA-256 `ETag`. | Any trailing index checksum mismatch or `409 Conflict` (`history_drift` / `membership_drift`) invalidates the cached index immediately and falls back or fails closed. |
| **Exact Span Calculation** | Sort `.idx` offsets (`[off_i, off_{i+1})` up to `pack_size - hash_len`) so non-delta objects need only **1 `Range GET`** (avoiding speculative fixed-window over-reads). | Out-of-bounds span or `Content-Range` length mismatch fails closed (`truncated_range`). |
| **Delta Resolution** | Recursive intra-pack `OBJ_OFS_DELTA` and cross-pack `OBJ_REF_DELTA` walk bounded at depth `<= 50` with cycle detection. | Missing or corrupted delta base in another pack fails closed (`missing_delta_base`, `pin_evicted`, `corrupt_checksum`). |
| **Mandatory Integrity** | Before returning object bytes: (1) check bearer auth + tenant isolation (`403` even on cache hit), (2) verify `.idx` `CRC32` over packed bytes, (3) verify `zlib` `EOF` and uncompressed size, (4) verify canonical `SHA-1`/`SHA-256` Git digest, and (5) walk commit/tree closure when full closure is required. | Partial bytes or spoofed `.idx` OID->offset mappings are rejected (`object_identity_mismatch`, `incomplete_closure`). |
| **Pin / GC / Backup Fence** | Range sessions hold explicit active retention pins (`#122`/`#151`) scoped to `(history_incarnation, membership_version)` so `#162` compaction or future GC cannot reclaim referenced packs mid-read; `#153` backup restore rotates `history_incarnation`, forcing cache invalidation. | Sweeping an active pin is refused (`#122`/`#151`); after pin release and sweep, late range reads receive `410 Gone` (`pin_evicted`). |

## 3. Observed Benchmark Data (`scripts/pando_range_read_eval.py`)

Measured on `git version 2.45.1.windows.1` using real multi-pack `SHA-1` (`506,962 B` pack, `6,036 B` `.idx`, `107` objects, `107` `MIDX` entries, `8` cross-pack thin `REF_DELTA` blobs) and `SHA-256` (`512,781 B` pack, `7,752 B` `.idx`, `107` objects, `8` cross-pack `REF_DELTA` blobs) repositories with `simulated_rtt_ms = 1.5 ms` over loopback HTTP/1.1 (`range_read` vs `#163`-style `full_pack_cache`):

| Format | Workload | Mode | Full GETs | Range GETs | Bytes Downloaded | Logical Bytes | Amp | P50 ms | P95 ms | CPU s | RSS KiB | Scratch B |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `sha1` | `sparse_cold_single_oid` (8 blobs) | `range_read` | 2 | 14 | 91,918 | 156,585 | 0.59x | 12.00 | 20.61 | 0.062 | 29,308 | 6,036 |
| `sha1` | `sparse_cold_single_oid` (8 blobs) | `full_pack_cache` | 4 | 0 | 512,998 | 156,585 | 3.28x | 6.04 | 103.33 | 0.094 | 30,300 | 512,998 |
| `sha1` | `shallow_tree_slice` (w/ closure) | `range_read` | 2 | 74 | 505,449 | 45,731 | 11.05x | 5.03 | 417.09 | 0.250 | 30,536 | 6,036 |
| `sha1` | `shallow_tree_slice` (w/ closure) | `full_pack_cache` | 4 | 0 | 512,998 | 45,731 | 11.22x | 5.87 | 67.13 | 0.062 | 30,536 | 512,998 |
| `sha1` | `cross_pack_delta_walk` (4 thin blobs) | `range_read` | 2 | 8 | 54,970 | 89,178 | 0.62x | 14.92 | 27.06 | 0.078 | 30,536 | 6,036 |
| `sha1` | `cross_pack_delta_walk` (4 thin blobs) | `full_pack_cache` | 4 | 0 | 512,998 | 89,178 | 5.75x | 6.03 | 82.69 | 0.047 | 30,536 | 512,998 |
| `sha1` | `warm_repeated_lookup` (3x6 reads) | `range_read` | 2 | 12 | 67,554 | 335,811 | 0.20x | 4.47 | 40.25 | 0.047 | 30,536 | 6,036 |
| `sha1` | `warm_repeated_lookup` (3x6 reads) | `full_pack_cache` | 4 | 0 | 512,998 | 335,811 | 1.53x | 5.40 | 42.10 | 0.203 | 30,536 | 512,998 |
| `sha1` | `full_clone_parity` (40 objects) | `range_read` | 2 | 64 | 258,150 | 456,277 | 0.57x | 14.56 | 43.10 | 0.344 | 30,536 | 6,036 |
| `sha1` | `full_clone_parity` (40 objects) | `full_pack_cache` | 4 | 0 | 512,998 | 456,277 | 1.12x | 5.42 | 28.56 | 0.203 | 30,536 | 512,998 |
| `sha256` | `sparse_cold_single_oid` (8 blobs) | `range_read` | 2 | 14 | 93,832 | 156,705 | 0.60x | 22.56 | 44.25 | 0.094 | 31,156 | 7,752 |
| `sha256` | `sparse_cold_single_oid` (8 blobs) | `full_pack_cache` | 4 | 0 | 520,533 | 156,705 | 3.32x | 10.37 | 61.16 | 0.109 | 31,632 | 520,533 |
| `sha256` | `shallow_tree_slice` (w/ closure) | `range_read` | 2 | 74 | 508,049 | 45,966 | 11.05x | 15.48 | 522.43 | 0.391 | 31,788 | 7,752 |
| `sha256` | `shallow_tree_slice` (w/ closure) | `full_pack_cache` | 4 | 0 | 520,533 | 45,966 | 11.32x | 5.50 | 73.29 | 0.078 | 31,788 | 520,533 |
| `sha256` | `cross_pack_delta_walk` (4 thin blobs) | `range_read` | 2 | 8 | 56,734 | 89,178 | 0.64x | 27.63 | 36.15 | 0.047 | 31,788 | 7,752 |
| `sha256` | `cross_pack_delta_walk` (4 thin blobs) | `full_pack_cache` | 4 | 0 | 520,533 | 89,178 | 5.84x | 14.70 | 64.15 | 0.016 | 31,788 | 520,533 |
| `sha256` | `warm_repeated_lookup` (3x6 reads) | `range_read` | 2 | 12 | 69,468 | 336,171 | 0.21x | 10.88 | 28.62 | 0.109 | 31,788 | 7,752 |
| `sha256` | `warm_repeated_lookup` (3x6 reads) | `full_pack_cache` | 4 | 0 | 520,533 | 336,171 | 1.55x | 6.24 | 34.98 | 0.125 | 31,788 | 520,533 |
| `sha256` | `full_clone_parity` (40 objects) | `range_read` | 2 | 57 | 260,645 | 457,553 | 0.57x | 14.93 | 33.27 | 0.266 | 31,788 | 7,752 |
| `sha256` | `full_clone_parity` (40 objects) | `full_pack_cache` | 4 | 0 | 520,533 | 457,553 | 1.14x | 5.84 | 25.86 | 0.203 | 31,788 | 520,533 |

*Adversarial fail-closed suite*: **12/12 SHA-1 & 12/12 SHA-256 vectors passed** (`truncated_range`, `bitflip_206`, `etag_if_match_drift`, `object_identity_mismatch`, `missing_cross_pack_delta_base`, `corrupt_cross_pack_delta_base`, `incomplete_tree_closure`, `cross_tenant_denial`, `revoked_token_warm_cache`, `history_incarnation_drift`, `membership_version_drift`, `unpinned_gc_sweep_read`). Live Garage 2.1 S3 `206` + `If-Match` parity runs inside `.github/workflows/pando-range-read-eval.yml`.

## 4. Provider Compatibility, Complexity, and Fallback

- **Provider Compatibility**: S3 (`Range: bytes=start-end` + `ETag` + `If-Match`, verified against Garage 2.1), Azure Blob (`Range` / `x-ms-range` + `If-Match`), and GCS (`Range` + `ETag` / `ifGenerationMatch`) all support authenticated byte-range reads natively, provided the client validates `206`, `Content-Range`, and exact payload length.
- **Complexity vs `#163`/`#162` Fallback**: Range reading increases `GET` request count (`1` GET per entry + delta depth), adds delta-fanout tail latency (`417–522 ms P95` for tree closure vs `67–73 ms` full pack at `1.5 ms` RTT), and requires per-membership `.idx` caching and pin alignment across `#162` compaction. Fallback is always simple and safe: pull full immutable `.pack`/`.idx` into `#163` local replica cache and serve with stock `git`.

## 5. Activation & Non-Activation Thresholds (`#163` & `#164` Bound)

- **Do NOT Start (`#179` remains parked)**:
  1. Active repository pack closure is `<= 256 MiB`, **or** `#163` compute-replica cache absorbs repeated reads (`warm_repeated_lookup` `P50 = 5.4–6.2 ms`, `0` pack GETs on hit).
  2. Read mix targets `>= 10–15%` of pack objects (Smart HTTP clones, CI checkouts in `#164`) where sequential `O(N_objects)` Range GETs lose on both `GET` API count (`57–74` vs `4`) and `P95` tail latency.
  3. Measured `#164` post-compaction (`#162`) / post-cache (`#163`) baselines do not show cold sparse-read egress or latency bottlenecks.
- **Justified Start Threshold**:
  Start bounded single-object/sparse Range GET prototyping **only if** `#162` + `#163` + `#164` production/baseline telemetry proves **all three**:
  1. Serving pack sets `>= 512 MiB–1 GiB` suffer frequent `#163` cold compute-cache misses,
  2. Significant read volume (`>= 20%` of requests or egress cost) touches `< 2–5%` of repository pack bytes with bounded delta chains (`depth <= 16`), **and**
  3. Full-pack cold downloads consume `> 25%` of egress or breach `#164` cold sparse-read `P95` latency SLOs even with `#163` warm replica routing.

## 6. Verification Commands

```bash
python3 scripts/check_design_docs.py
python3 -m unittest -v tests.test_ci_workflow_triggers tests.test_ci_cargo_fork_workflows tests.test_pando_range_read_eval
python3 scripts/pando_range_read_eval.py --scale full --simulated-rtt-ms 1.5 --output /tmp/pando-179.json
```
