# Ref-Store Verifier Resource Budgets & Safe Artifact Handoff (Issue #176)

Architecture, safety guarantees, and measured benchmarks for separating Blob network downloads, temporary disk staging, active read views, native Git verification, and foreground vs. maintenance admission in `src/ref_store/core/pack_commit/verifier/`.

## 1. Separated Budget Model

Process-wide resource budgets (`src/ref_store/core/pack_commit/verifier/budget.rs`) split verification and read materialization into four non-blocking pools acquired strictly in a deadlock-free DAG order:

`StagingReservation` -> `DownloadPermit` (released before Phase 2) -> `ViewPermit` (reads only) -> `NativePermit`

| Pool / Budget | Capacity Constant | Maintenance Sub-Cap (`<= 50%`) | Scope Held |
| :--- | :--- | :--- | :--- |
| Staging Bytes | `VERIFIER_STAGING_BYTES` = `384 MiB` (`64 KiB` units) | `192 MiB` | From Phase 1 download start until temp artifacts are reclaimed |
| Blob Download Slots | `DOWNLOAD_SLOTS` = `4` (`2`-way pair prefetch) | `2` | Phase 1 HTTP/S3 object transfers only; released BEFORE `NativePermit` |
| Active Materialized Views | `VIEW_SLOTS` = `2` | `1` | Live `MaterializedPackRead` session lifetime (`VerificationLease::with_view_budget`) |
| Native Git CPU/Process Slots | `VERIFIER_SLOTS` = `2` | `1` | Phase 2 stock `/usr/bin/git` verification (`verify-pack` / `index-pack` / `rev-list` / `fsck`) |
| Local Disk Headroom Floor | `VERIFIER_DISK_HEADROOM_BYTES` = `16 MiB` | Enforced on all classes | Linux `statvfs` (`f_bavail * f_frsize`) preflight before staging writes |

Every pool share is governed by a unified caller deadline (`min(caller_deadline, now + 30s)`); slow Blob transfers never occupy `VERIFIER_SLOTS`, and saturated maintenance jobs (`verify_maintenance`) cannot exceed 50% of any budget or starve foreground admissions.

## 2. Two-Phase Execution & Duplicate Disk Reclaim

Both `PackVerifier` (`verifier/mod.rs`), `verify_publication_artifacts` (`verifier/publication.rs`), and `NativeReadClosure::prepare` (`verifier/read.rs`) execute two strictly separated phases:

1. **Phase 1 (Blob Transfer)**:
   - Preflights `check_disk_headroom`, reserves `StagingReservation`, and acquires `DownloadPermit` (inside `DOWNLOAD_SLOTS`).
   - Streams pairs concurrently up to `VERIFIER_PAIR_PREFETCH_CONCURRENCY = 2`, sealing downloaded temp files (`0o400`, `nlink == 1`, `uid == geteuid()`, `!is_symlink()`), verifying byte length and SHA-256 against the DB-attested manifest.
   - Immediately releases `DownloadPermit` (`lease.release_download()`) before entering Phase 2.
2. **Phase 2 (Native Git Verification & Reclaim)**:
   - Acquires `NativePermit` (`VERIFIER_SLOTS`), creates an isolated `verify.git` bare repository, runs stock `/usr/bin/git`, and binds closure/pack digests.
   - Immediately unlinks raw `incoming/*.pack` and `incoming/*.idx` files right after each pair is indexed, and on materialized read views removes the temporary `verify.git` directory (`remove_directory_tree`) after `lease.release_native()`, calling `lease.shrink_staging_to(retained_bytes)` to drop steady-state local temp disk usage from ~2x (`incoming/` + `verify.git`) down to ~1x (`packs/` only) while keeping `Retained` `SIGKILL` reaper and `temp_dir` ownership intact.

## 3. Bounded Streaming & Evaluated `FICLONE` Artifact Handoff

- **Bounded streaming readback (`verifier/handoff.rs` -> `read_verified_streamed`)**: Replaces unbounded full-file buffering when reading verified pack/idx artifacts inside `NativeReadClosure::read_artifact` (`verifier/read.rs`). Streams in `64 KiB` chunks (`HANDOFF_CHUNK_BYTES = 65536`), opens descriptors with `O_NOFOLLOW`, asserts regular file mode (`0o400`/`0o444`), `nlink == 1`, `uid == geteuid()`, and `(st_dev, st_ino)` invariance across reads while hashing incrementally with SHA-256 and checking per-chunk deadlines.
- **Evaluated `FICLONE` reflink handoff (`verifier/handoff.rs::test_handoff::handoff_verified_file`)**: Because `pack_snapshot/**` and `retention_root/**` remain untouched under Issue #176 scope boundaries, the Linux `ioctl` `FICLONE` (`0x4004_9409`) + `64 KiB` bounded fallback with target seal (`0o600` -> `0o444`) and post-copy SHA-256 re-verification was built and verified under `#[cfg(test)]` (avoiding unused `--lib` dead-code lints while keeping production read paths strictly verified end-to-end). Bit-flip corruption after copy, writable-mode tamper, symlinks, and `nlink > 1` hardlink aliases fail closed (`handoff_tests.rs`).

## 4. Telemetry (`PackVerifier::budget_metrics_json`)

`verifier/budget_metrics.rs` exports `VerifierMetricsSnapshot` with atomic counters and queue wait totals (`download_*`, `native_*`, `view_*`, `staging_reserved_bytes_current`, `staging_reserved_bytes_peak`, `staging_reclaimed_bytes_total`, `blob_get_requests`, `blob_get_bytes`, `readback_bytes`, `disk_headroom_refusals`, `budget_timeouts`, and `handoff_*`).

## 5. Before vs. After Benchmark Receipt

Measured against real CI PostgreSQL (`ROOTYARD_TEST_DATABASE_URL`, PostgreSQL 17), loopback HTTP S3 via OpenDAL (`loopback_http_s3_via_opendal`), and stock Git (`git version 2.56.1`) on `linux / x86_64` (`ubuntu-22.04`) during `CI / verify` run `43709781296` (`job/132798616334`, artifact `e2e-report` -> `test-results/verifier-budget-bench.json`):

- **PR / Source Commit**: PR `#251` head `5658890f9b81f9cd64c51acc0e30b6810a03035f` (CI pull-request merge `GITHUB_SHA` `c8bb6b1bfa937a1f0865e37f64f36835af8c331c`)
- **Workload**: `3 slow (400ms GET delay, ~192KiB pack) + 4 fast (0ms GET delay, ~128KiB pack) per phase` (`7` ops/phase, `15ms` slow head-start ahead of fast ops in both phases)
- **Methodology**: `before_coupled` wraps `PackVerifier::verify + commit` in an outer `Semaphore(2)` spanning both Blob GET and native Git (mirroring pre-#176 single 2-slot pool coupling); `after_separated` runs uncoupled `DOWNLOAD_SLOTS=4` and `VERIFIER_SLOTS=2` via `tests/ref_store_verifier_budgets.rs` (`verifier_budget_before_vs_after_pg_s3_git_benchmark`).

| Metric | Before (Coupled `Semaphore(2)`) | After (Separated Budgets) | Delta / Ratio |
| :--- | ---: | ---: | :--- |
| Total Wall Time (`7` ops) | `4349.505 ms` | `2283.419 ms` | **`1.905x` faster** (`1.904821x`) |
| Throughput | `1.609 ops/s` | `3.066 ops/s` | `+90.5%` |
| Fast Ops Latency (`n=4`) Min | `2323.584 ms` | `139.598 ms` | `16.64x` lower |
| Fast Ops Latency (`n=4`) P50 | `2600.362 ms` | `248.994 ms` | `10.44x` faster |
| Fast Ops Latency (`n=4`) P95 / P99 / Max | `2735.173 ms` | `262.584 ms` | **`10.42x` faster** (`10.416373x`) |
| Fast Ops Latency (`n=4`) Mean | `2530.136 ms` | `201.999 ms` | `12.53x` faster |
| Slow Ops Latency (`n=3`) P50 / P95 / Mean | `2201.150 / 4349.366 / 2914.644 ms` | `2177.570 / 2283.278 / 2212.480 ms` | Tail `-47.5%` |
| Peak Active Ops (`in-flight`) | `2` | `7` | All `7` ops admitted without coupled head-of-line stall |
| Download / Native Slots In-Flight Peak | `3 / 2` | `4 / 2` | Download pool saturated independently |
| Download Queue Wait Total | `8 us` | `108,475 us` | `+108,467 us` |
| Native Queue Wait Total | `19 us` | `260,390 us` | `+260,371 us` |
| Verifier `blob_get_requests` / S3 `GET`s | `14 / 31` (`1,124,096 B`) | `14 / 31` (`1,124,102 B`) | Equivalent transfer volume (`6 B` pack/UUID framing delta) |
| Staging Reserved Peak | `1,310,720 B` | `2,686,976 B` | `+1,376,256 B` (`4` concurrent downloads vs `2`) |
| Staging Reclaimed Bytes Delta | `1,114,112 B` | `1,114,112 B` | `100%` temp pair staging reclaimed post-index |
| Process `VmHWM` (`/proc/self/status`) | `34,040 KiB` | `34,552 KiB` | `+512 KiB` (`+1.5%`) under `3.5x` peak task concurrency |

### Neutral / Trade-off Observations & Test Coverage

- **Expected queue-wait & staging-peak increase**: `before_coupled` held fast tasks behind the external `Semaphore(2)` before touching `BudgetRegistry`, keeping internal pool wait near zero (`8 us` / `19 us`) while pushing end-to-end fast latency to `2.74 s`. Under `after_separated`, all `7` concurrent operations enter `DOWNLOAD_SLOTS=4` and `VERIFIER_SLOTS=2` directly, cleanly shifting queuing from coupled head-of-line stalls into bounded download (`108.5 ms` cumulative wait) and native CPU (`260.4 ms` cumulative wait) pools and raising peak transient staging (`1.31 MiB` -> `2.69 MiB`) while reclaiming all `1,114,112 B` immediately after indexing.
- **Additional live integration tests (`tests/ref_store_verifier_budgets.rs`)**: Both `isolated-lab` (`43709781287`, `21.48s`) and `CI / verify` (`43709781296`, `17.61s`) passed `3 passed; 0 failed; 1 ignored` (`slow_blob_downloads_do_not_starve_fast_native_git_slots`, `maintenance_saturation_preserves_foreground_pg_commit_and_reclaim`, and `verifier_budget_before_vs_after_pg_s3_git_benchmark`), while `real_garage_s3_and_pg_verifier_budgets_smoke` remains `#[ignore = "requires real PG + Garage S3 + stock Git"]` for dedicated Garage clusters.

