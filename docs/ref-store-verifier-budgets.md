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

Measured in two fresh OS child processes (`ROOTYARD_VB_PHASE=before|after`, `process_isolation: fresh_child_process_per_cohort_via_current_exe`) against shared CI PostgreSQL (`ROOTYARD_TEST_DATABASE_URL`, PostgreSQL 17), loopback HTTP S3 via OpenDAL (`loopback_http_s3_via_opendal`), and stock Git (`git version 2.56.1`) on `linux / x86_64` during `CI / verify` run `43721396986` (`job/132833958616`, Step 16 `cargo test --locked --all-targets --features pando-lab` **`5 passed; 0 failed; 1 ignored` in `55.63s`**, artifact `e2e-report` `14165141497` -> `test-results/verifier-budget-bench.json`; note run `43721396986` later exited `139` in Step 31 from an unrelated CPython 3.12 `faulthandler` segfault, while `isolated-lab` run `43721396964` / `job/132833958576` passed `5 passed; 0 failed; 1 ignored` in `58.20s`):

- **PR / Source Commit**: PR `#251` head `7f987d46a1ad58086b8989b1e8810baf66b783ec` (CI merge `source_commit`: `cd062754d7038c53573dfe05814850d87f7d947b`)
- **Child Binary (`environment.binary_path`)**: `/home/runner/.cargo/targets/rootyard-ec2a3e00/debug/build/rootyard/0ce2649f55afce04/out/ref_store_verifier_budgets-19562c04fb46a672`
- **Baseline & Measurement Kinds**: `baseline_kind = simulated_coupled_semaphore_2_on_current_binary`; `rss_measurement = per_child_process_proc_self_status_VmHWM_kib`; `peak_measurement = fresh_child_process_budget_registry_peak_plus_5ms_cohort_gauge_sampler`
- **Workload**: `3 slow (400ms GET delay via 5105de1a- tag, ~192KiB pack) + 4 fast (0ms GET delay, ~128KiB pack) per isolated cohort` (`7` ops/cohort, `15ms` slow head-start ahead of fast ops in both phases)
- **Methodology & Limitations**: `before_coupled` wraps `PackVerifier::verify + commit` in a simulated external `Semaphore(2)` across Blob GET + native Git inside its own child process; `after_separated` runs uncoupled `DOWNLOAD_SLOTS=4` and `VERIFIER_SLOTS=2` in a separate child process via `tests/ref_store_verifier_budgets.rs` (`verifier_budget_before_vs_after_pg_s3_git_benchmark`). Explicit limitations: `before_coupled` is a simulated `Semaphore(2)` harness on the current binary rather than a checkout of pre-#176 `main`, and blob storage uses in-process `loopback_http_s3_via_opendal` with synthetic `400ms` GET delay on slow-tagged objects rather than a networked Garage S3 cluster.

| Metric | Before (Coupled `Semaphore(2)`) | After (Separated Budgets) | Delta / Ratio |
| :--- | ---: | ---: | :--- |
| Total Wall Time (`7` ops) | `4632.331 ms` | `2464.400 ms` | **`1.880x` faster** (`wall_speedup: 1.879700`) |
| Throughput | `1.511 ops/s` | `2.840 ops/s` | `+88.0%` (`+87.97%`) |
| Fast Ops Latency (`n=4`) Min | `2425.978 ms` | `174.219 ms` | `13.925x` lower |
| Fast Ops Latency (`n=4`) P50 | `2758.635 ms` | `286.316 ms` | `9.635x` faster |
| Fast Ops Latency (`n=4`) P95 / P99 / Max | `2923.696 ms` | `313.941 ms` | **`9.313x` faster** (`fast_p95_ratio: 9.312884`) |
| Fast Ops Latency (`n=4`) Mean | `2674.849 ms` | `245.482 ms` | `10.896x` faster |
| Slow Ops Latency (`n=3`) P50 / P95 / Mean | `2277.708 / 4632.144 / 3058.361 ms` | `2376.955 / 2464.216 / 2401.883 ms` | Tail `-46.8%` |
| All Ops Latency (`n=7`) P50 / P95 / Mean | `2591.088 / 4632.144 / 2839.211 ms` | `313.941 / 2464.216 / 1169.654 ms` | Tail `-46.8%` |
| Peak Active Ops (`in-flight`) | `2` | `7` | All `7` ops admitted without coupled head-of-line stall |
| Download / Native Peak (`BudgetRegistry` & `5ms` sampler) | `2 / 2` (`sampled: 2 / 2`) | `4 / 2` (`sampled: 4 / 2`) | Download pool saturated independently |
| Download Queue Wait Total | `8 us` | `202,509 us` | `+202,501 us` (`download_wait_delta_micros`) |
| Native Queue Wait Total | `18 us` | `207,218 us` | `+207,200 us` (`native_wait_delta_micros`) |
| View Queue Wait Total | `0 us` | `0 us` | Uncontended |
| Verifier `blob_get_requests` / Parent `s3_get_requests` | `14` (`1,124,099 B`) / `62` (`2,248,198 B`) | `14` (`1,124,104 B`) / `62` (`2,248,208 B`) | Equivalent transfer volume (`+5 B` / `+10 B` pack/UUID framing delta) |
| Staging Reserved Peak (`BudgetRegistry` / `5ms` sampler) | `917,504 B` (`sampled: 917,504 B`) | `2,686,976 B` (`sampled: 2,686,976 B`) | `+1,769,472 B` (`4` concurrent downloads vs `2`) |
| Staging Reclaimed Bytes Delta | `1,114,112 B` | `1,114,112 B` | `100%` (`reclaimed_bytes_after: 1,114,112 B`) |
| Per-Child `VmHWM` (`/proc/self/status`) | `26,192 KiB` | `26,192 KiB` | `0 KiB` delta under `3.5x` peak task concurrency |

### Neutral / Trade-off Observations & Test Coverage

- **Expected queue-wait & staging-peak increase**: `before_coupled` held fast tasks behind the external `Semaphore(2)` before touching `BudgetRegistry`, keeping internal pool wait near zero (`8 us` / `18 us`) while pushing end-to-end fast latency to `2.92 s`. Under `after_separated`, all `7` concurrent operations enter `DOWNLOAD_SLOTS=4` and `VERIFIER_SLOTS=2` directly, cleanly shifting queuing from coupled head-of-line stalls into bounded download (`202.5 ms` cumulative wait) and native CPU (`207.2 ms` cumulative wait) pools and raising peak transient staging (`917,504 B` -> `2,686,976 B`) while reclaiming `1,114,112 B` immediately after indexing with zero per-child `VmHWM` increase (`26,192 KiB` in both isolated cohorts).
- **Live integration & isolation regression coverage (`tests/ref_store_verifier_budgets.rs`)**: Both `CI / verify` (`43721396986`, Step 16 `55.63s`) and `isolated-lab` (`43721396964`, `58.20s`) ran `6` tests and passed **`5 passed; 0 failed; 1 ignored`** (`slow_blob_downloads_do_not_starve_fast_native_git_slots`, `maintenance_saturation_preserves_foreground_pg_commit_and_reclaim`, `timed_out_isolated_worker_cleans_up_owned_pg_schema`, `failed_reap_preserves_owned_schema_with_cleanup_not_complete_error`, and `verifier_budget_before_vs_after_pg_s3_git_benchmark`), while `real_garage_s3_and_pg_verifier_budgets_smoke` remains `#[ignore = "requires real PG + Garage S3 + stock Git"]` for dedicated Garage clusters.

