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

> Benchmark results below will be populated strictly from the Linux CI run artifact (`test-results/verifier-budget-bench.json` via `tests/ref_store_verifier_budgets.rs`) against real PostgreSQL + S3 + stock `/usr/bin/git` after push, including exact commit SHA, environment, workload, and any neutral/negative findings.
