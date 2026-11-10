# Worker backlog / workspace capture lag / lease / repair metrics (#80)

Base: effe2e9 (schema134/format10). Existing: GC 8 metrics + error log counter = 31 health series.

## Scope (allowed)
- `src/metrics.rs` and/or new module (each < 700 lines): fixed-label gauges
  - `workspace_capture_oldest_age_seconds` (host-scoped, state.storage.volume_id, ready + lease_until > db clock)
  - host ready-but-lease-expired count
  - `storage_maintenance_jobs` queued/running/due_queued/not_before/retry_delayed/expired_running_lease/oldest_queued_age/terminal_failed
  - `storage_maintenance_repo_state` missing_scan/due_timestamp/oldest_overdue/stale_generation
- `src/background.rs` only if needed for capture age semantics (no worker semantic change).
- `src/main.rs` metrics router: pass validated Policy + volume UUID (no env re-read).
- `tests/metrics.py` exact series count update; new `tests/worker_metrics.py` native PG test.
- `docs/metrics.md` PromQL + triage.

## Non-goals / constraints
- No migration/schema/backup/auth/worker semantic change; no GC-kind or unreachable/tombstone kinds.
- Single MVCC snapshot per SQL batch; existing 4s statement timeout + 5s HTTP; on SQL failure omit all SQL gauges, keep GC/process-pool/error-log, 503 postgres_up 0.
- Fixed label sets only; missing data still emits 0 series.
- No cargo build/test/network/push; verification = py_compile + scoped rustfmt (skip_children) + diff review.

## Steps
1. Inspect metrics.rs / background.rs / main.rs / storage jobs enums / migration 091 / tests.
2. Implement queries + gauges.
3. Wire router.
4. Update tests/metrics.py + add tests/worker_metrics.py.
5. Docs.
6. py_compile, rustfmt check (if available without cargo), diff check, scoped commit.

## Result / verification (this worker)

- Added `src/metrics_workers.rs` (fixed backend/kind/state series, one
  repeatable-read scrape transaction): 60 new series, 31 -> 91 total.
- `src/metrics.rs`: router takes validated `metrics_workers::Config`;
  `SET TRANSACTION ISOLATION LEVEL REPEATABLE READ` + 4s statement timeout;
  any query failure still omits every SQL gauge and returns 503 with
  `rootyard_postgres_up 0`, keeping GC/pool/error-log series.
- `src/main.rs`: passes `state.storage.volume_id` and the already parsed
  `maintenance_policy.scan_period_seconds`; no env re-read.
- `tests/metrics.py`: exact series count 91, fixed label allow-list, new
  zero-series presence and 503 omission checks. `py_compile` passes.
- `tests/worker_metrics.py`: new native harness (real HTTP repo/workspace
  baseline + SQL job/capture/scan fixtures, renamed-table 503, optional
  FUSE capture-refresh case). `py_compile` passes. NOT executed.
- `docs/metrics.md`: metric table, host-scoped vs cluster-wide scope,
  capture-age semantics, retry/terminal-failed semantics, PromQL and triage.

Not verifiable in this worker: no `cargo` build/`cargo test`, no `rustfmt`
binary, no PostgreSQL client or `ROOTYARD_TEST_DATABASE_URL`. The native suite
and the Rust unit tests were therefore not run; the current built binary lacks
these series. Typed errors, DB-timeout and remote-outage integration are
separate branches and are not claimed here.
