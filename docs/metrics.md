# Private operational metrics

Metrics are disabled by default. Set `ROOTYARD_METRICS_BIND=127.0.0.1:9108`
to enable a separate plaintext Prometheus listener, then scrape
`http://127.0.0.1:9108/metrics`. IPv6 `::1` is also supported. Wildcard,
LAN and public addresses are rejected at startup. The application listener
is unchanged and does not expose this metrics endpoint. No authentication is
provided on the metrics listener: keep it loopback-only and do not publish or
reverse-proxy its port. Local processes able to connect can see aggregate counts.

Responses use `text/plain; version=0.0.4; charset=utf-8` and `Cache-Control:
no-store`. Names and label values are fixed in code. There are no account,
repository, ref, token, filesystem-path, error-message or consumer-provided
labels. Database strings are never interpolated into exposition.

| Metric | Type | Meaning |
| --- | --- | --- |
| `rootyard_error_log_dropped_total` | counter | Accepted safe error records lost to queue/startup/write failure; excludes rate limiting and queued records at exit |
| `rootyard_postgres_up` | gauge | 1 only when the complete authoritative SQL snapshot succeeds |
| `rootyard_git_capacity` | gauge | Configured native Git concurrency limit |
| `rootyard_git_in_flight` | gauge | Occupied Git slots, including provisioning and process cleanup |
| `rootyard_db_pool_max_size` | gauge | Configured maximum PostgreSQL pool connections |
| `rootyard_db_pool_size` | gauge | Tracked established pool objects, excluding creation in progress |
| `rootyard_db_pool_available` | gauge | Approximate available objects derived from current pool users |
| `rootyard_db_pool_busy` | gauge | Derived occupied-object estimate: `size - available` |
| `rootyard_db_pool_waiting` | gauge | Approximate excess users; may include connection creation |
| `rootyard_git_transfers_total{outcome="success\|failure"}` | counter | Completed Git HTTP transfers by transport outcome |
| `rootyard_git_transfer_bytes_total{direction="received\|sent"}` | counter | Observed HTTP body bytes by direction |
| `rootyard_repositories{state="provisioning\|ready\|recovering"}` | gauge | Durable repository metadata counts |
| `rootyard_operations_unresolved` | gauge | Unknown operations with no corresponding explicit resolution |
| `rootyard_event_deliveries{state="pending\|leased"}` | gauge | Durable outstanding deliveries, summed across fixed consumers |
| `rootyard_event_delivery_oldest_age_seconds` | gauge | Age since event creation of oldest undelivered event |
| `rootyard_provisioning_backlog` | gauge | All provisioning rows, including delayed retries |
| `rootyard_provisioning_due` | gauge | Provisioning rows whose retry time has arrived |
| `rootyard_provisioning_oldest_age_seconds` | gauge | Age of oldest provisioning row |
| `rootyard_browser_web_sessions` | gauge | Stored browser session rows, including revoked and already expired rows |
| `rootyard_browser_tokens` | gauge | Stored browser child tokens, including revoked and already expired rows; API tokens are excluded |
| `rootyard_expired_browser_session_oldest_age_seconds` | gauge | Database-clock age of oldest expired browser session; an empty set or only unexpired rows report 0 |
| `rootyard_expired_browser_token_oldest_age_seconds` | gauge | Database-clock age of oldest expired browser token; an empty set or only unexpired rows report 0 |
| `rootyard_session_gc_cycles_total` | counter | GC cycles whose session and token passes both committed |
| `rootyard_session_gc_session_rows_deleted_total` | counter | Expired browser session rows whose own short transaction committed as deleted |
| `rootyard_session_gc_tokens_deleted_total` | counter | Expired browser tokens whose own short transaction committed as deleted after reference probes |
| `rootyard_session_gc_failures_total` | counter | Failed GC cycles; rows committed by an earlier pass remain counted |
| `rootyard_workspace_capture_oldest_age_seconds` | gauge | Database-clock age of the oldest verified capture/API-baseline timestamp among this host's ready, lease-valid workspaces; unverified rows are excluded |
| `rootyard_workspace_capture_never_sampled` | gauge | Ready, lease-valid workspaces on this host with no `workspace_capture_state` row |
| `rootyard_workspace_lease_expired` | gauge | Ready workspaces on this host whose lease is not in the future; not necessarily a fault |
| `rootyard_storage_maintenance_jobs{backend,kind,state}` | gauge | Durable maintenance jobs per fixed backend/kind; state is one of `queued`, `due_queued`, `retry_delayed`, `running`, `expired_running_lease`, `failed` |
| `rootyard_storage_maintenance_oldest_queued_age_seconds{backend,kind}` | gauge | Database-clock age since creation of the oldest queued job, retry delays included; empty set reports 0 |
| `rootyard_storage_maintenance_repos{backend,state}` | gauge | Ready cluster-wide eligible repositories per fixed scheduled-scan state: `missing_scan`, `due_scan`, `stale_generation` |
| `rootyard_storage_maintenance_oldest_overdue_scan_age_seconds{backend}` | gauge | Seconds past the scheduler scan due time for the oldest overdue repository; 0 when nothing is overdue |

The `|` notation in this table enumerates distinct label values; it is not a
literal label value. A healthy scrape always exports all 91 time series,
including zero-valued backend/kind/state combinations. Delivery age includes leased entries (including
expired leases) and delayed retries. Counts represent delivery rows, so one
event assigned to two consumers contributes two outstanding deliveries.
A resolved unknown operation remains an unknown historical fact; its explicit
resolution removes it from the unresolved gauge without rewriting history.

All four GC counters are process-local and label-free. Each GC pass records its
own committed rows once, immediately after that pass commits, so a cycle whose
session pass committed and whose token pass then failed increments the failure
counter while keeping the committed session-row count. `serve` and `worker`
each report only their own loop's counters.

The five `rootyard_db_pool_*` gauges read Deadpool 0.13.1 status before the
scrape acquires its own SQL snapshot connection. They are approximate and can
be internally inconsistent under concurrent load. `size` counts tracked
established pool objects, excluding creation in progress; it is not a live
socket probe. `available` and `waiting` are derived from pool users, and
`waiting` can include connection creation. `busy = size - available` is a
derived observation. A scrape that later fails to acquire a connection still
exports the process-local status it observed.

PostgreSQL is the source of truth. Each scrape opens one read-only
`REPEATABLE READ` transaction, so every statement in that scrape observes the
same MVCC snapshot without holding a lock or blocking writers. A four-second
server-side statement timeout bounds each query; pool acquisition and the whole
snapshot have a combined five-second timeout. On
any database/schema/query failure or timeout, the endpoint returns HTTP 503,
exports `rootyard_postgres_up 0` plus the process-local pool gauges, transfer
counters and four GC counters, and omits every database-derived gauge,
including all four browser-session gauges. The process-local metrics remain
exported because they do not assert database health. The endpoint never
substitutes an empty/healthy backlog or serves a stale cached snapshot. Alert on both
Prometheus scrape failure and PostgreSQL health; standard Prometheus marks a
503 scrape unsuccessful rather than ingesting its body.

Counters reset on process restart and saturate at `u64::MAX`. They measure
Git subprocess HTTP activity, not successful Git ref mutations, durable
receipts, or remote consumer acknowledgements. Failures include transport,
subprocess, deadline, size-limit and receipt-publication failures. Rejections
before a native Git process starts (such as authentication or capacity checks)
are not transfers. Client disconnects and rejected transfers
may have observed partial bytes. Bytes handed to the HTTP stream are not proof
that a client received them. Git protocol-level rejection can occur inside an
otherwise successful HTTP transfer. Use durable receipts and operation evidence
for correctness decisions, not these counters. Semaphore occupancy and pool
occupancy are point-in-time readings and are not transactionally synchronized
with SQL.

## Worker, capture and repair metrics

The workspace gauges are **host-scoped**: they use this process's
`state.storage.volume_id` as `workspaces.host_id` and the same predicate as the
capture loop (`state='ready' AND lease_until > clock_timestamp()`). A host-scoped
series is exported once per process, so two replicas serving the same volume
UUID export identical label sets with no replica label. Do not `sum` them: use
`max`/`min`/`avg` by the existing labels, or scrape one exporter per volume.
The recommended deployment is one metrics exporter per volume. Capture does
not have a fixed scan interval: `capture::reconcile_one` and the workspace
create/API baseline path both upsert `scanned_at`, even when file content is
unchanged. `rootyard_workspace_capture_oldest_age_seconds` therefore measures
the oldest recently verified capture or baseline, not a pure scheduled-scan
period and not `workspaces.updated_at`. A workspace with no
`workspace_capture_state` row contributes to
`rootyard_workspace_capture_never_sampled` only, never to the lag gauge:
creation normally writes the baseline immediately. A ready workspace whose lease
already passed is counted only by `rootyard_workspace_lease_expired`; lease
expiry can be a normal handoff or a finished workspace and is not by itself a
capture failure.

The maintenance gauges are **cluster-wide**: every ready repository the scheduler
predicate would consider, including Pando repositories with a stable, serving
authority state. The scheduler additionally filters by local shard primary; that
routing is not reproduced, so these are not "this node's" repositories. Every
API/worker instance that serves the metrics listener exports the same
cluster-wide values, and there is no instance label, so summing them
multiplies the real count. Use `max by (backend, kind)` / `max by (backend)`
(or run a single exporter). The same rule applies to the other cluster-wide
repository/operation gauges above. Only
non-GC kinds are fixed in code: `gitfs_stage_cleanup`, `gitfs_repack`,
`gitfs_cache_hydrate`, `gitfs_cache_evict`, `pando_repack`,
`pando_cache_hydrate`, `pando_cache_evict`. The GC admission kinds
(`*_unreachable_mark`, `*_tombstone_delete`) are excluded and tracked by the GC
issue. `pando_cache_hydrate` work is a repair backlog, not proof of remote
outage: it can be queued for locally incomplete packs.

`queued` and `running` are totals; `due_queued`/`retry_delayed` split `queued`
on `not_before`, and `expired_running_lease` splits `running` on `lease_until`.
`failed` is terminal, not retryable: `jobs::finish` re-queues a failed attempt
while `attempt < max_attempts`, so a `failed` row has exhausted its attempt
budget (or its lease expired at the last attempt). Failed rows are retained
terminal failure **history**; the gauge is not an unresolved-fault count and not
a retryable backlog, so do not keep an alert firing merely because it is
greater than zero indefinitely. No job history is deleted to produce these
gauges. `running` counts every `running` row, including one whose lease already
expired; `expired_running_lease` is the subset with `lease_until` not in the
future. `stale_generation` means a
scan was recorded for a different repository storage generation; it does not
change scheduler behaviour. `missing_scan` and `due_scan` use the scheduler's
own time predicate; `oldest_overdue` reports how far past that due time the
oldest such repository is.

## PromQL and triage

All samples are aggregate counts or ages; a failed snapshot removes every
SQL-derived series, so alert on the scrape itself as well.

```promql
# Capture verification is older than 16 minutes on one host.
max by () (rootyard_workspace_capture_oldest_age_seconds) > 960

# Workspaces that never recorded any baseline: investigate creation/API paths,
# not background-scan throughput.
rootyard_workspace_capture_never_sampled > 0

# Queued repair work that is due and not merely waiting for a retry delay.
max by (backend, kind) (rootyard_storage_maintenance_jobs{state="due_queued"}) > 0

# Retained terminal-failure history; not an unresolved-fault or retryable
# backlog. Investigate the referenced jobs, and do not alert on it forever just
# because old failed rows remain.
max by (backend, kind) (rootyard_storage_maintenance_jobs{state="failed"}) > 0

# A lease that expired while a worker still owned the job (crash or stall).
max by (backend, kind) (rootyard_storage_maintenance_jobs{state="expired_running_lease"}) > 0

# Repository scans are overdue for one backend, measured past the due time.
rootyard_storage_maintenance_oldest_overdue_scan_age_seconds > 3600

# Recorded scans for an older storage generation (informational; a scan will
# refresh it, and the scheduler behaviour is unchanged).
max by (backend) (rootyard_storage_maintenance_repos{state="stale_generation"}) > 0

# The scrape itself failed: every SQL gauge above disappears.
absent(rootyard_postgres_up) or rootyard_postgres_up == 0
```

Do not alert uniformly on `missing_scan`: a repository whose maintenance scan
was never recorded may be newly created, and the scheduler run is the recovery
path. Do not alert uniformly on leases either: ready-but-expired workspace
leases can be legitimate handoffs or finished sessions. Alert on sustained
capture age, on due backlog growth and expired running leases, and on
`rootyard_postgres_up == 0` / scrape failure. Treat terminal-failure history as
an investigation input, not a permanent fault or retryable-backlog alert.

## Tests

`cargo test metrics::tests` checks loopback binding, fixed labels/numeric format,
failed-snapshot omission, preservation of process-local pool gauges on failure
and saturating counters. With a dedicated PostgreSQL test database and a built
binary:

```
ROOTYARD_TEST_DATABASE_URL=postgresql://... python3 tests/metrics.py --binary target/debug/rootyard --report metrics-report.json
```

The harness owns and removes only its randomly named schema and temporary
storage. It seeds explicit synthetic metadata to verify aggregation and briefly
renames its own delivery table to verify fail-closed exposition. This is not a
PostgreSQL outage, production load, or monitoring-system integration test.

`tests/session_gc_metrics.py` exercises the GC counters end to end with the real
binary, a one-second GC interval and this listener. It seeds an expired browser
session/token, installs a temporary `BEFORE DELETE` trigger on `tokens` that
raises SQLSTATE `23503` only for `browser` rows so the session pass commits and
the token pass fails, then checks that `rootyard_session_gc_failures_total` and
`rootyard_session_gc_session_rows_deleted_total` grow, that
`rootyard_session_gc_tokens_deleted_total` does not, and that the session row is
gone while the token row remains. After dropping the trigger it waits for a
committed token pass and the real deletion, then renames `event_deliveries` to
force HTTP 503 and checks that every SQL-derived gauge is omitted while all four
GC counters remain. That script has not been executed against a built binary as
part of this change; native acceptance is pending.

`tests/worker_metrics.py` covers the worker/capture/repair series with real
HTTP-created repositories and workspace baselines plus controlled SQL fixtures
(job states, a past `scanned_at`, a workspace with no capture row, an expired
lease, scheduled-scan metadata and a serving Pando repository). It asserts exact
values, non-negative ages, fixed labels only, and a renamed-table 503 that omits
every SQL gauge while retaining process-local series. Its seeded rows are
metadata only; the scheduler is disabled and no maintenance job executes. The
`running` expectations count every running row, so the expired-lease fixture
appears in both `running` and `expired_running_lease`. Those job and scan rows
are metadata fixtures: they do not prove that a maintenance job executed or that
a repository scan ran. With `ROOTYARD_TEST_WORKSPACE_FUSE=1` an extra case lets
the real background capture loop refresh `scanned_at` after a filesystem scan
and checks that the exported lag recovers; it is skipped without a FUSE mount.
This harness has not been executed against a rebuilt binary in this change, and
a binary from an earlier branch does not contain these series.

```
ROOTYARD_TEST_DATABASE_URL=postgresql://... python3 tests/worker_metrics.py --binary target/debug/rootyard --report worker-metrics-report.json
```

`tests/worker_metrics_plan.py` is a SQL-only owned-PostgreSQL planner drill for
the schema135 partial covering index. It installs the real migration DDL in a
disposable schema, seeds 100,000 retained `succeeded` rows plus six counted jobs,
runs `ANALYZE`, and checks the default planner (no `enable_seqscan` or other
override) with `EXPLAIN (FORMAT JSON, ANALYZE, BUFFERS)` of the exact `JOBS_SQL`.
The expected plan is an `Index Only Scan` on `storage_maintenance_metrics` with
no sequential scan of `storage_maintenance_jobs`; the query also must return one
row per fixed kind without counting successful history. This is a planner drill,
not production load, latency, job-execution or deployment evidence. If a future
run does not select the index naturally, report that as pending rather than
claiming an optimization.

```
ROOTYARD_TEST_DATABASE_URL=postgresql://... python3 tests/worker_metrics_plan.py --report worker-metrics-plan-report.json
```

`tests/pool_metrics.py` runs the actual service on an owned loopback metrics
port with a fresh schema. It holds a PostgreSQL row lock on its repository
while 32 legitimate API reads contend for the 16-connection pool, then verifies
positive `busy`/`waiting` gauges and full capacity recovery after unlock.

```
ROOTYARD_TEST_DATABASE_URL=postgresql://... python3 tests/pool_metrics.py --binary target/debug/rootyard --report pool-metrics-report.json
```
