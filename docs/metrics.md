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

The `|` notation in this table enumerates distinct label values; it is not a
literal label value. A healthy scrape always exports all 31 time series,
including zero-valued states. Delivery age includes leased entries (including
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

PostgreSQL is the source of truth. Each scrape obtains a single-statement MVCC
snapshot inside a read-only transaction. A four-second server-side statement
timeout bounds the query; pool acquisition and query have a combined five-second
timeout. On
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

`tests/pool_metrics.py` runs the actual service on an owned loopback metrics
port with a fresh schema. It holds a PostgreSQL row lock on its repository
while 32 legitimate API reads contend for the 16-connection pool, then verifies
positive `busy`/`waiting` gauges and full capacity recovery after unlock.

```
ROOTYARD_TEST_DATABASE_URL=postgresql://... python3 tests/pool_metrics.py --binary target/debug/rootyard --report pool-metrics-report.json
```
