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
| `rootyard_postgres_up` | gauge | 1 only when the complete authoritative SQL snapshot succeeds |
| `rootyard_git_capacity` | gauge | Configured native Git concurrency limit |
| `rootyard_git_in_flight` | gauge | Occupied Git slots, including provisioning and process cleanup |
| `rootyard_db_pool_max_size` | gauge | Configured maximum PostgreSQL pool connections |
| `rootyard_db_pool_size` | gauge | Physical PostgreSQL pool connections currently established |
| `rootyard_db_pool_available` | gauge | Idle pool connections immediately available for checkout |
| `rootyard_db_pool_busy` | gauge | Checked-out pool connections, defined as `size - available` |
| `rootyard_db_pool_waiting` | gauge | Callers waiting for a pool connection when the scrape started |
| `rootyard_git_transfers_total{outcome="success\|failure"}` | counter | Completed Git HTTP transfers by transport outcome |
| `rootyard_git_transfer_bytes_total{direction="received\|sent"}` | counter | Observed HTTP body bytes by direction |
| `rootyard_repositories{state="provisioning\|ready\|recovering"}` | gauge | Durable repository metadata counts |
| `rootyard_operations_unresolved` | gauge | Unknown operations with no corresponding explicit resolution |
| `rootyard_event_deliveries{state="pending\|leased"}` | gauge | Durable outstanding deliveries, summed across fixed consumers |
| `rootyard_event_delivery_oldest_age_seconds` | gauge | Age since event creation of oldest undelivered event |
| `rootyard_provisioning_backlog` | gauge | All provisioning rows, including delayed retries |
| `rootyard_provisioning_due` | gauge | Provisioning rows whose retry time has arrived |
| `rootyard_provisioning_oldest_age_seconds` | gauge | Age of oldest provisioning row |

The `|` notation in this table enumerates distinct label values; it is not a
literal label value. A healthy scrape always exports all 22 time series,
including zero-valued states. Delivery age includes leased entries (including
expired leases) and delayed retries. Counts represent delivery rows, so one
event assigned to two consumers contributes two outstanding deliveries.
A resolved unknown operation remains an unknown historical fact; its explicit
resolution removes it from the unresolved gauge without rewriting history.

The five `rootyard_db_pool_*` gauges are a process-local reading taken at the
instant each scrape begins, before that scrape acquires its own snapshot
connection. `size` counts physical pooled connections currently established,
`available` counts idle ones, `busy = size - available` counts connections
checked out by callers, and `waiting` counts callers already queued for a
connection. `size` can be below `max_size` when connections have not yet been
opened on demand. A scrape that later fails because all pooled connections are
busy still reports the occupancy it observed.

PostgreSQL is the source of truth. Each scrape obtains a single-statement MVCC
snapshot inside a read-only transaction. A four-second server-side statement
timeout bounds the query; pool acquisition and query have a combined five-second
timeout. On
any database/schema/query failure or timeout, the endpoint returns HTTP 503,
exports `rootyard_postgres_up 0` plus process-local metrics, and omits every
database-derived gauge. The process-local pool gauges above remain exported
because they do not assert database health. The endpoint never substitutes an
empty/healthy backlog or serves a stale cached snapshot. Alert on both
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

`tests/pool_metrics.py` runs the actual service on an owned loopback metrics
port with a fresh schema. It holds a PostgreSQL row lock on its repository
while 32 legitimate API reads contend for the 16-connection pool, then verifies
positive `busy`/`waiting` gauges and full capacity recovery after unlock.

```
ROOTYARD_TEST_DATABASE_URL=postgresql://... python3 tests/pool_metrics.py --binary target/debug/rootyard --report pool-metrics-report.json
```

Deadpool 0.13.1 reports approximate pool snapshots under concurrent load.
`size` counts tracked established pool objects, excluding creation in progress;
it is not a live-socket probe. `available` and `waiting` are derived from pool
users, so `waiting` can include connection creation. `busy = size - available`
is a derived observation, not a coherent transaction across these counters.
