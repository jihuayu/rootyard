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
literal label value. A healthy scrape always exports all 17 time series,
including zero-valued states. Delivery age includes leased entries (including
expired leases) and delayed retries. Counts represent delivery rows, so one
event assigned to two consumers contributes two outstanding deliveries.
A resolved unknown operation remains an unknown historical fact; its explicit
resolution removes it from the unresolved gauge without rewriting history.

PostgreSQL is the source of truth. Each scrape obtains a single-statement MVCC
snapshot inside a read-only transaction. A four-second server-side statement
timeout bounds the query; pool acquisition and query have a combined five-second
timeout. On
any database/schema/query failure or timeout, the endpoint returns HTTP 503,
exports `rootyard_postgres_up 0` plus process-local metrics, and omits every
database-derived gauge. It never substitutes an empty/healthy backlog or
serves a stale cached snapshot. Alert on both Prometheus scrape failure and
PostgreSQL health; standard Prometheus marks a 503 scrape unsuccessful rather
than ingesting its body.

Counters reset on process restart and saturate at `u64::MAX`. They measure
Git subprocess HTTP activity, not successful Git ref mutations, durable
receipts, or remote consumer acknowledgements. Failures include transport,
subprocess, deadline, size-limit and receipt-publication failures. Rejections
before a native Git process starts (such as authentication or capacity checks)
are not transfers. Client disconnects and rejected transfers
may have observed partial bytes. Bytes handed to the HTTP stream are not proof
that a client received them. Git protocol-level rejection can occur inside an
otherwise successful HTTP transfer. Use durable receipts and operation evidence
for correctness decisions, not these counters. Semaphore occupancy is a
point-in-time reading and is not transactionally synchronized with SQL.

## Tests

`cargo test metrics::tests` checks loopback binding, fixed labels/numeric format,
failed-snapshot omission and saturating counters. With a dedicated PostgreSQL
test database and a built binary:

```
ROOTYARD_TEST_DATABASE_URL=postgresql://... python3 tests/metrics.py --binary target/debug/rootyard --report metrics-report.json
```

The harness owns and removes only its randomly named schema and temporary
storage. It seeds explicit synthetic metadata to verify aggregation and briefly
renames its own delivery table to verify fail-closed exposition. This is not a
PostgreSQL outage, production load, or monitoring-system integration test.
