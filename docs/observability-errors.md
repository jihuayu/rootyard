# Internal error observability

Phase 80 adds a central, privacy-preserving classification path for internal
errors. `Error` remains the two-field tuple `Error(pub StatusCode, pub &'static str)`;
its status, fixed body and auth/security headers are unchanged.

Each `Error::internal(error)` attempts to enqueue one safe JSON event for
best-effort stderr delivery, subject to the rate and queue limits below:

```json
{"event":"rootyard_error","event_id":"<uuid>","kind":"database","status":503,"scope":"request","request_id":"<uuid>","route":"/api/repos/{owner}/{name}","sqlstate":"23503"}
```

* `kind` is one of a fixed set: `database`, `database_pool`, `io`, `http`,
  `timeout`, `join`, `remote_store`, `internal`, `unknown`. Unrecognized
  concrete types always use `unknown`; Rust type names are never emitted.
* `kind:"remote_store"` is selected only when the chain contains the bounded
  `RemoteStoreError` from `src/storage/remote_objects.rs`. Its event adds
  `remote_op` (one fixed label: `get`, `head`, `put`, `delete`,
  `multipart_initiate`, `multipart_part`, `multipart_complete`,
  `multipart_abort`) and, only for a completed HTTP failure, `remote_status`
  (a numeric u16). A bare `reqwest::Error` still classifies as fixed `http` or
  `timeout`; when it carries one, its numeric status is likewise exposed as
  `remote_status`. URLs, object keys, query strings, headers, credentials,
  bodies and transport text are never copied.
* `sqlstate` is present only for a `tokio_postgres::Error` (directly or through an
  `anyhow::Error` chain) whose server code is exactly five ASCII alphanumeric
  units. The code is copied, never the database message, detail or hint.
* `request_id` and `route` come from request-scoped task-local state installed by
  the middleware in `src/lib.rs`. `route` is the router's matched path pattern,
  never the raw URL, query or headers.
* Detached work uses `"scope":"detached"`, a fresh server-generated `event_id`
  and no route or request ID. In particular, `tokio::spawn` does not inherit
  task-local request scope, so errors raised inside spawned handler futures are
  correlated by event UUID only; request context does not survive `tokio::spawn`.
  This is a documented limitation, not a claim of end-to-end propagation.

The middleware generates its own `X-Request-ID` UUID for every response and
ignores any client-supplied value. It wraps the routed future, so all responses
keep their status, body and existing header/security behavior.

Error text, `Display`/`Debug`, URLs, headers, query strings, user content and
source strings are never formatted into the event. Logging uses a bounded global
one-second monotonic window (100 events) serialized by one short mutex, with no
per-request map. Wall-clock changes do not reset the allowance. A first fault in a quiet window is therefore never
suppressed, while a storm cannot grow memory or log volume without bound.
Accepted events are then handed to one dedicated, named `rootyard-error-log`
thread through a bounded `std::sync::mpsc` channel of 128 records. The request path
only calls non-blocking `try_send`: it never awaits and never takes the stderr lock.
If the queue is full, output was disabled, or the writer is gone, the record is
discarded and a saturating process-wide dropped counter is incremented (exposed as
`dropped_event_count` and exported on the private metrics listener as
`rootyard_error_log_dropped_total`), so a slow or broken stderr can never
block or fail a request. The writer thread holds the stderr lock only for one complete
`write_all` plus newline, treats every `std::io::Error` as best-effort (no retry, no
panic) and performs no other I/O or async work. If the thread cannot be spawned,
logging is disabled safely and requests are unaffected. These events are best-effort
operational logs, not durable receipts: records still queued when the process exits
may be lost.

## Entry points and scope

The live entry points are:

* `application::Error::internal` for every internal HTTP failure; it calls
  `observability::observe_internal` before returning the fixed 503 body.
* `observability::middleware` for the server-generated `X-Request-ID`, matched
  route pattern and request-scoped task local.
* `storage::remote_objects::RemoteStoreError` for typed S3 GET/HEAD/PUT/DELETE
  and multipart stages. Retries retain only the last typed failure; a completed
  HTTP failure keeps a bounded `u16`, and a transport failure keeps its
  `reqwest::Error` as the error source.
* `lfs::hydration` preserves that typed failure across the shared single-flight
  result instead of flattening it to `Display` text, so a cold LFS read failure
  remains classifiable as `remote_store` with its fixed operation and status.
  The public LFS response remains the same bounded 5xx.

An owned PostgreSQL drill now covers two real cases: a synthetic
`BEFORE INSERT` trigger that raises SQLSTATE 23503 on one repository name, and a
separate synthetic trigger whose `PERFORM pg_sleep(6)` is cancelled by the pool's
`statement_timeout=5000` as SQLSTATE 57014. Both assert the fixed 503 body,
`no-store`, the server `X-Request-ID`, one correlated structured event, and that
tokens, URLs, query strings and header secrets do not reach the log.

The owned Garage drill in `tests/lfs_hydration_concurrency.py` gates a real
backend GET, returns a controlled 502, captures the failed response
`X-Request-ID`, finds the matching structured event in the owned service log and
asserts `kind:"remote_store"`, `remote_op:"get"`, `remote_status:502` and log
privacy before a clean retry succeeds. It does not mock the Rust error.

Still open (not part of this change): remote repair metrics and any other
metrics work, the 80-request full-backlog drill, and per-worker coverage. The
fault metrics on the private listener are unchanged. These scenarios were not
executed natively in this implementation branch; the reports in `evidence/`
remain the authority for what was actually run.

The private metric `rootyard_error_log_dropped_total` counts accepted records
lost to a full/disconnected queue, writer startup failure, or incomplete stderr
write. It excludes rate-limited faults and records still queued at process exit.
Alert on increases when diagnosing missing logs; it does not count every error.
