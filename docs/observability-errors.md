# Internal error observability

Phase 80 adds a central, privacy-preserving classification path for internal
errors. `Error` remains the two-field tuple `Error(pub StatusCode, pub &'static str)`;
its status, fixed body and auth/security headers are unchanged.

On every `Error::internal(error)` a single-line JSON event is written to stderr:

```json
{"event":"rootyard_error","event_id":"<uuid>","kind":"database","status":503,"scope":"request","request_id":"<uuid>","route":"/api/repos/{owner}/{name}","sqlstate":"23503"}
```

* `kind` is one of a fixed set: `database`, `database_pool`, `io`, `http`,
  `timeout`, `join`, `internal`, `unknown`. Unrecognized concrete types always
  use `unknown`; Rust type names are never emitted.
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

Backlog/fault metrics, per-worker coverage and the native hostile-database test
remain open for their later phases.
