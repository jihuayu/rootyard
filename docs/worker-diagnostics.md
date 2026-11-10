# Background worker diagnostics

This change extends the existing internal-error path (`src/observability.rs`)
with a bounded background-operation context. It does not add a metrics schema,
Retry policy, endpoint or unbounded label. The existing scheduler cadence,
concurrency, timeouts, lease renewal and retry decisions are unchanged; only
scope installation and fixed-key event fields were added around the real work.

## Event shape

A worker event keeps the same bounded logger and rate limit as request events,
but uses a `worker` scope:

```json
{"event":"rootyard_error","event_id":"<uuid>","kind":"database","status":503,"scope":"worker","worker":"storage_lifecycle","operation_id":"<uuid>","phase":"scan","sqlstate":"57014"}
```

When a maintenance job was actually claimed, the persisted attempt and
repository generation may be attached as non-negative integers:

```json
{"scope":"worker","worker":"storage_lifecycle","operation_id":"<uuid>","phase":"execute","attempt":2,"generation":17}
```

* `worker` is one fixed label from `WorkerKind`: `webhooks_background`,
  `storage_lifecycle`, `workspace_capture`, `workspace_remote_gc`,
  `durable_dispatch`.
* `phase` is one fixed label from `Phase`: `round`, `scan`, `reconcile`,
  `deliver`, `claim`, `execute`, `collect`, `dispatch`, `subscribe`.
* `operation_id` is a server-generated UUID sampled once per worker round. It is
  never a client, actor, repository, token, job, delivery or remote-object ID.
* `attempt` and `generation` are included only when they already exist as
  persisted numeric job metadata and are non-negative. Negative values are
  dropped.
* Raw actor/repository/tenant/job IDs, tokens, URLs, object keys, SQL text,
  headers, bodies/contents, `Display` and `Debug` text are never emitted. Error
  classification still uses only the typed, fixed kinds from the request path.

## HTTP and worker isolation

`REQUEST_SCOPE` and `OPERATION_SCOPE` are separate task locals.
`event_json` checks the operation scope first. The worker spawn helper
(`observability::worker::spawn`) installs only the selected operation context;
it does not copy request state. A plain `tokio::spawn` inherits neither scope and
remains `"scope":"detached"`. Unit tests cover:

* a worker operation run and spawned while an HTTP request scope is active
  reports `scope:"worker"` with no `request_id` or `route`;
* a spawn without an explicit operation context is detached;
* nested phases keep the round `operation_id` while changing only `phase`;
* attempt/generation are the only job-derived fields and negative values are
  omitted;
* a hostile error formatter is never called by the classifier.

## Covered background loops

Real scopes are installed around:

* `webhooks::background::worker`, including the candidate scan, PR
  reconciliation and delivery phases. Per-repository child futures spawned by
  the bounded `JoinSet` are wrapped with the selected round context explicitly.
* `storage_lifecycle::run`, including the scheduler scan and job claim. A
  claimed job switches to the `execute` phase with its persisted numeric
  attempt/generation.
* `workspaces::capture::run`, including eligibility scans and per-workspace
  reconciliation.
* `workspaces::remote_gc::run`, around each collect pass.
* `dispatch::worker`, around each durable delivery scan. The transport
  subscriber is spawned through the explicit operation-context helper.

## Native drill

`tests/worker_diagnostics.py` reuses `tests/e2e.py` and starts the real service
against a disposable owned PostgreSQL schema. It installs a synthetic trigger
on `storage_maintenance_repo_state` whose INSERT executes `pg_sleep(6)`; the
owned pool's `statement_timeout=5000` cancels the executing statement in
PostgreSQL with SQLSTATE 57014. The test asserts that the worker emits a real
`scope:"worker"`, `worker:"storage_lifecycle"`, `phase:"scan"` event with a
server-generated `operation_id` and no request ID or route. A second trigger
raises SQLSTATE 23503 for a real HTTP request; the test asserts that request
event has `scope:"request"` and no worker/operation fields, and that the two
correlation IDs differ. Trigger messages, tokens, URLs, query strings and
headers are checked against the retained log.

The drill's worker fault is a real database timeout, not a mocked Rust error.
It does not claim that every covered worker was exercised natively.

## Still missing / not claimed

* Native fault injection for `webhooks_background`, `workspace_capture`,
  `workspace_remote_gc` and `durable_dispatch`. Their scope wrapping has unit
  coverage only.
* A native claimed-job failure proving attempt/generation correlation; the
  current native timeout happens before a job claim.
* Session GC, the sharding controller and pending-transition reconciliation,
  journal/provisioning recovery, metrics workers, backup/restore jobs and the
  advisory wake publisher are outside worker operation scope.
* Durable storage of events: these remain best-effort bounded logs, with the
  existing queue/rate limits and possible loss at process exit.

This document records partial per-worker coverage. It is not a claim that all
of issue 80 or all background workers are complete.
