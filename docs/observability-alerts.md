# Observability alerts and operator troubleshooting runbook

This runbook pairs the privacy-preserving structured error log
([observability-errors.md](observability-errors.md) and
[worker-diagnostics.md](worker-diagnostics.md)) with the fixed-cardinality
loopback Prometheus exposition ([metrics.md](metrics.md)). Every `rootyard_*`
metric name, label key, `kind`, `scope`, `worker`, `phase`, and `remote_op`
referenced here is validated against the Rust source by
`tests/test_observability_runbook.py`.

## Fault taxonomy overview

Rootyard separates operational signals into three disjoint classes so operators
never page database or storage responders on client policy rejections and never
mistake relational invariant bugs for transient network blips:

1. **Expected client and policy rejections (`4xx`)**: deterministic authn,
   RBAC/PAT-scope, non-member privacy (`404`), browser CSRF/Origin, optimistic
   CAS/checkpoint conflict (`409`/`412`), validation/quota (`400`/`413`/`422`),
   and admission rate-limit (`429`) responses.
2. **Transient dependency failures**: PostgreSQL unavailability, connection-pool
   exhaustion, or `statement_timeout` cancellations, and S3/Garage remote
   object-store `5xx` or transport failures.
3. **Internal consistency, worker backlog, and scan-starvation anomalies**:
   PostgreSQL relational integrity violations (`23503`, `23505`, `23514`),
   unresolved Git operations, overdue outbox/webhook/maintenance/capture work,
   expired running worker leases, and dropped error-log records.

---

## 1. Expected rejections (`4xx` authz, RBAC, CSRF, CAS, quota, rate-limit)

### Detection and separation from `503` internal faults

* Expected policy rejections return `400`, `401`, `403`, `404`, `409`, `412`,
  `413`, `422`, or `429` with `Cache-Control: no-store` and a server-generated
  `X-Request-ID`. They **never** call `Error::internal` and **never** emit an
  `{"event":"rootyard_error",...}` record on stderr.
* Private repositories intentionally return `404` to unauthenticated callers and
  non-members so existence is never disclosed, and `403` only when a verified
  member lacks the required role or PAT action scope.
* Do **not** page infrastructure oncall for elevated `4xx` rates when
  `rootyard_postgres_up == 1` and HTTP `503` responses are zero.

```promql
# Healthy backend check while triaging external 4xx spikes:
rootyard_postgres_up == 1 and rootyard_db_pool_waiting == 0
```

### Operator troubleshooting entrypoint

1. Capture the response status and `X-Request-ID` header reported by the client.
2. Confirm no internal fault occurred behind the request by checking stderr:
   ```bash
   jq -c 'select(.event == "rootyard_error" and .request_id == "<x-request-id>")' server.log
   ```
   Zero matching lines plus a `4xx` HTTP status proves a policy or precondition
   rejection rather than a backend fault.
3. Triage by status class without restarting workers:
   * `401`: missing, revoked, or expired token/browser session (`tokens` /
     `web_sessions`).
   * `404` on a private repo: verify namespace/repository membership first
     before assuming a missing repository.
   * `403`: inspect member role (`read` / `triage` / `write` / `maintain` / `admin`)
     and PAT token action scope, or missing/mismatched browser `Origin` / CSRF
     token on `/web/*`.
   * `409` / `412`: stale Git ref CAS, PR `expected_version`, or workspace
     `expected_lease_epoch` / `expected_revision`; instruct caller to re-fetch.
   * `429`: auth admission or mirror sync rate limit triggered; inspect source
     request burst rather than scaling PostgreSQL.

---

## 2. Transient dependency failures (PostgreSQL and S3/object store)

### Executable PromQL alert predicates

```promql
# Alert: RootyardPostgresSnapshotDown (page, for: 1m)
# A failed or >5s SQL scrape returns HTTP 503 and omits SQL-derived gauges.
absent(rootyard_postgres_up) or rootyard_postgres_up == 0

# Alert: RootyardDbPoolSaturated (page, for: 2m)
# Pool checkout queue is backing up while zero idle connections remain.
rootyard_db_pool_available == 0 and rootyard_db_pool_waiting > 0

# Alert: RootyardGitCapacitySaturated (warning, for: 5m)
# Native Git semaphore slots are fully occupied.
rootyard_git_capacity > 0 and rootyard_git_in_flight >= rootyard_git_capacity

# Alert: RootyardLfsRemoteFailuresIncreasing (warning, for: 5m)
# Cold LFS hydration, deferred repair, or remote publication failed against S3.
increase(rootyard_lfs_remote_failures_total[5m]) > 0

# Alert: RootyardLfsRemoteRepairBacklogSustained (warning, for: 10m)
# Admitted in-flight LFS remote repair tasks are holding semaphore permits.
rootyard_lfs_remote_repair_backlog > 0
```

### Structured stderr correlation predicates

```bash
# PostgreSQL statement timeouts (57014), connection exhaustion (53300),
# connection exceptions (08*), or Deadpool checkout failures:
jq -c 'select(.event == "rootyard_error" and (
  .kind == "database_pool" or .kind == "timeout" or
  (.kind == "database" and (.sqlstate == "57014" or .sqlstate == "53300" or ((.sqlstate // "") | startswith("08"))))
))' server.log

# S3 / Garage remote object-store failures by bounded operation and HTTP status:
jq -c 'select(.event == "rootyard_error" and (.kind == "remote_store" or .kind == "http"))' server.log
```

* `kind:"remote_store"` carries `remote_op` (`get`, `head`, `put`, `delete`,
  `multipart_initiate`, `multipart_part`, `multipart_complete`,
  `multipart_abort`) and, when an HTTP response arrived, numeric `remote_status`
  (such as `500`, `502`, `503`). Missing `remote_status` on `remote_store`
  indicates a transport/connect/timeout error before headers completed.

### Operator troubleshooting entrypoint

1. **PostgreSQL saturation or timeout (`rootyard_postgres_up == 0`, `57014`, `53300`, `08*`)**:
   * Probe `GET /health/ready` and `curl -i http://127.0.0.1:9108/metrics`. On
     HTTP `503`, confirm whether `rootyard_db_pool_busy` equals
     `rootyard_db_pool_max_size` and whether `rootyard_db_pool_waiting > 0`.
   * Inspect PostgreSQL `pg_stat_activity` and `pg_locks` for long-running
     blockers cancelling statements at the 5 s app pool or 4 s metrics
     `statement_timeout` (`sqlstate:"57014"`).
   * Check whether `scope:"request"` (correlate `route` and `request_id`) or
     `scope:"worker"` (correlate `worker`, `phase`, and `operation_id`) is
     driving the timeouts.
2. **S3 / Garage degradation (`kind:"remote_store"`, `rootyard_lfs_remote_failures_total`)**:
   * Group recent `remote_store` events by `remote_op` and `remote_status`.
   * Warm LFS downloads with verified local files continue serving without
     touching S3; cold cache misses fail closed with `503` and increment
     `rootyard_lfs_remote_failures_total`.
   * When `rootyard_lfs_remote_repair_backlog > 0`, bounded deferred repairs are
     in flight re-uploading locally verified LFS objects to S3; once S3
     recovers, `rootyard_lfs_remote_repair_backlog` drains to `0` automatically.

---

## 3. Internal consistency, worker backlog, and scan starvation

### Executable PromQL alert predicates

Cluster-wide SQL gauges are exported identically by each metrics listener;
aggregate with `max` (never `sum`) across instances. Host-scoped workspace
gauges represent each serving volume's `workspaces.host_id`.

```promql
# Alert: RootyardUnresolvedGitOperations (page, for: 1m)
# Unknown Git ref mutation outcome requires explicit operator inspection.
max(rootyard_operations_unresolved) > 0

# Alert: RootyardEventDeliveryLag (warning, for: 5m)
# Durable outbox consumer deliveries (audit-log / ref-index) are stalling.
max(rootyard_event_delivery_oldest_age_seconds) > 120
  and (max(rootyard_event_deliveries{state="pending"}) > 0 or max(rootyard_event_deliveries{state="leased"}) > 0)

# Alert: RootyardWebhookDeliveryLag (warning, for: 5m)
# Active-hook webhook delivery (pending, retry-delayed failed, or leased) is overdue.
max(rootyard_webhook_delivery_oldest_age_seconds) > 300

# Alert: RootyardWorkspaceCaptureLag (warning, for: 5m)
# Ready, lease-valid workspace on this volume has not refreshed capture verification.
rootyard_workspace_capture_oldest_age_seconds > 960

# Alert: RootyardWorkspaceNeverSampled (warning, for: 5m)
# Ready, lease-valid workspace lacks its initial workspace_capture_state baseline row.
rootyard_workspace_capture_never_sampled > 0

# Alert: RootyardStorageMaintenanceExpiredLease (warning, for: 5m)
# A claimed maintenance job's running lease expired before completion or renewal.
max by (backend, kind) (rootyard_storage_maintenance_jobs{state="expired_running_lease"}) > 0

# Alert: RootyardStorageMaintenanceQueueLag (warning, for: 10m)
# Queued maintenance work is aging while due jobs remain unclaimed.
max by (backend, kind) (rootyard_storage_maintenance_oldest_queued_age_seconds) > 1800
  and max by (backend, kind) (rootyard_storage_maintenance_jobs{state="due_queued"}) > 0

# Alert: RootyardStorageMaintenanceScanStarvation (warning, for: 10m)
# Ready eligible repositories are overdue past Policy::scan_period_seconds.
max by (backend) (rootyard_storage_maintenance_oldest_overdue_scan_age_seconds) > 3600
  and max by (backend) (rootyard_storage_maintenance_repos{state="due_scan"}) > 0

# Alert: RootyardStorageMaintenanceNewTerminalFailure (warning, for: 5m)
# state="failed" is retained history; alert on new transitions, not static > 0.
max by (backend, kind) (changes(rootyard_storage_maintenance_jobs{state="failed"}[15m])) > 0

# Alert: RootyardSessionGcFailures (warning, for: 10m)
# Per-process session_gc loop recorded failed cycles.
increase(rootyard_session_gc_failures_total[10m]) > 0

# Alert: RootyardExpiredBrowserSessionBacklog (warning, for: 10m)
# Cluster-wide oldest expired browser session row exceeds 24 hours.
max(rootyard_expired_browser_session_oldest_age_seconds) > 86400

# Alert: RootyardErrorLogDropped (warning, for: 5m)
# Accepted structured error events were dropped by the 128-slot stderr writer queue.
increase(rootyard_error_log_dropped_total[5m]) > 0
```

* Note on `rootyard_workspace_lease_expired`: ready workspaces whose
  `lease_until` is in the past can reflect normal session completion or lease
  handoff; treat it as an informational capacity/handoff signal alongside
  `rootyard_workspace_capture_oldest_age_seconds`, not a standalone page.
* Note on `rootyard_storage_maintenance_repos{state="missing_scan"}` and
  `state="stale_generation"`: newly created or recently migrated repositories
  appear here briefly until the next `storage_lifecycle` `scan` pass; alert on
  sustained `rootyard_storage_maintenance_oldest_overdue_scan_age_seconds`
  instead of brief non-zero counts.

### Structured stderr correlation predicates

```bash
# Relational FK (23503), unique (23505), or CHECK (23514) invariant violations:
jq -c 'select(.event == "rootyard_error" and .kind == "database" and (
  .sqlstate == "23503" or .sqlstate == "23505" or .sqlstate == "23514"
))' server.log

# Background worker faults grouped by worker, phase, attempt, and generation:
jq -c 'select(.event == "rootyard_error" and .scope == "worker")
  | {worker, phase, kind, sqlstate, remote_op, remote_status, attempt, generation, operation_id}' server.log
```

### Operator troubleshooting entrypoint

1. **Relational integrity violation (`sqlstate:"23503"`, `"23505"`, `"23514"`)**:
   * Treat as a control-plane invariant or composite tenant-FK violation, never
     transient load.
   * If `scope == "request"`, match `route` and `request_id` to identify the API
     surface without exposing user payloads.
   * If `scope == "worker"`, match `worker` (`webhooks_background`,
     `storage_lifecycle`, `workspace_capture`, `workspace_remote_gc`, or
     `durable_dispatch`) and `phase` (`round`, `scan`, `reconcile`, `deliver`,
     `claim`, `execute`, `collect`, `dispatch`, `subscribe`).
2. **Unresolved Git operations (`rootyard_operations_unresolved > 0`)**:
   * Query `SELECT id, repository_id, storage_generation, sequence FROM git_operations o WHERE outcome='unknown' AND NOT EXISTS (SELECT 1 FROM operation_resolutions r WHERE r.operation_id=o.id);`.
   * Run `rootyard inspect-recovery <repository_uuid>` on the owning volume and
     complete explicit `rootyard resolve-unknown ...` or `rootyard reconcile`
     recovery; never delete `git_operations` rows manually.
3. **Worker backlog, expired leases, and scan starvation**:
   * `storage_lifecycle` (`phase:"scan"`, `"claim"`, `"execute"`): when an
     `execute` fault emits numeric `attempt` and `generation`, inspect
     `SELECT id, kind, state, attempt, repository_generation, claim_generation, lease_until, not_before FROM storage_maintenance_jobs WHERE state IN ('queued','running','failed') ORDER BY updated_at DESC LIMIT 20;`.
   * `webhooks_background` (`phase:"round"`, `"scan"`, `"reconcile"`,
     `"deliver"`): inspect `forge_webhook_deliveries` joined to active
     `forge_webhooks` for stuck `leased` or retry-delayed `failed` rows.
   * `durable_dispatch` (`phase:"dispatch"`, `"subscribe"`): inspect
     `event_deliveries` (`state IN ('pending','leased')`) and confirm either the
     embedded outbox worker (`ROOTYARD_OUTBOX_WORKER=true`) or standalone
     `rootyard worker` is running.
   * `workspace_capture` (`phase:"scan"`, `"reconcile"`) and
     `workspace_remote_gc` (`phase:"round"`, `"collect"`): compare
     `workspaces.host_id` against the volume `.volume-id`, inspect missing/stale
     `workspace_capture_state` rows, and inspect failed `workspace_checkpoints` /
     `workspace_remote_staging_objects` rows.
4. **Dropped structured error logs (`rootyard_error_log_dropped_total` increasing)**:
   * Indicates the `rootyard-error-log` writer thread could not drain the
     128-record queue fast enough (blocked container/systemd stderr consumer) or
     encountered a stderr `io` write error; restore non-blocking log collection
     so diagnostic events are not lost during incident storms.
