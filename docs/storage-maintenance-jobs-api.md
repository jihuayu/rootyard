# Maintenance job observability API

Read-only inspection of the durable `storage_maintenance_jobs` queue. This is
partial progress on issue #23: it adds no scheduler, worker, claim, deletion or
schema change, and an older milestone record does not attest to it.

```
GET /api/repos/{owner}/{name}/maintenance-jobs
GET /api/repos/{owner}/{name}/maintenance-jobs/{job_id}
```

## Authorization

Both endpoints authenticate a normal API/browser token and then use
`authenticate` + `authorize_repo_with_role(..., Role::Maintain)` inside one
transaction; the token is re-verified immediately before commit.

| Caller | Result |
| --- | --- |
| owner / collaborator or team role `maintain` or `admin`, writable token | `200` |
| repository `read`, `triage` or `write` role, or a read-only token | `403` |
| user with no role on the repository (all repositories are private) | `404` |
| missing, malformed, revoked or expired credentials | `401` |

A job id or cursor that belongs to another repository is never looked up
outside `repository_id = <resolved repository>`, so it cannot reveal a foreign
job or its state.

## List

Query parameters (strict; unknown, duplicate or empty values are `400`):

- `limit` — `1..=100`, default `25`.
- `state` — one of exactly `queued`, `running`, `succeeded`, `failed`.
- `after` — opaque cursor from the previous page's `next_after`.

Ordering is newest first over `(created_at DESC, id DESC)`; the id tiebreak
keeps pages deterministic when two jobs share a timestamp. The state filter is
applied in SQL before the bounded `limit + 1` read.

```json
{
  "items": [
    {
      "id": "0f2c…",
      "kind": "gitfs_repack",
      "state": "succeeded",
      "attempt": 1,
      "repository_generation": 3,
      "progress": {"phase": "succeeded", "attempt": 1},
      "result": {"repacked": true},
      "error": null,
      "created_at": "2026-01-01 00:00:01.25+00",
      "updated_at": "2026-01-01 00:00:04.75+00",
      "completed_at": "2026-01-01 00:00:04.75+00"
    }
  ],
  "next_after": "v1:0f2c…"
}
```

`next_after` is `null` exactly when no additional matching job exists.

### Cursor contract

A cursor is `v1:<job-id>` naming a durable job of **this** repository (normally
one returned by an earlier page). The server resolves the ordering key from that
row, so a client cannot inject a timestamp or offset, and a cursor does not
widen the repository scope. A correctly formatted job of the same repository is
accepted as a position even if no page has returned it yet; it only selects rows
on the authorized side of that job. A wrongly formatted value, an unknown id, or
a job id that belongs to another repository is `400 invalid request`; the
response does not distinguish "does not exist" from "belongs elsewhere".
Cursors are positions, not snapshot tokens: reuse a cursor with the same
`state` filter, and rows created later than the cursor are not returned by that
pagination run. If the cursor row were ever removed (for example with its
repository) the client must restart without `after`.

## Detail

`GET /api/repos/{owner}/{name}/maintenance-jobs/{job_id}` returns the same job
object directly; an unknown id or another repository's job is `404`, and a
non-UUID path segment is `400`.

## Exposed fields

Durable identity and lifecycle only: `id`, `kind`, `state`, `attempt`,
`repository_generation`, `progress`, `result`, `error` (the durable
`last_error`, already capped at 1024 characters on write), and the
`created_at`/`updated_at`/`completed_at` text timestamps.

Deliberately excluded: `lease_owner`, `lease_until` and `claim_generation`.
Those values are worker fencing capabilities; publishing them would expose
enough state to reason about a claim, so the projection never selects them.
Progress/result documents are the durable worker output and contain no
credentials. Worker progress may echo an attempt and claim generation, but
without the excluded lease owner and lease window those numbers grant no claim
capability; they are returned unmodified so progress stays faithful to the
durable row.

## Errors and limits

`400` invalid query/cursor/path, `401` unauthenticated, `403` insufficient
role or read-only token, `404` no access or unknown/foreign job, `409`
repository not ready (existing authorization behavior), `503` database
unavailable. Responses are `Cache-Control: no-store`.

The endpoints are bounded, but no index is added for
`(repository_id, created_at DESC, id DESC)`, so this does not promise a query
plan or large-repository performance. Lists are live views, not snapshots, and
no organization-wide, all-repository or cross-tenant view is offered.
