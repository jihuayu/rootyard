# Repository list pagination

`GET /api/repos` is the authenticated repository discovery endpoint. Its
authorization predicate is unchanged: only owned, collaborator, team, or
organization-member repositories are visible. The keyset cursor is appended
after that grouped predicate and cannot widen it.

## Query parameters

- `limit` — integer `1..=1000`, default `1000`.
- `cursor` — opaque cursor returned by the previous page.
- `page` — boolean; `true` selects the paged response envelope.

Unknown parameters, invalid booleans, out-of-range limits, and malformed or
foreign cursors return `400`. Missing, malformed, expired, or revoked
credentials still return `401`.

## Responses

Without `page=true`, the response stays a backward-compatible JSON array. With
`page=true` it is:

```json
{"items": [], "next_cursor": null}
```

When another page exists, `items` is capped at `limit`, `next_cursor` is a
non-empty string, and both `x-next-cursor` and a `Link: <...>; rel="next"`
header carry the same cursor. The final page has `next_cursor: null` and neither
header. The default 1000-row page therefore reports a cursor instead of
silently truncating a 1001st repository.

Ordering is the complete key `(namespace slug, repository name, repository id)`.
The UUID tie-breaker keeps pages deterministic for equal owner/name prefixes.
The cursor is bound to the authenticated actor; using another user's cursor is a
`400`, not an empty page.

## Mutation and restore semantics

Pagination is keyset-based, not a snapshot. Inserts that sort after the cursor
appear on later pages; inserts before it are not replayed and deletes simply
disappear. A rename or ownership transfer changes an ordering key and can make
a repository appear again or be skipped during an ongoing traversal; restart
discovery when a stable inventory is needed after such changes. Clients must
not assume a stable total count between pages. A backup
restore or other catalog rewind can move a cursor outside the current data set,
so clients restart from the first page after restore.

## Browser discovery list (`GET /web/repos`)

The browser discovery route now uses the same bounded keyset discipline with a
fixed page size of 100 (SQL asks for 101 to detect a next page). It never uses
`OFFSET`, and the final page emits no next link.

- Ordering key: `(namespace.slug, repository.name, repository.id)`, ascending.
- Cursor scope: `web-repos:discover:v1:<all|restricted>:<actor UUID>`.
  A cursor from another actor, another list kind, another audience, a different
  version, a wrong field count, an invalid slug/name or an invalid UUID is
  rejected with `400`.
- Every page re-authenticates, locks and re-verifies the live token, recomputes
  current RBAC visibility (owner, organisation member, organisation team,
  collaborator, repository team), and keeps the PAT foundation predicate. A
  restricted token additionally needs the exact `repo_read` grant, so it sees
  only repositories it was granted; an empty grant set returns an empty list
  and the empty HTML message.
- Only `state='ready'` repositories are listed. `auth::finish_tx` commits after
  the page has been read, so a revocation during the request fails closed.
- The next link is a relative `?cursor=...` href. The cursor is percent-encoded
  with `pagination::query_value` and the href is HTML-escaped; the last page has
  no link.
- Anonymous requests follow the existing middleware contract exactly: a plain
  request returns `401`; a browser navigation is redirected with `303` to
  `/web/login`. The route does not produce `302`.

### Verification status

`tests/web_repository_pagination.py` is the native acceptance harness. It
requires `ROOTYARD_TEST_DATABASE_URL` and a binary whose
`native_evidence.build_record` receipt is attested, whose binary SHA-256
matches the executed file, and whose `source_inputs_sha256` equals the current
`build_native.source_digest()`. The harness bulk-seeds 105 catalog rows by
explicit SQL (asserted count, `gen_random_uuid()`, no per-repository Git path),
creates the 106th repository through the real API, and traverses both pages
through real browser-session cookies and HTTP. The bulk seed is an operator
fixture shortcut, not a scalability or stress benchmark.

**The native harness has NOT been run in this implementation environment.**
No Cargo build, native acceptance suite or root fixture was executed here; the
coordinator must rebuild and run the harness on a disposable PostgreSQL schema.
The source and receipt digests must match at that time. The pre-existing browser
session, restricted-parent login rejection, schema and SSO contracts are out of
scope and were not changed.
