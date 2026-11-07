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
disappear. Clients must not assume a stable total count between pages. A backup
restore or other catalog rewind can move a cursor outside the current data set,
so clients restart from the first page after restore.
