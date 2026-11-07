# Organization member and team list pagination

`GET /api/orgs/{slug}/members` and `GET /api/orgs/{slug}/teams` keep their
existing authorization policy: the caller is re-authenticated, the organization
is resolved by slug, and the direct membership role (`read` or stronger) is
checked on every page. A cursor never substitutes for that check, so a removed
member cannot resume an earlier traversal.

## Query parameters

- `limit` — integer `1..=1000`, default `100`.
- `cursor` — opaque cursor returned by the previous page.

Unknown parameters and out-of-range or non-integer limits return `400`.
Malformed, oversized, invalid-UTF-8, NUL-containing, nil-UUID or foreign
cursors are `400`. Missing/invalid credentials remain `401`; when the caller is
not a member, the historical `403`/`404` is returned before the cursor is
decoded.

## Responses

The envelope is backward compatible; only `next_cursor` is added:

```json
{"items": [], "truncated": false, "next_cursor": null}
```

`items`, `truncated`, and every row field keep their previous names and meaning.
`truncated` is `true` exactly when another page exists. When it does,
`next_cursor` is a non-empty string and both `X-Next-Cursor` and
`Link: <...?cursor=...&limit=...>; rel="next"` carry the same cursor and the
requested limit. The final page has `next_cursor: null` and neither header.

Ordering is the complete key `(username, user_id)` for members and
`(slug, id)` for teams; the UUID tie-breaker makes equal names/slugs
deterministic. The cursor is bound to `(actor user, organization, list kind)`,
so replaying a member cursor against another actor, organization or the teams
list is a `400`, not an empty page.

## Mutation and restore semantics

This is keyset pagination, not a snapshot. Inserts that sort after the cursor
appear on later pages; inserts before it are not replayed; deletions simply
disappear. Renaming a user or team changes an ordering key and can make an item
appear again or be skipped mid-traversal. A backup restore or other metadata
rewind can move a cursor outside the current rows. Restart from the first page
when a stable inventory is needed after renames, membership changes or a
restore.
