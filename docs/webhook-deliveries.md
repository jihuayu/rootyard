# Webhook delivery listing and pagination

`GET /api/repos/{owner}/{name}/webhooks/{hook_id}/deliveries` lists one hook's
deliveries; see [webhook scheduling](webhook-scheduling.md) for allocation and
delivery. Optional filters are `state` and `event_type`. `limit` is 1–100
(default 50). Unknown query fields and malformed cursors are rejected with
`400`.

Items are ordered by `(sequence, id)` ascending. `sequence` is allocated per
hook under the parent hook's row lock, but historic rows written by the older
global `MAX(sequence)+1` allocator may share one `sequence` across several
deliveries. The `id` tiebreak is therefore part of the ordering contract.

## Complete traversal: `next_cursor`

Each response is
`{"webhook_id": ..., "items": [...], "next_after": <int|null>, "next_cursor": <string|null>}`.
When another page exists, `items` is capped at `limit` and `next_cursor` is the
opaque, hook-bound position `v1.{hook_id}.{sequence}.{id}` of the last returned
item. Passing it back as `cursor=` continues strictly after that item. The
final page has `next_cursor: null`.

To read every delivery of a hook exactly once, follow `next_cursor` until it is
`null`. This holds for any permitted `limit`, including 1, 50 and 100, and for
histories that contain duplicate `sequence` values. The
[#70 regression](../tests/webhook_pagination.py) walks one tied history at page
sizes 1, 2 and 50 and asserts each delivery ID appears exactly once in order.

Cursors are bound to their hook: a cursor issued for another hook, a different
version, a malformed field or a non-positive sequence returns `400`. A cursor
is only comparable to retained history; operator SQL pruning or a PITR rewind
can move it.

## Legacy `after=N` (kept in compatibility only, lossy)

`after=N` returns deliveries whose `sequence` is greater than `N`, which the
service evaluates as `(sequence, id) > (N, max-uuid)`. Any retained delivery
that shares `sequence = N` is skipped, so walking `after=last item's sequence`
(including via `next_after`) **cannot** return every delivery of a history with
duplicate sequences. It makes no lossless guarantee and is not a substitute for
`next_cursor`. `after` and `cursor` cannot be combined (`400`).

## Uniform limits

Any `limit` between 1 and 100 is accepted, so page sizes are not restricted to
one value; the completeness guarantee above applies to each of them.
