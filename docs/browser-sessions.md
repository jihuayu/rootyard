# Browser sign-in and sessions

Rootyard exchanges an existing CLI-issued API credential for a short-lived
browser session. Visit `/web/login` and enter the username and API token once.
The server verifies the API token, creates a separate `browser` token plus a
CSRF-bound `web_sessions` row, stores only SHA-256 digests in PostgreSQL, and
redirects to a normalized `/web/` or `/ui/` return target. The API token is never
placed in a URL, cookie, or rendered page.

The `rootyard_session` cookie is HTTP-only, `SameSite=Strict`, and `Secure` on
HTTPS. Plain HTTP cookies are allowed only for explicit loopback development
hosts. Deployments behind a TLS proxy must forward the original HTTPS scheme.
The separate readable `rootyard_csrf` cookie supplies the token required in
`X-CSRF-Token` for cookie-authenticated Issue and PR mutations. The server also
checks the browser Origin against the request host. Sign-out revokes the
persisted session and its browser-only token before clearing both cookies.
Expired or revoked sessions lose access on the next request.

The 68-character session secret embeds a parent API-token UUID plus a random
nonce. The UUID is an identifier, not an API secret, and the stored digest binds
the whole secret: changing the embedded UUID makes the session lookup fail
closed. HTTP admission checks that the parent API token is still unrevoked and
unexpired, so revoking or expiring the API token denies the browser session on
new requests. Browser sessions created before this upgrade are unparented and
fail closed; users must sign in once again after deployment.

Raw `rootyard_token`, `token`, and `X-Rootyard-Token` Web credentials are no
longer accepted. Only the login form exchange is supported. A browser-session
secret is rejected as a Git or `/api` Bearer/Basic credential and is rejected on
Web routes unless it is presented through the matching `rootyard_session`
cookie. An explicit API `Authorization` header takes priority over an unrelated
stale browser cookie.

Parent revocation is checked when a request is admitted. Once a Web write has
passed admission, the browser token, session row, and repository RBAC are
rechecked at normal transaction commit, but the parent token is not held or
rechecked for the whole in-flight request. A narrow write already in progress
may therefore finish after parent revocation; immediate interruption of
admitted operations is a separate concern. Revoke the child session directly
when that stronger bound is required. Browser session tokens cannot authenticate
Git or `/api` routes. CLI-issued API tokens remain independent, retain their
existing read-only and revocation rules, and never appear in Web page source. A
read-only API credential can open a read-only browser session but cannot perform
Web mutations.

## Expired-session retention and bounded garbage collection

Both the serving process and the PostgreSQL-only `worker` process run the same
background cleanup loop for expired browser sessions. The batch caps and SQL deadline are fixed; cadence and retention are
operator-configurable:

- **at most 128 selected token candidates and at most 128 rows deleted** per
  statement per cycle. The session pass locks and deletes one oldest-first
  window of `web_sessions` rows. The token pass first materialises one window of
  at most 128 expired `browser` tokens in `(expires_at, id)` index order with
  `LIMIT` before any reference probe, and only then probes those 128 rows
  against the durable foreign-key roots. A large population of permanently
  retained expired tokens therefore can no longer make a cycle scan an unbounded
  candidate prefix;
- **oldest expiry first** with `FOR UPDATE SKIP LOCKED`, so an in-flight
  authorization or commit lock is honored instead of waited on;
- the default cycle interval is 60 seconds and the default retention after a
  session's expiry is 7 days. `ROOTYARD_SESSION_GC=false`,
  `ROOTYARD_SESSION_GC_INTERVAL_SECONDS` and
  `ROOTYARD_SESSION_GC_RETENTION_SECONDS` (zero is allowed and still never
  deletes an unexpired row) are the only operator knobs. The public
  `purge_once` entry point rejects a negative retention before any SQL, so a
  future caller cannot move the cutoff into the future and delete active rows;
- each statement runs in its own transaction with a server-side
  `statement_timeout` of at most 5 seconds. The token cutoff uses
  `statement_timestamp()`, which is stable within a statement and remains
  indexable on `(expires_at, id)`;
- a hard cancellation stops the loop between cycles and the shutdown path
  awaits the task, so no GC task is orphaned.

The token pass walks forward with a small keyset cursor held only in process
memory. The cursor is the `(expires_at, id)` position of the last *candidate
window* — not the last deleted row — so a window whose 128 candidates are all
retained still advances the scan: later, deletable children are reached instead
of the loop retrying the same first 128 rows forever. The cursor is written only
after a batch commits; a failed or rolled-back cycle retries from the same
position. When a window is shorter than the limit (including an empty one) the
scan has reached the end of the eligible range and the cursor returns to the
head, so newly expired rows are seen again. A process restart simply starts at
the head, and `SKIP LOCKED` rows skipped past by another worker are picked up by
a later pass; repeated re-scanning of already-retained rows is expected and is
bounded by the per-statement 128-candidate limit and the statement timeout. The
cursor is not persisted, exactly like the rest of this best-effort loop, and no
migration or global in-memory map is involved.

The candidate window is one of two fixed statements — a first window and an
after-cursor window whose only difference is a strict row comparison
`(expires_at, id) > ($cursor)::text::timestamptz, $id::uuid`. The cursor expiry
is returned from SQL as `timestamptz::text` and re-parsed by PostgreSQL, so
microsecond precision and the session time zone survive the round trip. Both
branches keep the partial `tokens (expires_at, id) WHERE kind = 'browser'` index
usable; there is no `cursor IS NULL OR ...` predicate that would re-filter a
large prefix on every cycle. The delete stage rechecks `kind = 'browser'`, a
non-null expiry, the retention cutoff and all six reference roots, so a
reference that appeared between the candidate read and the delete still retains
the row.

Order matters. Expired `web_sessions` rows whose token kind is `browser` and
whose expiry is already past retention are purged first; they only ever hold
CSRF state and never authorize a request on their own. Only then are expired
`browser` child tokens considered. A child token is retained while any durable
foreign-key root still references it: `git_operations`, `git_ref_admissions`,
`ci_checkout_jobs`, `ci_checkout_delegations`, and `cluster_operator_tokens`, or
while its `web_sessions` row still exists. Migration 133 adds the index-only
support for those reference probes. Nothing is deleted by broadening a foreign
key to `ON DELETE CASCADE`, and no audit or Git history metadata is removed to
make cleanup succeed. The session-row deletion statement is unchanged.

`api` tokens — including operator-granted cluster tokens — are never GC input,
revoked or not. A browser token that is merely revoked or merely expired is not
early-deleted either; it becomes eligible only after its expiry plus the
retention window. If a token is retained by a reference root, only its expired
session row is removed, so every later authorization attempt still fails closed.

Failures are reported through the shared application error classification: the
loop logs a fixed status and message plus the validated SQLSTATE classification,
never PostgreSQL's message text, connection strings, row content or tokens.
Configuration errors name only the fixed `ROOTYARD_SESSION_GC*` variables.

The parent API token id is encoded only in the cookie-held session secret; there
is deliberately no parent/child SQL mapping to garbage collect. After a parent
revocation, the browser child still expires within the 12-hour session lifetime
and is then subject to the same retention window, which bounds eventual cleanup
without changing the admission-time parent validation described above.

### GC and browser-session metrics

The private metrics listener described in `docs/metrics.md` exports this loop's
counters and the stored browser-session gauges. Every series has a fixed name
and a fixed series count; none of them carries a tenant, account, session,
token, cookie, path or error-message label.

- `rootyard_session_gc_cycles_total` counts GC cycles whose session and
  token passes both committed, `rootyard_session_gc_session_rows_deleted_total`
  and `rootyard_session_gc_tokens_deleted_total` count rows whose own short
  transaction committed as deleted, and `rootyard_session_gc_failures_total`
  counts failed cycles. Each pass is recorded immediately after its `COMMIT`,
  so a cycle whose session pass committed and whose token pass then failed
  raises the failure counter while still counting the committed session rows;
  a successful cycle never counts its rows twice. They are rendered from the
  same counter set the loop increments (`Counters::snapshot()`), so there is
  no second, divergent count. All four are process-lifetime values: a restart starts at zero, and
  each increment saturates at `u64::MAX` instead of wrapping, so a saturated
  counter never reads as a decrease. `serve` and `worker` each report only
  their own process's cycles.
- `rootyard_browser_web_sessions` and `rootyard_browser_tokens` count every
  stored row of that kind, including revoked and already expired rows. A
  signed-out session is revoked rather than deleted, so it stays counted until
  the GC removes it after expiry plus retention. API and operator-issued tokens
  are excluded from the token gauge by `kind`, revoked or not.
- `rootyard_expired_browser_session_oldest_age_seconds` and
  `rootyard_expired_browser_token_oldest_age_seconds` are the age, measured by
  the database clock inside the snapshot statement, of the oldest row whose
  expiry is already in the past. Unexpired (active) rows never become the
  oldest sample, an empty set reports `0`, and the result is clamped at `0` so
  a clock adjustment cannot produce a negative age.

A high oldest-expired-token age is not by itself evidence of a stuck collector.
A token referenced by one of the six durable roots, or still carrying a
`web_sessions` row, is deliberately retained, so its stale expiry keeps that
age high while cleanup is behaving as designed. Alerting on the age gauge alone
would page for correct retention; it has to be read together with
`rootyard_session_gc_failures_total`, `rootyard_session_gc_cycles_total` and
the two row-count gauges.

Both row counts may use an index-only or a full relation scan, so their cost is
bounded only by the snapshot's server-side four-second statement timeout and
the five-second HTTP scrape timeout, not by the GC batch limit. If any part of
the snapshot fails, including these subqueries, the endpoint answers HTTP
`503`, exports `rootyard_postgres_up 0`, omits every database-derived gauge —
including all four browser-session gauges, rather than reporting a false zero —
and still exports the process-local GC counters above.

The native drill `tests/session_gc_metrics.py` starts this loop with a
one-second interval and the private metrics listener, seeds one expired browser
session/token, and installs a temporary PostgreSQL `BEFORE DELETE` trigger on
`tokens` that raises SQLSTATE `23503` for `browser` rows only. The session pass
must commit while the token pass fails; the drill asserts the failure and
session-deletion counters grow, the token-deletion counter does not, and the
real rows reflect exactly that. It drops the trigger, waits for the next
committed token pass and the real token deletion, then renames
`event_deliveries` to force a snapshot failure and checks HTTP `503`, omission
of every database-derived gauge and retention of all four GC counters. That
script has not been executed against a built binary as part of this change;
native acceptance is pending.

No `EXPLAIN` output is captured by the regression suite, so no claim is made
about measured scanned rows or about which plan the planner picks; the index
shapes are asserted from the migration source and `pg_indexes` only.

The candidate limit bounds the number of reference probes, not physical
PostgreSQL row or index-page visits. No physical scan-count or EXPLAIN
measurement is claimed here. Rows skipped while locked are revisited on a
later wrap; there is no fixed latency guarantee under an endlessly growing queue.
