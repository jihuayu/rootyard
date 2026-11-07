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
background cleanup loop for expired browser sessions. Its duration and the rows
it deletes per statement are bounded; the number of rows it inspects is not:

- one fixed-size batch of at most 128 session rows and at most 128 child tokens
  deleted per cycle, oldest expiry first, with `FOR UPDATE SKIP LOCKED` so an
  in-flight authorization or commit lock is honored instead of waited on;
- the default cycle interval is 60 seconds and the default retention after a
  session's expiry is 7 days. `ROOTYARD_SESSION_GC=false`,
  `ROOTYARD_SESSION_GC_INTERVAL_SECONDS` and
  `ROOTYARD_SESSION_GC_RETENTION_SECONDS` (zero is allowed and still never
  deletes an unexpired row) are the only operator knobs. The public
  `purge_once` entry point rejects a negative retention before any SQL, so a
  future caller cannot move the cutoff into the future and delete active rows;
- each statement runs in its own transaction with a server-side
  `statement_timeout` of at most 5 seconds. The deletion re-reads
  `clock_timestamp()` inside the deleting transaction, so a database clock that
  moved, a concurrent cleanup process, a restart, or a rolled-back cycle cannot
  turn into an early delete. The `NOT EXISTS` foreign-key probes run before
  `ORDER BY`/`LIMIT`, so one cycle may inspect many referenced expired tokens;
  only the statement timeout bounds its duration, and no scan-row bound is
  claimed;
- a hard cancellation stops the loop between cycles and the shutdown path
  awaits the task, so no GC task is orphaned.

Order matters. Expired `web_sessions` rows whose token kind is `browser` and
whose expiry is already past retention are purged first; they only ever hold
CSRF state and never authorize a request on their own. Only then are expired
`browser` child tokens considered. A child token is retained while any durable
foreign-key root still references it: `git_operations`, `git_ref_admissions`,
`ci_checkout_jobs`, `ci_checkout_delegations`, and `cluster_operator_tokens`, or
while its `web_sessions` row still exists. Migration 133 adds the index-only
support for those reference probes. Nothing is deleted by broadening a foreign
key to `ON DELETE CASCADE`, and no audit or Git history metadata is removed to
make cleanup succeed.

`api` tokens — including operator-granted cluster tokens — are never GC input,
revoked or not. A browser token that is merely revoked or merely expired is not
early-deleted either; it becomes eligible only after its expiry plus the
retention window. If a token is retained by a reference root, only its expired
session row is removed, so every later authorization attempt still fails closed.

The parent API token id is encoded only in the cookie-held session secret; there
is deliberately no parent/child SQL mapping to garbage collect. After a parent
revocation, the browser child still expires within the 12-hour session lifetime
and is then subject to the same retention window, which bounds eventual cleanup
without changing the admission-time parent validation described above.

Bounded monotonic counters (`cycles`, `session_rows_deleted`, `tokens_deleted`,
`failures`) live in the GC module for a later metrics surface; they carry no
per-session labels.
