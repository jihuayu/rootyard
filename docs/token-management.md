# Token and browser-session management (candidate)

The schema-136 / backup-format-12 candidate includes scoped PAT management, browser settings and the parent-token lock held through Git CAS. The coordinator ran all 15 [management native cases](acceptance/round5-token-management-evidence/management-native.json) successfully on source `a6e4200`, binary `c4d0ef514e45682b6bc554cc137630b720ea3bb39d12499458dbd15169f42d7d`; the [build receipt](acceptance/round5-token-management-evidence/management-build.json) binds compiled inputs. The three added regressions verify self-rotation, self-revocation and current browser-session revocation. Fresh authority checks follow target locks and precede intentional self-revocation; nonself targets retain the final verification. Luna Max found no remaining P1/P2 in the focused self-revocation correction.

All three [native CAS race cases](acceptance/round5-token-management-evidence/cas-native.json) passed on the earlier source `ba9a443`, binary `17606cc7a61225069ba2194b56ae24e05e5919df9488c9d26cac6aa60b83ff2d`, with its [own build receipt](acceptance/round5-token-management-evidence/cas-build.json). Later Rust changes resolve organization slugs through namespaces and correct the self-revocation commit boundary. The CAS report covers its recorded earlier candidate, not those later management-only changes. Six no-grant proof tests passed, including identity tampering and live-journal rejection.

This is not deployed or a complete issue-82 acceptance. Restricted parent tokens are rejected at browser login so their authority cannot widen; exact restricted browser-child inheritance remains unsupported. CI/job/trusted-credential regressions, genuine legacy archive qualification on the combined manager and a final integrated review remain outstanding. The management suite does not exercise CAS; its retained older notes about a separate CAS branch are superseded by the separate race invocation above.

## API (Authorization header only)

All routes accept only `Authorization` (Bearer or Basic API credential) and use
`auth::authenticate`. They never read browser cookies, `Origin`, or any
"browser" marker header, so an API request cannot claim browser authority.

| Method | Path | Result |
| --- | --- | --- |
| `GET` | `/api/tokens?limit=&after=` | Own `kind='api'` tokens, keyset page (default 50, max 100) |
| `POST` | `/api/tokens` | Create an explicitly restricted token; secret returned once |
| `GET` | `/api/tokens/{id}` | Safe metadata only |
| `PATCH` | `/api/tokens/{id}` | Replace the complete grant set (narrowing only) + optional rename, under `expected_scope_version` |
| `DELETE` | `/api/tokens/{id}` | Idempotent owner revoke (204); cross-user always 404 |
| `POST` | `/api/tokens/{id}/rotate` | Atomic rotation; new secret returned once; repeat 409 |
| `GET` | `/api/sessions` | Own live `kind='browser'` sessions (keyset, default 50, max 100) |
| `DELETE` | `/api/sessions/{session_token_id}` | Revoke own browser token/session row by `UPDATE ... revoked=true` |

Create/rotate responses carry `Cache-Control: no-store` and
`X-Content-Type-Options: nosniff`. Lists and reads never contain a digest,
plaintext secret, CSRF value, session cookie, or credential.

### Create contract

* `display_name` is required, 1..80 non-control characters.
* `expires_in_days` defaults to 30 and must be 1..365; infinite tokens are not
  offered.
* New tokens are always `is_restricted = true`. An empty grant set is an
  explicit deny-all; it is never "all repositories".
* At most 128 grant rows (repository + namespace actions) per token. Actions are
  a fixed enum, de-duplicated server-side; unknown actions are rejected.
* Repository actions require the actor's current role for that action
  (`contents_read`/`repo_read`/... => read, `issues_write` => triage,
  write actions => write, `repo_admin`/`members_admin` => admin, `hooks_admin`
  => maintain). Organisation actions require current membership:
  `org:read` => read, `org:members_write`/`org:teams_write` => admin.
* Repository and namespace grants occupy separate tables; an organisation grant
  can never become a repository grant or account-wide organisation admin.
* Legacy CLI `create-token` still issues unrestricted tokens; its behaviour is
  unchanged.

### PATCH contract

* `expected_scope_version` is required and compared under `FOR UPDATE`; a stale
  value is `409`.
* The submitted complete set must be a subset of the existing grant set;
  adding an action or a repository/namespace is `403`.
* A legacy unrestricted token may become restricted (the requested set is then
  the whole grant set). `is_restricted` never goes from `true` to `false`.
* Grants are replaced and `scope_version` is incremented in the same
  transaction as the `FOR UPDATE` token lock.

### Rotation contract

* Atomically mints a fresh 256-bit secret (only its SHA-256 digest is stored),
  copies the re-validated scopes, `read_only`, expiry and display name, and
  revokes the old row in the same transaction.
* Every copied grant is re-checked against the actor's current role. **Any**
  validation failure (lost role, non-ready repository, database error) aborts
  the whole rotation before a new row or revocation exists. It never silently
  drops a scope; callers that lost a role must narrow the scope first.
* Rotating an old/revoked/expired row returns `409`. There is no plaintext
  idempotency replay store.
* Revocation is idempotent for the owner; cross-user targets are always `404`
  and no full-table token delete exists.

## Locking

Every management transaction takes a per-user advisory transaction lock first,
then re-verifies the issuer `FOR SHARE` (live, unrestricted, writable for
mutations), then locks the target `FOR UPDATE` with a `user_id` ownership
predicate. Serialising same-user management prevents reciprocal
SHARE -> UPDATE upgrades from deadlocking; the pool `lock_timeout` bounds waits
against a slower publisher/reader instead of hanging the pool.

Restricted tokens and read-only tokens cannot act as managers: restricted
issuers are `403` for list/read/manage, read-only issuers are `403` for
mutations. Sessions are limited to the actor's own browser tokens.

## Browser UI

* `/web/settings/tokens` — create (name, expiry, read-only, one repository +
  actions, one organisation + actions; no action is checked by default so the
  least-privilege empty set stays explicit), list safe metadata, narrow a
  token's complete scope set via checkboxes, rotate, revoke.
* `/web/settings/sessions` — list live sessions and revoke them.
* All pages use `html_response` (CSP, `nosniff`, `no-store`, frame denial,
  referrer policy) and HTML-escape every dynamic value. The secret is delivered
  once into a `no-store` fetch response and written into the page with
  `textContent`; it never appears in a later page, URL, or query.
* Mutations go through the existing `session::middleware`: HttpOnly cookie,
  Origin match, and `X-CSRF-Token` header. **Ambient Basic** credentials are now
  rejected for web mutations (403) across all web/UI mutation routes; Bearer
  stays an explicit non-ambient credential. This closes the bypass where a
  browser-supplied Basic header skipped Origin/CSRF. The browser parent must
  also be an active, unrestricted API token.
* No internal implementation detail or release state is rendered on product
  pages. Repository/organisation selectors reuse the current bounded visibility
  queries (limit 100, no 1000-row hard truncation).

## Verification status

* `tests/token_management.py --binary --report` is the native end-to-end suite;
  the coordinator must run it against a real binary and PostgreSQL. It covers
  create-once/digest-only/no-secret lists, owner 404, restricted and read-only
  issuer 403, PATCH subset + CAS 409, rotation old-401/new exact scopes/repeat
  409, idempotent revoke, expiry bounds and time travel, keyset/actor cursors,
  session own-only revoke, cookie/CSRF/Basic cross-origin web mutations, and a
  non-ready-repository rotation abort that leaves the old token active.
* SQL is used only through the existing Harness bootstrap channel for repository
  ids, digest verification and two fixture manipulations (expiry time travel,
  repository provisioning state); no restricted token, grant, or session is
  SQL-seeded.
* Not run here: Cargo build/test, the native suite, rustfmt (the binary is not
  installed in the worker environment). `src/token_management/*` and
  `src/web/tokens.rs` are the only files this change adds; legacy handlers were
  not reformatted.
