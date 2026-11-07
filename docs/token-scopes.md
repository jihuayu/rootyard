# Personal access token scopes (schema 136)

> **Status:** the authorisation helpers, the discovery predicates, the common
> repository/namespace action enforcement and the browser-login rejection are
> wired in this private integration branch. The management API/UI and the
> parent-owned Git publication token lock are integrated. Real HTTP/DB/Git
> acceptance of their combined implementation is pending; no release is claimed.
> Restricted parent tokens are refused browser login, so this path cannot widen
> their scope. Restricted browser-child inheritance remains unsupported.
> The existing CLI still issues legacy unrestricted API tokens.


## Integration provenance

The module comes from `codex/round5-pat-scopes` (`dd1228f`, cumulative diff
`6abfddf..dd1228f`) applied *selectively* on top of the current main line
(schema 135 / backup format 11 at integration time; this branch now carries the
schema136 / format12 contract):

* Taken: `src/token_scopes.rs` (split below), `migrations/136_token_scopes.sql`,
  the explicit `RepoAction`/`NamespaceAction` call-site changes, the
  restricted-token discovery predicate, the browser-login rejection and
  `tests/pat_scope_auth.py`.
* Dropped from that branch: its own schema-reservation commits
  (`134_storage_identity_*`, `135_*metrics`) — this tree already carries the
  newer migration 134 foreign-key work and 135 worker-metrics work, so the old
  branch's earlier GC/FK/metrics state was never merged or overwritten.
* The old branch's large `organizations/handlers.rs` and
  `sharding/migration.rs` bodies were not copied over the current split
  (`organizations/listing.rs`, `sharding/migration_admin.rs`); the scope calls
  were added to the split modules instead.

## Data model

Migration `136_token_scopes.sql` adds to `tokens`:

* `is_restricted BOOLEAN NOT NULL DEFAULT false` — tokens that predate the
  migration keep their historical account-wide `read_only` semantics.
* `scope_version BIGINT NOT NULL DEFAULT 1 CHECK (scope_version > 0)` — bumped
  by every grant mutation.
* `display_name TEXT` — optional, 1..80 characters.

Grants live in `token_repository_scopes(token_id, repository_id, action)` and
`token_namespace_scopes(token_id, organization_id, action)`, both with composite
primary keys, `ON DELETE CASCADE` from tokens and the target, and an `action`
CHECK constrained to the fixed enum values in `RepoAction::as_str` /
`NamespaceAction::as_str`.

## Semantics

* A restricted token with no grant rows is denied everything. The empty set is
  never "all repositories" or "account admin": it lists zero repositories
  (`200 []`) and answers `403` for any repository metadata route.
* A repository grant never implies organisation administration, cluster
  operator status, or trusted-CI (`ryj_`) identity. Those remain separate
  authorities; scopes cannot be derived into them, and there is no wildcard
  scope or dynamic user label.
* `read_only` intersects with scopes: mutating actions (`*_write`,
  `hooks_admin`, `members_admin`, `ci_dispatch`, `repo_admin`,
  `org:members_write`, `org:teams_write`) are denied even when granted. A
  read-only token that carries `issues_write` still gets `403` on
  `POST /api/repos/{owner}/{name}/issues`.
* Repository and organisation creation is refused for restricted tokens
  (`reject_restricted_create`), because no create scope exists yet. Legacy
  unrestricted tokens keep the historical behaviour.

## Authorisation helper

`authorize_repository` / `authorize_namespace` take a real
`tokio_postgres::Transaction` and re-read the token by `token_id` + `actor_id`
inside that transaction: it must be unrevoked, unexpired and `kind = 'api'`,
and is locked `FOR SHARE OF t` until the transaction ends. Expiry uses
`clock_timestamp()`, not the transaction's fixed `now()`, so a request that
started before expiry is rejected once the token expires. Invalid token → 401
(`ScopeDenial::InvalidToken`); live token without a covering grant → 403
(`ScopeDenial::Forbidden`). Errors never contain SQL text or credentials.

This helper is **not** an RBAC replacement. Callers must first check that the
actor currently holds the required repository/org role; scopes only narrow.

## Discovery

For a restricted token, `GET /api/repos` and `/web/repos` require **both** the
current RBAC visibility predicate (owner, collaborator, repository team,
organisation membership, organisation team) **and** an exact `repo_read` grant
row for that repository. Other grants (`issues_read`, `contents_read`, …) never
expose repository metadata or the overview page.

Caveat that must not be overstated: `organization_team_members` has a composite
foreign key to `organization_memberships`, so every organisation-team membership
row implies an organisation membership row. The added organisation-team
predicate is therefore parity with `members/rbac.rs` and `web/session.rs`
(defence in depth); the harness cannot isolate that predicate from the
organisation-membership predicate, and this branch makes no such claim.

## Grant mutation protocol

Any future grant writer must `SELECT ... FOR UPDATE` the same token row, mutate
grants and increment `scope_version` in one transaction. `narrow_repository_scope`
and `revoke_repository_scope` implement this and can only remove rows; they
never insert or widen. Grant insertion (`grant_repository_for_test`,
`grant_namespace_for_test`) is `#[cfg(test)]`-only and lives in
`src/token_scopes/tests.rs`: the shared token-management service now issues and updates restricted tokens
under a per-user management lock and token row lock; its native acceptance is pending.

## Browser sessions

* `POST /web/login` (form-urlencoded `username` + `token`, browser `Origin`
  matching the service origin) still opens a session for an **unrestricted API
  token**, exactly as before this change.
* A **restricted** parent token is refused with `403` and no `Set-Cookie`: the
  response is the login page, never a session. The insert that mints the browser
  child token additionally requires `p.is_restricted = false`, so a restricted
  parent cannot become a session by another path.
* Browser child tokens are rejected by the scope helper itself (`kind = 'api'`
  only), and `token_is_restricted` treats only non-restricted browser children
  as live for scope purposes. Exact parent binding/inheritance for restricted
  tokens remains unimplemented future work.

## Publication boundary and remaining acceptance

After slow quota checks, the Git coordinator asks the existing publication owner
transaction to lock and verify the token before the grant marker or ACK. Lock
order is exact-ref advisory, repository advisory, local writer, token FOR SHARE,
then native CAS. No extra pooled connection is acquired. If publication locks
first, revocation/narrowing waits until child quiescence and journal settlement;
if revocation commits first, late authorization denies publication. Closed
receivers are checked before and after authorization. Native barrier acceptance
of this new boundary is still pending, as is the management HTTP/rotation/CSRF
suite. CI and operator/trusted-check authority remain independent.

## Verification

* Unit tests (`src/token_scopes/tests.rs`) cover stable action text, mutating
  classification, empty-grant denial, per-repository exactness, read-only
  intersection and display-name bounds.
* Ignored PostgreSQL tests exercise the real path against a random owned schema
  using `db::migrate_client` and real token/grant transactions (empty-grant
  denial, other-repository denial, exact action allow, read-only write denial,
  revoked/expired denial, grant rollback) plus two timing/locking regressions: an
  expiry after the reader's transaction timestamp is still rejected by
  `clock_timestamp()`, and a `FOR UPDATE` grant writer is observed blocked via
  `pg_blocking_pids` until the reader commits. `FOR SHARE` is only meaningful
  because those readers hold a real transaction until commit.
* The Git-native publication fence harness is pending. Its initial psql
  termination, row-lock evidence and marker/SIGSTOP race defects are being fixed
  before execution; it is not accepted native evidence.
* Foundation executable SHA256
  `38ad0ba7c445db156514a5650c408b59ac8feaabec33001167b7980e1d38334e`
  from source `6a72c41` passed twelve scope HTTP cases and actual-binary schema136
  checks. These results predate management/CAS and do not validate those additions.

## Contract status

`schema/136_catalog.sql` (the frozen 135 catalog projection query copied
unchanged) and the three `schema/136_*_catalog.json` fixtures were generated
from real PostgreSQL 17 databases with the reviewed SQL migration path
(`tests/schema_contract.py --sql-migrate --write`). The backup code now uses
format 12 / schema 136, keeps format 11 frozen at schema 135, and accepts a
genuine format11/schema135 archive only with
`--allow-legacy-schema135`, upgrading it through migration 136 in the same
restore session. The old format 4-10 contracts and their opt-ins are unchanged.

That foundation executable also passed seven genuine format11/schema135 archive
cases using previous executable SHA256
`9faf71fd95691a358157be0442e2efc47b595a67d0aa3aa9d0404d5266c51a96`:
strict opt-in, one new authority for two repositories, migrated scope defaults,
revoked browser credentials, exact clone/fetch/fsck and intact source objects.
The coordinator retains these attested reports. The combined management/CAS
candidate still needs its own build receipt and native gates.
