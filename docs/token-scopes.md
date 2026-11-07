# Personal access token scopes (schema 136)

> **Status:** the authorisation helpers, the discovery predicates, the common
> repository/namespace action enforcement and the browser-login rejection are
> wired in *this* integration branch. A private management API/UI for restricted
> PATs is staged separately (`/api/tokens`, `/api/sessions`,
> `/web/settings/tokens`, `/web/settings/sessions`; see
> `docs/token-management.md`), but it is **not** released: the Git CAS
> parent-token lock is still missing, exact browser-child inheritance for a
> restricted parent remains unimplemented, and the native management suite has
> not been executed by the implementation worker. The existing CLI
> `create-token` continues to issue unrestricted tokens and is unchanged. The
> schema/backup contract is now schema 136 / backup format 12 with real
> SQL-generated fixtures; the native format12 legacy135 restore drill has not
> been executed yet, so this remains a private integration branch and is not
> evidence that schema136 is production ready. Do not publish or deploy it.

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
`src/token_scopes/tests.rs`: no production issuance helper exists while the
API/CLI/UI is unwired.

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

## Release blockers (not claimed as done)

* No public issuer: no API, CLI flag or UI creates or edits restricted grants.
  Seeding restricted authority requires SQL in a test schema. This issue cannot
  be counted complete while that remains true.
* The late repository scope check (`authorize_repository_late`) takes `FOR SHARE`
  until commit **only when the caller supplies a real transaction**. A bare
  auto-commit `GenericClient` — which the Git HTTP publication path still uses —
  gets only the instantaneous statement check. The parent-token lock held across
  the Git CAS is therefore still a release blocker for Git-backed writes with
  restricted tokens; this branch does not claim it.
* `ryj_` CI credentials are independent; scopes cannot grant trusted-check or
  operator identity.

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
* `tests/pat_scope_auth.py` is the native end-to-end harness. It has **not been
  executed** in this branch (no cargo build, no native run): it needs
  `ROOTYARD_TEST_DATABASE_URL` and a built binary. It asserts exact status codes
  and shapes for: restricted list/metadata (200/403), empty grant set
  (`200 []` + `403`), grant-scoped issue create (`201`) vs read-only issue create
  (`403`), organisation-team RBAC + grant discovery, grant deletion (`403`), token
  revocation (`401`), legacy unrestricted read/write, and restricted-parent
  browser login (`POST /web/login`, form-urlencoded, `Origin` set → `403` with no
  `Set-Cookie`).

## Contract status

`schema/136_catalog.sql` (the frozen 135 catalog projection query copied
unchanged) and the three `schema/136_*_catalog.json` fixtures were generated
from real PostgreSQL 17 databases with the reviewed SQL migration path
(`tests/schema_contract.py --sql-migrate --write`). The backup code now uses
format 12 / schema 136, keeps format 11 frozen at schema 135, and accepts a
genuine format11/schema135 archive only with
`--allow-legacy-schema135`, upgrading it through migration 136 in the same
restore session. The old format 4-10 contracts and their opt-ins are unchanged.

Not yet verified: no cargo build, clippy run, native format12 restore drill or
`tests/backup_legacy135_scopes.py` execution was performed in this task. The
shared legacy runner now targets schema 136 for the 132/133/134/135 source
profiles and checks the restored PAT columns, token-scope tables and legacy
tokens' `is_restricted = false` default, but it still requires the coordinator's
prebuilt legacy binary. Native execution remains the publish gate.
