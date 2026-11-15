# Personal access token scopes

> **Status:** the authorisation helpers, discovery predicates, common
> repository/namespace action enforcement, self-service PAT management (`/api/tokens*`,
> `/api/sessions*`, `/web/settings/*`), parent-owned Git publication token lock,
> and bounded restricted browser-child inheritance are integrated on `main`.
> Restricted API tokens can sign into `/web/login` to open bounded `browser`
> sessions that inherit their parent's live `read_only`, `is_restricted`, expiry,
> revocation, and grant set without widening, while management routes refuse
> restricted browser children with `403 Forbidden` and Git CAS keeps rejecting
> browser tokens fail-closed (`BrowserTokenUnsupported`).
> The existing CLI still issues legacy unrestricted API tokens.
> Schema 137 narrows the historical Git admission bypass in the membership
> trigger.


## Integration provenance

The module comes from `codex/round5-pat-scopes` (`dd1228f`, cumulative diff
`6abfddf..dd1228f`) applied *selectively* on top of the current main line
(schema 135 / backup format 11 at integration time). That integration produced
the historic **schema136 / format12 foundation**; the branch now carries
**schema 137 / backup format 13**, whose only change is migration
`137_historical_admission_projection.sql` replacing the `git_operations` branch
of `enforce_repository_actor_membership`:

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

Migration `136_token_scopes.sql` (the format12 foundation) adds to `tokens`:

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

`authorize_repository` / `authorize_namespace` (and the parent-aware
`*_with_parent` variants in `src/token_scopes.rs` /
`src/token_scopes/browser_parent.rs`) take a real `tokio_postgres::Transaction`
and re-read the presented token inside that transaction:

* Direct `api` tokens lock the presented row `FOR SHARE OF t` and require
  `kind = 'api'`, unrevoked, and unexpired under `clock_timestamp()` (not the
  transaction's fixed `now()`).
* When `identity.parent_token_id` is `Some(parent_id)` (browser session child),
  the `*_with_parent` entry points also join and lock the parent row
  `FOR SHARE OF t, p`, requiring both child `t` (`kind = 'browser'`) and parent
  `p` (`kind = 'api'`) to remain active and unexpired under `clock_timestamp()`,
  and check repository/namespace grants and `read_only` (`t.read_only OR
  p.read_only`) strictly against the bounded parent authority (`Identity::scope_token_id()`).
* Invalid/expired/revoked credentials return `401` (`ScopeDenial::InvalidToken`);
  a live token lacking a covering grant or write permission returns `403`
  (`ScopeDenial::Forbidden`). Errors never contain SQL text or credentials.

This helper is **not** an RBAC replacement. Callers must first check that the
actor currently holds the required repository/org role; scopes only narrow.

## Discovery

For a restricted token (including a restricted browser-child session resolved via
`Identity::scope_token_id()`), `GET /api/repos`, `/web/repos`,
`GET /api/orgs/*`, and `/web/organizations/*` require **both** the current RBAC
visibility predicate (owner, collaborator, repository team, organisation
membership, organisation team) **and** an exact `repo_read` / `org:read` grant
row on the effective scope token (`scope_token_id()`). Other grants
(`issues_read`, `contents_read`, …) never expose repository metadata or the
overview page.

Caveat that must not be overstated: `organization_team_members` has a composite
foreign key to `organization_memberships`, so every organisation-team membership
row implies an organisation membership row. The added organisation-team
predicate is therefore parity with `members/rbac.rs` and `web/session.rs`
(defence in depth); the harness cannot isolate that predicate from the
organisation-membership predicate, and this branch makes no such claim.

## Grant mutation protocol

Any grant writer (`token_management::service` and the test/helper paths
`narrow_repository_scope` / `revoke_repository_scope`) acquires a `SELECT ...
FOR UPDATE` lock on the target token row, validates current RBAC roles and subsets,
replaces/narrows grants, and increments `scope_version` in one transaction.
Grant insertion helpers (`grant_repository_for_test`,
`grant_namespace_for_test`) remain `#[cfg(test)]`-only in
`src/token_scopes/tests.rs`. Self-service token management routes
(`/api/tokens*`, `/api/sessions*`, `/web/settings/*`) acquire a per-user
advisory transaction lock before locking issuer `FOR SHARE` and target `FOR
UPDATE`, and are continuously exercised by `tests/token_management.py` in CI.

## Browser sessions

* `POST /web/login` (form-urlencoded `username` + `token`, matching browser
  `Origin`, TLS/loopback guard) accepts active `kind = 'api'` tokens — both
  **unrestricted** and **restricted** — and rejects `kind = 'browser'` tokens
  with `401` (`StatusCode::UNAUTHORIZED`) so browser children cannot mint chained sessions.
* When minting a `kind = 'browser'` child in `src/web/session.rs`, `login` copies
  `is_restricted = p.is_restricted`, clamps `read_only = ($4 OR p.read_only)`,
  and caps `expires_at = LEAST(clock_timestamp() + interval '12 hours', COALESCE(p.expires_at, clock_timestamp() + interval '12 hours'))`. No mutable grant rows
  are duplicated onto the child token.
* On every browser request, `validate_session` and `auth::authenticate` join
  child `t` and parent `p` live (`LEFT JOIN` read), and transactional guards in
  `auth::browser_parent` and `token_scopes::{browser_parent, *_with_parent}`
  lock child `t` and parent `p` (`FOR SHARE OF t, p`) so parent revocation,
  expiry, rotation, RBAC role loss, `read_only` flip, `PATCH` narrowing, or
  legacy unrestricted-to-restricted upgrade take effect immediately on already-minted
  browser cookies without widening authority.
* Restricted browser children are rejected with `403 Forbidden` on
  `/web/settings/tokens*`, `/web/settings/sessions*`, `/api/tokens*`, and
  `/api/sessions*` (via `verify_browser_parent` in `src/web/tokens.rs` and
  `verify_issuer` in `src/token_management/service.rs`), while `/web/logout`
  remains allowed (`303`) and `/api/*` continues rejecting browser cookies with `401`.

## Publication boundary and CI acceptance

After slow quota checks, the Git coordinator asks the existing publication owner
transaction (`auth::authorize_publication_window`) to lock and verify the token
via `lock_publication_tokens` / `authorize_repository_late_with_parent` before the
grant marker or ACK, and re-verify via `recheck_publication_tokens` before CAS.
Lock order is exact-ref advisory, repository advisory, local writer, token
`FOR SHARE`, then native CAS. No extra pooled connection is acquired. Git-CAS
continues rejecting non-`api` tokens fail-closed (`BrowserTokenUnsupported`),
keeping browser sessions outside direct Git publication while direct `api` tokens
retain full `FOR SHARE` revocation/narrowing fencing. If publication locks first,
revocation/narrowing waits until child quiescence and journal settlement; if
revocation commits first, late authorization denies publication. Closed receivers
are checked before and after authorization.

End-to-end HTTP, cookie/CSRF, revocation, legacy->restricted upgrade, discovery
pagination, and restricted browser-child inheritance flows are continuously
verified in CI (`verify` job + `Bind native regressions to the built binary and
source inputs`) via `tests/pat_scope_auth.py`, `tests/token_management.py`, and
`tests/web_repository_pagination.py`. CI and operator/trusted-check authority
remain independent.

## Verification

* Unit and PostgreSQL integration tests in `src/token_scopes/{tests.rs, browser_parent.rs}`
  cover stable action text, mutating classification, empty-grant denial, per-repository
  exactness, read-only intersection, `clock_timestamp()` expiry, `FOR SHARE`
  vs `FOR UPDATE` blocking (`pg_blocking_pids`), display-name bounds,
  `inherited_authority_narrows_to_parent_repo_and_read_only_flags` (`browser_parent.rs`), and
  `browser_child_inherits_parent_scopes_and_live_mutations` (`tests.rs`).
* Native CI `verify` runs `tests/pat_scope_auth.py --binary --report`,
  `tests/token_management.py --binary --report`, and
  `tests/web_repository_pagination.py --binary --report` against a compiled
  `rootyard` binary and PostgreSQL 17, binding reports with
  `scripts/native_report_manifest.py` (including required cases
  `pat_scope_auth=restricted.browser_child_inheritance`,
  `token_management=sessions.restricted_browser_child_inheritance`, and
  `token_management=sessions.legacy_upgrade_and_parent_rotation_live`).

## Historical provenance

Migrations `136_token_scopes.sql` and `137_historical_admission_projection.sql`
originally landed alongside the earlier `schema 136 / format 12` and
`schema 137 / format 13` milestones (sealed historical evidence snapshots live
under `docs/acceptance/`). The active database schema (`schema 149`) and current
backup/restore formats (`format 25` and `format 26`, including legacy upgrade
flags) are documented in [operations.md](operations.md) and
[backup-restore.md](backup-restore.md).
