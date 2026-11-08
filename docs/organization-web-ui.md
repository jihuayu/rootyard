# Organization, member and team administration web UI (partial #87)

**Status: PARTIAL implementation of issue #87.** This slice delivers only the
organization / member / team administration pages under `/web/organizations`.
Usage, recovery and integration administration UI are **not** delivered, no
organization creation form is included, and no claims are made about them.

## Pages

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/web/organizations` | Keyset-paginated list of organizations with a direct membership |
| GET | `/web/organizations/{slug}` | Overview: organization version, created time, member/team/audit counts |
| GET | `/web/organizations/{slug}/members` | Keyset-paginated member list with role/version and remove actions |
| GET | `/web/organizations/{slug}/teams` | Keyset-paginated team list with member counts and a create form |
| GET | `/web/organizations/{slug}/teams/{team}` | Team detail with a keyset-paginated member list, add and remove actions |
| POST | `/web/organizations/{slug}/members` | Add a member, or set a role when `expected_version` is supplied |
| POST | `/web/organizations/{slug}/members/{username}/remove` | Remove a member |
| POST | `/web/organizations/{slug}/teams` | Create a team |
| POST | `/web/organizations/{slug}/teams/{team}/members` | Add an organization member to a team |
| POST | `/web/organizations/{slug}/teams/{team}/members/{username}/remove` | Remove a team member |

`/ui/organizations` aliases are intentionally not part of this slice.

## Authorization model

Every page and action reuses the existing organization backend instead of a
parallel implementation:

- The slug is resolved with the same `org_id` lookup and the token scope gate
  (`NamespaceAction::OrgRead`) plus the direct membership role check that the
  JSON API uses. A non-member receives the historical `404`; a token without an
  organization grant (restricted token) receives `403`.
- Mutation handlers call the existing `organizations::handlers` functions
  (`put_member`, `delete_member`, `create_team`, `put_team_member`,
  `delete_team_member`) after normalizing the browser credential with the shared
  web helper. There is no HTTP self-call and no second copy of the role,
  read-only, restricted-scope, last-admin or audit logic.
- Only an organization `admin` whose token scope allows `org:members_write`
  (`org:teams_write`) sees member (team) forms. A read-only token, a restricted
  token without the grant, or a lower organization role renders the list without
  any mutation form. This is presentation only: the backend re-authorizes every
  mutation, so hiding a form is never the enforcement.
- Cookie sessions are bound to the existing `/web` middleware: the Origin must
  match the request host, the `rootyard_session` cookie is `HttpOnly` and
  `SameSite=Strict`, and every mutation needs the `X-CSRF-Token` header that the
  first-party script copies from the readable `rootyard_csrf` cookie. Cross-origin
  or CSRF-less cookie mutations are `403` before a handler runs. Bearer API
  callers keep the documented non-browser contract of the other `/web` routes.

## Keyset pagination

All four lists are complete, bounded keyset traversals (`limit` 1..100, default
25) and never silently truncate at a fixed first page:

- organizations: `(namespace slug, organization id)`
- members: `(username, user id)`
- teams: `(team slug, team id)`
- team members: `(username, user id)`

Each cursor is an opaque, URL-safe `pagination::encode` value bound to the
actor, organization (and team for the team-member list) and list kind. Replaying
a cursor for another actor, organization, team or list kind is `400`; the cursor
never bypasses authentication or membership. A page that has more rows renders a
`Next page` link carrying the same cursor and limit; the final page renders no
link. Renames or membership changes move ordering keys, so a traversal is not a
snapshot.

## Forms, versions and replay

The HTML forms submit JSON through the shared `/web/app.js` handler. Every
existing member row carries a hidden `expected_version` equal to the version
currently rendered, so the backend's optimistic-concurrency check rejects a
stale form with `409`. An invalid or non-positive `expected_version` is `400`,
never treated as "no version". Only a completely absent field means "new
membership"; an explicitly empty value is `400`. A stale form carrying a
version for a membership removed elsewhere is `409`: it cannot recreate the
membership.

The add form is create-only. The decision and the write happen in the same
backend transaction, after the organization admin role check
(`put_member_atomic(..., create_only = true)`); a duplicate add is `409` and a
non-admin caller cannot tell an existing from a missing target. The web layer
performs no preflight lookup of users, memberships or teams: every such check
lives behind the same backend authorization, so unauthorized callers receive
the same response for existing and missing targets.

A repeated team-member add remains the historic idempotent `200` response with
the same `{"member":true}` body, but no second `organization.team.member.added`
audit row is written because no state changed. A repeated remove is `404` and
also adds no audit row.

Organization member/team API endpoints do not accept `Idempotency-Key`; their
mutation contract is the membership `expected_version` CAS (plus the last-admin
trigger). No idempotency-key storage or migration was added for this slice.

## Rendering safety

Every rendered value is passed through `escape_html`; identifiers are also
validated before use. Pages are served with `Cache-Control: no-store`, a
restrictive CSP (`default-src 'none'`, `script-src 'self'`,
`form-action 'self'`, `frame-ancestors 'none'`), `X-Content-Type-Options:
nosniff`, `X-Frame-Options: DENY` and `Referrer-Policy: no-referrer`. No API
token, browser session secret or CSRF value is ever placed in page source or a
URL; the CSRF token stays in its own `SameSite=Strict` cookie and is read by the
first-party script.

## Verification harness

`tests/organizations_web.py` is a runnable native harness. It starts the actual
binary against a disposable PostgreSQL schema, creates the organization, extra
accounts, members, roles and teams through the real CLI/API, and then drives the
web pages and forms over HTTP:

- complete keyset traversals of all four lists (no first-100 truncation);
- private organization cross-user `403`/`404`, including restricted tokens;
- read-only session mutation `403` and absent mutation forms;
- missing/wrong CSRF and cross-origin cookie mutations `403`;
- team-name script escaping and absence of tokens/secrets in page bytes;
- stale `expected_version` CAS `409`, an explicit blank version `400`, and a
  stale form that cannot recreate a removed membership (`409`);
- a non-admin member receives identical `403` bytes for existing, non-member and
  nonexistent member targets, and for existing/missing team and target probes;
- web add/remove flows for members and team members, including a duplicate team
  add that adds no second audit row and a repeated remove that is `404`.

```sh
ROOTYARD_TEST_DATABASE_URL=postgres://... python3 tests/organizations_web.py \
  --binary target/debug/rootyard --report /tmp/organizations-web.json
```

## Known limitations of this slice

- No organization creation/rename/delete or ownership-transfer UI; those API
  surfaces remain as they were (transfer is explicitly unsupported).
- No team edit/delete UI because the organization API exposes no such mutation;
  a team can be created and its membership managed.
- The JSON API keeps its historical upsert contract when no version is sent; the
  create-only precondition is a web call-site flag on the shared backend, not a
  new public API field.
- A duplicate team-member add still reports `"member":true` in the historic
  response even though no row changed; only the audit emission is suppressed.
- Listing ordering is keyset by name/slug, not a stable inventory across
  renames, backup restores or concurrent inserts.
- Usage, recovery and integration administration UI (other #87 areas) are not
  implemented.
