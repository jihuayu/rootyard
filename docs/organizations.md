# Organization ownership policy

An organization has its own durable namespace ID. A repository's `owner_id`
and tenant-scoped metadata use that ID; no human user stands in for an
organization. Existing personal repositories retain their user ID as the
namespace ID. Namespace slugs are unique across people and organizations.

An organization administrator manages direct members and teams. A member's
effective repository role is the strongest direct organization, organization
team, repository collaborator, or repository team role. Removing an
organization member also removes their team memberships and immediately
removes inherited access. Workspaces remain private to their creating agent
even when another person administers the repository.

The last organization administrator cannot be demoted or removed. The API
returns `409 Conflict` for either attempt, and a database trigger guards
against concurrent or non-API changes that would orphan the organization.

Repository ownership is currently immutable. An administrator's
`POST /api/repos/{owner}/{name}/transfer` request returns `409 Conflict` and
leaves the repository unchanged. Moving just the owner column would strand
tenant-scoped rows and remote object keys; a future transfer requires a
recoverable rekey of those records and objects before this policy can change.

## HTTP API surface

- `GET /api/orgs` (paginated direct memberships; restricted tokens filtered by `org:read`), `POST /api/orgs`, `GET /api/orgs/{slug}`
- `GET /api/orgs/{slug}/members`, `PUT/DELETE /api/orgs/{slug}/members/{username}`
- `GET/POST /api/orgs/{slug}/teams`, `GET/PATCH/DELETE /api/orgs/{slug}/teams/{team_slug}` (CAS `expected_version` on `PATCH`; `DELETE` cascades `organization_team_members`)
- `GET /api/orgs/{slug}/teams/{team_slug}/members`, `PUT/DELETE /api/orgs/{slug}/teams/{team_slug}/members/{username}`
- `GET /api/orgs/{slug}/audit` (`maintain`/`admin` paginated organization audit feed)

Verified end-to-end across Git HTTP, LFS objects/locks, Forge issues/PRs/branch-rules, Git views, Workspaces, Web UI, server restart, and offline PostgreSQL backup/restore by `tests/organizations.py`, `tests/organization_pagination.py`, `tests/organizations_web.py`, `tests/backup_capabilities.py`, and `tests/organizations_lifecycle.py`.
