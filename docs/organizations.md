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

## Repository Ownership Transfer Policy (#85)

Recoverable `personal <-> organization` ownership transfer is specified in [`docs/repository-lifecycle.md`](repository-lifecycle.md):

- `POST /api/repos/{owner}/{name}/transfer` requires `Role::Admin` (`RepoAction::RepoAdmin`) on the source repository, destination namespace authorization (`actor.id == target_user.id` for personal targets, or `Role::Maintain`/`Admin` for organization targets), and CAS `expected_version`. Unversioned requests omitting `expected_version` continue to return `409 Conflict` without mutating state.
- Transfers execute a crash-recoverable PostgreSQL state machine (`preparing -> draining -> copying_remote -> rekeying_db -> revoking_legacy -> completed`), copying tenant-scoped remote objects to the destination tenant before atomic DB rekeying, preserving historical clone URLs via `repository_aliases`, and revoking legacy organization/team/CI/collaborator grants per contract so restarts never leave split ownership.

## HTTP API surface

- `GET /api/orgs` (paginated direct memberships; restricted tokens filtered by `org:read`), `POST /api/orgs`, `GET /api/orgs/{slug}`
- `GET /api/orgs/{slug}/members`, `PUT/DELETE /api/orgs/{slug}/members/{username}`
- `GET/POST /api/orgs/{slug}/teams`, `GET/PATCH/DELETE /api/orgs/{slug}/teams/{team_slug}` (CAS `expected_version` on `PATCH`; `DELETE` cascades `organization_team_members`)
- `GET /api/orgs/{slug}/teams/{team_slug}/members`, `PUT/DELETE /api/orgs/{slug}/teams/{team_slug}/members/{username}`
- `GET /api/orgs/{slug}/audit` (`maintain`/`admin` paginated organization audit feed)
- `POST /api/repos/{owner}/{name}/transfer` (`expected_version`, optional `new_name` and `revoke_collaborators`)

Verified end-to-end across Git HTTP, LFS objects/locks, Forge issues/PRs/branch-rules, Git views, Workspaces, Web UI, server restart, and offline PostgreSQL backup/restore by `tests/organizations.py`, `tests/organization_pagination.py`, `tests/organizations_web.py`, `tests/backup_capabilities.py`, and `tests/organizations_lifecycle.py`.
