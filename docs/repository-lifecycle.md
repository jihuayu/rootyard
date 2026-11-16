# Repository Lifecycle, Redirects, Safe Purge, and Ownership Transfer

This document specifies Rootyard's repository lifecycle contracts (#85): archive/unarchive, rename and legacy URL alias resolution, soft-delete recovery grace windows, fail-closed final purge, and crash-recoverable ownership transfer between personal and organization namespaces.

## Common Concurrency, Authorization, and Idempotency Rules

1. **Admin permission**: Every lifecycle transition (`archive`, `unarchive`, `rename`, `delete`, `restore`, `purge`, `transfer`) requires `Role::Admin` (`RepoAction::RepoAdmin`), an active writable token (`!token.read_only`), and valid RBAC/token scopes.
   - Ownership transfer additionally requires write-capable authority over the destination namespace: either the actor's own personal namespace or `Role::Maintain`/`Role::Admin` in the destination organization (`authorize_namespace_create`).
2. **Optimistic CAS (`expected_version`)**:
   - Every lifecycle request validates `expected_version > 0` and checks `repositories.version = expected_version` inside the locking SQL transaction, bumping `version = version + 1` on commit.
   - Version mismatch returns `409 Conflict` without mutating state.
   - `POST /api/repos/{owner}/{name}/transfer` also returns `409 Conflict` if `expected_version` is omitted or mismatched, preserving backwards-compatible `409` rejection for unversioned callers.
3. **Idempotency (`Idempotency-Key`)**:
   - Lifecycle actions hash the canonical JSON payload (`request_sha256`).
   - Repeating the same `Idempotency-Key` with an identical payload replays the stored outcome cleanly; reusing a key with a different payload fails closed with `409 Conflict`.
   - Once soft-deleted (`deleted_at IS NOT NULL`), repeating `DELETE` with its stored `Idempotency-Key` replays its stored delete outcome, while `restore`, `purge`, and `GET /lifecycle` remain accessible; non-`delete` lifecycle endpoints (`archive`, `unarchive`, `rename`, `transfer`) return `404 Not Found` (preventing pre-delete key replay) until `POST /restore` completes.
4. **In-flight Git / LFS / CI / Maintenance Fencing**:
   - Mutations acquire exclusive repository coordination and reject with `409 Conflict` when a physical GC lease (`gc_owner IS NOT NULL AND gc_lease_until > now()`), storage backend transition (`transition_state <> 'stable'`), or active ownership transfer is in progress.
   - `pg_refstore` repositories preserve database-enforced immutable identity and append-only storage proofs: `archive`/`unarchive` and `delete`/`restore` are supported, while `rename`, `transfer`, and final `purge` fail closed with `409 Conflict`.

## Archive and Unarchive

- `POST /api/repos/{owner}/{name}/archive` sets `archived_at = clock_timestamp()`.
- `POST /api/repos/{owner}/{name}/unarchive` clears `archived_at = NULL`.
- **Behavior when archived**:
  - **Reads allowed (`200`)**: `GET /api/repos/{owner}/{name}`, browse/commits/tree/blob APIs, Git clone/fetch (`git-upload-pack`), LFS downloads (`batch` download + object GET), and Web UI read views remain readable.
  - **Mutations refused (`403 Forbidden`)**: `git-receive-pack` pushes, LFS batch uploads/writes, Issues/PRs/comments/reviews/branch-rules/webhooks, Workspace mutations, CI pin issuance, and repo settings writes reject with `403 Forbidden` (`repository is archived and read-only`).
  - Only `unarchive` and `delete` lifecycle actions remain permitted for repo admins on an archived repository.

## Rename and Legacy Address Resolution

- `POST /api/repos/{owner}/{name}/rename` updates `repositories.name`, updates denormalized `owner_slug`/`repository_name` columns in `workspaces`, `workspace_namespace_mounts`, and `workspace_changeset_steps`, and inserts the previous `(old_owner_id, old_name) -> repository_id` mapping into `repository_aliases`.
- **Conflict & Anti-Hijack Invariants**:
  - Creating a new repository or renaming another repository onto an `(owner_id, name)` already claimed in `repositories` OR reserved by a different repo's `repository_aliases` fails with `409 Conflict`.
  - Only the owning repository itself may reclaim one of its own aliases by renaming back to `(old_owner_id, old_name)` (moving the current name into `repository_aliases`).
- **Behavior Across Clients and Surfaces (`308 Permanent Redirect`)**:
  - **Authorization BEFORE redirect**: Alias resolution NEVER reveals canonical names or repository existence to unauthenticated or unauthorized actors. Unauthenticated requests keep normal `401`/`404` challenges; authenticated actors without read permission receive `404 Not Found`.
  - **Git Smart HTTP (`/git/{old_owner}/{old_name}.git/...`)**: After authz passes, responds with `308 Permanent Redirect` (`Cache-Control: no-store`) whose `Location` targets `/git/{new_owner}/{new_name}.git/...` preserving query strings (including `?service=git-upload-pack` and `?service=git-receive-pack`). Standard `git clone`, `git fetch`, and `git push` follow `308` automatically and warn `redirecting to ...`.
  - **Git LFS (`/git/{old_owner}/{old_name}.git/info/lfs/...`)**: Responds with same-origin `308 Permanent Redirect` to `/git/{new_owner}/{new_name}.git/info/lfs/...`; batch responses emit canonical download/upload `href` URLs.
  - **REST API (`/api/repos/{old_owner}/{old_name}...`) & Web UI (`/{old_owner}/{old_name}...`)**: After authz passes, responds with method-preserving `308 Permanent Redirect` to `/api/repos/{new_owner}/{new_name}...` and `/{new_owner}/{new_name}...`.

## Soft Delete, Recovery Window, and Safe Final Purge

- `DELETE /api/repos/{owner}/{name}` sets `deleted_at = clock_timestamp()` and `purge_after = deleted_at + grace_period_seconds` (default `604800`s = 7 days; bounded `0..=31536000`).
- **During recovery window (`deleted_at IS NOT NULL`)**:
  - Repository is hidden (`404 Not Found`) from normal `GET`, `list`, Git HTTP, LFS, Forge, Workspaces, CI, and Web UI routes, and active CI checkout jobs/pins cannot issue new tokens.
  - `POST /api/repos/{owner}/{name}/restore` clears `deleted_at` and `purge_after`, preserving original Git refs/content, LFS metadata, Forge issues/PRs, collaborators, and permissions verbatim.
- **Final Purge (`POST /api/repos/{owner}/{name}/purge`)**:
  - Requires `deleted_at IS NOT NULL`, `clock_timestamp() >= purge_after`, exact `confirm_repository == "{owner}/{name}"`, and exclusive read/write quiescence (`storage::read_leases::exclusive`).
  - **Fail-closed purge holds (`409 Conflict`)**: Refuses to purge if ANY of the following exist:
    - active backup or PITR retention roots (`pando_retention_roots` / `pando_retention_root_manifests`),
    - active serving read leases (`ref_store_core_serving_reads`, exclusive read-lease timeout),
    - active write admissions (`storage_write_admissions`) or physical GC fence (`gc_owner`),
    - queued/running storage maintenance jobs (`storage_maintenance_jobs`),
    - active CI pins (`refs/rootyard-ci/jobs/*` or disk pin intents) or active CI checkout jobs/leases,
    - active `artifact_holds` or `pando_publication_fences`.
  - **Shared Remote Object Protection**:
    - Never deletes remote `tenants/{tenant}/lfs/{oid}` or `tenants/{tenant}/workspace/{digest}` keys referenced by any other live repository in `tenant`, and never deletes objects belonging to another tenant.
    - Only authority-scoped Pando keys (`tenants/{tenant}/authorities/...`) unreferenced by other manifests/retention roots are retired through the PITR-fenced delete gate; legacy tenant-only keys are never deleted.

## Recoverable Ownership Transfer (`personal <-> organization`)

`POST /api/repos/{owner}/{name}/transfer` executes a crash-recoverable multi-phase state machine persisted in `repository_transfers`:

1. `preparing`: Validates RBAC, target namespace authority, target `(to_owner_id, target_name)` conflict/alias freedom, CAS `expected_version`, and acquires single-flight transfer row.
2. `draining`: Revokes/cancels active `ci_checkout_jobs`, deletes `ci_integration_checkout_jobs` / `ci_checkout_delegations` / `ci_integration_source_grants`, deactivates `ci_service_principals`, drains `storage_write_admissions` / maintenance jobs, and acquires exclusive read lease.
3. `copying_remote`: Copies live remote objects (`tenants/{from}/lfs/{oid}`, re-tenanted `RemoteManifest` + entry blobs in `tenants/{to}/workspace/...`, and Pando packs/envelopes under fresh destination keys in `tenants/{to}/authorities/...`) and verifies read-back BEFORE touching `repositories.owner_id`. Source objects are preserved until safely outside source failure windows.
4. `rekeying_db`: Single ACID PostgreSQL transaction:
   - removes legacy team bindings (`repository_team_members`, `repository_teams`), self-collaborator (`user_id = to_owner_id`), revoked collaborator/token scopes (`revoke_collaborators` defaults `true`),
   - records `(from_owner_id, old_name)` in `repository_aliases`,
   - updates `repositories` (`owner_id = to_owner_id`, `name = target_name`, `version = version + 1`),
   - cascades/rekeys all tenant-scoped tables (`forge_*`, `lfs_*`, `pando_*`, `storage_maintenance_*`, `repository_shard_routes`, `shard_failover_operations`, `workspaces` slugs, `workspace_remote_staging_objects`, `workspace_changeset_steps`),
   - writes audit entries to `repository_audit_log` and `organization_audit_log`,
   - transitions transfer to `revoking_legacy`.
5. `revoking_legacy` -> `completed`: Updates/rekeys surviving disk CI metadata if retained, verifies single authoritative owner and legacy revocation invariants, marks transfer `completed`.

### Crash and Restart Recovery (`repositories::recover`)

- If the server crashes in `preparing`, `draining`, or `copying_remote` (before `rekeying_db` commits), PostgreSQL still records solely `from_owner_id` as the repository owner. On restart, `repositories::recover` deterministically drives or rolls back the transfer (`rolling_back -> rolled_back` cleans destination-only `copied_objects` without ever deleting source keys).
- If the server crashes in `revoking_legacy` (after `rekeying_db` commits), PostgreSQL already records solely `to_owner_id` as owner; `repositories::recover` completes remaining legacy revocations and marks `completed`.
- At no point can two owners be simultaneously active for the same repository.
