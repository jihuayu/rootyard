# Online Namespace Revisions, Projected Git Views, and Cross-Repository ChangeSets

This document specifies the online HTTP and Smart HTTP interface exposed by `src/namespace_service.rs` and `src/namespace_service/*` for Issue `#31`, building on the local semantics prototype ([git-view-foundation.md](git-view-foundation.md)) and existing database schema (`migrations/093_workspace_namespaces.sql`, `migrations/096_workspace_changesets.sql`; see also [namespace-changesets.md](namespace-changesets.md)).

## Endpoint & Fine-Grained Authorization Matrix

Every endpoint authenticates platform credentials via `auth::authenticate`, evaluates live repository RBAC and `repositories.state == 'ready'` availability across the namespace mounts, and enforces fine-grained token scopes (`token_scopes::RepoAction`) and live token/parent liveness (`auth::authorize_repo_with_role`, `auth::verify_active`, `auth::finish_tx`):

| Endpoint | Min Repo Role | Required Token Scope | Behavior |
| --- | --- | --- | --- |
| `POST /api/namespaces` | `Role::Read` (all mounts) | `RepoAction::ContentsRead` | Validates unique tenant, normalized non-overlapping mount paths, and pinned `base_oid` commits |
| `GET /api/namespaces/{id}` | `Role::Read` (all mounts) | `RepoAction::ContentsRead` | Returns pinned mounts only while every mount remains authorized |
| `POST /api/namespaces/{id}/views` | `Role::Read` (all mounts) | `RepoAction::ContentsRead` | Validates `subdir` exists as a tree at `base_oid`, projects isolated `refs/heads/projected` clone, records `workspace_views` and `workspace_view_history` epoch `1` |
| `GET /api/views/{id}` | `Role::Read` (all mounts) | `RepoAction::ContentsRead` | Returns persisted view metadata (`source_oid`, `projected_oid`, `epoch`) |
| `GET /api/views/{id}/history` | `Role::Read` (all mounts) | `RepoAction::ContentsRead` | Returns persisted view definition and ordered `(epoch, source_oid, projected_oid)` mappings from `workspace_view_history` |
| `GET /api/views/{id}/bundle` | `Role::Read` (all mounts) | `RepoAction::ContentsRead` | Streams a bounded `application/x-git-bundle` of `refs/heads/projected` (`<= 32 MiB`) |
| `GET /git/views/{id}.git/info/refs?service=git-upload-pack` | `Role::Read` (all mounts) | `RepoAction::ContentsRead` | Advertises `refs/heads/projected` for stock `git clone` / `git fetch` under shared storage lease & snapshot lock |
| `POST /git/views/{id}.git/git-upload-pack` | `Role::Read` (all mounts) | `RepoAction::ContentsRead` | Serves bounded `git upload-pack --stateless-rpc` (plain or gzip-compressed request) sharing one absolute `git_timeout` deadline across slot hold, temp-file body spooling, lease/snapshot lock, and Git execution with temp/permit cleanup on timeout or cancel |
| `GET /git/views/{id}.git/info/refs?service=git-receive-pack`, `POST /git/views/{id}.git/git-receive-pack` | `Role::Read` (all mounts) | `RepoAction::ContentsRead` | Fails closed with `403 Forbidden`; projected Git views are strictly read-only |
| `POST /api/views/{id}/changesets` | `Role::Write` (target mount) / `Role::Read` (other mounts) | `RepoAction::ContentsWrite` / `ContentsRead` | Reverse-maps projected proposal bundle onto pinned source tree, checks source ref == `source_oid` (`409` on advance), pins `refs/heads/rootyard-proposals/{id}`, creates `proposed` ChangeSet |
| `POST /api/namespaces/{id}/changesets` | `Role::Write` (step mounts) / `Role::Read` (other mounts) | `RepoAction::ContentsWrite` / `ContentsRead` | Creates multi-repository `proposed` ChangeSet (`1..=32` steps) after validating candidate commits |
| `GET /api/changesets/{id}` | `Role::Read` (all mounts) | `RepoAction::ContentsRead` | Exposes ChangeSet `state` (`proposed`, `reviewed`, `integrating`, `partial`, `complete`, `conflict`) and per-step `applied` flags |
| `POST /api/changesets/{id}/review` | `Role::Maintain` (step mounts) | `RepoAction::ContentsWrite` | Requires an independent reviewer (`creator_id != actor.id`) and moves `proposed -> reviewed` |
| `POST /api/changesets/{id}/integrate` | `Role::Write` (step mounts) | `RepoAction::ContentsWrite` | Applies each step in ordinal order through `execute_ref_transaction` under a transaction-scoped advisory lock |
| `POST /api/changesets/{id}/recover` | `Role::Write` (step mounts) | `RepoAction::ContentsWrite` | Resumes `reviewed` / `partial` / `integrating` ChangeSets by inspecting live Git refs |

Unauthorized users lacking repository access receive `404 Not Found` (avoiding cross-tenant UUID existence leaks), while restricted tokens missing `contents_read` or `contents_write` receive `403 Forbidden`. Unauthenticated Smart HTTP requests receive `401 Unauthorized` with a `Basic` challenge (`WWW-Authenticate: Basic realm="Rootyard", charset="UTF-8"`).

## View Access Boundary & Projected Isolation

- A projected View repository under `workspace-service/views/{id}` is created via `--single-branch --branch projected` from the rewritten subtree commit (`projected_oid`).
- Unmounted files, unmounted repositories, and unprojected source commit OIDs are absent from the view object database; requesting an unmounted or source commit returns a Git error (`400 Bad Request`) without exposing source objects.
- If a mounted source repository is no longer `ready` or the caller's RBAC membership or `contents_read` scope is revoked, `/api/views/{id}`, `/api/views/{id}/history`, `/api/views/{id}/bundle`, and `/git/views/{id}.git/*` immediately reject access.

## Concurrent Conflicts & Non-Atomic Multi-Repository Crash Recovery

- **Concurrent source changes never overwrite source commits**:
  - Reverse mapping (`POST /api/views/{id}/changesets`) fails with `409 Conflict` (`source ref advanced`) if `source_ref` no longer resolves to `view.source_oid`.
  - Integration (`POST /api/changesets/{id}/integrate` and `/recover`) checks `storage_generation` and live Git ref OIDs under `read_leases::shared` and `read_snapshot_lock`, and passes `old_oid` + `storage_generation` into `browse::transactions::execute_ref_transaction`. Storage generation mismatches, live ref OID divergence (`actual != old_oid` and `actual != new_oid`), and `409` responses from `execute_ref_transaction` mark `workspace_changesets.state = 'conflict'` and return `409 Conflict` without overwriting the concurrent commit; non-conflict `execute_ref_transaction` failures transition to `state = 'partial'`. If `git rev-parse --verify` fails because the target ref is absent/deleted before a conflict transition writes to DB, integration returns `409 Conflict` leaving `workspace_changesets.state = 'integrating'` (without silent overwrite).
- **Known Scope / Follow-up Resource Bounds**:
  - `POST /api/namespaces/{id}/views` projection and `GET /api/views/{id}/bundle` retain the base synchronous `std::process::Command` helper (`views::git` / `views::clone`, without `git_slots` or an async timeout, and enforcing `/bundle`'s `32 MiB` response cap after bundle creation); moving projection and bundle generation onto bounded async subprocesses and RefStore/Blob storage (`#147`) remains follow-up scope.
- **Explicit reader-visible publication & crash recovery**:
  - Rootyard does **not** claim native Git provides a cross-repository atomic commit across separate repositories.
  - Multi-repository integration marks the ChangeSet `integrating` / `partial` after updating each step and sets `state = 'complete'` only after every `workspace_changeset_steps.applied` row is `true`.
  - If the server crashes right after updating the first repository (exercised with `ROOTYARD_CHANGESET_KILL_AFTER_STEP=1`), PostgreSQL automatically releases the transaction-scoped integration advisory lock on disconnect. Unrelated readers polling `GET /api/changesets/{id}` observe `state = 'partial'` (`steps[0].applied == true`, `steps[1].applied == false`), never a false `complete`.
  - An authorized writer calls `POST /api/changesets/{id}/recover`: already-updated steps (`actual == new_oid` or `applied == true`) are preserved idempotently, pending steps matching `old_oid` are executed through `execute_ref_transaction`, and diverged refs transition to `conflict`.

## Verification

- Offline contract tests: `python3 -m unittest tests.test_namespace_online_contracts`
- Unit tests: `cargo test --locked --lib namespace_service`
- Real PostgreSQL + stock `git` workflows: `python3 -m unittest tests.test_namespace_service` and `python3 tests/namespace_online_workflows.py --binary "$ROOTYARD_BIN"`
- Scoped CI workflow: `.github/workflows/namespace-online.yml`
