# S4 CI checkout pins, revocation and Namespace GitView

Refs #147 · tracker #105 · state `S4`.

This document describes the `pg_refstore` half of the CI retention and Namespace
GitView surfaces. It is intentionally additive: every `storage_backend = 'gitfs'`
path keeps its existing code, response codes and tests.

## Why a separate backend path exists

`pg_refstore` repositories have no local GitFS directory, no `storage.verify_path`
result and no `git-receive-pack`. Their durable objects live in Blob storage and
are addressed by the RefStore core (`PackSnapshot`, `RetentionRoot`). Three
questions therefore cannot be answered by the GitFS code at all:

1. *What exactly did this CI job build?* — an object id alone is not durable; the
   commit may become unreachable after a force-push or branch deletion.
2. *May this job still fetch it?* — a credential is not authority; revocation and
   ownership transfer must take effect during an active transfer.
3. *What does a Namespace view contain?* — there is no projection directory to
   clone from.

S4 answers all three from PostgreSQL plus the authoritative retained root.

## Invariants

- **One transaction.** The retained root registration
  (`register_serving_in_tx`), the `s4_ci_retention.ci_pins` row, the
  `ci_checkout_jobs` row, the `closure_grants` row and (for views) the
  `workspace_views` row commit together or not at all. A rollback leaves zero
  business rows and no durable root.
- **A grant is data, never a capability.** `S4ClosureGrant` is deserialized with
  `deny_unknown_fields` and re-proved against live rows on every request and at
  every stream interval. A copy of the JSON authorizes nothing.
- **Fixed object ids only.** `target_oid` must be a non-zero lowercase object id
  of the repository's exact format (`sha1` 40 digits, `sha256` 64 digits). Branch
  names, `HEAD`, `refs/...`, short ids, upper-case hex and all-zero ids are
  refused before any IO.
- **Narrow credentials only.** The data plane accepts `ryj_` job tokens. A
  `ryu_` user token is refused with `403` even when its owner is an administrator.
- **No `public` schema growth.** The migration-151 backup catalog checks the exact
  `public` table set, so S4 coordination rows live in
  `CREATE SCHEMA IF NOT EXISTS s4_ci_retention`. Authoritative retention state
  continues to use the existing `public` `PgRetentionRoots` and
  `PgArtifactHoldStore` tables.
- **Revocation wins over completion.** Release and cancel mark the pin, the
  grants and the job terminal *and* release the root in one transaction, so an
  in-flight stream observes revocation at its next 100 ms interval.

## Schema

Created idempotently by `ensure_s4_schema`:

| table | purpose |
| --- | --- |
| `s4_ci_retention.ci_pins` | durable pin: job, tenant, generation, format, target, root id, register digest, pack-set digest, state |
| `s4_ci_retention.closure_grants` | one credential digest per job, its canonical grant JSON, revocation flags |
| `s4_ci_retention.git_view_bindings` | view → retained root binding, source/projected oid, mount path and subdir |

## Producer flow

`POST /api/repos/{owner}/{name}/ci-pins` (and `POST .../ci-checkouts` when the
job was not pinned first):

1. Authenticate, require `ContentsWrite`, and resolve the repository only when it
   is served on `pg_refstore`.
2. Open a short-lease `PackSnapshot` (120 s) and prove the native + Blob closure
   with `prepare_serving` **outside** PostgreSQL.
3. In one transaction: register the root, re-check the source pin is live, verify
   RBAC, repository tenant/generation/state, insert the job, the grant and the
   pin. The transient source `MetadataPin` is released only after that commit.
4. Return the `ryj_` token. An exact replay of `(target, generation, tenant)` is
   idempotent; any other reuse of the job id is `409`.

## Data plane

- `GET /ci/{target}/git/{owner}/{name}/info/refs`
- `POST /ci/{target}/git/{owner}/{name}/git-upload-pack`
- `POST .../git-receive-pack` → always `403`.

The transfer is served from a disposable `0o700` bare repository rebuilt from the
retained root's verified `.pack`/`.idx` bytes, with a single `refs/heads/main`,
`uploadpack.allowAnySHA1InWant=false`, `allowReachableSHA1InWant=false` and
`allowFilter=false`. Any `want` that is not the granted commit is refused. Output
is streamed in 16 KiB chunks while the authorization is re-proved every 100 ms;
on revocation the child `upload-pack` is killed and the stream ends with
`checkout authorization revoked during transfer`. The shared `state.git_slots`
permit is owned by the stream and returns to the semaphore on every exit path.

## Namespace GitView

`pg_refstore` views never write under `workspace-service/views`. Creation first
materializes the verified `.pack`/`.idx` pairs of the mounted commit into a
disposable bare repository, then projects `subdir` with
`filter-branch --subdirectory-filter`. Only after the projected oid is known does
one PostgreSQL transaction begin: `register_serving_in_tx`, the live source-pin
recheck, RBAC, `workspace_views`, `workspace_view_history` and
`s4_ci_retention.git_view_bindings` commit together or not at all. A rollback
leaves no durable root and no view row.

`GET /api/views/{id}/bundle` rebuilds the projection on demand, verifies the
recorded head and the current repository owner, then creates a bundle containing
only `refs/heads/projected` and `HEAD` — never `--all`, remote-tracking refs or
`refs/original/*`.

## Reverse merge into `pg_refstore`

`POST /api/views/{id}/changesets` is implemented for `pg_refstore`. The retained
source root is materialized into a disposable bare repository, the proposal
projection clone, then ancestry, object budget, `fsck --strict` and the unchanged
projected tree are checked. The projected tree is grafted back under `subdir`
and committed with `commit-tree` against the pinned source oid.

The new objects become one `.pack`/`.idx` pair. Publication follows the ordinary
A4 path: `begin_serving_pending_in_tx` reserves the operation, the pair is
acquired through `PgArtifactHoldStore` and uploaded by `ProtectedUploader`,
`PgPackCommit.register_publication` records it, and `PgAuthorizedCommit`
drives `prepare` → `select` → `verify` → `commit`. Only a committed terminal
writes the `workspace_changesets` row and its applied
`workspace_changeset_steps` row and returns `201`.

## Verification

`tests/s4_ci_pins_git_view.rs` holds the PG17 + LoopbackS3 + native Git E2E
matrix. The shared harness lives at
`tests/s4_ci_pins_git_view_support/harness.rs` and each scenario runs under one
global S3 environment lock. The three named scenarios cover atomic retention plus
cold clone, wide-credential/cross-job isolation and mid-transfer revocation, and
reverse merge for both SHA-1 and SHA-256 repositories. The test is `#[ignore]`d
and runs only with `ROOTYARD_TEST_DATABASE_URL`; the CI job is
`.github/workflows/s4-ci-pins-git-view.yml`.

`tests/test_s4_ci_pins_git_view_contracts.py` is static only. It must never invoke
`cargo`, `rustc`, `rustup` or `install_ci_cargo_fork.sh`, because
`tests/test_ci_cargo_fork_workflows.py` verifies that no Python test shells out to
a build.
