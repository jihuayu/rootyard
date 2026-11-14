# Git LFS locks: current supported behavior

**Status:** this page is the current supported behavior contract for Git LFS
locks. It is not an execution record and does not claim a new test run. The
dated client matrix in [client-compatibility.md](client-compatibility.md)
remains a historical record of specific builds; current evidence must come from
running the native suite on the source being reviewed.

## Endpoints and scope

Git LFS lock operations are available at the clone-path endpoints below and at
the equivalent `/{owner}/{name}/...` and `/api/repos/{owner}/{name}/lfs/...`
aliases:

- `GET|POST /git/{owner}/{name}.git/info/lfs/locks`
- `POST /git/{owner}/{name}.git/info/lfs/locks/verify`
- `POST /git/{owner}/{name}.git/info/lfs/locks/{id}/unlock`

Every lock belongs to exactly one repository and tenant. Paths are exact,
repository-relative lock keys, not globs or directory prefixes. The same path
can therefore be locked independently in two repositories, and a lock ID is
only addressable through its owning repository URL.

Create, list, verify and unlock resolve repository authorization before lock
lookup. List and verify only return that repository's locks. An ID from another
repository is absent from list and verify results, and an unlock request for it
returns a generic `404` without echoing the foreign path or ID.

## Authorization and results

| Operation | Minimum repository role | Behavior |
| --- | --- | --- |
| Create lock | `write` | Requires a contents-write token scope. One lock per repository/path; success is `201`, an existing lock is `409` with the existing lock returned. |
| List locks | `read` | Requires a contents-read token scope. Supports exact path and ID filters plus cursor/limit pagination. |
| Verify locks | `write` | Requires a contents-write token scope. Returns `ours` and `theirs` for the authenticated actor, with cursor/limit pagination. |
| Unlock as owner | `write` | Requires a contents-write token scope and that the actor owns the lock. No force flag is needed. |
| Force-unlock another actor's lock | `write` plus effective `admin` | Requires a contents-write token scope. The repository owner counts as `admin`; `maintain` and lower roles do not. |

A non-owner cannot unlock a lock with `force: false`, and a non-admin cannot
force-unlock it. Unlock hides unknown and foreign-repository IDs as `404`; list
and verify omit those IDs instead. Lock creation, removal and forced removal are
audited.

## One winner and persistence

`lfs_locks` has a database uniqueness constraint on `(repository_id, path)`.
Concurrent creates for the same repository/path therefore have one `201`
winner; the remaining requests receive `409`. Listing and verification use the
lock ID as a keyset cursor and cap a page at 100 entries.

Lock rows are durable PostgreSQL state tied to the repository and owner. A
service restart does not clear them. Paired database and volume backup/restore
preserves both the rows and their owner/path/lock-time state. The service has no
lock expiry: a lock remains until an authorized unlock or repository deletion.

## Locks versus push

A lock is a path-level collaboration lock, not a working-tree, object-transfer
or filesystem lock:

- Client-side lock checks are advisory. The service independently enforces the
  lock during ref publication, so disabling a client hook does not bypass it.
- A user can edit and commit locally while another user holds the lock.
- LFS object uploads are not rejected merely because a path is locked.
- Before a ref update is published, the native receive/publication path checks
  the changed paths. It derives paths from commits not already reachable from a
  ref and from the old-tip-to-new-tip diff, so an earlier commit hidden in a new
  branch is not missed.
- When a push would publish a changed path locked by another user, the native
  receive-pack/ref-publication check rejects that ref update. Stock Git reports
  the pushed ref as rejected and exits nonzero; this is a Git ref rejection, not
  an HTTP `409` response from the Git transport. The lock API's `409` remains the
  create-conflict response for a path already locked. The lock owner may publish
  the path. History and path scans are bounded and fail closed if they cannot be
  completed.
- An `admin` does not get an implicit push bypass while another user's lock
  exists. An authorized force-unlock removes the lock, records the audit event,
  and then the normal ref authorization applies. Force unlock does not revert
  refs or content.
- Pull-request merge and other native ref-publication paths use the same
  changed-path lock check. Locks do not replace branch protection, reviews, or
  repository RBAC.

Lock ownership and state are not transferred between repositories. A lock is
not a global namespace reservation and does not reserve an object ID.

## Stock client behavior

Stock `git lfs` uses these repository endpoints:

- `git lfs lock <path>` creates the path lock.
- `git lfs locks` lists the repository's locks.
- `git lfs locks --verify` asks the server to classify locks as `ours` or
  `theirs`; the text output marks our locks with `O`, including locks created
  from another clone.
- `git lfs locks --verify --json` writes the same split as JSON with `ours` and
  `theirs` arrays.
- `git lfs unlock <path>` unlocks the actor's own lock; `git lfs unlock --force`
  requests forced removal and succeeds only for an authorized admin/owner.

The owner mark and JSON split describe only the repository selected by the Git
remote. Locks and lock IDs from another repository are not returned by these
client operations.
