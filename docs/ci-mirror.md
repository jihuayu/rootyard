# Exact-commit CI read mirror: first slice

The primary remains the only Git writer and authoritative repository store.
`rootyard serve-mirror` starts a separate, read-only smart-HTTP service using its
own storage directory and the **same authoritative PostgreSQL database**. It
serves Git packs locally, rather than proxying reads to the primary.

This slice establishes a correctness boundary, not production CI capacity or
high availability. Sync is synchronous and full-clone-only. There is no scheduler,
incremental fetch, automatic fallback, snapshot garbage collection, or throughput
SLA. Account and repository administration remain on the primary.

## Configuration and storage separation

```sh
DATABASE_URL='postgresql://.../rootyard' \
ROOTYARD_DATA_DIR=/srv/rootyard-ci-mirror \
ROOTYARD_BIND=127.0.0.1:8081 \
ROOTYARD_PRIMARY_URL=http://127.0.0.1:8080 \
rootyard serve-mirror
```

Use a distinct mirror-owned directory, never the primary's volume. The mirror
marks its directory with `.rootyard-mirror`; a primary must refuse that volume,
and the mirror must refuse a primary-owned volume. Do not remove role markers to
reuse a directory. The primary and mirror can run concurrently with separate
volume locks. The mirror does not run migrations, reconcile primary repository
storage, provision repositories, or run primary background workers. It does not
install write hooks or require an executable data volume. Use a PostgreSQL role
restricted to reading users, tokens and repository metadata where practical; the
mirror still depends on the primary database for current authorization.

The configured primary URL is fixed by the operator, not supplied in sync
requests. HTTPS is required outside loopback; loopback HTTP is for development.
Tokens are sent to this configured primary for the requested owner's repository
sync, so configure only the trusted primary. Do not embed credentials in URLs or
logs. Protect the mirror's own external endpoint with HTTPS as well.

## Explicit sync

Send `POST /api/repos/{owner}/{name}/mirror-sync` with an ordinary owner token.
A read-only token is sufficient. The mirror checks authoritative permissions and
the ready repository generation, clones a complete new bare Git snapshot over
the primary's smart HTTP endpoint, checks its object integrity with `git fsck`,
and atomically publishes it. It returns HTTP 200 with `repository_id`,
`storage_generation`, and `snapshot`. Snapshot identifiers are opaque.

An upstream sync failure returns HTTP 503 and leaves the previously published
snapshot usable. A failed or incomplete clone is never substituted for a complete
snapshot. A successful sync is the snapshot observed by that sync, not a promise
that the primary cannot change immediately afterward. A newly requested commit
may still require another sync.

## Exact-commit clone and fetch

Use the complete lowercase 40-character commit object ID in the Git URL:

```text
https://mirror.example/ci/{commit_oid}/git/{owner}/{name}.git
```

Supply the normal owner read token using your CI platform's secret mechanism.
Do not put tokens in the URL. Standard Git clone and fetch use this URL without a
custom client protocol. The mirror advertises only `refs/heads/main`, with `HEAD`
pointing to that branch and both resolving to the requested commit. This is a
synthetic pinned branch, not a copy of the primary's current branch names.
An ordinary clone therefore checks out the exact commit, even after the primary
branch moves. Fetching the same pinned URL does not advance it to a newer commit.
Use a new exact-commit URL when the desired commit changes.

Git normally reuses a clone remote for pushes. Set an explicit primary push URL
if this checkout will ever push, so its fetch source remains the mirror while
all writes target the primary:

```sh
git -C checkout remote set-url --push origin https://primary.example/git/owner/name.git
```

For CI, keep the injected credential read-only unless a separate, explicitly
authorized write job needs it. The server cannot change a standard client's local
remote configuration; an attempted push to the mirror is rejected, never forwarded.

The mirror checks that the exact object is a commit in a complete snapshot for
the authoritative repository generation. Missing snapshots, stale generations,
and unavailable exact commits return HTTP 409. A repository that is not ready
returns HTTP 503. The caller can sync and retry,
or explicitly choose the primary under its own policy. The mirror never redirects
the request, serves a different commit, or silently falls back to the primary.
Once a commit has been pinned, its generation-scoped mapping retains the original
immutable snapshot. Later full syncs can drop that commit from the latest snapshot
without changing the existing pin, including when a unique source branch is deleted.
A pin never crosses a repository generation change. Retained data is not an archive
or backup guarantee, and manual deletion or corruption can make a pin unavailable.
Pinned views reference snapshot objects locally. Existing snapshots can serve
complete clones while the primary is stopped, provided the authoritative PostgreSQL
database remains available. Git replacement refs are ignored for object-type checks:
a blob or tree cannot become an eligible commit through a replacement ref. Changed
pin HEAD/ref metadata is rejected rather than served as a different revision.

## Authorization and write boundary

Every request checks the authoritative PostgreSQL token and repository state.
There is no permission or token cache: a revoked token is rejected on the next
request. Read access remains private to the repository owner. Authentication or
repository-state lookup failure fails closed. This is not a promise to cancel a
Git stream already authorized before revocation or a generation transition.

All receive-pack requests are denied, including discovery and POST RPC, even for
a writable owner token. The unpinned `/git/...` route is unavailable on the mirror.
Repository creation and other primary write APIs are unavailable. Never configure
a mirror endpoint as a push remote. Health routes are available for process and
readiness checks.

## Verification

Use only a disposable dedicated PostgreSQL database and synthetic credentials.
The harness creates one random schema and separate temporary primary and mirror
volumes, launches real processes, and cleans only its own schema and directories.
See [development prerequisites](development.md) before running:

```sh
python3 tests/ci_mirror.py --binary target/debug/rootyard \
  --report test-results/ci-mirror.json
```

CI runs this harness and retains its report. `--keep` retains temporary private
files for diagnosis; it does not preserve the SQL schema. Implemented test cases
cover ordinary pinned clone/fetch and fsck, primary branch movement, absent commits,
separate-process local packs with the primary stopped, sync failure preservation,
a corrupt synthetic primary ref pointing at a missing object, owner isolation,
invalid/revoked tokens, rejected writes, storage role guards,
restart, repository ready-state and generation fencing, and failed authoritative
auth queries. Additional regression cases cover retained pins after unique source
branch deletion and a newer snapshot lacking the commit, blob/tree-to-commit and
commit-to-blob replacement refs, and offline pin HEAD/ref corruption followed by
fixture restoration. The query-failure fixture temporarily renames a table within the
run-owned schema; it is not a PostgreSQL server or network outage test.

A test's presence is not an execution result. Inspect the report and tested tool
versions before claiming verification. These tests do not establish concurrent
sync behavior, disk-full safety, power-loss durability, in-flight authorization
cancellation, multi-region behavior, production scaling, or automatic failover.
Full snapshots and pinned views accumulate; capacity planning and a safe retention
policy remain operator responsibilities until garbage collection is implemented.

Treat the mirror filesystem and configured primary as trusted operator resources.
Pin metadata checks catch selected corruption and path/HEAD changes; they are not
a complete defense against a hostile process that can rewrite the service's data
volume. Do not grant other users write access to this volume. Snapshot publication
uses fsync and rename, but power-loss behavior still requires storage-specific tests.
