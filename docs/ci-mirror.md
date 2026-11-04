# Exact-commit CI source retention and read mirror

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

## Trusted-controller checkout flow

This slice accepts an **exact SHA-1 commit**, not a branch/tag expression. A
trusted controller uses its writable owner token only against the primary:

```http
POST /api/repos/{owner}/{name}/ci-pins
Authorization: Bearer <controller-owner-token>
Content-Type: application/json

{"job_id":"<caller UUID>","target_oid":"<40 lowercase hex>","storage_generation":1}
```

HTTP 200 is a verified durable source-retention receipt. Its fields are
`version: 1`, `job_id`, `owner_id`, `repository_id`, `storage_generation`,
`object_format: "sha1"`, `target_oid`,
`retention_ref: "refs/rootyard-ci/jobs/<job UUID>"`, and `state: "pinned"`.
The writable owner is the controller authority in this release; there is no
separate controller role or job-scoped token. Read-only tokens cannot create
source roots. Unknown, revoked, expired, or other-owner tokens fail closed.

The same job UUID is immutable within its repository, including across storage
generations. Identical retries verify/converge on the same root; a different OID
or generation is HTTP 409. Expected-generation mismatch is 409; a recovering
repository is unavailable. Missing objects and noncommits are 409; malformed
inputs are 400. Replacement refs are disabled for type/identity checks. Neither
annotated tags nor symbolic names are peeled/resolved by this API.

The controller must perform these steps in order:

1. Obtain the primary pinned receipt **before** deleting/moving the target's last
   ordinary source ref or asking a mirror to copy it.
2. Perform the manual full `mirror-sync` described below.
3. Send `POST /api/repos/{owner}/{name}/mirror-prepare` to the mirror with
   `{"target_oid":"<same OID>","storage_generation":1}` and an owner read token.
4. Match `repository_id`, `storage_generation`, `object_format`, and `target_oid`
   against the source receipt. A 200 prepare response also supplies opaque
   `snapshot` identity and `clone_path: "/ci/<OID>/git/<owner>/<name>.git"`.
5. Use ordinary Git clone with that path, verify the full `git rev-parse HEAD`
   equals the receipt's OID, and bind the build result to it. Fail on mismatch.

Preparation does not sync or contact the primary Git service. It durably pins a
complete local snapshot, revalidates pin metadata, actual commit type and full
Git fsck, then rechecks current authorization/generation before reporting ready.
It works while the primary is stopped if PostgreSQL remains available. The old
exact-commit Git URL still lazily establishes a snapshot pin for compatibility.

**Source retention and mirror readiness are separate receipts.** Mirror prepare
has no primary-volume job metadata and does not approve a job, verify its source
receipt, or promise source retention. The controller owns matching and retrying
these two explicit steps. A source root can be pinned while a mirror is still
unready. An old generation cannot become ready merely because its objects remain
on disk. `storage_generation` is a storage/recovery fence, not `source_epoch`, a
publication watermark, authorization policy version, or cross-repository version.
Those richer checkout-plan fields, job cancellation and scheduling are not
implemented. There is no inferred expiry or automatic release.

## Primary retention, recovery and backup

All ordinary pushes reject creation, update and deletion of `refs/rootyard-ci`
and every descendant. Mandatory pre-receive rejects the **whole** mixed push,
including non-atomic pushes, before ref changes; reference-transaction also
checks the boundary. Preexisting unmanaged refs, symbolic refs and namespace
ancestor collisions make activation fail. They are never overwritten or removed.
Operators must investigate collisions; the API does not migrate user refs.

Under the existing repository writer mutex and recovery/backlog/quota fences,
the primary persists a versioned intent at
`ci-pins/<repository UUID>/<job UUID>.json`, records a typed exact-create operation
in the normal durable journal, uses native Git `update-ref --no-deref` with
zero-old-OID CAS, verifies the retained commit, and writes the immutable
`<job UUID>.pinned.json` receipt. A journal grant authorizes only that one exact
absent-to-OID maintenance change. It is not a push flag or inherited environment
bypass. Hooks reject any other transaction or a receive-pack using that grant.
GitFS remains the authority for objects and refs.

Crash before intent publication has no job. Intent-only state requires a new
authenticated POST retry to create its root. Startup can settle an interrupted
CAS journal from the exact native root; the next POST verifies or completes its
pinned receipt. No success is returned from an intent alone. A root with missing receipt is verified before
completing the receipt. Changed/corrupt roots or evidence fail closed. Once a CI
operation is imported as `unknown`, later ref observation cannot promote it to
success: existing explicit operator recovery/resolution is required. Recovery
preserves that history, old-generation intents and native roots. Reusing an old
job ID in the new generation is forbidden; create a new job explicitly.

CI operations retain exact-change outbox and audit-log events with operation
evidence kind `observed_immutable_ci_root`, never fabricated post-receive data.
The `ref-index` consumer acknowledges those events without projecting internal
CI roots as `push_receipt`. Explicit offline recovery snapshots may include
these roots, accurately labeled `recovery_snapshot`.

Metadata lives on the primary volume because retaining a native Git ref is a
GitFS operation. Existing **paired offline backups** include intent/receipt files,
journals and native roots in the checksummed full-volume inventory together with
PostgreSQL audit/recovery state. Schema 007 and backup format 4 remain unchanged.
Do not restore only the database or only these files. Restoring does not change
job generation identity; existing recovery fences still apply. Do not downgrade
to an older binary that lacks the namespace guard or typed journal decoder while
these roots exist. The mirror volume remains separate and is not a primary backup.

Admission is bounded to 1,024 primary job intents per repository, including old
generations and pending intents, and 1,024 generation/OID mirror mappings per
repository. New requests beyond the bound are HTTP 429; existing identical
retries remain possible. Native repository byte quota, Git process limits and
outbox backlog gates still apply. These limits are not garbage collection:
operators must plan storage; this release does not expire, release or delete pins.

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

Only trusted controller/mirror validation jobs may use the current owner read
token through a protected secret mechanism. These credentials are owner-wide;
delivery to untrusted CI runners is **unsupported** until separately scoped
credentials exist. A read-only token still reads every repository of that owner.
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

For trusted validation jobs, keep injected credentials read-only. Do not deliver
the writable controller token to runners. Separate scoped write-back credentials
remain future work. The server cannot change a standard client's local
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

CI runs this harness plus `tests/ci_source_pins.py` and
`tests/backup_ci_pins.py`, and retains their reports. Source-pin coverage includes
pre-first-sync source-ref deletion, concurrent job retries/conflicts, reserved
namespace rejection, synthetic durable interruption boundaries, current
authorization and generation fences. Paired-backup coverage uses a fresh owned
database and restored volume. Synthetic boundary fixtures do not establish
hardware power-loss behavior. A real SHA-256 upstream fixture also verifies
that a resolving 40-character prefix cannot create a source pin, and unsupported
mirror sync preserves the prior published snapshot/config byte-for-byte. `--keep` retains temporary private
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
