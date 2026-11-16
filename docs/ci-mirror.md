# Exact-commit CI source retention and read mirror

The primary remains the only Git writer and authoritative repository store.
`rootyard serve-mirror` starts a separate, read-only smart-HTTP service using its
own storage directory and the **same authoritative PostgreSQL database**. It
serves Git packs locally, rather than proxying reads to the primary.

This slice establishes an explicit correctness and capacity-management boundary.
Sync is synchronous and full-clone-only with bounded per-repository and global
concurrency (`ROOTYARD_MIRROR_MAX_CONCURRENT_SYNCS`), lease-coordinated source
pin release (`DELETE /api/repos/{owner}/{name}/ci-pins/{job}`), safe LRU and
watermark mirror eviction (`POST /api/repos/{owner}/{name}/mirror-evict` and
`mirror-prune`), and mirror status/metrics observability. Account and repository
administration remain on the primary.

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
restricted to reading users, tokens, repositories and ci_checkout_jobs where practical; the
mirror still depends on the primary database for current authorization.

The configured primary URL is fixed by the operator, not supplied in sync
requests. HTTPS is required outside loopback; loopback HTTP is for development.
Tokens are sent to this configured primary for the requested owner's repository
sync, so configure only the trusted primary. Do not embed credentials in URLs or
logs. Protect the mirror's own external endpoint with HTTPS as well.

## Trusted-controller checkout flow

This slice accepts an **exact SHA-1 or SHA-256 commit**, not a branch/tag expression. A
trusted controller uses its writable owner token only against the primary:

```http
POST /api/repos/{owner}/{name}/ci-pins
Authorization: Bearer <controller-owner-token>
Content-Type: application/json

{"job_id":"<caller UUID>","target_oid":"<40 or 64 lowercase hex>","storage_generation":1}
```

HTTP 200 is a verified durable source-retention receipt. Its fields are
`version: 1`, `job_id`, `owner_id`, `repository_id`, `storage_generation`,
`object_format: "sha1"` or `"sha256"`, `target_oid`,
`retention_ref: "refs/rootyard-ci/jobs/<job UUID>"`, and `state: "pinned"`.
The writable owner is the controller authority in this release; there is no
separate controller role. Job-scoped runner credentials are described below; ordinary read-only tokens cannot create
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
Source-publication watermarks and storage generations remain separate fences.
There is no inferred expiry or automatic release of the source pin.

## Fenced CI run and dependency checkout

A protected branch can bind a required check context to an active webhook
integration. Pull synchronization creates a fixed `ci_runs` candidate and a
durable source pin. The integration calls `POST .../integrations/{hook_id}/runs/{run_id}/claim`
with its secret and a `runner_id`. A successful claim returns the exact head,
base, storage generation, attempt, lease generation, selected source, and a
one-time `checkout` plan with a `ryj_` bearer. The bearer is stored only as a
SHA-256 digest and is usable for a pinned upload-pack and its declared Git LFS objects. The
integration calls `.../heartbeat` before each 60-second lease expires and
`.../report` with the active attempt and lease generation. Candidate changes,
reclaims, completed runs, disabled webhooks and revoked context bindings end
checkout authority. A repeated valid result remains idempotent.

Plans include full or target history, requested tags, every required LFS
object and nested gitlink commit. A source administrator grants an integration
read access to each separate submodule repository through its
`PUT /api/repos/{owner}/{name}/ci-source-grants/{hook_id}` endpoint. Unsafe `.gitmodules` URLs, absent Git
objects, missing or corrupt LFS bytes and unauthorized submodule sources stop
issuance. The first claim delivers separate one-time tokens for each nested
repository; a parent token never authorizes those sources. The mirror's
`POST /api/repos/{owner}/{name}/ci-checkouts/{job}/prepare-dependencies`
syncs and verifies every declared source and LFS object before declaring the
checkout ready. Runners use stock Git against each plan's pinned `/ci/{oid}/git/...`
URL and configure each nested submodule's URL and token from the manifest.
Git LFS needs a credential helper for the corresponding job token; after a
clone with `GIT_LFS_SKIP_SMUDGE=1`, run `git lfs install --local`, `git lfs pull`,
then `git lfs checkout` in that pinned repository.

An integration-triggered mirror preparation requires
`ROOTYARD_CI_MIRROR_SOURCE_TOKEN=ryt_...` on the mirror, supplied explicitly
by the operator. This transport token must have read access to each declared
source repository; it stays on the mirror and is never returned to a runner.
The mirror also needs the same `ROOTYARD_CI_MIRROR_AUDIENCE` as the primary and
its own HTTPS `ROOTYARD_CI_MIRROR_PUBLIC_URL` for Git LFS download actions.
The primary needs `ROOTYARD_CI_ORIGIN_PUBLIC_URL` to advertise its scoped LFS
download actions when a run uses its bounded origin fallback. Origin job reads
use the same one-time `ryj_` token and a locally materialized view containing
only the exact planned Git closure; they do not expose ordinary primary refs.
Without the configured transport token, preparation fails closed. Before each
primary Git/LFS fetch and before publishing a mirror snapshot, the mirror
rechecks the run lease, exact attempt, active binding and source grant.
Active Git and CI LFS response producers recheck authority each second even
when the consumer stops reading, and abort a transfer after cancellation,
revocation, expiry or authority-service failure.

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
PostgreSQL audit/recovery state. Checkout authorization adds schema 008 and backup
format 5; exact schema 007 / format 4 restore remains an explicit compatibility path.
Do not restore only the database or only these files. Restoring does not change
source-pin generation identity; existing recovery fences still apply. Every restored
issued job credential is permanently revoked before restore completion. Do not downgrade
to an older binary that lacks the namespace guard or typed journal decoder while
these roots exist. The mirror volume remains separate and is not a primary backup.

Admission is bounded to 1,024 primary job intents per repository, including old
generations and pending intents, and 1,024 generation/OID mirror mappings per
repository. New requests beyond the bound are HTTP 429; existing identical
retries remain possible. Native repository byte quota, Git process limits and
outbox backlog gates still apply. Controllers can inspect active pins via
`GET /api/repos/{owner}/{name}/ci-pins` and release completed pins via
`DELETE /api/repos/{owner}/{name}/ci-pins/{job}` (or `POST .../release`) once
no active checkout lease remains.

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
never deliver them to untrusted runners. Use the separately issued job credential
below instead. An ordinary read-only token still reads every repository of that owner.
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

## Bounded job checkout credentials

Configure the same operator-selected UUID `ROOTYARD_CI_MIRROR_AUDIENCE` on the
primary and the one intended mirror. A missing audience disables job issuance
and job reads. It is not derived from a request Host header or caller-selected
URL. Manual owner-authorized sync remains separate and must happen before reads;
job credentials cannot sync, prepare or ask the primary for objects.

After creating a durable source pin, the writable owner/controller requests:

```http
POST /api/repos/{owner}/{name}/ci-checkouts
Authorization: Bearer <controller-owner-token>
Content-Type: application/json

{"job_id":"<same source-pin UUID>","target_oid":"<full lowercase SHA-1>","storage_generation":1,"mirror_audience":"<configured UUID>","expires_unix":<absolute Unix seconds>}
```

Expiry must be in the next hour according to the authoritative database clock.
The primary holds its repository writer lock while verifying the exact durable
intent, pinned receipt and native retention ref and until grant commit. It locks
and freshly checks issuer, owner and ready repository authority before committing.
A database row never fabricates a source retention receipt. A crash between pinning
and issuance may leave retained but unusable bytes.

The first successful response contains `plan` and a random `ryj_` credential in
`token`. The immutable version-1 plan binds owner/repository/job UUIDs, storage
generation, SHA-1 object format, full target OID, SHA-256 of the exact source
receipt bytes, configured mirror audience and absolute expiry. Storage generation
is not a source publication epoch or version. Only the credential digest and
authorization metadata are persisted. Responses are `Cache-Control: no-store`.

**Credential delivery is one-time.** An exact retry returns the same plan and
`credential_issued: true`, but no token; it never rotates or extends authorization.
A lost response or lost token requires a new explicit job UUID and source pin.
Changing an existing plan, cancelling it or revoking its credential prevents
issuance for that job forever. Do not use a new ID to circumvent cancellation.

The runner supplies the job token through an HTTP Authorization secret injection
mechanism to the exact mirror URL above. Bearer and Basic (matching owner username)
are accepted. Never put it in URLs, remote configuration, logs or committed files.
Job tokens authorize only upload-pack discovery/RPC for that repository, target
and configured mirror. They cannot use primary Git, primary APIs, mirror sync or
prepare, other repositories/targets, receive-pack or static object/pack URLs.

Each request freshly checks the database grant, expiry, cancellation, credential
revocation, issuer token revocation/read-only status/expiry, owner and repository
ready state/storage generation. The check is repeated after potentially slow
object preparation immediately before Git starts. Database failure denies the
request; no stale authorization cache is used. Admitted streams are also
re-authorized while they run under the configured transfer bound. The bound is
measured from the committed authority change, not from a deliberately paused
client resuming its read: buffered transport can make a later client exception
look slower than the server cutoff. A Git process-group observation is
independent evidence that the native producer and its descendants stopped. No
zero-duration, race-free revocation guarantee is claimed.

The controller can POST to `.../ci-checkouts/{job_id}/cancel` or `/revoke`.
Cancellation creates a permanent tombstone even before issuance, serializing
cancel/first-issue races. Revoke applies only to an issued grant. Both transitions
are monotonic and cannot reset metadata, expiry or terminal state. There is no
renewal, cancellation cleanup or credential cleanup API in this slice.

The 1,024 native source-pin admission bound does not cap SQL cancellation
tombstones created before issuance. Only trusted writable controllers can create
these records, but they are permanent and unbounded. This slice does not claim
production resource controls for that SQL growth.

### Target closure, not hidden references

An owner-token legacy pin uses alternates into a full snapshot and is **not** a
privacy boundary. A job token never serves that view. It gets a separate
`job-views` Git repository containing only its declared target and tag object
closures. Full history includes the target's ancestors. Target history writes
a shallow boundary at the target commit, so an ordinary clone sees only that
commit's history unless a declared tag independently includes older commits.
Gitlinks require separate source grants and credentials, and LFS pointers
require ready, independently authorized bytes.

Preparation writes a fresh non-thin pack without delta/object reuse, checks its
actual object set against the declared target and tag reachability set, verifies
native `fsck --full --strict`, then fsyncs and atomically publishes. No alternates,
external delta bases, unrelated objects, extra refs, replacement refs, grafts,
promisor metadata, hooks or arbitrary configuration are allowed. Target-history
views permit only the plan's exact shallow boundary. Reuse
revalidates the strict on-disk grammar, exact target identity, native integrity
and physical-object-set equality. Git replacement semantics are disabled.

This intentionally conservative materialization duplicates objects and checks
them on each request. Object enumeration is capped at 64 MiB per command and
fails closed beyond that bound. Existing Git process, CPU, memory, file-size and
repository limits apply. The trusted operator controls the mirror filesystem;
a hostile same-UID process able to race file mutations is outside this boundary.
Target-history clones use stock Git shallow fetches; filter-based partial clone
remains unsupported. Validate deployment-specific capacity separately.

`tests/ci_job_checkouts.py` exercises native protocol v0/v2, exact target clones,
known unrelated commit/blob wants, physical closure equality, endpoint scoping,
terminal races, live authority changes, corrupted views and slow-preparation
revocation/database failure. `tests/backup_ci_checkouts.py` covers restored grant
invalidation and a genuine historical format-4 archive, including explicit
`--allow-legacy-schema007` compatibility opt-in. See the execution reports for
actual results; synthetic tests do not establish host/disk power-loss guarantees.

Job upload-pack RPCs inspect at most the first 65,520-byte protocol packet before
committing HTTP response headers. A complete native `ERR` refusal returns an
explicit HTTP 403 with a generic message, after process-group cleanup. This
avoids losing the native denial to an input BrokenPipe or failed-stream flush
race. Successful prefixes are replayed unchanged through the normal output quota,
deadline and process-exit checks; an incomplete or failed PACK never becomes a
clean successful response. The bounded packet inspection does not parse or
authorize object wants in place of native Git and the isolated object closure.

## Source pin listing and lease-coordinated release

Trusted controllers and read-only owner tokens can list retained CI source pins on
the primary or inspect a single job's pin metadata:

```http
GET /api/repos/{owner}/{name}/ci-pins
Authorization: Bearer <owner-token>
```

```http
GET /api/repos/{owner}/{name}/ci-pins/{job_id}
Authorization: Bearer <owner-token>
```

Each entry reports `version`, `job_id`, `owner_id`, `repository_id`,
`storage_generation`, `object_format`, `target_oid`, `retention_ref`, `state`
(`"pinned"` or `"intent"`), and `active_checkout_lease` (`true` or `false`).

When a CI build completes and its source pin is no longer needed, a writable
owner/controller token can release the pin:

```http
DELETE /api/repos/{owner}/{name}/ci-pins/{job_id}
Authorization: Bearer <controller-owner-token>
```

(`POST /api/repos/{owner}/{name}/ci-pins/{job_id}/release` is also accepted.)

Release is coordinated with `ci_checkout_jobs` under the repository writer lock
and per-job PostgreSQL advisory lock (`ci-checkout:{repo_id}:{job_id}`):

1. If an active checkout lease exists (`plan IS NOT NULL`, `NOT cancelled`,
   `NOT revoked`, and `expires_unix > extract(epoch FROM clock_timestamp())`),
   release is rejected with **HTTP 409 Conflict** (`active checkout lease exists
   for job`) and both `refs/rootyard-ci/jobs/{job_id}` and `<job_id>.pinned.json`
   remain intact.
2. Once the lease has expired, been cancelled, or been revoked, release executes
   a crash-safe 3-step cleanup: removes `<job_id>.pinned.json`, deletes the
   native retention ref `refs/rootyard-ci/jobs/{job_id}` via a journaled
   `observed_immutable_ci_root` operation (`action: "released"`, `new_oid` zero),
   and removes `<job_id>.json` to free a slot under the 1,024 `MAX_PINS` cap.
3. Re-releasing an already-released job is idempotent and returns HTTP 200 with
   `"state": "released", "released": true`.

## Disk watermarks and safe LRU eviction

Read mirrors support both automatic watermark eviction (via
`ROOTYARD_MIRROR_HIGH_WATERMARK_BYTES`, `ROOTYARD_MIRROR_LOW_WATERMARK_BYTES`,
and `ROOTYARD_MIRROR_MAX_SNAPSHOTS` after snapshot sync or closure
materialization) and explicit operator/controller eviction:

```http
POST /api/repos/{owner}/{name}/mirror-evict
Authorization: Bearer <owner-token>
Content-Type: application/json

{"target_bytes": 1073741824, "max_pins": 128, "max_job_views": 128, "max_snapshots": 4}
```

(`POST /api/repos/{owner}/{name}/mirror-prune` with an empty or `{}` body prunes
all unprotected pins, unprotected job views, and unreferenced historical
snapshots.)

Eviction enforces strict fail-closed preservation invariants:

- `current.json` and the active snapshot directory it references are **never**
  evicted.
- Any target OID protected by an active checkout lease in `ci_checkout_jobs` is
  **never** evicted.
- Any target OID retained by an active `refs/rootyard-ci/jobs/*` pin in the
  current storage generation is **never** evicted.
- A historical snapshot directory is evicted only after all retained
  `pin-{generation}-{oid}.json` mappings referencing that snapshot have been
  evicted.
- Every eviction run that reclaims artifacts records a durable audit row in
  `ci_mirror_evictions` (schema migration `030_ci_mirror.sql`) and returns an
  `EvictionReport` with `eviction_id`, `evicted_pins`, `evicted_job_views`,
  `evicted_snapshots`, `reclaimed_bytes`, `disk_bytes_before`, `disk_bytes_after`,
  and `protected_oids`.

## Concurrent sync rate limiting and mirror observability

To prevent sync or closure-materialization stampedes on a read mirror,
`serve-mirror` enforces bounded concurrency semaphores and per-repository
in-flight serialization:

- `ROOTYARD_MIRROR_MAX_CONCURRENT_SYNCS` (default `4`): maximum concurrent
  `mirror-sync` operations across the mirror volume.
- `ROOTYARD_MIRROR_MAX_CONCURRENT_CLOSURES` (default `4`): maximum concurrent
  `job-views` reachability-closure pack materializations.
- `ROOTYARD_MIRROR_SYNC_COOLDOWN_MS` (default `0`): optional minimum cooldown
  between completed syncs of the same repository.
- Concurrent sync requests for a repository that already has a sync in flight, or
  requests that exceed the global semaphore/cooldown, fail immediately with
  **HTTP 429 Too Many Requests** and increment rate-limit counters.

Operators and controllers can inspect per-repository mirror state via:

```http
GET /api/repos/{owner}/{name}/mirror-status
Authorization: Bearer <owner-token>
```

And scrape fixed-cardinality Prometheus metrics (`Cache-Control: no-store`) from
`GET /metrics` on the mirror listener (`rootyard_mirror_sync_in_flight`,
`rootyard_mirror_sync_limit`, `rootyard_mirror_syncs_total`,
`rootyard_mirror_rate_limited_total`, `rootyard_mirror_evictions_total`,
`rootyard_mirror_evicted_items_total`, `rootyard_mirror_reclaimed_bytes_total`,
`rootyard_mirror_disk_bytes`, `rootyard_mirror_snapshots`,
`rootyard_mirror_pins`, `rootyard_mirror_job_views`, and
`rootyard_mirror_active_leases`).

## Durable multi-mirror orchestration, failover, and bounded bursts

When multiple read mirrors register via `POST /api/repos/{owner}/{name}/ci-mirrors/{mirror_id}/heartbeat`,
the primary validates the mirror URL (requiring HTTPS outside loopback and
rejecting credentials, queries, paths, or origin-spoof `"origin"` targets) and
requires `audience` to equal the configured `ROOTYARD_CI_MIRROR_AUDIENCE`. Operators
and controllers can inspect registered mirrors and origin fallback headroom via:

```http
GET /api/repos/{owner}/{name}/ci-mirrors?target_oid=<optional-oid>
```

The scheduler and `POST .../integrations/{hook_id}/runs/{run_id}/claim` enforce:

- **Audience-matched load-balanced selection**: only active, recently
  heartbeating mirrors matching `storage_generation`, `ROOTYARD_CI_MIRROR_AUDIENCE`,
  exact `target_oid` readiness, and spare `capacity` are eligible, ordered by
  fewest active `leased` runs and largest capacity headroom.
- **Explicit deterministic state classification**: `inspect`, `claim`,
  `failover`, and `mirror-auto-fetch` classify outcomes as `ready`, `waiting`,
  `denied`, `missing`, or `overloaded` in both the JSON `classification` field
  and the `X-Rootyard-CI-State` response header.
- **Coalesced prewarming & bounded waiting**: on PR sync (`on_pull_synchronized`),
  background reconciliation (`reconcile_runs`), and unready `claim`, the primary
  coalesces singleflight `mirror-auto-fetch` prewarm requests strictly to
  operator-allowlisted origins configured in `ROOTYARD_CI_MIRROR_PREWARM_ORIGINS`
  using a dedicated low-privilege prewarm token (`ROOTYARD_CI_MIRROR_PREWARM_TOKEN`;
  the mirror's primary-pull credential `ROOTYARD_CI_MIRROR_SOURCE_TOKEN` is never
  transmitted by the primary). Callers may pass optional
  `wait_for_ready_ms` (bounded by `ROOTYARD_CI_CHECKOUT_WAIT_QUEUE`, default `64`)
  on `claim` or `wait_ms` (bounded by `ROOTYARD_MIRROR_SYNC_QUEUE_LIMIT`, default
  `32`) on `mirror-auto-fetch` to wait cleanly under burst contention.
- **Mid-job failover & durable lease reconciliation**: runners holding an active
  fenced `(attempt, lease_generation, runner_id)` lease may call
  `POST .../integrations/{hook_id}/runs/{run_id}/failover` (with optional
  `failed_source`, `exclude_sources`, or `requeue_only: true`) to rotate to another
  ready mirror or origin fallback with incremented `(attempt, lease_generation)`
  and freshly minted checkout credentials. Closed/drifted PR runs are cancelled
  and expired leases are reaped back to `queued` automatically without shifting
  the target commit OID.

## Bounded transfer revocation (`ROOTYARD_TRANSFER_REVOCATION_BOUND_MS`)

Active Git HTTP (`git-upload-pack`, `git-receive-pack`), Git LFS downloads, and
mirror origin-preparation transfers (`mirror-sync` / `mirror-prepare`) enforce
a configurable end-to-end revocation bound via
`ROOTYARD_TRANSFER_REVOCATION_BOUND_MS` (default `3000` ms; accepted range
`300..=60000` ms, validated at startup):

- **Budget partitioning**: each transfer derives `check_interval` (`total / 4`,
  clamped `50..=5000` ms), `reauth_timeout` (`total / 3`, clamped `100..=2000`
  ms), and `stop_grace` (`total / 4`, clamped `50..=1000` ms) so detection,
  PostgreSQL authority re-verification, and process-group termination fit inside
  the configured bound.
- **Covered revocation triggers**: user token revocation/expiry, browser session
  revocation/expiry, collaborator/organization membership removal or role
  downgrade, restricted grant narrowing, `ci_checkout_jobs` and
  `ci_integration_checkout_jobs` cancellation/revocation/expiry, webhook or
  trusted-context deactivation, closed PRs, repository non-`ready` states, and
  `storage_generation` increments.
- **Fail-closed authority & origin non-bypass**: if PostgreSQL or authority
  verification errors or exceeds `reauth_timeout`, the active stream aborts
  immediately and sends `SIGTERM` to the entire native Git process group (`-pgid`),
  polling `/proc` quiescence up to `stop_grace` before escalating to `SIGKILL`
  and waiting for all descendants to exit before releasing repository locks or
  reaping the leader PID. Mirror preparation (`mirror-prepare` using
  `ROOTYARD_CI_MIRROR_SOURCE_TOKEN`) periodically revalidates the underlying job
  scope during both `git clone --mirror` and origin LFS fetches and aborts
  without publishing partial snapshots or permitting origin fallback bypass.

### What the configured-bound acceptance measures

`tests/ci_job_checkouts.py` and the standalone `tests/transfer_revocation.py`
record a typed monotonic trigger interval. For a committed mutation,
`t_before` is taken immediately before the real revoke/cancel/remove/generation
operation and `t_after` after its successful commit; one conservative deadline
`D = t_before + configured_bound` is used for every observation and is never
reset to the API response time. For a natural grant or token expiry, the
authoritative PostgreSQL clock is sampled before and after the scenario and the
expiry is mapped into monotonic time. The earliest mapped expiry is the lower
bound, an inconsistent clock mapping is rejected, and no `expiry + 0.35 s`
fresh-clock shortcut is used.

The real transfer is opened with a fixture-owned small `SO_RCVBUF` set before
connect; the effective `getsockopt` value is recorded but is not treated as a
payload-capacity proof. A 16/24/32 MiB incompressible payload and bounded
producer channels make the consumer pause meaningful. The harness proves a
live fixture 4-tuple and a service-owned socket inode, then requires a
**continuous sender-stall window**: the server TX queue and client RX queue are
positive on every qualifying sample, the paused receiver queue is stably
non-draining, sampling gaps are bounded, and any missing, unobservable, reset,
or nonqualifying sample invalidates the window. Time spent before the first
qualifying sample does not count. The minimum qualified interval is 500 ms, not
merely the last few samples. The large unfinished payload plus bounded producer
source is the precondition that prevents a producer that already finished all
bytes into the socket buffer from being mistaken for sustained backpressure.
No zero-window kernel witness is claimed; if this sustained sender-stall
evidence cannot be observed, the result remains unproven.

The healthy read pause is before the mutation and the final qualifying sample
is taken immediately before the mutation trigger (or shortly before the mapped
natural expiry). After the trigger the consumer stays paused for a shorter
interval (the CI starting point is 800 ms at `B=1200`, inside `D`), then drains
promptly with the remaining absolute deadline and `read1`-style incremental
reads. A timeout, local close, or harness cancellation is never a pass.

Only confirmed transport truncation (incomplete framing, short
`Content-Length` EOF, or reset) can be a client observation. A later observation
does not prove a late server cutoff because buffered bytes can delay visibility.
For Git, the harness independently captures the actual service-descendant
process-group leader, start time, and PGID before the trigger, tracks every
member including non-Git descendants, treats `Z`/`X` as non-running like the
production quiescence check, and rejects PGID reuse or unobservable `/proc`
state. The pass rule is exactly `S_upper - E_lower <= B`, with no additive CI
tolerance. Leak/reap, GC-lock, and staging checks remain separate sanity checks
and do not reset the bound clock.

Each subcase reports the configured bound, trigger kind and interval (or expiry
clock bracket), backpressure witness and effective receive buffer, target and
actual pre/post-trigger pauses, client stop kind/time, Git group quiescence and
polling gaps, and `configured_bound_proven`. The harness timestamps the body
reader's actual monotonic resume, not just the planned hold, and derives every
relative elapsed field from the final validated natural-expiry `E_lower` (the
initial single-sample bracket is retained only for audit). The same final
`E_lower` drives the pass booleans and report values; an invalid or inconsistent
clock mapping fails rather than passing. Existing top-level case IDs and the
original 17-case inventory are preserved; added report fields are timing
evidence, not a new runtime qualification. These are harness measurements, not
a new server telemetry endpoint, and a timed-out or unobservable run remains
unproven.

## Live multi-mirror and multi-controller HA qualification

Multi-daemon deployments couple live `rootyard serve` controllers,
`rootyard worker`, and multiple `rootyard serve-mirror` daemons over shared
PostgreSQL 17 state:

- **Typed mirror identity & continuous keepalive**: `mirror-auto-fetch` parses
  `ROOTYARD_CI_MIRROR_ID` / explicit `mirror_id` as a `UUID` before upserting
  `ci_mirror_nodes` (`publish_ready_oid`), starts a periodic background keepalive
  (`8`s interval, inside `MIRROR_HEARTBEAT_TTL_SECS = 30`) so healthy mirrors
  stay `alive=true` across long jobs, and `GET /api/repos/{owner}/{name}/ci-mirrors`
  decodes the PostgreSQL `UUID` column directly without conversion panics.
- **Parallel prewarm fanout**: `trigger_coalesced_prewarm` dispatches bounded
  coalesced `mirror-auto-fetch` requests across up to 8 healthy unready
  allowlisted origins in parallel (`JoinSet`), keeping `ROOTYARD_CI_MIRROR_SOURCE_TOKEN`
  isolated from primary-issued prewarm calls.
- **Qualification harness & workflow**: `tests/ci_mirror_ha_qualification.py`
  exercises live multi-controller/multi-mirror checkout (Scenario A), dual
  `SIGKILL` of mirror #1 and controller #1 with `worker`/`reconcile`/failover
  and `409` stale attempt fencing (Scenario B), and all-mirrors-down
  simultaneous origin-fallback bursts covering all 5 `X-Rootyard-CI-State`
  outcomes and leak checks (Scenario C) on single-host loopback PG 17 (not a
  multi-host WAN/power-loss test). Enforced statically by
  `tests/test_ci_mirror_ha_contracts.py` and in CI by
  `.github/workflows/ci-mirror-ha.yml`.


