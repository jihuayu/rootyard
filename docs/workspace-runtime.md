# Native workspace runtime

The service persists workspace identity, repository authorization, lease epoch,
revisions, and checkpoint roots in PostgreSQL. `ROOTYARD_WORKSPACE_MOUNT_MODE=fuse`
mounts each ready workspace through a Linux FUSE overlay. Its cloned Git repository
is the lower layer; writes from standard tools go to a private upper layer. The
service remounts ready local workspaces at startup. Mount creation requires a
usable `/dev/fuse` and mount namespace permission; the native regression runs
the service inside `unshare -Urm` while sharing the test PostgreSQL network.

`POST /api/workspaces/{id}/sandbox-jobs` accepts `workspace_access: "live"` only
when FUSE mode and `ROOTYARD_SANDBOX_MODE=dev` are both enabled. It binds that
mount at `/workspace` in the isolated process. The default private mode copies
the workspace; production `cgroup` mode uses private copy plus cgroup CPU,
memory, and process limits. Development live mode is not an aggregate resource
isolation boundary.

FUSE mutation callbacks check the current lease deadline and share a mutation
gate. Checkpoint capture holds that gate exclusively while it copies the working
tree and native `.git` state. This makes the copy one filesystem-operation
boundary, including editor rename-overwrite and Git index updates, but does not
turn a multi-file application edit into one atomic transaction. Mandatory scans
capture external changes every two seconds; event replay exposes revisions.

## Capture and native Git bounds

Background capture runs in three phases: a lock-free eligibility read, one
full-tree fingerprint on a bounded blocking worker (entered inside the FUSE
mutation gate, so a freeze snapshot stays stable and a cancelled caller never
releases the gate early), and a short `FOR UPDATE` transaction that re-reads
`host_id`, `state`, the live lease, `revision` and `lease_epoch`. A scan is
discarded unless the row still matches the values read before the scan, so a
stale scan can never overwrite a newer API edit, checkpoint or lease handoff.
The fingerprint row, the revision bump and the `external_capture` event commit
in that one transaction; an unchanged fingerprint writes no revision and no
event.

Eligible workspaces are paged by `id` (`id > cursor ORDER BY id LIMIT 100`), so
every local workspace is visited each round instead of rescanning one fixed
prefix. A workspace that is slow, errors, or exceeds the scan budget occupies at
most its own worker and is retried on a later round. `ROOTYARD_WORKSPACE_SCAN_WORKERS`
(1-16, default 3) and `ROOTYARD_WORKSPACE_SCAN_QUEUE` (1-64 per worker, default
4) bound concurrency and queueing; `ROOTYARD_WORKSPACE_SCAN_TIMEOUT_MS` (default
30000) bounds how long a caller waits for a result. A timed-out or cancelled
scan keeps its worker slot and the FUSE gate until the filesystem closure
really returns, so shutdown or lease loss never unfreezes a workspace while a
scan is still running.

API mutations (`POST /workspaces`, `POST /lease`, `PUT /files`, `POST /git`,
`POST /checkpoints`, and `POST /checkpoints/{id}/restore`) serialize per
workspace in memory behind `MutationGuard` (`lock_mutation`), which drains any
active `ScanToken`s before admitting a foreground mutation and blocks
overlapping background `begin_scan` rounds without holding PostgreSQL row locks
across filesystem, Git, or object-store I/O:

1. **Phase 1 (Read-only preflight)**: a short transaction verifies repository
   authorization, idempotency replay, live lease authority, and expected
   revision/entry/Git generation, then releases the database connection.
2. **Phase 2 (Bounded off-TX execution)**: working-tree writes, checkpoint and
   restore copies, cross-host takeover materialization, FUSE prewarm, and
   post-mutation fingerprint hashing execute off-thread behind the Data I/O
   bulkhead (`io_slots`). Concurrency and caller waits are bounded by
   `ROOTYARD_WORKSPACE_IO_CONCURRENCY` (1-64, default 8),
   `ROOTYARD_WORKSPACE_IO_ACQUIRE_TIMEOUT_MS` (1-300000, default 5000; returns
   retryable `503` on exhaustion), and `ROOTYARD_WORKSPACE_IO_TIMEOUT_MS`
   (1-600000, default 120000; returns `504` when the caller stops waiting while
   the worker keeps its slot until syscalls finish). Workspace-mutating closures
   and returned pre-`COMMIT` guards (`PutRollback`, `GitRollback`, `Published`,
   `LazyPublished`, `DirCleanupGuard`) retain `ScanToken`s plus caller
   abandonment flags until both the OS thread and any rollback/cleanup complete
   on disk. Fast FUSE mount/freeze/observe operations use an isolated control
   bulkhead (`control_slots`) so data copies do not starve control traffic.
3. **Phase 3 (Short `FOR UPDATE` CAS commit and pre-`COMMIT` rollback)**: a
   short `FOR UPDATE` transaction rechecks idempotency, live lease epoch, and
   expected versions/fingerprints, records the pre-computed baseline, and
   commits. Definite pre-`COMMIT` conflicts (`409`) or Phase 2 failures run
   restoration/cleanup on a dedicated non-rejecting `cleanup_bulkhead` (with
   `Drop` vacating canonical directory/sidecar paths via O(1) `.trash-*` renames
   and finishing removal off-thread while keeping `ScanToken` armed).

Workspace repository inspection and mutation commands run through one bounded
native Git wrapper that reuses the GitFS collector: stdout is capped per call
(4 MiB for file views, 64 KiB for `add`/`reset`), stderr is drained and
discarded, the command runs in its own process group, and the shared Git
timeout applies. A timed-out or cancelled command kills and reaps the whole
process group before the caller continues, so no descendant outlives the job.

`PUT /files` (`put_slots`, capacity 32) and Git reads/mutations (`git_slots`,
`ROOTYARD_MAX_CONCURRENT_GIT`) reserve an owned admission permit up front, so
full capacity fails fast with retryable `503`. Both `PUT /files` and `POST /git`
execute inside an owned Tokio `JoinSet` job registry: a client disconnect drops
only the HTTP response future while the owned job finishes its 3-phase execution
(and any pre-`COMMIT` rollback), allowing a retry with the same
`Idempotency-Key` to replay a committed result. Completed jobs are pruned on
admission and graceful HTTP shutdown drains every owned job before exiting (the
grace duration is a warning threshold rather than an abort). An operator
`SIGKILL` or power loss remains outside graceful guarantees. Before spawning
`git`, `GitRollback` snapshots `.git/index`, bounded `.git/objects` entries
(failing closed before spawning if `.git/objects` cannot be read or exceeds the
entry cap), and whether `.git/index.lock` already existed. A pre-existing
`.git/index.lock` created outside that owned job is never unlinked; only when
`.git/index.lock` was absent before the job and left behind after process-group
termination or a pre-`COMMIT` rejection does `GitRollback` remove that newly
created lock, restore `.git/index`, and prune newly created loose objects (with
direct upper-layer and synchronized `.rootyard-whiteouts.json` fallback if the
FUSE mount was fenced mid-flight).
Lease handoff rejects active sandbox jobs, and sandbox admission and execution
are bound to a persisted lease epoch. A running job is cancelled when its lease
or database authority disappears. Database lease changes are reflected in the
FUSE gate on the next scan or at the previous deadline. An operation admitted
before expiry may finish on the old host's local upper layer; the old epoch
cannot publish a checkpoint or remote manifest after lease handoff.

Workspace FUSE writes pass a process-local mutation gate with `Healthy`,
`Frozen` and `Fenced` states. A freeze first stops new admissions and then waits
for already admitted mutations to drain before running its closure; reads are
not gated. Dispatch is bounded per mount: the kernel shim copies each request
into an owned operation and a single actor per mount owns the overlay and asks
the gate for admission exactly once. A frozen gate parks writes/creates/
setattr/mkdir/unlink/rmdir/rename/write-open in a bounded FIFO with their
replies held, while reads, lookup, readdir and read-only open continue. After a
successful thaw the actor drains the FIFO in order; it notices the thaw with a
bounded 10 ms poll and an enqueue notification, not a new kernel request. A
fenced or lease-expired gate returns `EROFS` for parked and new mutations;
neither path changes content. A queued mutation is stamped with the lease epoch
seen at enqueue, and admission checks the guard's epoch against that stamp, so
an actor poll that misses a transient fence and observes the new healthy epoch
still rejects the old write with `EROFS`. Only a queue-limit breach returns `EAGAIN`
(per mount 128 operations/8 MiB, all mounts 1024/32 MiB, released exactly once
when the reply is sent). Lazy reads use the global 4-worker/256-job pool and a
saturated pool replies `EAGAIN` instead of running inline on the actor. On
normal shutdown the gate is fenced and the queue closed; the actor checks
shutdown before gate phase handling and fails ready and parked replies with
`EIO` without executing them, while an already-admitted mutation may finish. A
lazy read already executing in the pool replays no content but checks shutdown
after I/O and returns `EIO`; joining that in-flight read belongs to the helper
phase. See [fuse-dispatch-phase2](fuse-dispatch-phase2.md). A fence is terminal for the current lease epoch and does not
wait for a freeze or for an in-flight mutation. It wakes blocked waiters with
`EROFS`, ignores the legacy deadline-only lease update, and cannot be cleared by
that update or by reusing the old epoch. Only a strictly higher epoch restores
writes. Both `re_authorize` and the lease handoff reject a request that arrives
during a freeze or while a guard admitted under the old epoch is still alive;
that rejection is `EWOULDBLOCK` and is never bypassed. The gate's RAII admission
count is released on error and panic, and a fenced state is never thawed by a
freeze guard being dropped.

A same-host lease commit acquires its FUSE freeze (`with_frozen_fenced`, holding
a `ScanToken`) before checking out the Phase 3 PostgreSQL connection or `FOR
UPDATE` row lock, fences the old epoch before that freeze is released, and
authorizes the committed epoch afterwards through the same fence-then-authorize
handoff used by the mount `ensure` path. Freeze acquisition is bounded
independently from Phase 3 commit execution (and helper freeze completion runs
on `cleanup_bulkhead`), so control-slot saturation or a slow commit never turns
a proven pre-`COMMIT` rollback into a false fence or discards a committed epoch.
The old epoch can therefore not admit a new mutation in the window between the
commit and the new-epoch authorization, and a handoff that is rejected leaves
the gate `Fenced` instead of `Healthy` on the superseded epoch. The wrapper
separates a proven pre-COMMIT rollback from an unknown outcome: an error before
the commit flag is signalled as a known rollback and thaws the original epoch,
while commit success, a COMMIT transport error, a panic or a cancelled caller
during Phase 3 leaves the gate `Fenced`. A pre-COMMIT conflict such as an active
sandbox therefore returns normally and keeps the same healthy epoch writable.
Such a fenced mount stays read-only, returning `EROFS` for new mutations, until
a later committed lease epoch is authorized by a lease acquire, checkpoint
completion or startup reconcile.

Lease refresh observations are epoch-ordered under the gate lock. A late epoch
`N` response that arrives after handoff `N+1` is ignored: it neither fences the
new epoch nor lowers its deadline. An equal observation renews only a `Healthy`
gate and cannot clear a fence; a newer observed epoch fences the current one but
never authorizes the observed epoch, which still requires an explicit handoff
that passes the fence floor. A missing refresh row may be an old query snapshot,
so it fences only if the gate's epoch and generation still match the snapshot
taken before the query; a concurrent handoff wins over the old missing row.

This gate is only a prerequisite for an independent FUSE helper. The session is
still a `BackgroundSession` in the API process, so an operator `SIGKILL` can
still leave a thread in `request_wait_answer` holding the same-process FUSE
descriptor; the helper and parent-loss lifecycle remain open and have no native
acceptance. The bounded per-mount freeze queue described above is a prototype
inside that same process, not the helper: it has no independent child, IPC or
heartbeat, cannot fence a second process, and keeps queued work in memory only.
Parked freeze writes do survive a normal thaw, but an operator `SIGKILL` still
loses them and remains unhandled. The native freeze-queue tests are `#[ignore]`d
and executed by the coordinator; an explicit `--ignored` run without
`ROOTYARD_FUSE_NATIVE=1` fails instead of passing. See
[fuse-dispatch-phase2](fuse-dispatch-phase2.md).

A new host can acquire an expired workspace lease only when its latest revision
has a committed checkpoint. It verifies and materializes that checkpoint from
the tenant-scoped remote object store before changing host ownership, then
mounts the existing workspace ID on its own volume. Edits made after that
checkpoint on the old host have no durable takeover guarantee. A workspace
without a committed current checkpoint must be restored as a new workspace or
recovered from its original volume.

The FUSE overlay currently materializes a complete local Git clone as its lower
layer. It does not lazily fetch individual files from remote CAS, implement
dirty-safe cache eviction, or prewarm an offline sparse tree. Checkpoints become
remote-durable only after the separate authenticated publish step reports
`committed`; local capture reports `local_complete`.

Signed CI integrations can start an origin-backed sandbox at
`/api/repos/{owner}/{name}/integrations/{hook_id}/runs/{run_id}/sandbox-jobs`.
The request supplies the claimed runner ID, attempt, lease generation, head OID,
storage generation, command and timeout. The service rechecks the signed
integration, active trusted context and open PR candidate, exact root checkout
plan, and run lease before preparing a local checkout at that OID. It stores the
CI run tuple without a user identity, executes the command in bubblewrap, and
rechecks authority until completion. The same signed tuple authorizes status,
cancellation and bounded logs. Ordinary user sandbox routes cannot access CI
jobs. In-service execution currently accepts `source=origin`; mirror-scheduled
claims use the external runner because a trusted in-service mirror materializer
is not present. The native CI test uses development namespace mode; production
aggregate resource limits require a delegated cgroup v2 root.
