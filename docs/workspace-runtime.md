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

API mutations (file PUT, `git add`/`reset`, checkpoint, restore) still compute
their post-write fingerprint synchronously inside their existing workspace-lock
transaction. That preserves the historical revision/event contract: an API
write is never reported as an external capture, a later native edit still is,
and a failed baseline cannot silently adopt native changes. It is the remaining
per-request full-tree read on a locked row; removing it is follow-up work, not
part of this change. Checkpoint capture still performs its existing full working-tree
copy; that copy is not covered by the bounded background-scan worker and must
not be treated as a short-lock or off-thread operation. Explicit API fingerprint
hashing and checkpoint copy remain existing costs pending a separate safe design.

Workspace repository inspection and mutation commands run through one bounded
native Git wrapper that reuses the GitFS collector: stdout is capped per call
(4 MiB for file views, 64 KiB for `add`/`reset`), stderr is drained and
discarded, the command runs in its own process group, and the shared Git
timeout applies. A timed-out or cancelled command kills the whole process group
before the caller continues, so no descendant outlives the request.

Reads and mutations take one owned `git_slots` permit before the child is
spawned, so a full capacity is a retryable 503 instead of unbounded spawning.
Mutations additionally hand the *entire* operation to an owned Tokio job:
authentication, transaction, `FOR UPDATE` row lock, lease checks, the Git
child, and the fingerprint/event/idempotency commit. A client disconnect drops
only the response future; the job keeps its permit, row lock and child until
the normal Git deadline and commit finish. The response is then unknown and a
retry must reuse the same `Idempotency-Key`, which replays the committed result
instead of repeating the mutation. Completed jobs are pruned on admission and
graceful HTTP shutdown joins every owned job before the runtime exits. The
shutdown grace duration is only a warning threshold: the process keeps waiting
for owned jobs rather than aborting them, because aborting would drop a live
child into the collector's process-group kill and could leave a real
`.git/index.lock` behind. An operator force-kill (`SIGKILL`) or a power loss is
outside that graceful guarantee. Nothing unlinks
`.git/index.lock`: a lock this process did not create stays untouched and the
mutation fails cleanly rather than deleting another writer's lock.
Lease handoff rejects active sandbox jobs, and sandbox admission and execution
are bound to a persisted lease epoch. A running job is cancelled when its lease
or database authority disappears. Database lease changes are reflected in the
FUSE gate on the next scan or at the previous deadline. An operation admitted
before expiry may finish on the old host's local upper layer; the old epoch
cannot publish a checkpoint or remote manifest after lease handoff.

Workspace FUSE writes pass a process-local mutation gate with `Healthy`,
`Frozen` and `Fenced` states. A freeze first stops new admissions and then waits
for already admitted mutations to drain before running its closure; reads are
not gated. Because FUSE dispatch is a single session thread, a new mutation on a
frozen gate is rejected immediately with `EAGAIN` instead of sleeping behind the
freeze, while a fenced or lease-expired gate returns `EROFS`; neither path
changes content. A fence is terminal for the current lease epoch and does not
wait for a freeze or for an in-flight mutation. It wakes blocked waiters with
`EROFS`, ignores the legacy deadline-only lease update, and cannot be cleared by
that update or by reusing the old epoch. Only `re_authorize` with a strictly
higher epoch restores writes, and a re-authorization that arrives during a
freeze still waits for the freeze to finish. The gate's RAII admission count is
released on error and panic, and a fenced state is never thawed by a freeze
guard being dropped.

This gate is only a prerequisite for an independent FUSE helper. The session is
still a `BackgroundSession` in the API process, so an operator `SIGKILL` can
still leave a thread in `request_wait_answer` holding the same-process FUSE
descriptor; the helper and parent-loss lifecycle remain open and have no native
acceptance. Rejected freeze/expiry writes are not queued: a bounded
asynchronous mutation queue is future work if editors need retry-free behavior
during checkpoint or scan freezes.

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
