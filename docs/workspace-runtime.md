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
Lease handoff rejects active sandbox jobs, and sandbox admission and execution
are bound to a persisted lease epoch. A running job is cancelled when its lease
or database authority disappears. Database lease changes are reflected in the
FUSE gate on the next scan or at the previous deadline. An operation admitted
before expiry may finish on the old host's local upper layer; the old epoch
cannot publish a checkpoint or remote manifest after lease handoff.

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
