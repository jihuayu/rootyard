# Durable GitFS maintenance

Set `ROOTYARD_STORAGE_MAINTENANCE=true` on a native-volume server to run the
maintenance scheduler. It is disabled by default. `worker` and `worker-once`
are control-plane consumers and never touch the Git volume.

The scheduler samples `git count-objects -v` for ready repositories on the
local primary. `ROOTYARD_STORAGE_REPACK_LOOSE_OBJECTS` (default 1024) and
`ROOTYARD_STORAGE_REPACK_PACKS` (default 8) cause a nonpruning repack when
counts cross the thresholds, then rebuilds the reachable commit-graph cache.
The last completed repack records a count baseline, so unchanged counts do not
produce repeated packs. The scheduler
also queues cleanup of stale LFS `.tmp-<uuid>` upload files and a bounded Git
reachability scan. Unreachable OIDs become durable grace-period tombstones;
reflogs and native CI pin refs remain roots. `ROOTYARD_STORAGE_SCAN_PERIOD_SECONDS` (default 3600),
`ROOTYARD_STORAGE_STAGE_AGE_SECONDS` (default 3600), and
`ROOTYARD_STORAGE_MAINTENANCE_POLL_SECONDS` (default 5) control those tasks.
The cache eviction age is `ROOTYARD_STORAGE_CACHE_MAX_AGE_SECONDS` (default
seven days). Physical cleanup stays behind the same fence as every other
destructive maintenance step.

Jobs in `storage_maintenance_jobs` carry repository and tenant identities, a
storage generation, a short lease, an attempt count, and a claim generation.
Every renewal and completion compares the owner, attempt, and generation;
an expired worker cannot publish a late result. The server holds the global
shared backup advisory lock, a PostgreSQL repository-exclusive reader lease,
the local reader gate, and then the repository write lock while running native Git.
It checks the shard primary and storage fence after admission. Git children
inherit the data-volume flock and receive a Linux parent-death signal.

Physical tombstone deletion is enabled only through the durable admission
fence added by migration 127. A collector takes the repository row `FOR UPDATE`,
increments the monotonic `gc_epoch`, commits a renewable maintenance lease,
and writes a durable fence owner/job identity. Writers must insert a
`storage_write_admissions` row while holding `repositories FOR SHARE`; a
committed fence rejects the write with `503` instead of queueing it behind a
long native operation. The collector waits for every unexpired active
admission to finish or expire before it inspects or prunes Git objects. The
fence heartbeat fails closed if the PostgreSQL session, epoch, claim, or backup
barrier is lost.

Phase 1 collects the complete reachability root union before any physical
rewrite: all native refs (public and hidden), open/merged pull request head,
base, merge and review pins, active CI run and checkout pins, workspace and
checkpoint base commits, namespace mounts, view source pins, view history,
non-complete two-phase ChangeSet proposal pins, CI sandbox heads, and the
durable ref projection. It locks every existing retention row, then anchors
every SQL pin under `refs/keep/gc-epoch-<epoch>/` and verifies the native ref
snapshot still matches. A retention-root trigger rejects new root rows or
state changes while the committed fence is active, so the snapshot cannot
drift. A missing pinned object aborts collection rather than guessing.

For a due tombstone still inside a Git pack, the collector runs `git repack -A
-d` only after the keep refs exist. Git loosens unreachable objects from old
packs; the worker runs fsck again and unlinks only due, still-unreachable loose
objects. Unmarked objects keep their grace period even when a pack is
rewritten.

Phase 2 stages each candidate loose object in a private quarantine directory,
then re-verifies the durable epoch, fence owner, job claim, reader lease,
backup barrier, native-root snapshot, SQL-root snapshot, and zero concurrent
admissions. Only after that proof does it unlink the quarantined files. If any
check fails it renames every staged object back to the object directory before
returning an error. A crash leaves a fsynced manifest; the next collection
restores abandoned entries. Every tombstone delete intent is committed on a
separate connection before staging, so a crash after unlink is reconciled
against fresh native object existence and a transient Git inspection error
never counts as a successful delete.

The worker also defers every unlink until all objects currently reported by
native `git fsck --unreachable` have due tombstones at the same repository
generation. This conservative closure rule keeps a newly unreachable commit
and its older shared tree/blob intact throughout the commit's grace period.
After taking the exclusive PostgreSQL reader lease, physical jobs wait five
seconds before touching the volume while renewing their claim, fence, and
backup barrier. A remote reader or collector whose database session died can
detect the loss and SIGKILL/reap its native Git process group during this
window. `ROOTYARD_STORAGE_MAINTENANCE_QUIESCENCE_SECONDS` (default 15) bounds
the wait for admitted writers; an unexpired writer that does not finish makes
the collector retry instead of pruning.

The collector measures every unreachable object's expanded size and refuses
the pack rewrite unless the volume has room for twice Git's reported pack
plus loose storage, all loosened objects, and a 256 MiB reserve. This is a
conservative admission estimate; an actual ENOSPC remains retryable without
discarding retained objects. An oversized or malformed object listing
fails closed.

Migration 112 reserves `pando_*` job kinds in the same durable queue. The
GitFS scheduler does not enqueue them and its worker rejects them until the
production Pando gateway can resolve pack manifests from PostgreSQL and
verify ref, CI, workspace, migration, and backup retention before remote
deletion. S3 listing and synthetic Pando lab commands are not retention
authorities.
