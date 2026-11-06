# Durable GitFS maintenance

Set `ROOTYARD_STORAGE_MAINTENANCE=true` on a native-volume server to run the
maintenance scheduler. It is disabled by default. `worker` and `worker-once`
are control-plane consumers and never touch the Git volume.

The scheduler samples `git count-objects -v` for ready repositories on the
local primary. `ROOTYARD_STORAGE_REPACK_LOOSE_OBJECTS` (default 1024) and
`ROOTYARD_STORAGE_REPACK_PACKS` (default 8) cause a nonpruning repack when
counts cross the thresholds. The last completed repack records a count
baseline, so unchanged counts do not produce repeated packs. The scheduler
also queues cleanup of stale LFS `.tmp-<uuid>` upload files and an unreachable
object inspection. `ROOTYARD_STORAGE_SCAN_PERIOD_SECONDS` (default 3600),
`ROOTYARD_STORAGE_STAGE_AGE_SECONDS` (default 3600), and
`ROOTYARD_STORAGE_MAINTENANCE_POLL_SECONDS` (default 5) control those tasks.

Jobs in `storage_maintenance_jobs` carry repository and tenant identities, a
storage generation, a short lease, an attempt count, and a claim generation.
Every renewal and completion compares the owner, attempt, and generation;
an expired worker cannot publish a late result. The server holds the global
shared backup advisory lock, a PostgreSQL repository-exclusive reader lease,
the local write lock, and the local reader gate while running native Git.
It checks the shard primary and storage fence after admission. Git children
inherit the data-volume flock and receive a Linux parent-death signal.

Repacking currently retains old packs and `git fsck` only reports unreachable
objects. Physical tombstone deletion and pack pruning remain disabled pending
complete durable lease coverage across all source readers, including CI and
workspace paths. An unavailable lease, backup barrier, shard route, or job
generation fails closed and retries within the configured attempt limit.
