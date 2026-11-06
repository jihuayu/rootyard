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
seven days), but eviction remains disabled with physical cleanup until every
source reader uses a durable lease.

Jobs in `storage_maintenance_jobs` carry repository and tenant identities, a
storage generation, a short lease, an attempt count, and a claim generation.
Every renewal and completion compares the owner, attempt, and generation;
an expired worker cannot publish a late result. The server holds the global
shared backup advisory lock, a PostgreSQL repository-exclusive reader lease,
the local reader gate, and then the repository write lock while running native Git.
It checks the shard primary and storage fence after admission. Git children
inherit the data-volume flock and receive a Linux parent-death signal.

Repacking currently retains old packs. Physical tombstone deletion and pack pruning remain disabled pending
complete durable lease coverage across all source readers, including CI and
workspace paths. An unavailable lease, backup barrier, shard route, or job
generation fails closed and retries within the configured attempt limit.
When enabled, deletion takes a `NOWAIT` repository row lock and locks existing
workspace, CI, and pull retention rows before reachability inspection. New
foreign-key-backed roots and state changes cannot race the unlink decision;
an in-progress root writer makes the collector retry.

Migration 112 reserves `pando_*` job kinds in the same durable queue. The
GitFS scheduler does not enqueue them and its worker rejects them until the
production Pando gateway can resolve pack manifests from PostgreSQL and
verify ref, CI, workspace, migration, and backup retention before remote
deletion. S3 listing and synthetic Pando lab commands are not retention
authorities.
