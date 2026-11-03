# Cross-process workers and paired restore verification

Local verification on 2026-11-03 integrates recovery/backup `89a536754441c492c36511aa781a093acca3ecd7` and cross-process workers `770d5bba327852c097f3dceef3f3de23de79822a` in a new worktree. No main-branch merge, deployment, production access or traffic change was performed. Schema003 remains unchanged.

## Executable and environment

- Fixed tested binary SHA-256: `5d9c3033119c6bcd2cc31813a95ddbb6e9fdec4511b870cb39c4b5a82ed7d1dd`.
- Linux x86-64; Rust/cargo 1.99.1; Git client/server 2.56.0.
- PostgreSQL server and clients 17.11 (Debian 17.11-0+deb13u1).
- Real Redis server 7.2.7, reached through a `redis-server` multicall symlink. Its executable name is preserved, and the Redis suite actually ran rather than being skipped.
- Fresh synthetic PostgreSQL clusters on random loopback ports. Backup/restore drills used a different cluster and nonexistent private volume for the destination. Tests stop/drop only their own processes and databases.

## Merge boundaries

The CLI merge retains `backup-verify` before database configuration, and `worker`/`worker-once` before Git/data-volume configuration. Serving still rechecks the persistent restore guard after waiting for the migration advisory lock and before recovery or listening. Both AppState constructors initialize dispatch signals. Docker still includes the schema contract files at build time and PostgreSQL 17 clients at runtime. CI retains all backup/recovery tests, the real Redis test and the actual image-build smoke job, and adds restored-worker acceptance.

Database-only workers intentionally cannot inspect the filesystem restore guard. Consequently all target workers and database clients must remain stopped/isolated until restore succeeds and is reviewed. A crash guard is not permission to start workers against an ambiguous target database. No new PostgreSQL restore-fence schema or distributed storage fencing is claimed.

## Full local regression

All of the following passed against the fixed executable:

- Formatting and clippy with warnings denied.
- 31 Rust tests, plus both explicitly ignored PostgreSQL integration tests run separately (`outbox` and `resolution_fences`).
- Both pristine migration and real dump/restore schema-contract comparisons.
- 15 e2e, 18 durable reliability, seven explicit recovery and five metrics groups.
- Seven backup fault groups and six schema003 full-data restoration groups.
- Six cross-process groups, including four real workers, consumer failure isolation, SIGKILL of a leased worker, lease reclaim, lost/duplicate Redis hints, Redis disconnection and restart.
- Four new `tests/restored_workers.py` groups described below.

A preliminary schema003 backup fixture used embedded workers while expecting immediate deterministic drain. A reproduced stop left four legitimate leased rows with roughly 60 seconds remaining, exceeding that fixture's 30-second drain bound. The fixture now explicitly disables embedded workers and owns its transitions with worker-once; no production lease behavior was weakened. The restored-worker suite separately proves both unexpired-lease preservation and expiry/reclaim, and the affected suites were rerun.

A separate read-only review of the CLI merge and restore/worker isolation documentation found no blocker in that narrow scope; it did not substitute for the runtime suites.

The exact published commit's CI result is separate from this local record. CI builds and smoke-tests the actual Docker image; no local Docker daemon was available. A successful workflow must be checked for the final head, not inferred from either parent. Reports include the executable hash; CI uploads JSON artifacts.

## Restored-worker drill

1. Two resolved unknown incidents and one unresolved incident supply real schema003 recovery history and snapshots. Native Git pushes create two genuine new pending events. The fixture leaves five outstanding delivery rows: two pending, two expired leases (including one genuine old-generation event requeued as a stale-lease fixture), and one unexpired lease. The synthetic lease transitions do not claim another successful push.
2. A full backup restores into the other fresh PostgreSQL cluster and new GitFS directory. All eleven public tables compare row-for-row, including lease owners/generations/deadlines, effect state, historical resolutions and snapshot provenance. Volume UUID and journal bytes match exactly before any worker starts.
3. Two independent workers run with no Git executable in PATH and an invalid configured volume path. They drain eligible rows, increase reclaimed lease generations, and leave every restored GitFS byte unchanged. The unexpired lease row remains exactly unchanged and has no audit effect until the test explicitly advances that synthetic deadline; it is then reclaimed with a newer fence. The old-generation ref event is retired as `superseded_generation`, leaving the generation-2 main snapshot unchanged. Resolved unknown operations remain unknown and immutable, and discarded unknown candidates never gain audit events.
4. Authenticated clone/fsck recover the expected native content; revoked/read-only restrictions and the unresolved repository block remain effective. A new real generation-2 push queues two deliveries while embedded workers are disabled. Independent workers apply them once; another worker-once invocation changes no database rows or historical resolutions.

The ordinary backup fault drill also passes on the integrated binary: live-volume lock exclusion, commit while waiting for the barrier, unsafe/corrupt inputs, exporter death, queued DDL, real interrupted pg_restore cleanup and the startup guard. Tiny-sample command times were backup **10.969 seconds**, restore **7.923 seconds**; the richer pending-lease restore took **9.481 seconds**. No captured-boundary commit was missing. One deliberately acknowledged post-boundary commit, made **96.590 seconds later**, was absent after restore. This demonstrates finite RPO, not lossless recovery or a production RTO promise.

## Limits

The existing [backup contract](backup-restore.md), [manual recovery](manual-recovery.md) and [worker contract](cross-process-workers.md) still apply. Redis is only a wake hint and is not backup state. PostgreSQL remains the only delivery/lease/effect authority. Exactly-once checks cover transactional PostgreSQL effects, not arbitrary external effects. Unexpired source leases can delay restored delivery until their deadlines.

Not established: host/power loss, PostgreSQL crash or partitions, distributed volume fencing, production scale or RPO/RTO, online/PITR backup, remote retained backup authenticity, a Kafka adapter, or privileged-administrator tamper resistance. Keep an interrupted restore target isolated and review or discard both stores; workers are not a recovery override.
