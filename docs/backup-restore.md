# ADR 004: an offline backup and isolated restore slice

Status: phase two, integrated with durable events and explicit incident recovery (schema migrations 1, 2 and 3). This is a Linux, single-node GitFS maintenance tool, not online replication, failover, PITR, encrypted object storage or a zero-loss guarantee. It does not stop or deploy a service, switch traffic, or automatically repair unknown pushes.

## Supported boundary

Use the exact Rootyard executable that made the backup, Git >= 2.43, PostgreSQL 17 and matching `pg_dump`/`pg_restore` clients. Keep that executable separately in your trusted release archive. The manifest includes its SHA-256; the copied hook runner is evidence, never an executable used by the restore tool.

This integrated slice supports only a dedicated database with the exact reviewed schema-003 structure and migration versions `[1, 2, 3]`: eleven tables, five functions and six non-internal triggers. A fixed catalog contract checks columns/defaults, constraints, indexes, function definitions and attributes, enabled triggers, rules and row-security policies against the migrations; simply retaining expected table/function names is insufficient. Backup format 2 binds this contract and the existing volume UUID. Format-1/schema-002 archives require their original trusted executable and a separate reviewed upgrade, not this restore command. Unknown tables, non-public application schemas, additional/modified routines, user-defined types, extensions other than plpgsql, large objects, non-permanent/non-ordinary tables and connection `options` are rejected. The connection must explicitly name one host, a user and a database; URLs and passwords are never passed as subprocess arguments. There is no automatic migration on backup or restore. Future schema versions or catalog/deparser changes require an explicit reviewed contract update and another fresh-database restore drill. Database roles, ACLs, configuration, credentials, extensions and tablespaces are not portable backup inputs; restoration owns the imported tables as the destination service identity and does not import owners/ACLs.

The existing data directory, the backup's parent, the destination's parent and all their ancestors must be real operator-controlled directories. Do not use symlink paths, hostile shared writable parents, nested mounts or concurrent manual filesystem changes. Only the three managed hook symlinks pointing to `.runner` are accepted. Other symlinks, hard-linked regular files, special files, setuid/setgid/sticky modes and non-UTF-8 filenames are rejected. Repositories using alternates/http-alternates, shallow/promisor/partial-clone object storage, commondir/linked-worktree routing or include configuration are rejected rather than depending on the source machine to pass integrity checks.

The existing private `.volume-id` must be present and valid; this tool does not generate or replace it. Every historical recovery resolution must refer to that same volume UUID. All files, hidden files, journals, sequence counters, retained operation evidence, provisioning trees, refs, reflogs, configuration, objects and managed hook bytes are copied. File and subdirectory modes are preserved. The new root is private (0700), files belong to the invoking service identity, and numeric ownership, ACLs, xattrs, timestamps and sparse extents are not preserved. Do not use this tool if those features are needed for your deployment.

## Create a backup

1. Disable ingress and scheduled maintenance, stop Rootyard and wait for its Git descendants to exit. Do not run manual Git, migrations, DDL or direct filesystem changes. The tool does **not** stop processes for you. CLI token/admin writes and outbox DML are blocked by the database barrier during capture and can time out, so pause them too.
2. Supply `DATABASE_URL` and `ROOTYARD_DATA_DIR` through your trusted secret/config mechanism. Use the service identity, not root. The backup path must not exist and must be outside the data directory.
3. Run:

```sh
rootyard backup /private-backups/set-2026-11-03 --offline
rootyard backup-verify /private-backups/set-2026-11-03
```

`backup-verify` does not need PostgreSQL, Git or database configuration. It verifies the exact file inventory, types, modes, lengths, hashes and manifest completion marker. It does not authenticate the producer, run fsck or promise that every repository is healthy.

4. Preserve the complete set and its matching trusted binary together. Restrict and encrypt storage and transport using your deployment's reviewed tooling. Resume the source only after successful publication and review. Uploading or scheduling backups is a separate action, not performed here.

### Why the two captures are consistent

The command obtains the existing `.rootyard.lock` exclusively, using `O_NOFOLLOW`. A running server or surviving Git child holds that same inherited flock, so capture refuses rather than scanning a changing Git tree.

A dedicated PostgreSQL connection obtains the existing migration advisory lock **before** starting REPEATABLE READ. Inside the transaction, `LOCK TABLE ... IN SHARE MODE` obtains every current Rootyard table lock before the first snapshot-taking SELECT. This waits for in-flight DML commits and blocks new DML and conflicting table DDL. This is not a global PostgreSQL DDL fence: independent DDL, including `CREATE OR REPLACE FUNCTION`, remains forbidden operationally for the entire maintenance window. Acquiring an advisory lock with SELECT inside REPEATABLE READ before waiting for the tables would establish a stale snapshot; that ordering is deliberately not used.

Only after the full barrier is held does the command inventory repositories and export a snapshot. `pg_dump` imports that snapshot and dumps the complete validated public schema as one custom archive, including the recovery-protection functions and triggers. A table-only dump would omit those dependent functions and is not used. The command keeps the table transaction and volume flock across the database dump, whole-volume copy and source/staging inventory comparison. A final connection check and confirmed transaction end are required before the COMPLETE marker is written. Final publication uses Linux `renameat2(RENAME_NOREPLACE)` and parent-directory fsync.

This is a stopped-writer boundary across two transaction domains. It does not turn PostgreSQL and GitFS into one transaction, repair an already-mismatched source pair, or recover retired events from a newer journal-free volume plus an older unrelated database. Operators must select the actual database/volume pair used by that service.

Backup barrier lock waits are limited to five seconds, and pg_dump uses `--lock-wait-timeout=5s`. Conflicting queued DDL may cause a safe failure rather than an unbounded self-deadlock. Restore SQL does not have a five-second lock deadline. Each native tool has a one-hour deadline and a 64 MiB stdout bound. Inventory is capped at two million entries, 4096-byte relative names and a 256 MiB manifest. The total maintenance duration also depends on hashing/copying the complete tree and is not an SLA.

## Restore to a genuinely isolated environment

A PostgreSQL dump can execute SQL selected by its producer. Hashes detect corruption, **not authenticity**. Use only a trusted backup; do not inspect unknown archives by executing them. `--trust-backup` is an explicit trust decision, not a sandbox.

1. Create a fresh, unused dedicated PostgreSQL 17 database and a private destination parent, with no public ingress, service process, external workers or other clients. The destination data directory itself must not exist. Firewall/credentials/process isolation remains an operator responsibility: `--isolated` does not prove that arbitrary clients cannot connect later.
2. Configure `DATABASE_URL` for that new database and `ROOTYARD_DATA_DIR` for the new path. Use the same trusted binary as the backup. Do not point at the source database: the nonempty-database check rejects it, even if a different DSN spelling or proxy is used.
3. Run:

```sh
rootyard restore /private-backups/set-2026-11-03 --isolated --trust-backup
```

4. The command validates the complete backup before mutating the target, holds the migration advisory lock, refuses existing database objects/other sessions and reserves a persistent `.<destination-name>.rootyard-restoring` guard in the destination's parent. It copies to a new private staging directory, takes its volume lock, runs native `git fsck --full --strict` for every existing repository and compares repository identity, HEAD and refs. It then imports PostgreSQL with `--clean --if-exists --single-transaction --exit-on-error --no-owner --no-privileges`, checks the full schema contract and repository IDs/generations/incident revisions/states/unknown counts, and publishes the directory without replacement. The clean flags allow recreating the initially empty public schema inside the import transaction; they do not authorize replacing a used database, and the operator must prevent clients or DDL from appearing after the empty-target check. Only after parent fsync does it remove and fsync the startup guard.
5. No service is started. In the isolated environment, start the matching service deliberately, inspect startup recovery and owner audit APIs, perform authenticated clone/fetch, compare expected refs/content, verify revoked/read-only credentials and test a disposable controlled push before considering any separately approved traffic change.

SQL unknown counts and retained journal-record counts are separate manifest facts. An unfinished journal may not yet have a SQL operation. Raw evidence, generations, immutable recovery/operation resolutions, incident revisions, observed snapshots, projection provenance and delivery effects are preserved; refs and fsck are never used to manufacture success receipts or clear unknown outcomes. Startup recovery follows the existing protocol, and unresolved unknown repositories stay blocked. Historical inspection fingerprints remain opaque evidence: a new filesystem inode can legitimately change a new inspection fingerprint while the stable volume UUID remains unchanged. Resolved unknown history stays unknown; startup cleanup only accepts the exact evidence already covered by the resolution. Changed or newly introduced journals remain incidents. Database owners/superusers remain trusted administrators: trigger-based immutable history is not protection against privileged TRUNCATE, disabled triggers or direct catalog changes.

Expired delivery leases are retained as recorded and may be reclaimed by normal workers after a deliberate restart.

## Failures and interruptions

- Before publication, temporary directories are named `.rootyard-backup-<uuid>.partial` or `.rootyard-restore-<uuid>.partial`. Failure does not delete forensic material or pretend the backup succeeded. Treat any retained files as private.
- Files and directories are fsynced, but their power-loss guarantees still depend on the filesystem, hardware and PostgreSQL deployment. Local hashes cannot validate those guarantees.
- Linux parent-death signals kill spawned tools when the CLI dies, including after SIGKILL; normal cancellation also kills and reaps them. Import/export sessions set PostgreSQL client_connection_check_interval to one second so the server can notice a closed local client socket even while waiting for a lock; network-failure detection still depends on the connection/proxy/kernel. A database commit can nevertheless occur before acknowledgment is lost. A failed restore therefore has an **uncertain target database**, not an automatic rollback promise across both stores.
- A restore guard survives failure, including between SQL commit and volume publication. Rootyard checks it before opening storage, after the volume lock and after migration locking before recovery/serving. Do not remove it merely to make startup work. Keep the targets isolated, inspect them, and either complete a reviewed recovery or discard the **entire disposable target database and data/staging directories**. Only then remove the individually verified guard and start a new restore into fresh targets. The command never overwrites or blindly retries an uncertain target.
- The tool does not intentionally serialize database URLs, connection passwords or issued tokens into manifests or normal CLI diagnostics. User-controlled path/ref text can itself contain sensitive information, so do not treat manifests as safe public reports. Subprocess diagnostics are suppressed because they can contain private content. Database credentials are supplied through a cleared subprocess environment, not argv; the service OS account and administrators can still read process environments and backups. Token digests, actor IDs, repository names and evidence remain sensitive data in the archive.
- A valid backup is not necessarily a healthy service: unknown journals and recovering states are intentionally preserved. Structural corruption can fail restoration/fsck; preserve the backup for investigation rather than altering evidence to get a pass.

## RPO/RTO and verification

The backup records its stopped-writer boundary time. Work acknowledged **after** that boundary is outside the backup and can be lost if the primary volume is destroyed. The backup interval and actual failure determine RPO. RTO includes transfer, provisioning, import, integrity checks, startup review and the separately authorized traffic change, not just the command timer.

`tests/backup.py` creates random databases and private Git trees on synthetic test servers, exercises real Git push/clone/fsck, verifies in-flight metadata writes at the barrier, rejects corrupt/unsafe sets, and restores into a fresh database/directory. Set `ROOTYARD_RESTORE_TEST_DATABASE_URL` to a separate disposable server to exercise a different PostgreSQL instance. It requires CREATEDB and the interrupted-import fault test requires the test administrator to lock a PostgreSQL catalog; never run it against production. It only drops databases it creates.

```sh
python3 tests/backup.py --binary target/debug/rootyard --report test-results/backup.json
```

The schema contract fixtures are generated only from pristine synthetic migrations and their real pg_dump/pg_restore round trip using `tests/schema_contract.py`. PostgreSQL normalizes one BETWEEN-derived CHECK expression on the round trip, so exactly two complete reviewed catalog shapes are accepted, not arbitrary expression normalization. Do not regenerate fixtures from an altered production database to bypass a rejection. `tests/backup_recovery.py` additionally proves all eleven tables, resolution protections, volume identity and authenticated operation after a cross-cluster restore.

See [the integrated verification record](integration-verification.md) and [the original schema-002 drill](backup-verification.md) for actual measured outcomes and remaining gaps. PostgreSQL's [snapshot lock ordering](https://www.postgresql.org/docs/17/sql-lock.html), [pg_dump snapshot/lock behavior](https://www.postgresql.org/docs/17/app-pgdump.html) and [pg_restore trust/transaction boundary](https://www.postgresql.org/docs/17/app-pgrestore.html) are the underlying contracts.
