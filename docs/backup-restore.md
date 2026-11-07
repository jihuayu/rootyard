# ADR 004: an offline backup and isolated restore slice

Status: current integration uses backup format 12 and the exact migration/catalog set embedded in the producing executable (`src/db.rs`, `schema/136_*`). Formats 6, 7, 8, 9, 10 and 11 stay frozen at schema 130, 131, 132, 133, 134 and 135 for archives made before later migrations; restoring them requires the explicit `--allow-legacy-schema130`, `--allow-legacy-schema131`, `--allow-legacy-schema132`, `--allow-legacy-schema133`, `--allow-legacy-schema134` or `--allow-legacy-schema135` upgrade path, at most one per restore. This is a Linux, single-node GitFS maintenance tool, not online replication, failover, PITR, encrypted object storage or a zero-loss guarantee. PITR and the delete broker (#77) remain unresolved and are not provided by this slice. It does not stop or deploy a service, switch traffic, or automatically repair unknown pushes.

## Supported boundary

Except for the explicit legacy schema007 compatibility option below, use the exact Rootyard executable that made the backup, Git >= 2.43, PostgreSQL 17 and matching `pg_dump`/`pg_restore` clients. Keep that executable separately in your trusted release archive. The manifest includes its SHA-256; the copied hook runner is evidence, never an executable used by the restore tool.

The current format requires the reviewed public catalog embedded in its executable: columns/defaults, constraints, indexes, function definitions and attributes, enabled triggers, rules and row-security policies. Format 12 binds the complete schema136 catalog, including the token `is_restricted`/`scope_version`/`display_name` columns and the token repository/namespace scope tables and reference indexes added by migration 136, the composite repository/tenant identity foreign keys and unique key added by migration 134, the schema135 partial covering storage-maintenance metrics index, the index-only browser-session/token GC reference indexes from migration 133, and the existing volume UUID. Format 11 stays frozen at schema135, format 9 at schema133, format 8 at schema132 with the Pando remote-retention authority state, format 7 at the frozen schema131 catalog and format 6 at the frozen schema130 catalog; each is verified against its own `schema/13*_*` fixture set before the reviewed later migrations are applied in the same restore session. Retain each producing executable with its archive; schema125 is still evolving on the draft integration branch and is not a released cross-version compatibility promise. Earlier format-1/schema-002, format-2/schema-003 and format-3/schema-006 archives require their original trusted executable and a separate reviewed upgrade, not this restore command. Unknown tables, non-public application schemas, additional/modified routines, user-defined types, extensions other than plpgsql, large objects, non-permanent/non-ordinary tables and connection `options` are rejected. The connection must explicitly name one host, a user and a database; URLs and passwords are never passed as subprocess arguments. There is no automatic migration on backup or restore. Future schema versions or catalog/deparser changes require an explicit reviewed contract update and another fresh-database restore drill. Database roles, ACLs, configuration, credentials, extensions and tablespaces are not portable backup inputs; restoration owns the imported tables as the destination service identity and does not import owners/ACLs.

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

1. Create a fresh, unused dedicated PostgreSQL 17 database and a private destination parent, with no public ingress, service process, external workers or other clients. The destination data directory itself must not exist. Keep standalone `worker`, `worker-once`, embedded workers and every other target database client stopped until restore succeeds and the target is reviewed. Firewall/credentials/process isolation remains an operator responsibility: `--isolated` does not prove that arbitrary clients cannot connect later.
2. Configure `DATABASE_URL` for that new database and `ROOTYARD_DATA_DIR` for the new path. Use the same trusted binary as the backup, or the explicit schema007 compatibility option below. Do not point at the source database: the nonempty-database check rejects it, even if a different DSN spelling or proxy is used.
3. Run:

```sh
rootyard restore /private-backups/set-2026-11-03 --isolated --trust-backup
```

4. The command validates the complete backup before mutating the target, holds the migration advisory lock, refuses existing database objects/other sessions and reserves a persistent `.<destination-name>.rootyard-restoring` guard in the destination's parent. It copies to a new private staging directory, takes its volume lock, runs native `git fsck --full --strict` for every existing repository and compares repository identity, HEAD and refs. It then imports PostgreSQL with `--clean --if-exists --single-transaction --exit-on-error --no-owner --no-privileges`, checks the full schema contract and repository IDs/generations/incident revisions/states/unknown counts, and publishes the directory without replacement. The clean flags allow recreating the initially empty public schema inside the import transaction; they do not authorize replacing a used database, and the operator must prevent clients or DDL from appearing after the empty-target check. Only after parent fsync does it remove and fsync the startup guard.
5. No service is started. In the isolated environment, start the matching service deliberately, inspect startup recovery and owner audit APIs, perform authenticated clone/fetch, compare expected refs/content, verify revoked/read-only credentials and test a disposable controlled push before considering any separately approved traffic change.

All four Forge tables are captured in full, including personal owner/repository/author identity, Issue/comment text, open/closed state, CAS versions, timestamps and both numbering counters. The durable creation-key table preserves canonical request payloads and original creation responses, even where the current Issue/comment has since been edited. Keys have no automatic expiry or retention deletion. Backup and post-import validation reject committed entries whose creation response is null; such placeholders are valid only inside an uncommitted creation transaction. Restore preserves the captured counters, states and authors, and does not convert Forge changes into Git operations/outbox events. Counters can be lower than the lost source's later values: Issue/comment numbers allocated only after the backup boundary may be reused after restore. This is not global monotonic numbering across data loss; review references to post-boundary content before reopening the service. Issue/comment versions rewind too and can recur in the restored timeline. CAS protects only the current database history, not continuity across disaster recovery. Keys first committed after the backup are lost too: retrying those keys after restore may create another object. Idempotency is scoped to the captured database history, not a disaster-recovery fence. Clients must GET and confirm current content/version after cutover rather than treating cached post-boundary resource/version pairs as a recovery fence. Ready-state and token authorization remain API checks after restore; a recovering repository is not made writable simply because its Issues were restored.

SQL unknown counts and retained journal-record counts are separate manifest facts. An unfinished journal may not yet have a SQL operation. Raw evidence, generations, immutable recovery/operation resolutions, incident revisions, observed snapshots, projection provenance and delivery effects are preserved; refs and fsck are never used to manufacture success receipts or clear unknown outcomes. Startup recovery follows the existing protocol, and unresolved unknown repositories stay blocked. Historical inspection fingerprints remain opaque evidence: a new filesystem inode can legitimately change a new inspection fingerprint while the stable volume UUID remains unchanged. Resolved unknown history stays unknown; startup cleanup only accepts the exact evidence already covered by the resolution. Changed or newly introduced journals remain incidents. Database owners/superusers remain trusted administrators: trigger-based immutable history is not protection against privileged TRUNCATE, disabled triggers or direct catalog changes.

Pending deliveries and lease owners/generations/deadlines are retained as recorded. After successful restore and review, independently started PostgreSQL workers reclaim expired leases through the normal fence; an unexpired source lease can delay delivery until its deadline. Redis wake hints are not backup inputs and losing them cannot erase durable delivery state. Reconnect workers to the correct restored database explicitly, never both an ambiguous target and the source.

## Failures and interruptions

- Before publication, temporary directories are named `.rootyard-backup-<uuid>.partial` or `.rootyard-restore-<uuid>.partial`. Failure does not delete forensic material or pretend the backup succeeded. Treat any retained files as private.
- Files and directories are fsynced, but their power-loss guarantees still depend on the filesystem, hardware and PostgreSQL deployment. Local hashes cannot validate those guarantees.
- Linux parent-death signals kill spawned tools when the CLI dies, including after SIGKILL; normal cancellation also kills and reaps them. Import/export sessions set PostgreSQL client_connection_check_interval to one second so the server can notice a closed local client socket even while waiting for a lock; network-failure detection still depends on the connection/proxy/kernel. A database commit can nevertheless occur before acknowledgment is lost. A failed restore therefore has an **uncertain target database**, not an automatic rollback promise across both stores.
- A restore guard survives failure, including between SQL commit and volume publication. Rootyard checks it before opening storage, after the volume lock and after migration locking before recovery/serving. Do not remove it merely to make startup work. Keep the targets isolated, inspect them, and either complete a reviewed recovery or discard the **entire disposable target database and data/staging directories**. Only then remove the individually verified guard and start a new restore into fresh targets. The command never overwrites or blindly retries an uncertain target. The filesystem guard fences volume-opening commands, not PostgreSQL-only `worker`/`worker-once`: those deliberately cannot inspect GitFS. A failed restore target must remain inaccessible to those workers as well; the guard is not a substitute for target database isolation.
- The tool does not intentionally serialize database URLs, connection passwords or issued tokens into manifests or normal CLI diagnostics. User-controlled path/ref text can itself contain sensitive information, so do not treat manifests as safe public reports. Subprocess diagnostics are suppressed because they can contain private content. Database credentials are supplied through a cleared subprocess environment, not argv; the service OS account and administrators can still read process environments and backups. Token digests, actor IDs, repository names and evidence remain sensitive data in the archive.
- A valid backup is not necessarily a healthy service: unknown journals and recovering states are intentionally preserved. Structural corruption can fail restoration/fsck; preserve the backup for investigation rather than altering evidence to get a pass.

## RPO/RTO and verification

The backup records its stopped-writer boundary time. Work acknowledged **after** that boundary is outside the backup and can be lost if the primary volume is destroyed. The backup interval and actual failure determine RPO. RTO includes transfer, provisioning, import, integrity checks, startup review and the separately authorized traffic change, not just the command timer.

`tests/backup.py` creates random databases and private Git trees on synthetic test servers, exercises real Git push/clone/fsck, verifies in-flight metadata writes at the barrier, rejects corrupt/unsafe sets, and restores into a fresh database/directory. Set `ROOTYARD_RESTORE_TEST_DATABASE_URL` to a separate disposable server to exercise a different PostgreSQL instance. It requires CREATEDB and the interrupted-import fault test requires the test administrator to lock a PostgreSQL catalog; never run it against production. It only drops databases it creates.

```sh
python3 tests/backup.py --binary target/debug/rootyard --report test-results/backup.json
```

The schema contract fixtures are generated only from pristine synthetic migrations and their real pg_dump/pg_restore and restored003-upgrade paths using `tests/schema_contract.py`. PostgreSQL normalizes three BETWEEN-derived CHECK expressions on the round trip, so exactly three complete reviewed catalog shapes are accepted: the pristine current migration set, its full pg_dump/pg_restore, and a restored schema003 subsequently upgraded through the current migrations. The last has a normalized old ref CHECK beside native new Forge CHECKs. No arbitrary expression normalization is performed. Do not regenerate fixtures from an altered production database to bypass a rejection. `tests/backup_recovery.py` additionally proves all sixteen tables, resolution protections, volume identity and authenticated operation after a cross-cluster restore.

See [the populated Forge integration record](forge-backup-verification.md) and [the earlier recovery integration record](integration-verification.md) and [the original schema-002 drill](backup-verification.md) for actual measured outcomes and remaining gaps. PostgreSQL's [snapshot lock ordering](https://www.postgresql.org/docs/17/sql-lock.html), [pg_dump snapshot/lock behavior](https://www.postgresql.org/docs/17/app-pgdump.html) and [pg_restore trust/transaction boundary](https://www.postgresql.org/docs/17/app-pgrestore.html) are the underlying contracts.

### Workspace remote checkpoint objects

Workspace checkpoint objects in the shared object store are outside this
archive's LFS/Pando closure and outside the current PITR/delete-broker
contract. Physical deletion of those tenant/workspace/SHA-256 keys is disabled
by default. Abandoning a failed checkpoint still marks its SQL row `failed`
and reports that remote cleanup is pending, but every staging reference is
retained as a retryable key reference and audit trail. The bytes continue to
count against object-store quota and retention until a controlled external
delete broker removes them; the API must not describe them as reclaimed.

The only destructive switch is the explicitly unsafe legacy operator opt-in
`ROOTYARD_WORKSPACE_UNSAFE_REMOTE_DELETE=true`. It runs the old guarded
collector, which keeps the advisory lock and refuses a key while any committed
or resumable staging reference for the same tenant still exists. It never
derives a key from a caller-supplied tenant, source or authority. This mode is
not a PITR or disaster-recovery proof: a PostgreSQL clone/PITR rollback of
workspace root metadata can disagree with the shared bucket, and this mode does
not detect that. A future delete broker must carry an external deletion epoch
and isolate PUT credentials; until then the workspace remote-delete fence (#77)
remains open. Never point an out-of-band metadata copy at the shared bucket.

### Restored execution authority

New backups use format12 with the executable's current schema136 catalog and include
`ci_checkout_jobs` grants, permanent cancellation tombstones and the Pando
remote-retention authority state. The paired
volume still supplies source-pin files and native Git roots; SQL rows alone do
not prove retention. All restored issued checkout grants are permanently marked
revoked before the restore guard is removed. This deliberately differs from the
backup's `revoked` values: restoring a snapshot taken before cancellation must
never resurrect an old bearer. Plans, tombstones and source pins remain intact.
Use a new job ID and establish its source pin before issuing a new checkout.
Every restored format 6 or newer archive (legacy 6/7/8/9/10/11 and current 12) also rotates cluster delegation incarnation, clears transport nonces, cancels queued/leased CI runs and queued/running sandbox jobs, disables mirror readiness, expires Workspace epochs and revokes browser sessions/tokens. Leased webhook deliveries become pending with a new lease generation. Ordinary
owner tokens retain the existing backup-boundary restore behavior; reconcile
post-backup owner-token revocations before reopening external ingress.

Format4/schema007 archives remain readable against their original, exact
catalogs and contract digest. Restoring an archive made by a different historical
binary requires the explicit final option `--allow-legacy-schema007`:

```
rootyard restore /absolute/backup --isolated --trust-backup --allow-legacy-schema007
```

This opt-in is rejected for every other format. It bypasses only the exact-binary hash
comparison for an already verified format4/schema007 archive. All archive
checksums, isolated target requirements, restored schema and repository identity
checks remain mandatory. Restore verifies schema007 before any later `migrate`
upgrades it to the current schema. Neither checksums nor this compatibility flag establish
archive authenticity; use only trusted, operator-controlled archives.

Format6/schema130 archives remain readable against their frozen catalogs and
contract digest. Restoring one with the current format11 binary requires a
different explicit final option, because the current binary hash necessarily
differs from the historical producer:

```
rootyard restore /absolute/backup --isolated --trust-backup --allow-legacy-schema130
```

This verifies the complete format6/schema130 catalog before applying the
reviewed migrations 131 through 136 on the same restore session; it never relabels
an archive as format11 or rewrites its manifest. A format6 archive is rejected
without this option, and the option is rejected for other formats. Format7/schema131
archives have the equivalent final opt-in:

```
rootyard restore /absolute/backup --isolated --trust-backup --allow-legacy-schema131
```

It verifies the frozen schema131 catalog and its contract digest before applying
migrations 132 through 136, it is rejected for formats other than 7, and at most one
legacy opt-in may be chosen. Format8/schema132 archives have the equivalent final
opt-in:

```
rootyard restore /absolute/backup --isolated --trust-backup --allow-legacy-schema132
```

This verifies the frozen schema132 catalog and contract digest, then applies the
reviewed migrations 133 (index-only GC reference indexes), 134 (composite
repository/tenant identity constraints), 135 (partial metrics index) and 136
(token scopes) in the
same restore session. A format8
archive is always rejected without this option, so a restored database can never
serve the current schema without those reviewed upgrades. Format9/schema133
archives have the equivalent final opt-in:

```
rootyard restore /absolute/backup --isolated --trust-backup --allow-legacy-schema133
```

This verifies the frozen schema133 catalog and contract digest, then applies the
reviewed migrations 134 (identity constraints), 135 (partial metrics index) and
136 (token scopes)
in the same restore session. A format9 archive is always rejected without this
option, and the option is rejected for every other format. Format10/schema134
archives have the equivalent final opt-in:

```
rootyard restore /absolute/backup --isolated --trust-backup --allow-legacy-schema134
```

This verifies the frozen schema134 catalog and contract digest, then applies the
reviewed migrations 135 and 136 in the same restore session, after which the current
schema136 catalog and every migration version are verified again. A format10
archive is always rejected without this option, and the option is rejected for
every other format. Format11/schema135 archives have the equivalent final opt-in:

```
rootyard restore /absolute/backup --isolated --trust-backup --allow-legacy-schema135
```

This verifies the frozen schema135 catalog and contract digest, then applies the
reviewed migration 136 (token scope columns, tables and indexes) in the same
restore session, after which the current schema136 catalog and every migration
version are verified again. A format11 archive is always rejected without this
option, and the option is rejected for every other format. Format4/format5 archives retain their existing exact-producer
rule except for the explicit format4/schema007 option above.

### Remote LFS closure

Formats 6 through 12 inventory every ready LFS object by tenant/repository/OID/size while the database and volume barriers are held. Missing local bytes are downloaded through the configured authenticated remote store, then SHA-256 and size are verified before copying. The manifest carries this closure; backup verification checks local bytes and restore compares imported metadata against it. The restored target needs no remote endpoint for these objects. Failed hydration or digest mismatch prevents backup publication.

Pando repositories are captured the same way: the archive carries `pando_refs`/`HEAD` rows plus the encrypted pack closure of every `storage_backend='pando'` repository, and restore re-imports that closure through the configured object store before the volume is published. A missing or unreachable closure fails the restore instead of publishing a partially complete target. Stop Workspace mounts and all service descendants before the offline capture.

Executed receipts: `evidence/backup-integration.json`, `evidence/backup-remote-lfs.json`, `evidence/backup-upgrade-integration.json` and `evidence/backup-recovery-integration.json`. They record local functional/fault drills, not production RPO/RTO guarantees.
