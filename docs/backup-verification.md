# Offline backup/restore verification

Local verification date: 2026-11-03. Scope: the phase-two offline backup branch, stacked on durable events and the provisioning-test timing correction. No production instance was accessed, no deployment or traffic change was performed, and no pull request was opened.

## Runtime and exact executable

- Linux x86-64, unprivileged service process.
- Rust/cargo 1.99.1; native Git client/server 2.56.0.
- PostgreSQL server, pg_dump and pg_restore 17.11 (Debian 17.11-0+deb13u1).
- Tested debug executable SHA-256: `8c665cc1b238c6340350d8a9cb6c80de4307763ae7cc58d7d94edaf2546a23cb`.
- Two independently initialized disposable PostgreSQL clusters, random loopback ports and run-owned random databases. Restore used the other cluster and a nonexistent private data directory. The harness cleaned only its own databases and fixtures.

## Passed commands

- `cargo fmt --all -- --check`
- `cargo clippy --locked --all-targets -- -D warnings`
- `cargo test --locked --all-targets`: 23 Rust tests passed; the one PostgreSQL test is explicitly ignored by this default command.
- `cargo test --locked --test outbox -- --ignored`: the real durable-outbox PostgreSQL test passed separately.
- `python3 tests/reliability.py ...`: all 18 durable-push/outbox regression groups passed.
- `python3 tests/backup.py ...`: all seven groups below passed against the final executable.
- `python3 tests/e2e.py ...`: all 15 phase-one regression groups passed after rebasing onto `373138a` (the baseline provisioning fixture timing correction).

The e2e and reliability reports recorded the exact executable hash above; the backup manifest binds the same executable, and the executable was unchanged throughout the final drill. CI is not implied by these local results; the exact pushed commit's checks must be reviewed before merge.

## Backup drill results

1. A real HTTP server with Git descendants/volume ownership prevents backup. Synthetic users, read-only/revoked tokens and a normal Git two-commit round trip supplied the source. A separate recovering repository contained one SQL unknown operation and an unfinished retained journal.
2. An in-flight token revocation held an uncommitted row update while backup waited for SHARE locks. After it committed, the dump and restored database included the revocation. The inherited volume lock also blocked capture independently.
3. Before SQL import, verification rejected corrupt/truncated dumps, modified/missing/extra files, path traversal, ordinary external symlinks, a symlink volume root, FIFO and oversized completion markers, existing targets, nested backup destinations and external Git object/commondir dependencies. Extra schemas (including `pgxevil`), functions, array domains and composite types were rejected on source and target.
4. Terminating the exporting PostgreSQL connection prevented publication. Queued conflicting DDL caused a bounded safe pg_dump failure rather than a self-deadlock or a published partial backup.
5. A real pg_restore was deliberately held on a PostgreSQL catalog lock, then its Rootyard parent was SIGKILLed. The native child and backend import exited, no partial public tables remained, and the crash-persistent guard blocked server startup before creating the target directory.
6. After backup, a new standard Git push was acknowledged. It was deliberately outside the captured boundary.
7. Restore into the other fresh PostgreSQL cluster succeeded. Native fsck ran on every existing repository, and an independently authenticated HTTP clone passed fsck with matching boundary refs/content. Revoked and read-only tokens retained their restrictions. The unknown repository remained recovering and blocked. Its raw journal bytes were preserved before deliberate service startup.

Final local sample timings:

- Backup command: **9.446 seconds**.
- Restore command (copy, native integrity checks, SQL import and publication): **6.521 seconds**.
- Backup boundary commits missing after restore: **0**.
- Acknowledged commits made after the boundary and not recovered: **1**. Its acknowledgment was **79.625 seconds after** the captured boundary.

These measurements are from a tiny synthetic fixture and a roughly 69 MB debug hook runner; repeated hashing/copying of that runner is included. They are not an SLA or production RTO. The deliberate lost post-backup commit demonstrates the backup's finite recovery point; it is not a zero-loss design. Full RTO also includes provisioning/transfer, operator review and traffic changes, none of which were measured here.

## Review and remaining gaps

An independent read-only review covered snapshot ordering, lock queueing, interruption cleanup, persistent startup fencing, unsafe paths/links, archive trust, PostgreSQL scope and state fidelity. Findings were fixed and the affected tests rerun. The manifest's file digests detect accidental corruption, not a malicious producer.

Not established: hardware/kernel/power-loss safety, physical host failure, network partitions/proxy failure, NFS or distributed-volume semantics, production RPO/RTO, high concurrency or large repositories, PITR, encrypted remote retention, signatures/authenticity, cross-version/schema-003 recovery, ACL/xattr/ownership portability or all possible failures around an ambiguous SQL COMMIT. A test-harness run exhausted `/tmp` while retaining multiple private fixture copies; only this task's fixtures were cleaned, temporary data moved to the workspace, and the complete affected tests rerun. This was not counted as a successful product disk-full fault test.

Restore failures remain uncertain across PostgreSQL and the filesystem, even after single-transaction SQL import. The target stays isolated and its guard must not be removed without reviewing or discarding both targets. See [the operational contract](backup-restore.md).
