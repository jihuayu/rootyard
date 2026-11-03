# Schema-003 recovery and backup integration verification

Verified locally on 2026-11-03 in a separate integration worktree. Parents are offline backup `041d962763d8be7ffbd3e20a9868d267f6fa2923` and recovery/metrics `e473b6a100c389b072bd03794009e4870e692e35`, both including the `373138a` baseline fixture correction. This record does not include the later cross-process-worker increment. No production database, deployment, traffic change or main-branch merge was involved.

This historical two-way integration record is followed by [cross-process-worker integration verification](workers-integration-verification.md). Its executable and timings remain specific to the earlier tested increment.

## Exact runtime

- Linux x86-64, Rust/cargo 1.99.1, Git client/server 2.56.0.
- PostgreSQL server, pg_dump, pg_restore and psql 17.11 (Debian 17.11-0+deb13u1).
- Tested executable SHA-256: `da56d9d08ae275d269d099ac08b568fbfb4eaff615b5403a8b03e2e1d6c53a43`.
- Final suites used one fixed executable, separate from the build output, and report that same hash. Backup tests used independently initialized disposable source and destination PostgreSQL clusters with random loopback ports, run-owned databases and private volume directories.

## Completed checks

- `cargo fmt --all -- --check` and `cargo clippy --locked --all-targets -- -D warnings`.
- `cargo test --locked --all-targets`: 27 tests passed, with two PostgreSQL integration tests intentionally ignored by the default command.
- `cargo test --locked --test outbox --test resolution_fences -- --ignored`: both real PostgreSQL tests passed separately.
- `tests/schema_contract.py`: pristine schema-003 migration and actual pg_dump/pg_restore catalog round trip matched the two reviewed fixtures: eleven tables, five functions and six application triggers, plus enabled internal-FK-trigger checks.
- `tests/e2e.py`: all 15 groups passed.
- `tests/reliability.py`: all 18 groups passed.
- `tests/recovery_ops.py`: all seven groups passed.
- `tests/metrics.py`: all five groups passed.
- `tests/backup.py`: all seven groups passed.
- `tests/backup_recovery.py`: all six groups passed.

These commands and the added schema/restore tests are also wired into CI. A separate container job builds the actual Dockerfile and checks the unprivileged hook executable, Git and PostgreSQL 17 dump/restore clients. Packaging review added the embedded schema fixtures to the build context and the matching PostgreSQL clients to the runtime image. No local Docker daemon was available, so image-build evidence must come from that CI job, not the local Rust tests. The exact published commit's CI is a separate result and must be checked before merge; this record establishes local results only. CI's default database service is one cluster; the local cross-cluster result above is not inferred from CI.

## Restored schema-003 evidence

The integration fixture includes two explicitly resolved unknown incidents and one unresolved incident. It captures every row of all eleven public tables, then performs a real restore into a new database on the other PostgreSQL cluster and a nonexistent data directory. Before deliberate service startup, every row, volume UUID and retained journal byte matches the source. This includes resolution reasons/actors/timestamps, old/new generations, incident revisions, opaque historical fingerprints, snapshots, operation digests, missing-evidence records, projection provenance and delivery effects. Restored rows do not turn an unknown push into success.

The test proves that the restored database rejects UPDATE and DELETE of both resolution history and resolved operations, rejects fabricated events for resolved unknown operations, rejects INSERT and UPDATE of old-generation projections, and enforces snapshot/event provenance. Original resolution retry is idempotent. A newer incident revision cannot be silently overridden. An authenticated HTTP clone and native fsck recover the expected content; revoked and read-only credentials retain their restrictions. A real controlled generation-2 push creates one genuine audit record. The unresolved repository remains blocked.

Matching retained resolved evidence is cleaned up idempotently after deliberate startup. Modified evidence and a journal that reappears after a recorded missing-evidence resolution are preserved as incidents and block writes rather than being silently discarded.

Negative tests reject an altered freeze-function body, a disabled application trigger, a single disabled internal FK trigger, a weakened provenance constraint, and an otherwise empty restore target containing one known Rootyard function. The full-schema dump preserves function bodies and triggers; a table-only dump would not. Fixed catalog comparison accepts only the complete migration and round-trip shapes, whose sole difference is PostgreSQL's equivalent parenthesis normalization of the ref-name CHECK.

## Backup fault drill and finite recovery point

The original seven-group fault drill was rerun on schema003. Live server/inherited volume ownership blocks backup; an in-flight token revocation committed while the table barrier waits appears in the restored database. Corrupt files, missing/extra inventory, traversal, symlinks including the volume root, a FIFO/oversized COMPLETE marker, external Git object/commondir dependencies, existing destinations and unsupported database objects are refused. Terminating the snapshot exporter prevents publication; queued DDL causes bounded safe failure. A real SIGKILL of the parent while pg_restore waits on a catalog lock leaves no orphan import or partial public tables and retains a startup-blocking guard.

Measured tiny synthetic sample: backup **10.834 seconds**, full restore **7.716 seconds**; the richer schema003 restore took **8.027 seconds**. Zero commits from the captured boundary were missing. One acknowledged commit made **89.283 seconds after** the boundary was deliberately absent after restore. These are measured command times, not production RPO/RTO or a lossless guarantee. Full RTO includes transfer, provisioning, operator review and traffic changes.

An intermediate test run still watched the previous schema002 final metadata query, so the exporter-loss injector did not fire. The observer was corrected to schema003's volume-history check and the complete seven-group suite rerun successfully. Final results exclude preliminary runs and use the fixed executable above.

## Review and remaining limits

Independent read-only review found the internal-FK-trigger enabled-state omission; it was fixed, a focused rejection test was added, and the six-group schema003 drill rerun. No remaining review blocker was reported. The contract fixtures come from pristine synthetic migrations, never from production; `--write` is a review aid, not automatic approval of a changed schema.

Backup still requires stopped GitFS writers and no independent DDL. SHARE table locks are not a global function/DDL fence. The target must stay isolated throughout import; emptiness/session checks cannot prevent a privileged external client appearing afterward. Trigger immutability does not defend against a trusted database owner/superuser disabling protection or using TRUNCATE. Exact-binary/format/schema requirements remain deliberate fail-closed limitations.

Not established: hardware/power-loss safety, distributed fencing, network partitions, hostile administrators, production scale/RPO/RTO, signatures/authenticity, online/PITR backup, remote encrypted retention, or ownership/ACL/xattr portability. A restore interrupted around SQL COMMIT can still leave an uncertain target database; keep the persistent guard and inspect or discard both disposable targets. See [the operational contract](backup-restore.md).
