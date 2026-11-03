# Operations and recovery

## Deployment boundary

Run on Linux as a dedicated unprivileged identity with exclusive write access to the data directory. Keep the binary and configuration outside that directory. Do not permit tenants to edit bare repositories, hooks, configuration or parent directories. Never share the volume among serving nodes or run manual Git maintenance while writes are active.

Terminate HTTPS at a trusted reverse proxy before exposing the service beyond localhost. Do not log authorization headers or token-bearing URLs. Set upstream request/time limits consistently with Rootyard; a proxy disconnect can leave a push outcome unknown. Use a private PostgreSQL connection or local TLS proxy. `sslmode=require` is not a way to enable TLS in this application.

The database and volume together comprise the service state. Protect database credentials and backups; token digests are not plaintext credentials but the database remains sensitive. CLI token issuance is an administrative capability requiring database access.

## Resource limits

Request/output limits count streamed bytes; oversized Git operations can fail after transport has begun. Git subprocess deadlines run independently of a slow client reading responses. Normal cancellation uses TERM followed by a one-second grace period and KILL; cleanup keeps process-group identity until the leader is reaped. Encoded gzip/x-gzip requests have both wire-byte and decoded-byte caps. These deadlines, address-space limits and process concurrency are defensive bounds, not a workload sizing model. Address space is not identical to resident memory. Reserve capacity for the Rust server, database, filesystem cache and concurrent processes.

The repository byte threshold is an admission check, not a hard atomic storage quota. Concurrent receive operations, quarantine packs and temporary files need headroom. Use filesystem quotas, disk alerts and an appropriate container/system service memory limit for stronger deployment-level controls. Never infer a safe arbitrary-concurrency load from defaults.

Failures after HTTP headers have been sent cannot change the status code: a response that began with `200` can end as a failed/truncated stream. The Git client must consume and validate the complete protocol result, not treat the status alone as success. A push rejected by timeout, stream cap or disconnected transport may have reached a ref update already. Reconnect, inspect the actual remote refs and run a normal fetch before deciding whether to retry. Native Git's result is authoritative.

## Startup and interrupted provisioning

Use the same database and data volume when restarting. Only one serving process may own the directory. Startup and periodic scans reconcile pending provisioning records with on-disk repositories, at most 64 due records per scan with persisted attempt counts and 30-second retry backoff. Recovery can rebuild an unpublished `.init` tree under the exclusive volume lock, including stale staging `config.lock` files; it is not a comprehensive repair tool for missing ready repositories, corrupted objects or arbitrary manual changes.

If startup reports a lock conflict, find and stop the existing owner normally; do not bypass locking. Git children inherit the volume lock, so a receiver surviving an abrupt parent termination can intentionally prevent another server from starting until the child exits. If storage is missing or corrupt, stop writes and investigate the database/volume pair. Do not delete database rows or initialize an empty replacement repository over existing state. Preserve evidence and restore a matched backup when necessary.

A force-killed Git operation can leave `.lock` files in a **ready** repository. These are never automatically deleted. Before any manual repair: stop Rootyard and every writer/maintenance process, take a coordinated database-and-volume backup, inspect the repository and process state, run `git fsck --full`, and establish that the specific lock is stale rather than owned by an active operation. Remove only the individually verified stale lock as an explicit operator repair, then recheck refs and integrity before reopening writes. Do not use a blanket `find ... -delete` cleanup.

Revoking a token blocks subsequent authentication checks; it cannot retract bytes already delivered or necessarily cancel an operation already authenticated.

## Coordinated offline backup and isolated restore

The executable phase-two slice is `rootyard backup PATH --offline`, `rootyard backup-verify PATH` and `rootyard restore PATH --isolated --trust-backup`. Read [the full backup/restore contract](backup-restore.md) before using them. Backup refuses a live volume owner, freezes the supported PostgreSQL tables and copies a matched snapshot and full data tree. Restore requires a fresh dedicated database and a nonexistent data directory, verifies hashes and native integrity, preserves unknown evidence, and never starts a service or switches traffic.

This is not an online or lossless-backup promise. Restore failures leave private partial material and may have an uncertain SQL commit; a persistent target guard blocks startup pending operator review. Do not overwrite targets, mix backup generations or remove the guard to bypass an incident. See [measured integrated verification](integration-verification.md), not a successful dump alone, for the tested recovery boundary.

## Durable operation recovery (phase two A)

Read [ADR 002](reliability.md) before upgrading. Migration 002 is incremental and keeps native Git authoritative. The data volume now must allow execution of the private hook runner; startup performs a harmless execution probe and requests verify actual executable access. A `noexec` data volume fails closed. Linux procfs must expose every service-UID process for safe descendant cleanup.

Keep the entire data directory, not only `repos/`, in coordinated offline backups. Do not remove journals or sequence counters, manually clear an unknown operation, or lower a generation. An unknown result may mean Git changed refs even if the client received an error. Owner operation summaries are available at `/api/repos/{owner}/{name}/operations`. PostgreSQL holds full bounded evidence. `rootyard worker-once` drains one bounded batch for each built-in consumer; it does not resolve unknown writes.
