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

## Coordinated offline backup procedure

This is an operator procedure, not automated backup infrastructure or an RPO/RTO guarantee. The integration harness exercises a smaller offline paired dump/restore drill for its own schema and Git tree; it does not validate a fresh external database or production disaster recovery.

1. Block new HTTP requests at the ingress and stop Rootyard. Wait for its Git children to exit. Do not leave another writer or maintenance task accessing the volume.
2. Also stop administrative metadata changes such as creating users/tokens. The database and Git files must remain unchanged throughout the backup window.
3. Capture a PostgreSQL custom-format dump using `pg_dump --format=custom` for the Rootyard database. Record PostgreSQL, Git and Rootyard versions and the configuration needed for restoration, excluding plaintext secrets from ordinary manifests.
4. Snapshot or copy the **entire** durable data directory, preserving ownership, modes, symlinks and all Git files, including hidden files. Do not copy just refs or loose objects. Preserve the database dump and volume snapshot as a single named backup set.
5. Check the dump is readable and the snapshot is complete. Encrypt/restrict backup access and retain checksums. Only then restart the service and reopen ingress.

Because writes are stopped across both captures, this avoids claiming online atomicity between a database snapshot and changing Git state. Crash consistency of a raw volume snapshot remains a property of the storage implementation.

## Restore drill

1. Restore into an isolated environment with ingress disabled and no running Rootyard process. Use a fresh PostgreSQL database and an empty destination volume.
2. Restore the matching database dump and whole data-directory snapshot. Restore service ownership and permissions. Never combine unrelated backup generations or mount the same volume into two servers.
3. Start the matching Rootyard version and allow startup recovery. Inspect failures before making the instance writable. Upgrade only as a separate verified step.
4. Compare repository IDs, owners, states and expected refs/OIDs to the backup inventory. Run `git fsck --full` against each bare repository while no writes or maintenance occur. Authenticate a standard Git client and clone/fetch representative repositories; compare file content and refs.
5. Test read-only restrictions, revocation and a controlled write on a disposable restored repository. Only then switch traffic. Record measured data loss and restore duration rather than asserting RPO/RTO targets that have not been tested.

A successful dump or a passing process-restart test alone does not validate disaster recovery, hardware failure behavior or power-loss durability.
