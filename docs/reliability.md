# ADR 002: durable GitFS evidence and PostgreSQL consumers

Status: phase-two increment A. GitFS remains the only authority for refs and objects. This increment is not HA, a distributed filesystem, or a complete disaster recovery system.

## Write path and outcome contract

1. Authenticate discovery and RPC, reserve a Git process slot, and acquire the repository write mutex. Writes to the same repository are serialized, including writes to different refs.
2. Reconcile any previous retained journal before another receiver starts. Check the durable delivery backlog threshold and the current repository generation/state.
3. Reserve a monotonically increasing repository operation sequence on the private durable volume. Persist operation identity, repository, generation and actor/token IDs before spawning Git. Credentials are never recorded.
4. Run native `git http-backend` with controlled hooks. The private data volume must allow executable files (not `noexec`); startup executes a side-effect-free hook self-check, and admission/settlement check actual `X_OK`, not only mode bits. Startup copies and fsyncs the hook executable into the private volume, so deployment removal of the original binary cannot silently disable hooks. Admission and settlement verify the installed hook links and executable identity. Pre-receive validates the entire push before any ref mutation, rejecting oversized batches, oversized names and repeated target refs. The synchronous hook executable does not initialize PostgreSQL or an async runtime. Every reference-transaction callback appends and fsyncs its complete ordered ref list and phase. Native transaction callbacks may nest, repeat or contain rejected updates. They are diagnostic evidence, not success receipts and not a synthetic transaction ID.
5. Native post-receive writes a separate atomic, fsynced receipt containing Git's successful ref subset. It is not a promise that every requested update succeeded or that the client received an acknowledgment. A non-atomic push can partially succeed. An HTTP 200 or native exit code is not a per-ref result.
6. The owned supervisor retains the mutex and capacity permit through input/output cleanup. It observes the leader without reaping, terminates remaining group members and waits until all members are stopped before reaping the leader. A stuck uninterruptible process retains admission rather than permitting another writer. CGI-header failures and downstream cancellation follow this same ownership rule.
7. Persist the operation, original evidence and successful-subset outbox events in one PostgreSQL transaction. Retire the local journal only after PostgreSQL confirms commit. A failed or lost commit response leaves the journal for idempotent replay. A durable retirement rename makes interrupted cleanup safe.

Operation outcomes are deliberately limited:

- `recorded`: a complete post-receive receipt was captured; successful changes are recorded. This is **not** whole-push success. Repeated target refs in one receipt are conservatively ambiguous.
- `no_ref_changes`: the writer stopped normally with verified hooks and no nonempty reference callback or receipt exists. Unfinished operations recovered after restart do not gain this classification merely because evidence is absent. Empty native callback lists are allowed.
- `unknown`: incomplete/corrupt evidence, missing success receipt after nonempty reference callbacks, repeated receipt refs, unfinished runtime operation, or generation mismatch. No successful update events are created by the gateway for this state. The repository enters `recovering`, blocks further Git operations and remains inspectable through owner-authenticated metadata/audit APIs.

Current refs, reflogs, matching OIDs, callback phase pairing, and successful client status are never used to manufacture a successful operation. No unknown push is automatically replayed. This is intentionally conservative: an actually rejected update may require recovery if evidence cannot prove the successful subset. For example, Git 2.56 may emit a nonempty preparing callback for a stale CAS that is then rejected; without a success receipt the operation remains unknown and the repository is blocked.

Startup may mark retained operations stopped only after obtaining the volume flock inherited by old Git descendants. Runtime recovery cannot assume an unfinished writer stopped. A complete receipt can settle an interrupted operation and clear only Rootyard's own unknown-outcome flag when no other unknown operation remains. Other incident reasons stay blocked. Every five seconds it attempts retained journals under the same repository mutex, skipping busy repositories; it does not remove unknown evidence or ready-repository Git lock files.

## Durable outbox

`git_operations`, `outbox_events` and independent `event_deliveries` rows commit atomically. Stable event IDs hash the operation UUID, successful receipt ordinal and ref name. The schema's `transaction_sequence` is this **receipt line ordinal**, not a Git-native transaction identifier. Original callback order remains in the evidence JSON. No callback list is collapsed by ref.

The built-in `audit-log` and `ref-index` consumers use PostgreSQL row locks, `SKIP LOCKED`, expiring leases, owner UUIDs and increasing claim generations. Acknowledgment rechecks its fence after obtaining the row lock and again after its effect. The effect and delivery acknowledgment commit together. Expired workers cannot acknowledge a later claim. Pending earlier events prevent per-ref delivery from overtaking; unknown earlier operations block later operations for that repository. No maximum global event ID is used as a commit watermark.

The ref projection is a rebuildable asynchronous cache and is never used to advertise refs or authorize a push. The audit consumer is a local database projection. External webhooks, Kafka/Redis consumers and external exactly-once effects are not implemented here.

`rootyard worker-once` executes one bounded batch for each local consumer and requires database configuration, but not the storage-volume lock. Multiple worker processes may run against the same PostgreSQL schema. The server also runs the local consumers every five seconds unless `ROOTYARD_OUTBOX_WORKER=false`.

## Bounds and operational controls

- `ROOTYARD_MAX_PENDING_DELIVERIES`, default 100000, rejects new writes when the observed undelivered count reaches the threshold. Two local consumers produce two delivery rows per event. This is an admission threshold, not a strictly reserved global disk quota; already admitted operations can exceed it.
- Hook stdin is limited to 1 MiB and 4096 ordered changes per callback; ref names are limited to 1024 UTF-8 bytes. SHA-1 refs only. Symbolic reference mutations are rejected. Individual persisted JSON records allow 2 MiB after serialization, and raw events have a 16 MiB aggregate operation limit. Exceeding a terminal logging limit can leave an unknown operation because terminal hook failure cannot undo native Git.
- Owner APIs `/api/repos/{owner}/{name}/operations` (latest 100 summaries) and `/events` (latest 1000 events) are read-only. Evidence remains in PostgreSQL; list responses expose counts rather than unbounded evidence arrays. These bounded lists are not a complete paginated export API.
- Journal corruption or unknown outcome is a fail-closed operator incident. Preserve the volume and database, stop all writers, investigate the recorded evidence and run native integrity checks in a safe maintenance copy. There is deliberately no automatic “mark successful” or delete-lock command. A reviewed offline acknowledgment workflow is now implemented in [ADR 003](manual-recovery.md); it preserves unknown history and explicitly records an audit gap. It does not repair malformed journals or arbitrary storage incidents.
- PostgreSQL and GitFS are separate transaction domains. Backups must include metadata **and** the complete storage tree, including journal counters/receipts, at a coordinated stopped-writer boundary. Restoring an older database with a newer journal-free Git volume cannot reconstruct retired events. Never pair unrelated backups or silently lower a storage generation.
- Filesystem/fsync behavior, reliable local `/proc` readable for every service-UID process, Linux process-group behavior and a private service-owned local volume are required. No user hooks, shell scripts, direct filesystem writes or external ref-changing Git commands are supported. An administrator who changes refs outside this protocol invalidates the audit assumptions.

## Remaining phase-two gates

Formal backup manifests and isolated new-environment restores with measured RPO/RTO; distributed routing and storage fencing; independent process/node workers and message adapters; fault tests covering actual PostgreSQL outage/ambiguous commit replies, every Git commit interruption boundary, disk exhaustion and corruption; production storage fencing and failover. None is implied by loopback tests or this increment.
