# RefStore metadata core increment (#107-A1, partial)

Status: **partial, isolated and internal**. This change adds a PostgreSQL
gate/ref metadata core on top of the migration-138 operation registry. It does
**not** close #107 or #105, does not become the repository serving authority, and
does not implement reads, pins, roots, holds, decisions, Blob receipts, GC or a
client-facing commit route. A repository with a core gate is **not serve-ready**:
activating it requires a later, explicit cutover API that is not part of this
increment.

## Public transaction boundary

The public adapter methods in `src/ref_store/core/pg.rs` own one short
transaction started from `&mut tokio_postgres::Client`:

```
initialize(client, ...)       create the explicit gate
commit_refs(client, ...)      exact old/new CAS + terminal + event
check_version(client, ...)    read-only gate observation
query_operation(client, ...)  read-only registry lookup
cancel(client, ...)           migration-138 cancellation tombstone
```

A returned receipt means the transaction `COMMIT` was acknowledged. Every `Err`
returned before `COMMIT` is issued — validation, an expired absolute deadline,
the authority fence or a database error — rolls the owned transaction back, so
a public mutation cannot leave refs, a gate revision, a pending operation, a
terminal or an event committable after such an error. Callers do not own a
transaction and are never asked to repair a partially written one.

`BEGIN` and `COMMIT` use the shared helpers in `src/ref_store/tx.rs`:

- `begin_bounded` wraps the `tokio-postgres` `Client::transaction()` future in
  `timeout_at(deadline, ...)`. In the pinned SDK (0.7.18,
  `src/transaction_builder.rs`) the `BEGIN` message is sent synchronously and a
  `RollbackIfNotDone` guard queues `ROLLBACK` if the builder future is dropped
  before the `Transaction` is created. A queued or cancelled `BEGIN` therefore
  cannot leak an open server transaction; this slice relies on that SDK
  guarantee instead of writing `BEGIN`/`ROLLBACK` protocol itself.
- `commit_bounded` checks the absolute deadline before issuing `COMMIT`. If it
  has already expired, it rolls back and returns `Timeout` without sending
  `COMMIT`. Once `COMMIT` is sent, only an acknowledged success is a success.
  A client-side timeout or an error reply returns typed
  `RefStoreError::CommitUnknown { repository_id, operation_id }` (bootstrap uses
  `operation_id: None`) because the commit may still land or the reply may be
  lost. `CommitUnknown` is not a conflict or a rejection, and it is never
  collapsed into `Timeout`/abort. Callers query the same operation identity
  (`query_operation`) or, for bootstrap, resolve the gate idempotently via
  `check_version`.

Rollback cleanup may itself finish after the absolute deadline; this slice does
not claim a hard physical return bound for cleanup. The important guarantees
are that a deadline-expired pre-commit path sends no `COMMIT`, that only an
acknowledged `COMMIT` returns a receipt, and that a possibly-landed `COMMIT` is
reported as unknown rather than aborted.

## Terminal budget

The migration-138 registry stores the terminal result as a canonical JSON body
bounded to 64 KiB. That bound is unchanged. `CommitRefsRequest` may carry 128
refs with 1024-byte names, so `validate()` serializes the exact worst case of
**both** the committed and the rejected terminal (actual request names, widest
object id, longest HEAD branch, largest revision and largest rejection detail)
before `PgRefStore::begin` runs. A batch whose aggregate receipt could not be
stored is rejected before the registry, ref rows, gate revision or events are
touched. Individual maximum-length ref names remain valid; only the aggregate
overflow is refused. This removes the former failure mode where the refs and
gate revision were applied and then `to_terminal_result` returned a Rust error
while the caller still held a committable transaction.

## Authority fence

Bootstrap (`initialize`) is restricted to a repository that is explicitly
unserved and empty:

- `repositories.state='provisioning'`;
- `repositories.storage_backend='gitfs'`;
- `repositories.transition_state='stable'`;
- no `pando_repository_states` row (no legacy Pando authority);
- no `repository_ref_projection` rows (no existing legacy refs);
- matching owner/tenant and `object_format`.

The repository row is locked (`FOR UPDATE`) for the check and gate insertion.
Initialization never updates `repositories`, `pando_repository_states`,
`pando_refs` or any legacy ref projection, and never changes serving authority.

Every new core commit locks and rechecks the same repository row after the
operation/lane registry and before the core gate:

```text
operation advisory key -> issuer lane -> repository row -> core gate -> ref rows
```

If the repository became `ready`, started `draining`, switched to the `pando`
backend or gained a Pando authority row, the new mutation returns `Err` and its
transaction is rolled back. Immutable replay of an older terminal and
`query_operation`/`check_version` still return the old proof; replay never
rewrites refs. Restoring an explicitly unserved stable state allows a new
mutation from the unchanged gate revision. Legacy Pando/GitFS call sites, the
runtime profile, HTTP routing and GitFS authority are untouched, so the
component cannot create a simultaneously exposed legacy/core write path by
itself. Moving a repository into service with the core requires a separate,
explicit cutover API in a later increment.

## Implemented boundary

`src/ref_store/core/` defines:

- `CoreGateInit` with explicit repository, tenant, object format,
  `history_incarnation`, `authority_epoch`, `group_epoch`, HEAD branch and a
  database-owned initial revision of 1.
- `CoreGate`/`CoreGateVersion` with a canonical gate digest.
- `check_version`: a linearized gate observation returning `Unknown`,
  `Unchanged` or `Changed`. `Unknown` is never treated as unchanged or aborted.
- `CommitRefsRequest`: exact old/new ref CAS, explicit `Atomic` mode and a typed
  `AcceptedSubset` mode, bounded to 1..=128 refs. The canonical SHA-256 digest
  covers repository, tenant, issuer, lane, sequence, operation id, expected
  revision, history incarnation, authority/group epochs, object format, HEAD
  keep/retarget value, mode and every per-ref old/new field.
- `GitOid`/`GitObjectFormat` with exact SHA-1/SHA-256 lengths. A live OID may
  never be all zero; the Git zero value is converted explicitly to
  `RefPrecondition::Absent`/`RefTarget::Delete`.
- `RefName` Git-safe component validation, including HEAD-only branch checks and
  current/batch prefix-conflict helpers.
- Immutable `CommitTerminal`, deterministic per-ref `RefCommitResult`, the
  pre-write terminal budget, and a `CommitRefsReceipt` that distinguishes
  committed from rejected and replayed.

`src/ref_store/core/pg.rs` implements the owned short transactions above. A
commit calls `PgRefStore::begin` first; the same transaction then locks the
repository row and gate, locks relevant refs in name order, validates
tenant/format/history/authority/group/revision, exact old OIDs, current and
in-batch prefix conflicts and HEAD deletion/retarget rules, applies all refs
plus the gate revision increment, records the immutable operation terminal and
inserts the correlated event. `query_operation` and `cancel` delegate to the
migration-138 registry (including cancel-before-register tombstones).

## Terminal semantics

- A successful batch records `Committed` with `revision = old revision + 1`,
  the new HEAD and all refs `Applied`.
- Tenant, object-format, history-incarnation, authority-epoch, group-epoch,
  revision, old-OID, prefix, HEAD-deletion and HEAD-target failures are domain
  rejections. They return `Ok(CommitRefsReceipt)` with a `Rejected` terminal,
  written together with its event in the same transaction that then commits.
  They do not change refs or the gate revision. Callers MUST inspect
  `receipt.is_committed()`.
- Errors detected before `COMMIT` is issued return `Err` after the owned
  transaction was rolled back. A deadline that expires before `COMMIT` is sent
  is `Timeout` and sends no `COMMIT`; a timeout or error after `COMMIT` was
  issued is `CommitUnknown` and may still commit. It is never reported as an
  abort or domain rejection; the caller queries/retries the same identity.
- Same operation id and same canonical digest replays the exact stored
  `TerminalResult`. Same id with a different digest is `DigestConflict`.
- A durable `Pending` record that this transaction did not create returns
  `OperationPending`; it is unknown, not aborted. A durable cancellation returns
  `Cancelled`, and a cancellation tombstone observed by `begin` prevents any ref
  mutation.
- `AcceptedSubset` is a typed mode and fails closed with `Unsupported`; it is
  never silently executed as atomic. Its per-ref terminal semantics are not
  claimed in this increment.

## Explicitly not implemented

The following remain false in `Capabilities::pg_core_increment()` and have no
implementation in this slice:

- atomic read snapshots, durable snapshot pins, GC observation of pins;
- logical roots, artifact holds, publication decisions;
- Blob receipts or any receipt foreign key (waiting for #109);
- pack membership, pack/object IO or content durability;
- client-idempotent publish and any public/HTTP commit or query route;
- serving cutover, core/legacy dual writes, maintenance claims;
- automatic dedup/cancel/event trimming or TTL release.

Legacy Pando call sites and long PG read leases are unchanged. The migration-138
registry remains the only operation/cancellation state; nothing here claims
durable ACK, authority transfer, pin/root/hold coverage or GC eligibility.

## Schema and backup

`migrations/139_ref_store_core.sql` adds only `ref_store_core_gates`,
`ref_store_core_refs` and `ref_store_core_events` (plus one event-immutability
trigger). Migration 138 and `schema/138_*` are not rewritten. The current backup
format is bumped to 15 / schema 139 while format 14 / schema 138 stays frozen.
Format 15 catalogs must be generated from real PostgreSQL by the root runner;
this checkout does not fabricate `schema/139_*` snapshots and does not claim a
qualified backup or restore.

Root command checklist (not executed here; no Cargo/native/Docker/services):

```text
# after building the candidate binary
ROOTYARD_TEST_DATABASE_URL=... python3 scripts/generate_schema_catalog.py \
  --binary target/debug/rootyard --legacy-binary <frozen schema138 binary>
cargo test --lib ref_store
cargo test --test ref_store_core -- --ignored
python3 -m pytest tests/backup*.py   # or the repository's native backup suite
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
```

## Verification in this increment

Unit tests in `core/types.rs`, `core/contract.rs` and `core/terminal.rs` cover
OID/ref/HEAD validation, zero-OID delete/absent conversion, batch prefix
conflicts, canonical digest coverage, accepted-subset fail-closed behavior,
terminal serialization and the unchanged 64 KiB aggregate budget (including a
rejection for 128 maximum-length names and acceptance of one maximum-length
name).

`tests/ref_store_core.rs` is an ignored real-PostgreSQL suite. It panics if
selected without `ROOTYARD_TEST_DATABASE_URL`. It covers:

- bootstrap acceptance only for a provisioning/gitfs/stable empty repository,
  and rejection of ready, draining, non-gitfs, Pando-authority, legacy-ref and
  tenant/format-conflicting repositories;
- exact terminal replay, digest conflict and cancel-before-register;
- a `pg_stat_activity` gate-lock barrier with two connections holding the same
  old OID where exactly one commits and one receives a durable revision
  rejection;
- atomic no-partial rejection and epoch/history/tenant/format/revision/prefix
  rejection;
- HEAD retarget/delete policy;
- a failure injected after refs, revision and terminal were written, asserting
  the owned transaction rolled back everything (including the pending operation
  and lane sequence) and that a client `COMMIT` issued after the error cannot
  publish partial state;
- aggregate oversized receipts rejected before the registry (no pending
  operation, lane, ref, revision or event), one maximum-length name accepted and
  a full 128-ref bounded batch accepted;
- repository state/backend/transition/Pando-authority changes after
  initialization rejecting new mutations while exact terminal replay and lookup
  remain stable, and mutations resuming after the repository is explicitly
  unserved again;
- a queued `BEGIN`: a prior polled-then-dropped blocking statement on the same
  connection holds the server busy behind an advisory lock; core `BEGIN` is
  queued, its absolute deadline returns `Timeout`, and after the barrier is
  released the SDK rollback guard leaves that backend `idle` (not idle in
  transaction) with no gate/ref/operation/event write;
- a `COMMIT` deadline: a fixture-owned `DEFERRABLE INITIALLY DEFERRED`
  constraint trigger on core events waits on an advisory lock held by another
  connection, proven through `pg_locks`/`pg_stat_activity`; `commit_refs`
  returns `CommitUnknown` at the deadline. After release, the server either
  committed (in which case the exact terminal/ref/event is consistent) or its
  own statement timeout aborted it (unknown with no refs/events). Retrying the
  same operation id after removing the owned trigger commits or replays
  exactly once, never as a false abort;
- unknown gates.

## A2: bounded metadata snapshot + durable metadata pin

A2 adds an internal, **metadata-only** snapshot/pin increment on top of the A1
unserved core gate. It is not a Git `ReadSnapshot`: refs/HEAD rows are copied
with the exact gate revision/digest they were read with, pack membership is
typed `Unavailable`, and a metadata pin is not protective of Git objects. No
HTTP route, serving cutover, Blob receipt, artifact hold, logical root, GC
consumer, `git fsck` or physical protection is added, and the existing long PG
read leases remain the only Git-object read protection.

Capabilities (`Capabilities::pg_core_increment()`): `metadata_snapshot_capture`,
`metadata_snapshot_pagination`, `metadata_pin_lease` and
`metadata_quota_admission` are true. `atomic_read_snapshot`,
`durable_snapshot_pin`, `gc_observes_pins`, `logical_roots`, `artifact_holds`,
`pack_membership_snapshot`, `serving_cutover` and `client_idempotent_publish`
stay false.

APIs (`PgRefStoreCore`, migration `140_ref_store_core_snapshots.sql`):

- `create_metadata_snapshot(CreateMetadataSnapshotRequest) -> MetadataSnapshotReceipt`
  — caller fixes request/pin/snapshot ids, lease and the expected gate digest
  before the call. One short owned transaction locks the advisory request key,
  the tenant usage row, the repository usage row, the repository row
  `FOR SHARE`, the gate `FOR UPDATE` (the same lock `CommitRefs` takes), then
  inserts the immutable header, the immutable ref rows, the durable pin and the
  creation receipt. There is no list-then-pin sequence.
- `read_metadata_snapshot_page(ReadMetadataSnapshotPageRequest) -> MetadataSnapshotPage`
  — bounded (`limit` 1..=256, `limit + 1` fetched) byte-ordered keyset page over
  immutable rows with an optional literal bounded prefix. It rechecks the
  current A1 unserved predicate (provisioning/gitfs/stable, no Pando authority,
  no legacy ref projection, tenant/format), the stored snapshot scope, and the
  live pin generation, holding repository/gate and pin `FOR SHARE`.
- `renew_metadata_pin(RenewMetadataPinRequest) -> MetadataPinReceipt` — same
  unserved predicate and generation CAS; advances the generation by exactly one
  and re-bases `expires_at` on `clock_timestamp()`.
- `release_metadata_pin(ReleaseMetadataPinRequest) -> MetadataPinReceipt` —
  explicit terminal release at the expected generation; allowed after expiry or
  a repository transition, never on a newer generation and never on another pin.
- `metadata_receipt(scope, request_id) -> MetadataReceiptLookup` — scoped
  receipt/pin-status lookup for an unknown COMMIT. A missing id is `Unknown`,
  never a success or abort guess; there is no unrestricted get-by-UUID path.

Lifecycle and replay: one globally unique request-id ledger (bounded body
≤4096 bytes, fixed action/purpose/reason enums) records `create`/`renew`/
`release`. An identical request id + canonical digest (which covers the action
and every semantic field) replays the original immutable receipt and ids only —
never a page, never a revived lease, never an extended expiry. A different
digest, or the same id in another repository, is a conflict. `COMMIT` errors
after the reply was sent are typed `MetadataCommitUnknown` with the stable
request/pin/action identity; the same request id resolves them. Released pins
are terminal and pin ids are not reused; `expires_at` only denies new pages and
renewals, and never deletes or refunds anything.

Retained admission bounds (logical, at repository **and** tenant scope, over all
history including expired/released rows): per repository 64 snapshots / 16384
snapshot-ref rows / 16 MiB logical metadata / 2048 successful receipts; per
tenant 256 / 65536 / 64 MiB / 8192. Snapshot capture itself is bounded to 4096
refs and 8 MiB logical bytes. Receipts are at most 4096 bytes. Counters live in
`ref_store_core_repo_usage` / `ref_store_core_tenant_usage`, are charged in the
creating transaction and are never refunded by release or expiry: hitting a
bound is explicit `MetadataQuotaExceeded` backpressure, not eviction. These are
admission bounds, not physical SQL page, WAL, disk or RSS quotas.

Schema: `ref_store_core_snapshots`, `ref_store_core_snapshot_refs`,
`ref_store_core_pins`, `ref_store_core_receipts`, `ref_store_core_repo_usage`,
`ref_store_core_tenant_usage`, with update-immutability triggers on snapshots,
snapshot refs and receipts, and a pin guard trigger (identity columns immutable,
generation advances by at most one, released is terminal, no lease change
without a generation advance). Snapshot headers keep
`pack_membership_state = 'unavailable'`; there is no pack/receipt FK. Lock order
for new mutations is documentation-of-record in `core/snapshot_pg.rs`:
request advisory key → tenant usage → repository usage → repository → gate →
snapshot/pin → receipt; A1 `CommitRefs` keeps operation → lane → repository →
gate and no path takes quota after the gate.

Known limitations (not claims): no Git object closure, pack membership, Blob
receipt FK, artifact hold, GC observation/roots, serving cutover or archival
protocol. All retained budgets stay full forever until such a reviewed protocol
exists. The real-PG suite `tests/ref_store_core_snapshot.rs` is ignored and
requires `ROOTYARD_TEST_DATABASE_URL`; it proves metadata rows, generation CAS,
replay, rollback, quota races and fences only. Migration 140 registration,
schema catalogs and backup/restore qualification for the new tables are owned by
the separate backup/registration change and the root runner.
