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

A returned receipt means the transaction `COMMIT` succeeded. Every `Err` —
validation, deadline expiry, authority fence or a database error at any point —
rolls the owned transaction back before returning, so a public mutation cannot
leave refs, a gate revision, a pending operation, a terminal or an event
committable after a Rust error. A failed commit reply is reported as an error
(unknown outcome); it is never reported as a false abort. Callers do not own a
transaction and are never asked to repair a partially written one.

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
- Infrastructure/deadline errors return `Err` after the owned transaction was
  rolled back. A lost commit reply therefore leaves the outcome unknown, not
  false-aborted.
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
- unknown gates.
