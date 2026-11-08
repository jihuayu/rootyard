# RefStore operation identity increment (#107, partial)

Status: **partial**. This change installs a typed, durable operation registry in
the existing Pando PostgreSQL transaction. It does **not** close Rootyard #107
or #105 and it does not make PostgreSQL a full Ref-CAS authority.

## What is implemented

`src/ref_store/contract.rs` defines:

- `OperationIdentity` = repository UUID + issuer UUID + issuer lane + positive
  per-lane sequence + stable operation UUID + SHA-256 request digest.
- `RequestDigest::of` with length-delimited fields and a domain prefix.
- `IssuerLane`, bounded to 64 ASCII characters.
- `OperationState` (`pending`, `committed`, `rejected`, `cancelled`) and
  immutable `TerminalResult` JSON objects (bounded to 64 KiB).
- `Capabilities::pg_transition_increment()` with every unsupported authority
  feature explicitly `false`.

`src/ref_store/pg.rs` implements, inside a caller-owned transaction:

- `reserve_sequence`: transactional preallocation of a lane sequence.
- `begin`: register pending or replay the exact durable record.
- `cancel`: persistent tombstone even when the operation has not been
  registered; a later registration becomes terminal `cancelled`.
- `record_terminal`: one terminal state/result; identical replay is accepted,
  any different state/result is rejected.
- `get`: repository-scoped internal lookup. Missing is `Unknown`, not aborted.

Every mutation first takes a transaction advisory lock derived from the common
repository + operation UUID, before any lane row is locked or read. It then
locks the issuer lane and rechecks the full durable identity. This means a
foreign issuer/lane cannot concurrently commit a pending operation and a
cancellation tombstone for the same operation UUID; exactly one identity wins
and different identity/digest is a conflict. Hash collisions in the advisory
key only add serialization, not authority. One caller transaction must contain
at most one operation mutation; a future multi-operation API must use sorted lock
order.

The lane head row then serializes `begin`/`cancel`/`record_terminal` for one
`(repository, issuer, lane)` and makes cancel-before-register deterministic.
Every public registry method future is also wrapped in
`tokio::time::timeout_at` at the caller's absolute deadline, while SQL keeps a
server `statement_timeout`/`lock_timeout` upper bound to drain cancelled queries.
A later phase never receives a fresh 30s window beyond that deadline. Callers
must roll back the transaction on any registry error; Pando's `?` path already
drops the transaction. Pando also checks the absolute deadline before final
`auth::finish_tx`. A connection drop after PG commit remains an unknown outcome
and is not converted into an invented rollback.

`migrations/138_ref_store_operation_identity.sql` adds lane heads, operations
and cancellations. Database triggers reject identity changes and any rewrite of
a terminal result, so the guarantee does not depend only on adapter code. The
migration is registered in `src/db.rs`. The root owner must regenerate canonical
schema/fixture artifacts with real PostgreSQL; this checkout does not hand-edit
generated schema files.

## Existing Pando publication

`src/pando_gateway/publish.rs` continues to perform:

- live token/role authorization;
- repository/transition/generation checks;
- branch, LFS pointer and lock policy validation;
- old-OID CAS and authoritative ref/pack mutation;
- `events::publish_in_tx` in the same transaction;
- `auth::finish_tx` immediately before commit.

The migration does not backfill old `git_operations` rows. An operation committed before
this migration has no registry row and `get` returns `Unknown`, not committed or aborted;
retention of pre-migration history remains the existing event/audit boundary.

Backup readiness is **not** claimed here. The root owner must first generate the
format-14 backup/catalog artifacts and run their real-PG tests; this increment
does not edit `src/backup` or canonical schema fixtures.

This change preallocates the operation UUID and digest **before ref mutation**,
registers the pending identity before the mutation statements, and records the
terminal result before `finish_tx`. A rollback drops all registry rows with the
ref CAS. The existing long PG read lease still protects reads.

### Important limitation: no client retry idempotency yet

The current publish caller has no protocol field for a client-supplied stable
operation id. The server therefore mints a new operation id inside each publish
attempt. A client that retries after a lost reply creates a **new** operation;
it does not replay the previous terminal result. The registry API is ready for
a trusted caller that carries its own operation id/digest across retries, but
that caller preallocation protocol is not implemented. Do not describe this
increment as end-to-end idempotent publish.

## Explicitly unsupported / disabled for a new authority

`Capabilities::pg_transition_increment()` reports these as false:

- atomic read snapshot;
- durable snapshot pin and GC observation of pins;
- publication decisions;
- logical retention roots;
- artifact holds;
- authority-epoch checks;
- automatic dedup/cancel trimming;
- client-idempotent publish.

There is no disconnected full parallel ref store, no fake pin, and no route that
exposes the internal operation lookup. Reads remain on the old lease mechanism.
The operation registry has no unauthenticated HTTP surface and accepts no
boolean "authorized" argument; only the existing trusted Pando transaction calls
it today.

Full #107 remains open until read snapshots and pins are integrated with the GC
consumer, roots/holds/decisions and epoch validation exist, backup/restore
covers operation/dedup/cancel state, and the client preallocation protocol is
defined. Raft decision state remains #116 work.

## Verification

`src/ref_store/contract.rs` unit tests cover invalid identities, lane bounds,
digest canonicalization, terminal-result limits, record invariants and disabled
authority capabilities.

`tests/ref_store_operations.rs` is an ignored, real-PostgreSQL suite for the root
runner (`ROOTYARD_TEST_DATABASE_URL`), covering:

- same-id/same-digest replay and same-id/different-digest conflict;
- duplicate lane sequence conflict;
- cancel before registration observed across fresh connections;
- pending vs terminal cancel ordering;
- replay of committed results and rejection of terminal rewrites;
- database triggers rejecting direct terminal/identity rewrites;
- cross-lane begin vs foreign cancel producing exactly one identity;
- lock-blocked begin/cancel/record_terminal/reserve_sequence returning a timely timeout;
- transactional, monotonic sequence reservation;
- cross-repository lookup returning `Unknown`.

The suite uses an isolated schema and does not use an in-memory fake.
