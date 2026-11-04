# Durable Issue creation retry verification

Verified on 2026-11-04 in a Linux cloud workspace, starting from
`19fd53653ba9096c8635332e37f9d7e0a2de1fe6`. All database resources were synthetic
and disposable. Backup tests used two independently initialized PostgreSQL
clusters on loopback, with a fresh destination database and volume per restore.
No production repository, merge, deployment or traffic cutover was involved.

Toolchain: Rust/Cargo 1.85.1, Git 2.52.0, PostgreSQL 17.11, Redis 8.0.2 and Python
3.12.14. The tested debug binary SHA-256 was
`9b29efde80b81c1495aee2211f896c45951e47b6c386829b79ad7bd34e15b195`.

## Contract and fault coverage

- Optional keys preserve the old unkeyed API. One 1–128-byte ASCII header is
  accepted; empty, repeated, non-ASCII, malformed and overlong keys are rejected.
  Omitted/empty Issue bodies canonicalize identically, while meaningful text,
  operation and target changes conflict. Different owners/repositories remain
  isolated; a replacement write token for the same owner may retry.
- Same-key creation returns the original 201 JSON after edits and process restart.
  A real raw HTTP client also waits for visible PostgreSQL commit, then closes
  without reading any response bytes. Retrying both resource types returns the
  saved result without changing any Forge row or counter.
- Sixteen concurrent identical requests allocate once. Eight concurrent distinct
  payloads sharing one key produce one creation and seven conflicts, with no
  counter gaps, for both Issue and comment creation.
- Injected resource-insert and receipt-finalization failures roll back keys,
  resources and counters. A waiting request takes over after an uncommitted SQL
  creator aborts. Real HTTP creators are also killed after reserving their key
  while blocked on allocation; their PostgreSQL transaction closes without a
  receipt or allocation, and restart/retry creates once.
- Token revocation, read-only downgrade and digest replacement during locked
  authorization deny both fresh writes and replay. Expiry while waiting for a
  fresh key or existing receipt rolls back/denies success. Recovering repositories
  remain frozen. Maximum-sized escaped payloads round-trip within all bounds.
- Direct SQL rejects invalid keys, non-object or oversized request/response JSON,
  and cross-owner repository references. A committed incomplete receipt returns
  503 without creating anything; backup rejects that state as well.

## Schema and backup verification

Migration007 is transactional and replay-safe. Its conflict test preserves the
already installed Issue schema and leaves no migration007 marker. The three
reviewed schema007 catalog fixtures were generated from real PostgreSQL migration
and dump/restore operations, then checked with the compiled executable. Their
only differences from their corresponding schema006 fixtures are the new table,
five columns, five constraints and one unique index. The catalog extraction SQL
is unchanged.

The executable schema test covers fresh migration, complete dump/restore,
restored003-to007, restored006-to007, and dump/restore of the upgraded shape.
Only the three exact reviewed forms are accepted. Format4 captures exactly
fifteen tables and rejects earlier formats rather than silently changing their
meaning.

The populated Forge backup test retains 36 HTTP-created retry records and a
37th transaction-barrier fixture. It proves the backup waits for a ShareLock on
`forge_creation_requests`, then includes the writer's committed response and
allocation. Restored content, counters, original responses, permissions and
conflicts match the snapshot even after subsequent Issue/comment edits. A key
created only after backup is absent after restore and may be used again in the
restored timeline. Dropping the key CHECK constraint is rejected as schema drift.

## Passed checks

- `cargo fmt --all -- --check`.
- `cargo clippy --locked --all-targets -- -D warnings`.
- `cargo test --locked --all-targets`: 33 unit tests passed.
- Explicit ignored PostgreSQL tests: outbox and resolution fences both passed.
- `cargo build --locked` and `tests/schema_contract.py`.
- `tests/forge_idempotency.py`: 13 groups.
- `tests/forge.py`: 11 groups.
- `tests/backup_forge.py`: 9 groups.
- `tests/backup_upgrade.py`: 5 groups.
- `tests/e2e.py`: 15 groups.
- `tests/reliability.py`: 18 groups.
- `tests/backup.py`: 7 groups.
- `tests/backup_recovery.py`: 6 groups.
- `tests/restored_workers.py`: 4 groups.
- `tests/recovery_ops.py`: 7 groups.
- `tests/metrics.py`: 5 groups.
- `tests/cross_process.py`: 6 groups, including real Redis.

A pre-existing test helper's string construction was rewritten without changing
its bytes to satisfy the Rust 1.85 Clippy `format_collect` warning. The new
permission-race fixture initially reused one replacement token digest; the unique
index correctly rejected the second fixture update. It now uses distinct
synthetic digests, and the complete suite passes without weakening that index.

## Limits

Keys do not automatically expire. Individual entries are bounded, but there is
no new rate limit, quota or retention sweeper. Key history and resource history
rewind together at restore; this is not idempotency across disaster-recovery
timelines, global exactly-once delivery, or a protection against trusted database
administrators. Unkeyed POST remains non-idempotent. Tests cover service-process
interruption and selected SQL faults, not PostgreSQL crash, power loss, exhaustive
network faults, HA, production load or a production RPO/RTO. Container-image and
hosted CI results must be checked separately against the exact pushed commit.
