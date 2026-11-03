# Private-owner Issue slice verification

Verified locally on 2026-11-03 in a Linux cloud execution workspace, using
independently initialized disposable PostgreSQL clusters bound only to loopback.
Every Python test run owned and removed a randomly named schema. No production
repository or external service was used.

Toolchain: Rust/Cargo 1.99.1, Git 2.56.0, PostgreSQL 17.11 and Python 3.12.14.
The verified binary SHA-256 was
`54493a6b3e6b5fe17bf5103f8b94e5ef3c7f66d85711a1c055796dfa1a908807`.

Passed checks:

- `cargo fmt --all -- --check`.
- `cargo clippy --locked --all-targets -- -D warnings`.
- `cargo test --locked --all-targets`: 24 unit tests; the two database tests
  intentionally remain ignored in this default invocation.
- `cargo test --locked --test outbox --test resolution_fences -- --ignored`:
  both real PostgreSQL integration tests passed when explicitly enabled.
- `tests/e2e.py`: all 15 baseline Git/API/backup-roundtrip groups passed.
- `tests/reliability.py`: all 18 groups passed, including upgrade from the
  phase-one schema with user/repository preservation and migration replay.
- `tests/recovery_ops.py`: all 7 explicit-recovery groups passed.
- `tests/metrics.py`: all 5 private-operational-metrics groups passed.
- `tests/forge.py`: all 11 new real HTTP/PostgreSQL groups passed.

The new suite verifies fresh/upgrade migration version set `[1,2,3,6]`, replay,
transactional migration failure, Issue open/close/reopen, independent comment
revisions, owner/read-only/revoked/expired credential behavior, cross-repository
and cross-owner reads/writes, forged identities, composite database constraints,
request/UTF-8 limits, stable-number pagination and restart survival. It exercises
24 concurrent Issue allocations and 24 comment allocations with unique,
consecutive local numbers. For each of Issue and comment edits, eight requests
using the same expected version yield exactly one success and seven conflicts.

Injected SQL insert failures roll back counter allocation. Held SQL transactions
make revocation, read-only downgrade and credential digest replacement commit
while HTTP authorization waits; each request is denied afterward. A token that
expires while waiting on an allocation lock cannot commit its insert or counter
increment. These are measured transaction boundaries, not mocked assertions.

During development the real database caught a duplicate name for an already
existing phase-two repository ownership index. The final migration reuses that
index. The final complete regression also updates the baseline migration test's
exact expected version set to include version 6; no schema check was loosened.
The lock-wait test fixture was corrected to consume the actual output of its
SQL `SELECT` before waiting for its marker; the final run passed all cases.

## Remaining gates

Independent review and integrated backup/workspace/worker schema verification
are separate from these local tests. The branch has no automated backup module;
its baseline backup roundtrip does not establish that a later branch's strict
backup manifest/table whitelist includes Forge. The three new tables and version
6 must be added to that explicit contract, followed by a populated Forge restore
roundtrip. No deployed CI result, merge, deployment or independent review is
claimed by this record.

This is a personal owner-only Issue/comment slice. Organization/member ACLs,
PR/review/check/merge semantics, task/thread/ChangeSet relations, LFS, external CI,
Web UI, deletion, quotas and idempotent POST creation remain unimplemented. The
suite does not prove HA, hard power-loss behavior, throughput limits or full
infrastructure disaster recovery. See [the scope/API contract](forge-issues.md).
