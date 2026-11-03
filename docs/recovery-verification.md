# Offline unknown-outcome resolution verification

`tests/recovery_ops.py` exercises the public maintenance CLI against real
PostgreSQL, a temporary native bare repository, and authenticated HTTP Git pushes.
It reuses the existing isolated test harness. Run only against a dedicated test
database: every run owns a random schema and temporary storage directory, but
migration extension installation can affect the database. Tokens are redacted.

```sh
cargo build
ROOTYARD_TEST_DATABASE_URL=postgresql://localhost/rootyard_test \
  python3 tests/recovery_ops.py --report recovery-report.json
```

`--binary` selects the executable; `--keep` preserves the temporary repository and
service log for investigation. Reports include the tested binary's SHA-256.
The report's seven named cases contain multiple individual assertions.

## Verified behavior

- Two actual Git pushes establish known native refs. A third actual push creates
  a ref whose old pending projection event must not resurrect it later.
- An explicitly synthetic prepared-only journal has no successful receipt. It is
  refused by inspection before import. Offline reconciliation imports it as
  `unknown`; a service restart continues refusing writes.
- Maintenance operations refuse the service's active volume lock. Inspection and
  resolution refuse Git `.lock` files. Inspection rejects symlinks and fails a
  native integrity check when a ref names a missing object.
- Wrong expected generation or fingerprint, changed refs, changed symbolic HEAD,
  changed journal evidence, changed journal sequence counter, changed stored SQL
  evidence, and an intervening incident revision invalidate the reviewed
  fingerprint. An unrelated recovery reason cannot be cleared by this command.
- An explicit reason is required. Successful resolution increments the storage
  generation, leaves the original unknown operation unchanged, preserves evidence
  in the operation-resolution record, and creates no synthetic outbox events.
- The rebuilt projection contains exactly the native snapshot refs, with
  `source_kind='recovery_snapshot'`, a resolution ID, no event ID, and the new
  generation. Direct stale-generation projection updates are rejected.
- Recovery and operation resolutions reject UPDATE and DELETE. Resolved unknown
  history cannot change to recorded, and inserting an event for it is rejected.
- Duplicate operation IDs in distinct journal directories are rejected.
- Repeating the same fingerprint, generation and reason is idempotent. Changing
  the reason or using another storage volume fails. Identical post-commit leftover journal evidence can be safely
  retired again.
- Draining old pending ref-index deliveries marks them `superseded_generation`
  without changing the snapshot or resurrecting a removed ref. Restart followed
  by an actual HTTP push records new-generation history and receipt provenance.
- Candidate events already attached to unknown history remain as evidence, but
  both delivery rows become `discarded_unknown`, active leases are fenced, and no
  audit or projection success is emitted. A later real same-ref event drains
  through both consumers and leaves no pending deliveries.
- Reintroduced changed journal evidence is preserved. Reconciliation marks the
  repository `resolved_journal_changed`, and a subsequent push is refused.
- Malformed journal evidence cannot be inspected. Disappearance of a previously
  reviewed journal invalidates the fingerprint. A missing or rolled-back local
  sequence counter below PostgreSQL history is refused. A fresh inspection can explicitly
  acknowledge a gap where the journal is missing: its digest and evidence remain
  NULL, not fabricated. A journal discovered later is not authorized for removal
  by that missing-evidence acknowledgment.

## Scope and limits

The prepared journal and offline ref deletion are deliberate fault fixtures, not
claims that a real interrupted push succeeded. Real pushes are used before and
after the incident, but this suite does not simulate kernel/power loss, disk
controller durability, multi-host fencing, external exactly-once consumers, or a
concurrent PostgreSQL worker/resolve lock race. Worker/resolve ordering requires
separate PostgreSQL transaction tests. This is functional verification, not a
performance benchmark or production recovery certification.

Verification on 2026-11-03 passed all seven cases against binary SHA-256
`46dc3576380fd494821a661d8b64ab829e8f9e9b97db8af2c61638d33561a8e5`.
The wrong-volume replay regression exposed and verified a fix for a missing
fast-path volume check. Re-run after source changes; the report is authoritative
for the binary tested.

## Increment-wide regression record

On 2026-11-03 the same debug binary passed, separately with Git client/server
2.47.3 and 2.56.0 and PostgreSQL 17.11:

- 15 baseline Git/HTTP/recovery cases (`tests/e2e.py`).
- 18 durable push/outbox cases (`tests/reliability.py`), including incremental
  migration through schema version 3.
- The seven manual resolution cases above (`tests/recovery_ops.py`).

The same build passed 23 Rust unit tests, the explicitly enabled durable outbox
PostgreSQL contract test, and `tests/resolution_fences.rs`. The latter runs real
concurrent PostgreSQL sessions: a worker retaining the repository share lock
while blocked on a projection row prevents the resolver lock; the reverse order
makes an already-claimed old event observe the new generation without recreating
a deleted row; a lease expiring during that wait cannot acknowledge; and a newly
visible unknown predecessor blocks acknowledgment. Its resolver SQL transitions
model the maintenance transaction; it does not run the CLI concurrently with a
worker. The Python suite separately verifies the actual filesystem/CLI path.

Five metrics cases passed against the same binary, covering private fixed-label
exposition, durable aggregate counts, resolved-unknown exclusion, a missing-table
failure returning 503 without healthy backlog gauges, and non-loopback rejection.
Formatting and warning-free Clippy checks passed. CI explicitly runs both ignored
PostgreSQL tests and all four Python suites; default `cargo test` alone is not the
complete verification command.

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo test --locked --test outbox --test resolution_fences -- --ignored
cargo build --locked
python3 tests/e2e.py --report test-results/e2e.json
python3 tests/reliability.py --report test-results/reliability.json
python3 tests/recovery_ops.py --report test-results/recovery-ops.json
python3 tests/metrics.py --report test-results/metrics.json
```

Use a dedicated `ROOTYARD_TEST_DATABASE_URL` for all database-backed commands.
This increment does not include the separate offline backup/restore command
workstream. It does not certify power-loss durability or production readiness.
