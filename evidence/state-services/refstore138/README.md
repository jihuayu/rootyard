# Transitional operation-registry qualification

This increment advances #107 under #105. It preserves the existing Pando PG
ref/pack CAS and long read leases; it does not implement a complete RefStore,
durable snapshot pins, holds, publication decisions, Raft or GC.

Seven real PostgreSQL cases passed, including cancel-before-register, immutable
terminal replay, cross-lane same-operation conflict, absolute deadlines, sequence
rollback and a reservation/begin/cancel race synchronized against an actual
ungranted PostgreSQL advisory lock. One transaction must operate on one operation
identity; arbitrary callers can still misuse the public low-level API, and this
adapter exposes no new unauthenticated route or client retry-idempotency promise.

The real binary schema gate passed fresh/dump/restore, legacy003/006/007 upgrades
and custom-search-path/idempotency checks: 90 tables, 15 functions, 35 triggers.
Seven format14 backup/restore cases passed, including corrupt input refusal,
barriers, interrupted restore, clone/fsck and revoked/read-only credentials.
Seven genuine predecessor-format13/schema137 upgrade cases passed: the original
137 binary produced an unedited archive; missing/mismatched opt-ins were rejected;
the candidate restored and upgraded to138, rotated one authority, retained Git and
session boundaries, and left source authority/remote objects available.

The source-bound native Pando workload passed 41 cases and observed 18 durable
committed operation records, zero pending records and 18 terminal results. It is
ordinary Git workload evidence, not synchronized old-OID CAS or rejection-atomicity
qualification. The loser of competing Git pushes may receive HTTP409 rather than
a Git report-status rejection (tracked separately in #126).

All accepted application reports bind to binary SHA-256
a060369d0c55ddf543d25f9bcda0cb9a0bde8e9bbca35339a4b06d063b8a434d.
The app used for backup/publication was built at3998fe5; the final f1d7919 build
changed only the regression test and produced the identical app digest. Its full
source/build receipt is included. Root-package debug symbols were explicitly
disabled; these loopback tests do not establish power-loss, HA or production
latency/RPO/RTO guarantees.

Earlier failures were retained locally, and an explicit ENOSPC backup failure is
included. A minimal restore subsequently passed; full backup and genuine legacy
restore were rerun successfully with adequate space. The earlier generic failure
messages alone did not establish their root cause.

To reproduce the extra publication audit with a trusted built binary and a
disposable configured fixture, set ROOTYARD_BASELINE_HARNESS_ROOT to the checkout
and run native_publication_runner.py with --binary, --source-root and --report.
It requires real configured PG/S3/Vault services; credentials are never evidence.
