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

The original reports (`native-publication.json`, `backup-format14.json`,
`legacy137-restore.json` and `application.build.json`) remain historical evidence
for binary `a060369d0c55ddf543d25f9bcda0cb9a0bde8e9bbca35339a4b06d063b8a434d`
from3998fe5/f1d7919. They are not re-labelled as current-head qualification.

The fresh application receipt `current-app.build.json` binds clean194caff
(the shared-contract/backup-test fixes included) and binary
`9f861ff7b098836fc9b80bba945545c4e9b2fb1e78fe5136c76c316a91fda8db`.
Its `current-app-publication.json` passed41 cases with18 committed,0 pending,
18 terminal rows; `current-backup-format14.json` passed all7 backup/restore cases.
`current-pg-operations-core.json` records7 realPG cases on the unchanged registry
core at9e8c450, with its separate source-bound test receipt; it is not a194caff
rebuild of that test. The genuine legacy137 restore report is historical above.

`current-browse.json` passed all11 native Browse cases against the new application
using the shared harness at a261c99. That Python-only fix uses an explicit manual
recovery reason for the synthetic fence: the real reconciler legitimately clears
`push_outcome_unknown` without unresolved operations. The prior fixture raced
that reconciler and failed with a200 instead of409. The11 original HTTP/security
assertions remain; another remote first-read404 has not been reproduced locally.

Root-package debug symbols were explicitly disabled. These loopback tests do not
establish power-loss, HA or production latency/RPO/RTO guarantees.

Earlier failures were retained locally, and an explicit ENOSPC backup failure is
included. A minimal restore subsequently passed; full backup and genuine legacy
restore were rerun successfully with adequate space. The earlier generic failure
messages alone did not establish their root cause.

To reproduce the extra publication audit with a trusted built binary and a
disposable configured fixture, set ROOTYARD_BASELINE_HARNESS_ROOT to the checkout
and run native_publication_runner.py with --binary, --source-root and --report.
It requires real configured PG/S3/Vault services; credentials are never evidence.
