# Permanent artifact holds and protected uploads: A3 evidence

This is an unserved library foundation for #105/#107 and part of #113. It adds
permanent global holds, single-use grants, a durable consume before provider IO,
physical backend binding and verified Blob read-back. It does not complete these
issues. Stacked on PR #136 and the Blob/KeyProvider work in #131/#133.

## Source and actual results

All five candidate executables were freshly built at
`4c039d142bd7b9615fd57152e00db3c25eac13a4` with Rust 1.99.1 and source-input
SHA-256 `cafca60c5f0043cf018655256f6be30ccc6f10c2021b945cd7c135104cad7e2e`.
Cargo Fresh=false artifacts, selected test source digests and executable hashes
are in the receipts. No new MSRV or Azure provider-runtime qualification is made.

| Check | Result |
| --- | --- |
| Real PostgreSQL contracts | 19 passed, zero failed/ignored |
| Protected PostgreSQL + S3 upload | 1 passed; two artifacts; durable consume, full GET and range/length/SHA-256 checks |
| Library tests | 348 passed, 9 ignored (names retained); the new real-provider test ran separately |
| Raw real-S3 provider contract | 1 passed, including a 21 MiB object, streaming/read-back/error/abort behavior |
| Strict all-target Clippy | passed for pando-lab, and pando-lab + blob-azblob |
| Source Python | 286 run, zero failures/errors, 6 existing skips; 13 native/service/kernel modules excluded |
| Actual binary migration matrix | schema141: 105 tables, 33 functions, 69 triggers; fresh, roundtrip, 003/006/007 upgrade, custom schema and idempotence |
| Populated current-format backup | 7/7; six nonempty new tables, all 64 shards, typed seed, exact global/scoped restore and immutable replay |
| Genuine previous-format restore | 7/7; retained schema140/format16 producer, explicit opt-in, upgrade to141 |
| Same-crate privacy compile probes | 8 exact privacy rejections; permissive control compiles; original source restored |

The privacy probe used the retained pre-format input digest. Applying only
`cargo fmt --all` to those restored inputs produces exactly the candidate source
input digest (see privacy/rustfmt-equivalence.json); no receipt was relabelled.
The application binary is retained as a genuine schema141/format17 producer for
future compatibility drills; the current16 source binary was never manufactured
by editing a manifest.

## Contract and limits

Only fresh attempt paths are registered. A grant and consumed token have private
PG mint points; raw Blob writes, provider handles, path mapping, profile and
credential getters are sealed to the Blob subtree. Blob receipts are read-only
and mintable only by the bounded transfer verifier. There is no raw-write hook
under pando-lab. The physical identity binds provider, origin, bucket/container,
root, region and account identity; secrets/session tokens are excluded.

Acquisition is all-or-none (1..16 artifacts). The ACK carries a stable consume ID.
Replay and historical queries validate the complete immutable batch but mint no
IO authority. Consumption rechecks exact parent pending/cancel state and gate
scope, commits once with synchronous_commit=on, then returns the PG pool lease
before any provider IO. A client deadline on an in-flight COMMIT returns Unknown
and no token; the fixture proves COMMIT is still parked, releases its real
advisory barrier, and resolves the committed rows without regranting. Its local
server-budget trigger is fault injection, not a production timeout change or a
response-packet-loss experiment. PostgreSQL fsync and full_page_writes were on;
no restart, disk-loss, multi-host or HA claim follows.

Holds, successful ACKs, consumption receipts and quota are retained permanently.
Active generation1 rows cannot be updated, deleted, truncated, expired or
refunded; deletion of business repository/user rows does not remove them.
Repo limits are 256 holds, 128 MiB declared bytes, 4 MiB logical bytes and 2048
receipts; tenant limits are 4x those counts/bytes. Sixty-four fixed global shards
each admit 256 holds, 128 MiB declared bytes, 1 MiB logical bytes and 1024
receipts. ACK bodies and consume bodies count toward retained quotas. These are
logical admission limits, not database disk/WAL/RSS bounds.

A cancellation after acknowledged consumption may still leave a delayed upload
orphan, permanently held. No release, retirement, reuse, candidate, pack
membership, complete Git snapshot, logical root, destructive GC, serving route,
production encryption or Blob-byte backup closure is provided. The backup drill
preserves metadata; restored ACKs establish no byte availability or upload right.
The parent core gate/refs and parent operation fixture are plainly direct SQL;
new hold/consume rows are generated through the actual typed adapters.

## Failure history and scope

The first dirty-checkout diagnostic passed11/19. Seven fixture assertions omitted
acquire ACKs from receipt budgets; one non-CASCADE TRUNCATE stopped first at an
unrelated FK. Strict v2 passed18/19 and exposed personal-namespace teardown order.
Strict v3 passed18/19 and exposed ambiguous-COMMIT fixture timeout/connection reuse.
DeepSeek corrected quota assertions, constrained FK-vs-trigger checks, isolated
writer/observer pools and added fixture-only server budgets; v4 passed19/19.
The first S3 run rejected the runner's oversized root segment before IO; splitting
the task-owned prefix fixed configuration, and the same binary passed. Reports,
exact build receipts, logs and runner versions are retained, not overwritten.

Implementation was primarily real DeepSeek subagents; Luna Max reviewed the
production boundaries, adversarial tests and backup fixtures. Root integrated,
built and ran native qualification. Full remote CI is pending; the parent retains
the separately tracked #95 FUSE-service failure. Old FUSE artifacts were untouched.
