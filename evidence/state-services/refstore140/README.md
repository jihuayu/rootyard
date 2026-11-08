# PgRefStore metadata snapshots and pin receipts (schema 140)

This increment captures bounded refs/HEAD and a durable **metadata-only** pin,
successful receipt and retained quota in one owned short PostgreSQL transaction.
It adds immutable keyset paging, database-clock renewal/release CAS, exact historical
receipt replay, full-scope constraints and retained identity/delete guards. It does
not provide complete Git snapshots, pack membership, physical holds/roots, GC or serving.
#105 and #107 remain open. Parent: PR #135.

## Bound source and validation

All four fresh executables were built at `3c0ad400de1b43825c45a5e5938f47860aaec3c2`
with Rust 1.99.1 and matching compiled-input digest (see checks/receipts). Their
Fresh=false Cargo artifacts and byte hashes are retained. The later commits
`8b2731a`/`73d66f5` change only the Python backup harness: a missing import and
libtest output format. Native backup reports retain their actual tested HEAD;
build receipts have not been relabelled. No new MSRV qualification is claimed.

| Check | Actual result |
| --- | --- |
| Real PostgreSQL contracts | 17 passed, zero failed/ignored |
| Library tests | 295 passed, 8 existing ignored |
| All-target pando-lab Clippy, warnings denied | passed |
| Source Python | 286 run, zero failures/errors, 6 existing skips; 13 native/service/kernel modules excluded |
| Actual Rust binary migration | schema140, 99 tables, 27 functions, 48 triggers; fresh/roundtrip/upgrades/custom schema/idempotence |
| Populated current-format backup | 7/7; all six schema140 tables seeded through actual typed adapter, exact global/scoped restore and receipt replay |
| Genuine previous-format restore | 7/7; real schema139/format15 producer, explicit opt-in, upgrade to schema140 |

The populated drill includes active+renewed, released and real database-clock-expired
pins. Restored replays return old receipts without writing, refunding, renewing or
reviving state. The schema139 core seed is explicitly a direct-SQL unserved fixture,
not a Git or adapter acknowledgement. Normal authenticated clone/fsck and revocation
checks also run. Tests use one loopback PG17.11 host and fresh owned databases/directories;
there is no HA, disk-loss, SLA or production RPO/RTO result here. Full remote CI is pending;
the parent has the separately tracked #95 FUSE-service failure.

## Semantics and limits

- At most 4096 captured refs, 256 refs/page and 4096-byte successful receipts.
- Retained per-repo/tenant limits are 64/256 snapshots, 16384/65536 refs,
  16/64 MiB logical admission bytes and 2048/8192 successful receipts. These
  are logical admission budgets, not database disk/WAL/RSS bounds. Expiry and
  release do not refund them; no automatic history/identity trimming exists.
- Pack membership remains unavailable. Existing full-snapshot, physical-pin,
  root/hold, GC and serving capabilities remain false. These internal APIs only
  admit explicitly unserved stable GitFS repositories and do not change legacy serving.
- Format16 uses schema140. Format15 is frozen to schema139 and requires the exact
  `--allow-legacy-schema139` opt-in before verified restore/upgrading. The old
  producer is the retained A1 executable (its receipt is included), not a patched manifest.

## Reproduce and CI

Use dedicated synthetic PostgreSQL/remote fixtures per the repository harness docs.
CI compiles the selected helper via `scripts/build_native_test.py` outside Cargo's
target directory, rebuilds the app last, then invokes
`tests/backup_refstore_snapshot140.py --binary ... --snapshot-fixture-binary ... --report ...`.
The harness requires matching app/helper byte hashes, matching compiled inputs,
the exact helper source SHA and one freshly built test artifact. It runs exactly
one ignored helper test in each mode and rejects zero tests, extra/missing markers
or skips. See the copied root orchestration scripts for this run's exact provenance;
they contain workspace paths and require the corresponding environment, not credentials.

## Preserved history

`history/` keeps actual pre-fix results rather than replacing them: PG v1 failed
on the int4/i64 boundary; v2 hit UNIQUE before the intended FK negative; v3 exposed
the existing namespace/user FK in tenant-deletion setup. PG v4 passed before the
unit-only scope fixture correction; final v5 is freshly built from the current
compiled inputs. Library v1 used two unrelated random scope fixtures. Backup v1
missed the UUID validator import; v2's pretty libtest prefix hid the marker.
The final native rerun uses terse output without relaxing assertions. Compiler
and source-inventory failures are retained too. Binaries remain outside Git as
hash-verified gzip artifacts; receipts and reports are unchanged.
