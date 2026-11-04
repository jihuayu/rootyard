# Issue state-filter verification

Verified on 2026-11-04 in a Linux cloud workspace, based on
`5fa85b20c284505888dbba11297a2cb3ecf99aa9`. The change adds optional
`state=open` or `state=closed` only to the private-owner Issue list. Omitting the
filter retains the original response and number-keyset pagination contract.

Toolchain: Rust/Cargo 1.85.1, Git 2.52.0, PostgreSQL 17.11, Redis 8.0.2 and Python
3.12.14. The verified debug binary SHA-256 was
`3d6324c578624a634b11bbe02967d3fa89d41fb41482b2a8856f89204adecbd1`.
All database tests used synthetic disposable resources; backup/restore suites
used two independently initialized PostgreSQL clusters bound to loopback.

## Contract checks

The separate Issue query extractor accepts only lowercase `open` and `closed`.
It rejects empty/unknown values, duplicate fields including percent-encoded
aliases, unsupported fields and invalid pagination bounds. Comment lists retain
their old extractor and still reject `state`.

The state is a bound SQL parameter. Tenant and repository scope, current-token
checks, token/repository row locks and final expiry verification are unchanged.
The predicate applies before `limit+1`, and `next_after` is the last returned
matching number only when an additional match was observed.

Eight real HTTP/PostgreSQL test groups exercise:

- Sparse multi-page open and closed results, plus unchanged unfiltered lists.
- Zero, one, exact-limit and extra-match tails, both limit boundaries and the
  largest signed 64-bit cursor.
- Malformed, unknown, repeated and comment-only-inapplicable query parameters.
- Owner/repository isolation, read-only access, Bearer and matching Basic
  credentials, revoked/expired tokens, and recovering repositories.
- Held token/repository updates proving reads wait and recheck authorization.
- Changes ahead of a cursor that add/remove later matches; newly matching or
  reopened earlier numbers are not revisited. New higher numbers can appear.
  Changing the filter preserves the cursor's numeric lower bound.
- Full Forge-table snapshots showing successful reads and denied requests do
  not change content, versions, timestamps, numbering or idempotency records.

Independent read-only review found no correctness or security blocker. The
change introduces no table, index, migration or backup-format modification.
Schema007's three exact catalog forms and format4 remain unchanged. The existing
primary-key index remains available, but planner choice is not guaranteed.
Sparse matches may require scanning many rows; these small functional fixtures
are not a large-repository performance qualification.

## Passed checks

- Formatting and strict all-target Clippy.
- All-target Rust tests: 34 unit tests passed.
- Explicit ignored PostgreSQL outbox and resolution-fence tests both passed.
- Locked build and the actual-binary schema catalog/dump/upgrade tests.
- `tests/forge_state_filter.py`: 8 groups.
- `tests/forge.py`: 11 groups.
- `tests/forge_idempotency.py`: 13 groups.
- `tests/e2e.py`: 15 groups.
- `tests/reliability.py`: 18 groups.
- `tests/backup_forge.py`: 9 groups.
- `tests/backup_upgrade.py`: 5 groups.
- `tests/backup.py`: 7 groups.
- `tests/backup_recovery.py`: 6 groups.
- `tests/restored_workers.py`: 4 groups.
- `tests/recovery_ops.py`: 7 groups.
- `tests/metrics.py`: 5 groups.
- `tests/cross_process.py`: 6 groups, including real Redis.

All 13 Python suites passed, covering 114 groups.

## Limits

Filtered pagination is a live view rather than a snapshot across requests. A
client needing earlier newly matching Issues must restart from `after=0`.
Authorization remains personal-owner-only, with no organization or collaborator
model. No search, labels, new write permissions, schema migration, index promise,
HA or production throughput guarantee is added. Hosted CI and image validation
must be checked separately for the exact published commit.
