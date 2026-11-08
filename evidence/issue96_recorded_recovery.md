# Issue #96: journal-proven recorded settlement (native not run)

Status: **implementation complete, native execution NOT performed in this environment.**
`cargo` build/test, the native harness, any Git push and any deployment were intentionally
not run here; the root agent executes them with a real binary, PostgreSQL and Git.

## Confirmed defect (from `tests/reliability.py`)

`publication_replay` (native line ~143) injects a BEFORE trigger that rejects a terminal
`git_operations` settlement, so native Git has already advanced refs, written a real
`post-receive.json` and the `finished` marker, and the server is stopped. The test then
drops the trigger, removes `finished`, seeds the matching `unknown` `git_operations` row,
sets the repository to `recovering`/`push_outcome_unknown` and restarts
(`tests/reliability.py:164` expects `state = ready`).

`reliability::reconcile` correctly derives `recorded` from that real receipt and retires
the journal only after SQL commit. Before this change, `events::publish` ->
`ref_admission::settle_in_tx` unconditionally ran `auth::verify_repo_write_access`, whose
repository check (`src/auth.rs:333-340`) rejects any `state != 'ready'`. The historical,
already-committed fact therefore could not be projected: no `ADMITTED -> COMMITTED`,
no outbox row, no journal retirement, and the repository stayed `recovering`.

Ordinary new writes must keep requiring a live `ready` repository, a live token and an
effective `Write` role.

## Change

New capability module `src/storage/recorded_receipt_proof.rs`:

- `RecordedReceiptProof` has private fields and no public constructor.
- `from_journal(operation, outcome, generation)` only mints for a finished,
  parent-publication human operation at the reconciled generation and epoch, and only
  when the *same journal* contains:
  - a non-empty pre-receive request (sorted, unique `refs/*` names),
  - a unique, non-empty successful post-receive receipt whose refs/OIDs appear verbatim
    in that request (a non-atomic successful subset is supported),
  - committed `reference-transaction` hook events whose `refs/*` union is exactly the
    receipt set, with no unrequested ref/OID.
- The proof binds the complete `OperationRecord` (id within admission, repository,
  actor, token, storage generation, shard epoch) and the exact derived
  `RefEventInput` list; `matches_record` and `matches_admission` reject any rebinding.
- A database JSON row claiming `outcome = recorded` cannot mint it.

Settlement (`src/storage/ref_admission.rs::settle_in_tx`, called only from
`src/events.rs` in the same transaction):

- Re-reads `repositories` `FOR SHARE`: current `storage_generation` must equal the
  operation generation; state must be `ready` or, only when a journal capability is
  present, `recovering` with exactly `push_outcome_unknown`. Other operator recovery
  reasons and every other state reject.
- Re-reads `git_ref_admissions` `FOR UPDATE` including `actor_id`, `token_id`,
  `ref_names`: DB actor/token must equal the operation identity for *both* capability
  paths; the recorded proof must also match the complete admitted ref-name set, the
  admission writer/epoch and the event payload. The existing `NoGrantAbort` path gets
  the same DB actor/token check and invents no ref names when there is no request.
- Route `FOR SHARE` epoch/fence/draining/degraded and local-primary checks are unchanged.
- Only a matching `RecordedReceiptProof` (or the existing `NoGrantAbort` for
  `no_ref_changes`) may skip the *current* token/RBAC recheck, because it projects a
  past committed transaction; it never authorizes new refs. Everything else still runs
  `auth::verify_repo_write_access`.
- The terminal update stays `ADMITTED -> COMMITTED` (or `ABORTED`) in the same
  transaction as `git_operations`/outbox; `reliability::reconcile` then retires the
  journal and clears only its own `push_outcome_unknown` flag to `ready`.

`src/reliability.rs` mints the proof only in the actual receipt-derived `recorded`
branch, and only if it matches the record and derived changes; otherwise it falls back
to ordinary current-authority publication.

Public API wrappers `events::publish`, `events::publish_with_no_grant` and
`events::publish_in_tx` keep their signatures, so outbox/resolution/pando tests are not
broken. No migration or schema-version change is introduced.

## Tests added

Rust module unit tests (run with a normal `cargo test`, no database):

- successful non-atomic receipt subset binding; wrong outcome/generation; missing
  request, receipt or committed hook; receipt outside the request/committed set;
  rebinding to another operation/actor/token/generation/ref set/changes; present grant
  never mints `NoGrantAbort`.

PostgreSQL tests in the same module are marked
`#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]`:

- recorded proof settles a `recovering`/`push_outcome_unknown` repository with a token
  revoked after the real push (`COMMITTED`, one outbox row);
- another operator recovery reason is rejected and the admission stays `ADMITTED`;
- admitted `ref_names`/`shard_epoch` drift is rejected;
- a read-only *current* token is still rejected on the ordinary settlement path.

Native harness `tests/recorded_recovery.py` reuses `ReliabilityHarness` and the same
real SQL fault setup as `publication_replay`. It uses a dedicated token, real receipt,
revokes the token before restart, and reports `required_matching_receipt`,
`receipt_sha256` and `journal_evidence_digest` without emitting the DSN, environment or
token. Its report records `native_executed_by_implementer: false` when run unless the
caller changes it; this environment did not run it.

Run (root agent):

```bash
ROOTYARD_TEST_DATABASE_URL=... python3 tests/recorded_recovery.py \
  --binary target/debug/rootyard --report evidence/issue96_recorded_recovery.report.json
```

## Verification performed here

- Static review of the four touched modules and the new test script.
- `python3 -m py_compile tests/recorded_recovery.py` passed.
- No Cargo build/test, no native binary, no Git push, no native harness execution.
  Consequently the Rust changes and the native scenario are **not** claimed to have
  compiled or passed here.
