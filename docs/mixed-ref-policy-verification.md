# Mixed protected/unprotected multi-ref refusal in `tests/browse.py` (#18)

Status: harness code, offline oracles and the CI execution/manifest binding are
in place. This is a verification specification, **not native evidence**.
Everything below describes what the code asserts. A native conclusion requires
a report bound to the exact candidate and binary that shows both mixed case IDs
`passed` and a `source_head` equal to the built commit (see "Native evidence" at
the end).

## Wiring

The cases live in `tests/mixed_ref_cases.py` (`MixedRefPolicyCases`), mixed into
`BrowseHarness` in `tests/browse.py`. They are **opt-in via `--mixed-refs`**:

- The fixed inventory `CASE_NAMES` has **17 IDs**: 12 original contracts, the two
  deadline cases (`list_commits_deadline`, `compare_commits_deadline`), exactly
  one `ref_scale_complete_traversal`, and the two Issue #14 recovery cases
  (`ref_transaction_settlement_recovery`, `ref_transaction_crash_recovery`).
  The tuple is pinned by
  `tests/test_browse_git_read_steps.py::test_browse_contract_is_unchanged`.
- The two mixed IDs are **not** in `CASE_NAMES`:
  `mixed_protected_unprotected_atomic_push` and
  `mixed_protected_unprotected_ref_transaction`. A module-level assertion in
  `tests/browse.py` pins `len(CASE_NAMES) == 17` and the exact mixed tuple.
- `selected_cases(mixed_refs)` is the fixed inventory followed, only under
  `--mixed-refs`, by the two mixed IDs: the combined run selects **19** IDs with
  the two exact mixed names last.
- `execute()` runs the fixed inventory and keeps its original
  `executed != list(CASE_NAMES)` assertion before the opt-in loop, then runs the
  mixed cases and asserts `completed == selected`. The runner fails if any
  selected case was not executed. `--mixed-refs` without a declared Git is
  refused before the harness is built. The report records `source_head` (the
  executing checkout's `HEAD`) in addition to the selected/fixed case records.
- CI **executes** the mixed mode in the `native` job:
  `python3 tests/browse.py --mixed-refs --git "$(command -v git)" --binary
  target/debug/rootyard --report test-results/browse.json`. The declared
  executable is the runner's pinned stock Git and is used by both the Rust
  server and the Git client.
- The same `native` job's `scripts/native_report_manifest.py --mode job` step
  binds `--report browse=test-results/browse.json`, the Browse runtime and
  imported helper harnesses (`tests/browse.py`, `tests/browse_ref_scale.py`,
  `tests/mixed_ref_cases.py`, `tests/mixed_ref_support.py`,
  `tests/refusal_audit_sql.py`), and requires all
  four fixed Browse cases plus both mixed case IDs to be present and passing.
  The manifest additionally requires the Browse report's `source_head` to be
  present and exactly equal to the build receipt's workspace commit; a missing
  or foreign head fails the gate.

## Trusted Git

One declared stock Git is **both** the Git client and the server's Git:

- `--git` and/or an inherited `ROOTYARD_GIT` may declare it. Every declaration
  present must be an **absolute executable path**, and all of them must
  **resolve to the same file**; otherwise construction is refused. A conflict
  names both resolved paths.
- `_bind_declared_git()` runs in `BrowseHarness.__init__`, so the resolved value
  is written to the server environment **before any start**.
- Each successful `BrowseHarness.start()` records `server_git`: the Git the live
  server process actually started with, frozen for that process. Helpers never
  rewrite it, and `git_as()` gives the client only its own per-command copy of
  the environment, so a mixed command can never make the live server *look*
  bound to a Git it did not start on.
- Instrumentation wrappers (the deadline wrapper, the `cat-file` counter and
  the `git-fault-wrapper`) exec the bound declared Git when one is configured;
  PATH Git is only the fixed-inventory fallback when no declaration exists.
  The fault wrapper is left in `ROOTYARD_GIT` by its last restart. Before the
  first mixed case, `execute()` calls `restore_declared_git()`, which restores
  the bound Git and restarts the server **only if** the live process started
  under something else. The mixed proof therefore always starts on the declared
  binary.
- Mixed Git writes (atomic pairs, the protected-only refusal, the `features`
  push behind the pull, the unprotected control and `ls-remote`) run through one
  helper that executes the declared executable with its own per-call
  `-c http.extraHeader=Authorization: Basic <alice>` credential; no credential
  from clone persists to a later push. `push_with()` refuses the proof when the
  executed client, the probed client and the captured server-start Git are not
  the same declared executable.
- The report records `source_head`, `selected_cases`, `fixed_cases`,
  `fixed_case_count`, `mixed_ref_cases`, `mixed_ref_results`, plus `git` (the binding: declared path,
  environment value, `mixed_refs`), `git_handoff` (whether the pre-mixed restart
  happened and what the previous process started on) and `git_evidence`
  (client path, SHA-256, version, whether declared, push actor/header,
  `server_git` — the **captured server-start identity**, not the current
  environment — plus the managed hook runner digest). `case_count` is the
  selected count.

## Ref reads: public API and physical refs

`ref_state()` takes one snapshot:

- **Physical refs** come only from stock `for-each-ref` run with the declared
  executable against the run-owned bare repository
  (`self.bare = <data>/repos/<id>.git`).
- **Public refs** come from a **separate** authenticated `/refs` API read and
  are stored as `api_refs`.
- The snapshot also records the operation high-water, the outbox count, the
  admission-state map, the per-outcome count map, the pending journal directory
  names and the repository marker (`state` + `COALESCE(recovery_reason,'-')`,
  which both audits require to be exactly `ready/-` before and after).
- `outcomes` is this run-owned repository's own `git_operations` rows,
  `outcome -> count`, read by one read-only `GROUP BY outcome` through the same
  `self.sql` path as the other counts. It has the same text-map shape as
  `admissions` (`no_ref_changes:1,recorded:2`), so both interval audits can
  report it without KeyError. It is never taken from the unit snapshot
  fixtures.
- The outbox, admission and outcome counts are recorded beside the interval
  evidence for the report only (`diagnostics.before`/`diagnostics.after` in
  the API refusal audit); no audit gates on them, and they never decide
  acceptance.

The Git-refusal audit compares the physical refs before/after (requested refs
must not move, and any other changed ref must belong to a validated CI-service
operation) and separately requires the public `api_refs` view to be unchanged.
The API-refusal audit requires the physical `refs` and the public `api_refs` to
be unchanged across the refusal, and a zero user-operation interval.

## Rule isolation and restoration

Every mixed case runs inside `isolated_rules()` (a context manager). Earlier
cases leave rules on the shared fixture repository, so a case does not assume a
global inventory: every pre-existing rule is deleted through the API (DELETE),
the empty set is asserted, the case applies exactly the rules it needs, and
afterwards every case-left rule is deleted and every original is re-created
without `expected_version` (a recreated rule is a new row). Only policy fields
(`branch_ref`, approvals, checks, fast-forward, deletion, force-push,
self-approval) are compared. A restore error is raised in the context of the
case's exception, so it cannot mask the original cause.

## Case 1: `mixed_protected_unprotected_atomic_push`

`main` and `main`/`mixed-topic`. Stock Git must be 2.43 or newer (`--atomic`).
Every push is authenticated with Alice's own owner grant (`create-user`); a
`create-token` grant would not be the writer under test.

1. **Rule-free native group.** No branch rule exists on `main` or the topic
   (`assert_rule_state({})`; no rule is created and no flag relaxed) and no pull
   was opened. The bare repository still has
   `receive.denyNonFastForwards=true`. One authenticated
   `git push --atomic` pushes `+first:main` (forced non-fast-forward) and the
   topic in the same push. Stock Git must refuse **both** refs with a server
   `[remote rejected]` line; a local `=` no-op or a local `[rejected]` fails the
   case. The Git-level refusal is then audited as an **exact one-row**
   witness: exactly one new operation, settled, `no_ref_changes`, with an
   `ABORTED` admission whose actor/token/repository match Alice's grant and
   whose `ref_names` are exactly the two pushed refs. The audit also requires:
   - the folded evidence contract on the human refusal row: all four values
     (`finished`, `storage_generation_matches`, `interrupted`,
     `ungranted_without_hooks`) are JSON booleans as the human `git_operations`
     row stores them; the first two must be exactly `true` for a valid refusal,
     the last two accept either boolean, and an interrupted operation requires
     `ungranted_without_hooks true`; no `post_receive` receipt;
   - no outbox event or outbox ref for the operation;
   - journal directories empty before and after, and every journal entry (if
     any appears) linked to an exact interval row; the marker `ready/-`;
   - no ref outside a validated CI-service operation (`ci-scheduler`,
     `observed_immutable_ci_root`, one `refs/rootyard-ci/jobs/<id>` outbox
     event) may change during the interval, and the requested refs must not.
     A service event whitelists one **exact transition**, not a ref name: the
     physical before/after OIDs must equal that event's `old_oid`/`new_oid`
     (an absent side normalized to the zero OID of the event's format, so a
     create is zero -> new), or the change is an out-of-band overwrite and
     fails. An unchanged ref need not materialize an event, and two validated
     service events naming the same ref in one interval are ambiguous and fail
     closed;
   - the public `api_refs` view unchanged.
   This witness is what "+1 settled operation" means: one settled operation,
   exactly audited, never a global counter comparison.
2. **Approvals-only policy group.** `main` gets one approval with
   `require_fast_forward=false`, `prevent_force_push=false` and
   `prevent_deletion=false`, so the branch rule alone can deny. The update is a
   `commit-tree` commit whose parent is the tip `ls-remote` advertises (the
   local checkout is never moved), with a real pull opened for that head —
   recorded as evidence that a pull alone does not authorize a direct push. One
   atomic push of `main` and the topic is refused for both refs and audited like
   group 1. A **paired unprotected-only** push of the topic then succeeds
   (transport control), and the topic OID is re-read.
3. **Protected half alone.** Only after the control does the protected update get
   its own **fresh** `ref_state` baseline (asserted to already contain the
   control's topic OID) before a protected-only push is refused and audited with
   the same one-row rule. No state from before the control is reused.

The two groups run inside one `isolated_rules()` context. The report labels both
groups and keeps the native group's audit as the policy group's independent
`git_refusal` evidence; the policy group separately records the protected-only
push and its audit.

4. **Causal one-flag matrix.** With `required_approvals=0` and
   `required_checks=[]`, only one protected-tip flag varies at a time:
   `require_fast_forward=True` alone and `prevent_force_push=True` alone must
   each refuse a mixed non-fast-forward `git push --atomic --force`; and
   `prevent_deletion=False` with either flag set must refuse deleting a
   non-HEAD protected branch in a mixed push. Every refusal is audited with the
   same one-row interval evidence, the protected ref keeps its old OID and the
   unprotected sibling branch is not created. This closes the
   delete-then-recreate rewind vector.

## Case 2: `mixed_protected_unprotected_ref_transaction`

`main` and `main`/`mixed-tx-topic`, through the **API**
(`POST /ref-transactions`, atomic), not Git. Steps, in order:

1. **Seed:** no rule exists; a ref-transaction create of the topic is admitted
   (200) and the physical OID is read.
2. **Mixed 403 first:** a protected `main` rule (approvals only; every
   fast-forward/force-push/deletion flag off) and an unprotected topic rule
   (zero approvals) exist. `main` (live CAS, fast-forward) and the topic (live
   CAS, fast-forward) in one transaction → `403 protected branch policy denied`;
   the topic did not move.
3. **Control:** the unprotected topic update and a control ref are admitted in
   one request (200), proving the request shape is legal with the protected rule
   present.
4. **Protected alone:** a fresh baseline is taken after the control; the same
   `main` update alone → `403`.
5. **Stale CAS:** the topic `old_oid` that the control already moved →
   `409 reference old_oid mismatch` (the CAS gate still runs before policy).

The API refuses inside its handler, before it journals anything, so every API
refusal must preserve the **full interval evidence with zero user operations**:
no user (human-principal) operation row appears in the interval, the final read
is classified like every other read, and only source-validated CI-service
operations may change refs, with the same source-bound OID match (and the
same duplicate-event refusal) as the Git interval. The journal, marker and the
public `api_refs` view are unchanged. The Git "+1 settled operation" rule is
**deliberately not applied**
to API refusals; adding it there would be false. After a worker pass, no refused
update is projected (`repository_ref_projection`), and the final physical refs
equal the post-control baseline.

6. **Causal one-flag matrix.** The same matrix runs through
   `POST /ref-transactions` with `required_approvals=0`,
   `required_checks=[]` and one flag at a time: `require_fast_forward=True`
   alone and `prevent_force_push=True` alone each refuse a mixed
   non-fast-forward transaction; and `prevent_deletion=False` with either flag
   set refuses deleting a non-HEAD protected branch alongside an unprotected
   sibling update. Every transaction is a `403 protected branch policy denied`
   with zero user operations, the protected ref unchanged and the sibling
   unmoved.

## Refusal oracles

- `refusal_audit_sql.refusal_audit_verdict()`: an exact settled
  `no_ref_changes` with an `ABORTED` admission passes; `unknown`/`recorded` and
  any unsettled row never do; every single defect fails, including a wrong
  principal combination, admission state/settlement/identity, a non-exact
  `ref_names` set, any outbox event, a non-null receipt, wrong evidence types
  (a text `"true"`/`"false"` or an integer for a boolean field fails), a missing
  or non-empty journal,
  and any `reference_events` entry recording a change. `reference_events` must
  be the stored array: a missing, null, string or object value fails, and every
  entry must be a journal event whose `changes` list is empty.
- The interval decoder accepts only the complete `jsonb_build_object` key set.
  The SQL projects all four evidence keys with `->` (never `->>`) and an absent
  key becomes the JSON sentinel `EVIDENCE_MISSING_BOOL` (`"missing"`), so the
  stored booleans survive end to end; the Rust serialization of the four keys is
  pinned in the shared `src/journal/record.rs` evidence builder so a change
  needs deliberate review.
- There are two stored service evidence shapes, and the interval deliberately
  reads every service and human row:
  - the receive-pack shape built by `src/journal/record.rs` for live
    ref-transaction settlement and `src/reliability.rs` (human rows too) stores
    `finished`, `interrupted`, `reference_events`,
    `storage_generation_matches` and `ungranted_without_hooks`;
  - the alternate `kind=observed_immutable_ci_root` `ci_pin` shape, written by
    `src/reliability.rs` and `src/webhooks/delivery.rs`, stores `finished`,
    `interrupted`, `reference_events` and `retained`, but **not**
  `storage_generation_matches` or `ungranted_without_hooks`; those two keys
  project as the sentinel on such a row. A separate recovery record in
  `src/reliability.rs` may store only `finished` and
  `storage_generation_matches`; it lacks the required `reference_events` array
  and this audit rejects it during decoding. Such a row is never accepted as
  service evidence; a settled service row must have the exact retained evidence
  and outbox event required by the source query.

  The four receive-pack keys therefore do not exist on every operation row.
  The decoder still requires a JSON boolean for every evidence key on a human
  row, and on a service row for `finished`, `interrupted` and the
  `reference_events` array. Only a row carrying exactly the service-principal
  flags (`human_principal` false, `service_principal` true, no actor/token
  match) may present the sentinel, and only for `storage_generation_matches` and
  `ungranted_without_hooks`. Any other string (`"true"`/`"false"`), an integer,
  null, or the sentinel on any other principal combination fails. Decoding a
  service row is not acceptance: `service_release_valid` (the exact
  source-bound query of `service_release_valid_query`) still gates every
  settled service event in both interval audits, and the human receipt is
  folded from the human row only, so the sentinel never reaches
  `assert_evidence_contract` or the verdict.
- `reference_events` keeps a missing key as a non-array sentinel (never `[]`),
  and the decoder requires a source-shaped array matching `journal::events()`:
  each entry is exactly `ordinal` (positive, contiguous and ordered from 1),
  `phase` (one of the serialized `HookPhase` names) and `changes` (a list of
  `ref_name`/`old_oid`/`new_oid` strings). The key is serialized directly from
  a `Vec<HookEvent>` and that source shape is pinned.
- Every SQL value passes through `BrowseHarness._sql_literal`; identifiers are
  UUID-validated.

## Offline oracle (not native evidence)

From the repository root:

```bash
python3 -m unittest tests.test_browse_mixed_refs
```

The suite pins the exact case IDs and the 17+2 = 19 selection order, the
`CASE_NAMES` inventory (compared against a literal expected tuple with no
history lookup, so a shallow CI checkout cannot skip the check; a focused test
asserts the guard has no skip path), the runner's
fixed-inventory assertion before the opt-in loop and the selected-case
completion check, the CI opt-in arguments and report fields, the pre-start Git
binding (absolute executable, agreement of declarations, inherited-only,
conflict refusal) and that the transparent wrappers exec the bound declaration,
the `--porcelain` refusal parser, rule isolation and restoration, the physical
`for-each-ref` plus a separate, fully paginated public `/refs` walk (explicit
limit, advancing cursors, pages bounded by their own `next_after`, bounded
termination; proven with 201 refs across three pages), the `ref_state`
`outcomes` map (present with the exact source pin, parsed from this repository's
`git_operations` rows through a read-only `GROUP BY` and reported by the API
interval, not gated on), the SQL/decoder/contract
types end to end (including the alternate `observed_immutable_ci_root` service
evidence: its sentinel decodes for a service row only, `"true"`/`"false"` texts
and the sentinel on a human row still fail, and accepted service events still
pass `service_release_valid`), the final API read being classified (a human row only on the
final read fails the audit), the API interval's stable read (rows are read and
classified, the refs are captured, then the rows are re-read: a settled service
create for an operation absent from the pre-snapshot read forces a second
snapshot that follows it, and the reported `changed_refs` include the job ref;
the reviewed pre-fix loops on the same interleaving accepted the stale
snapshot), and the `refusal_audit_verdict` truth table.

These tests are **not native evidence**. They cannot stand in for a native run
and never claim it passed.

## Native evidence

A native run is performed later:

```bash
python3 tests/browse.py --mixed-refs --git /usr/bin/git \
  --binary <attested-binary> --report <unique>.json
```

In CI this is `--git "$(command -v git)"`, the same pinned stock Git whose
version is recorded as the `git` fixture. Only a report bound to the exact
candidate and binary that shows `mixed_ref_results` with **both** mixed IDs
`passed`, a passing `selected_cases` of **19**, and a `source_head` equal to the
build receipt's workspace commit supports the conclusion that the native proof
holds. `scripts/native_report_manifest.py` enforces that Browse `source_head`
binding. The report, not this specification, is the evidence for that
conclusion.
