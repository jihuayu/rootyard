# Mixed protected/unprotected multi-ref refusal in `tests/browse.py` (#18)

Status: harness code, offline oracles and the CI opt-in are in place. This is a
verification specification, **not native evidence**. Everything below
describes what the code asserts. A native conclusion requires a report bound to
the exact candidate and binary that shows both mixed case IDs `passed` (see
"Native evidence" at the end).

## Wiring

The cases live in `tests/mixed_ref_cases.py` (`MixedRefPolicyCases`), mixed into
`BrowseHarness` in `tests/browse.py`. They are **opt-in via `--mixed-refs`**:

- The fixed inventory `CASE_NAMES` has **15 IDs**: 14 main IDs plus exactly one
  `ref_scale_complete_traversal`. The two deadline cases (`list_commits_deadline`,
  `compare_commits_deadline`) are part of the 14 main IDs. The tuple stays
  byte-for-byte unchanged and is still pinned by
  `tests/test_browse_git_read_steps.py::test_browse_contract_is_unchanged`.
- The two mixed IDs are **not** in `CASE_NAMES`:
  `mixed_protected_unprotected_atomic_push` and
  `mixed_protected_unprotected_ref_transaction`. A module-level assertion in
  `tests/browse.py` pins `len(CASE_NAMES) == 15` and the exact mixed tuple.
- `selected_cases(mixed_refs)` is the fixed inventory followed, only under
  `--mixed-refs`, by the two mixed IDs: the combined run selects **17** IDs with
  the two exact mixed names last.
- `execute()` runs the fixed inventory and keeps its original
  `executed != list(CASE_NAMES)` assertion before the opt-in loop, then runs the
  mixed cases and asserts `completed == selected`. The runner fails if any
  selected case was not executed. `--mixed-refs` without a declared Git is
  refused before the harness is built.
- CI's Browse step only gains the opt-in arguments:
  `--mixed-refs --git "$(command -v git)"`, so the Rust server and the Git
  client are source-bound to the same executable. The step keeps its name and
  every other workflow command is unchanged.

## Trusted Git

One declared stock Git is **both** the Git client and the server's Git:

- `--git` and/or an inherited `ROOTYARD_GIT` may declare it. Every declaration
  present must be an **absolute executable path**, and all of them must
  **resolve to the same file**; otherwise construction is refused. A conflict
  names both resolved paths.
- `_bind_declared_git()` runs in `BrowseHarness.__init__`, so the resolved value
  is written to the server environment **before any start** and is restored on
  every `stop()`/`start()` restart.
- The transparent Git wrappers (the deadline wrapper and the `cat-file` counter
  wrapper) exec that same **bound** executable. The PATH Git is only the fixed
  inventory's fallback when nothing is declared.
- Mixed Git writes (atomic pairs, the protected-only refusal, the `features`
  push behind the pull, the unprotected control and `ls-remote`) run through one
  helper that executes the declared executable with its own per-call
  `-c http.extraHeader=Authorization: Basic <alice>` credential; no credential
  from clone persists to a later push.
- The report records `selected_cases`, `fixed_cases`, `fixed_case_count`,
  `mixed_ref_cases`, `mixed_ref_results`, plus `git` (the binding: declared path,
  environment value, `mixed_refs`) and `git_evidence` (client path, SHA-256,
  version, whether declared, push actor/header, server Git and the managed hook
  runner digest). `case_count` is the selected count.

## Ref reads: public API and physical refs

`ref_state()` takes one snapshot:

- **Physical refs** come only from stock `for-each-ref` run with the declared
  executable against the run-owned bare repository
  (`self.bare = <data>/repos/<id>.git`).
- **Public refs** come from a **separate** authenticated `/refs` API read and
  are stored as `api_refs`.
- The snapshot also records the operation high-water, the outbox count, the
  admission-state map, the pending journal directory names and the repository
  marker (`state` + `COALESCE(recovery_reason,'-')`, which both audits require
  to be exactly `ready/-` before and after).
- The outbox and admission counts are recorded beside the interval evidence for
  the report only; no audit gates on them.

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
   - the folded evidence contract: `finished` and `storage_generation_matches`
     are JSON booleans; `interrupted` and `ungranted_without_hooks` are
     text `"true"`/`"false"`; no `post_receive` receipt;
   - no outbox event or outbox ref for the operation;
   - journal directories empty before and after, and every journal entry (if
     any appears) linked to an exact interval row; the marker `ready/-`;
   - no ref outside a validated CI-service operation (`ci-scheduler`,
     `observed_immutable_ci_root`, one `refs/rootyard-ci/jobs/<id>` outbox
     event) may change during the interval, and the requested refs must not;
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
operations may change refs; journal, marker and the public `api_refs` view are
unchanged. The Git "+1 settled operation" rule is **deliberately not applied**
to API refusals; adding it there would be false. After a worker pass, no refused
update is projected (`repository_ref_projection`), and the final physical refs
equal the post-control baseline.

## Refusal oracles

- `refusal_audit_sql.refusal_audit_verdict()`: an exact settled
  `no_ref_changes` with an `ABORTED` admission passes; `unknown`/`recorded` and
  any unsettled row never do; every single defect fails, including a wrong
  principal combination, admission state/settlement/identity, a non-exact
  `ref_names` set, any outbox event, a non-null receipt, wrong evidence types
  (a text `"true"` for a boolean field fails), a missing or non-empty journal,
  and any `reference_events` entry recording a change.
- The interval decoder accepts only the complete `jsonb_build_object` key set,
  with booleans for `finished`/`storage_generation_matches` and text for
  `interrupted`/`ungranted_without_hooks`. The SQL projects the two booleans
  with `->` so the JSON keeps them as booleans end to end.
- Every SQL value passes through `BrowseHarness._sql_literal`; identifiers are
  UUID-validated.

## Offline oracle (not native evidence)

From the repository root:

```bash
python3 -m unittest tests.test_browse_mixed_refs
```

The suite currently has **83 tests**. It pins the exact case IDs and the
15+2 = 17 selection order, the unchanged `CASE_NAMES`, the runner's
fixed-inventory assertion before the opt-in loop and the selected-case
completion check, the CI opt-in arguments and report fields, the pre-start Git
binding (absolute executable, agreement of declarations, inherited-only,
conflict refusal) and that the transparent wrappers exec the bound declaration,
the `--porcelain` refusal parser, rule isolation and restoration, the physical
`for-each-ref` plus separate public `/refs` reads, the SQL/decoder/contract
types end to end, the final API read being classified (a human row only on the
final read fails the audit), and the `refusal_audit_verdict` truth table.

These tests are **not native evidence**. They cannot stand in for a native run
and never claim it passed.

## Native evidence

A native run is performed later:

```bash
python3 tests/browse.py --binary <attested-binary> --report <unique>.json \
  --mixed-refs --git /usr/bin/git
```

Only a report bound to the exact candidate and binary that shows
`mixed_ref_results` with **both** mixed IDs `passed` (and a passing
`selected_cases` of 17) supports the conclusion that the native proof holds.
The report, not this specification, is the evidence for that conclusion.
