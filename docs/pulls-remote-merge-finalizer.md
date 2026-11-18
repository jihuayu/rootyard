# PR Merge Remote-Authz Ref-CAS Receipt Projector & Recoverable Finalizer

- Issue: `Refs #156` (keeps Issue #156 **OPEN** until full integration rollout completes)
- Crate / Domain Module: `rootyard::pulls::remote_merge_finalizer`

## Overview

`src/pulls/remote_merge_finalizer.rs` provides an isolated, crash-recoverable PR merge
coordinator (`PullRemoteMergeProducer`) paired with a monotonic Ref-CAS receipt projector
(`PullMergeReceiptProjector`) and recovery scanner (`RecoverablePullMergeFinalizer`).

Authority Ref-CAS log order (`RefCasStateMachine` over 3-node mTLS Raft) is the **sole
commit point** for target-ref advances (`refs/heads/<base>`). PostgreSQL projection is
purely a monotonic materialization of durable CAS outcomes and never acts as an independent
split-brain truth source.

## State Machine & Monotonic Lifecycle

Every merge attempt writes a pre-CAS `PendingMerge` durable intent row bound to:
`(attempt_id, tenant_id, repository_id, pull_number, operation_id, decision_id, expected_base_ref,
expected_head_oid, expected_base_oid, candidate_target_oid, strategy, expected_version,
expected_storage_generation, authz_epoch, pack_sha256, facts_digest)`.
Signed grant `facts_digest` binds `compute_merge_binding_digest` including canonical
`compute_observed_checks_digest` over `observed_checks`, expected head/base OIDs, required
checks, and `min_check_sequence`.

From `PendingMerge`, attempts transition strictly forward into terminal states:

1. `CommittedMerge`: Ref-CAS applied the scoped ref update at `(log_term, log_index)`.
   Replaying or re-projecting the same `CommittedMergeReceipt` is idempotent (`replayed: true`),
   preserves the original commit `(log_term, log_index)` via `original_operation_log_id`, verifies
   the full receipt identity tuple (`verify_committed_receipt_tuple`), and can never revert to
   `open`, `rejected`, or `aborted`, nor overwrite `merged_oid`.
2. `RejectedMerge`: Ref-CAS terminally rejected the operation or precondition failed before CAS.
   Verifies the full rejected tuple (`verify_rejected_receipt_tuple`) and leaves `forge_pulls` in
   `open` without clearing prior committed receipts.
3. `AbortedBeforeCas`: Coordinator disconnected, timed out, or recovered when Ref-CAS confirms
   `OperationLookup::Unknown` for `operation_id` after crash.

In PostgreSQL (`PgMergeStore`), `pull_remote_merge_attempts` enforces full-tuple SQL `WHERE`
predicates (`ATTEMPT_TUPLE_WHERE`) and `pull_remote_merge_monotonic_trig` under
`SET LOCAL synchronous_commit = 'on'`, and only a fresh transition to `CommittedMerge` updates
`forge_pulls` (`state = 'merged'`) after confirming `base_ref`, `head_oid`, and `base_oid`.

## Fail-Closed Preconditions & Error Contract

Before contacting Ref-CAS (and re-verified inside `RefCasStateMachine`), `validation.rs`
validates snapshot integrity, live ref heads, trusted check conclusions/sequences, and the
signed remote authorization grant (`DecisionGrantKeyring` + `build_scoped_commit_from_grant`):

| Condition | Named Error |
|---|---|
| Missing, failed, untrusted, or stale check sequence / wrong commit OID | `StaleRequiredChecks` |
| PR head ref / snapshot `head_oid` mismatch or stale version/generation | `StaleHeadOid` |
| Base ref moved (`live_base_ref_oid != expected_base_oid`) or CAS `RevisionMismatch` | `TargetRefMoved` |
| Scope closed (`Closing`/`Closed`/`Revoked`) or `authz_floor >= authz_epoch` or cancelled op | `RevokedAuthorization` |
| Invalid grant signature, expired tick, realm mismatch, or `facts_digest` mismatch | `RemoteAuthzDenied` |

## Crash / Timeout Recovery & Stock Git

- **Git Candidate Preparation (`git_pack.rs`)**: Computes fast-forward ancestry and isolated
  3-way merge commits via stock `git merge-tree --write-tree` + `commit-tree` + `pack-objects`
  for both `SHA-1` and `SHA-256` without updating `refs/heads/*`.
- **Reconciliation (`RecoverablePullMergeFinalizer::reconcile_pending`)**: Scans `PendingMerge`
  rows after coordinator timeout or crash and queries `MergeAuthorityBackend::query_operation_outcome`.
  If Ref-CAS committed during the blind window, the reconciler finalizes `CommittedMerge` and
  projects `forge_pulls` cleanly; if Ref-CAS has no record (`Unknown`), it closes the row as
  `AbortedBeforeCas`.
- **Same-Ref Concurrency**: Concurrent merges against the same base ref contend inside Ref-CAS;
  at most one CAS winner advances the ref while contenders fail closed with `TargetRefMoved`.

## Verification Surface

- Offline contract checks: `python3 -m unittest tests.test_pulls_remote_merge_contracts`
- Stock-Git (`SHA-1`/`SHA-256`) + reference model: `python3 scripts/eval_pulls_remote_merge.py`
- Rust unit & in-process integration suites:
  `cargo test --locked --lib pulls::remote_merge_finalizer` and
  `cargo test --locked --test pulls_remote_merge_finalizer`
- Full E2E (`PG 17` + 3-node mTLS `raft-node` + leader restart + concurrent race):
  `cargo test --locked --test pulls_remote_merge_finalizer -- --ignored --test-threads=1`

## Non-Goals

- Does **not** replace `src/pulls/handlers.rs` HTTP API wiring or legacy `src/pulls/merge.rs`.
- Does **not** perform physical branch deletion or repository GC (#122).
- `scripts/eval_pulls_remote_merge.py` is a stock-Git + Python reference model evaluator and does
  not substitute for the `--ignored` PostgreSQL 17 + 3-node mTLS Raft acceptance suite.
