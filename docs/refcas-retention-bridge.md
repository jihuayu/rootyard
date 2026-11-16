# Global PG Artifact Hold <-> Ref-CAS Retention Bridge (`#151`)

Status: Delivered alongside `#151` under `src/ref_store/core/artifact_hold/`.

## Design Summary

This bridge connects the global PostgreSQL physical artifact hold ledger
(Migration `141`: `artifact_hold_requests`, `artifact_holds`,
`artifact_hold_consume_receipts`, `artifact_hold_repo_usage`,
`artifact_hold_tenant_usage`) to deterministic Ref-CAS state machines
(`RefCasStateMachine`) and Migration `149` projection cursors
(`ref_cas_projection_cursors`) with strict failure atomicity and fail-closed
multi-group safety.

## Implemented Architecture

1. **Contracts (`src/ref_store/core/artifact_hold/bridge_contract.rs`)**
   - `BridgeBinding`: binds `(tenant_id, repository_id, owner_id, authority_id, authority_generation, authority_epoch, backend_identity, history_incarnation, group_id, group_epoch, issuer_id, lane, sequence, operation_id, operation_digest)` into a canonical `RequestDigest` proof.
   - `GlobalHoldReservation`, `ReservedGlobalHold`, `GroupHoldBinding`, `SharedHoldReference`, `PgHoldRowSummary`, `PgCrossRepoSiblingHold`, `PgArtifactHoldReconciliationView`, and `SharedHoldRetirementStatus` (strictly rejecting unknown JSON fields via `#[serde(deny_unknown_fields)]`).

2. **Reserve-Before-Publish & Deterministic Recovery (`src/ref_store/core/artifact_hold/retention_bridge.rs`)**
   - **Phase 1 (`reserve_global_hold_first`)**: durably reserves PG `artifact_holds` first via `PgArtifactHoldStore::acquire` after checking physical `BlobStore::backend_identity()`, tenant/authority/operation bindings, and generation/epoch fences.
   - **Lost-ACK Recovery (`recover_global_hold_by_operation` / `recover_global_hold_by_request`)**: resolves ambiguous or interrupted PG commits strictly by `(repository_id, operation_id, operation_digest)` / `request_id` without minting duplicate grants or double-charging quotas.
   - **Phase 2 & 3 (`verify_state_machine_gate_for_binding`, `apply_reserved_hold_to_sm`, `publish_pin_and_root_after_hold`)**: pure Ref-CAS helpers performing **zero** PG or Blob I/O; refuse snapshot-pin / retention-root publication if the reserved hold is absent (`MissingDurableHold`), fenced by `Cancel-before-Register` or `cancel_cutoff`, stale in `authority_epoch` / `group_epoch` / `history_incarnation` (`GenerationConflict` / `RealmMismatch`), or past a one-way `Closing` / `Closed` barrier (`ScopeClosingOrClosed`).
   - **Idempotent Replay & Non-Refunding Quotas (`apply_release_root_idempotent`, `apply_retire_hold_batch_idempotent`, `read_sm_quota_counters`)**: snapshot restore + exact command replay never double-charge or refund hold/pin/root quotas in either PG or `RefCasStateMachine`.

3. **Multi-Group Retirement & PG Cursor Reconciliation (`src/ref_store/core/artifact_hold/retirement_reconcile.rs`)**
   - `observe_group_retirement_from_sm`: inspects a Ref-CAS snapshot and seals a `GroupRetirementReceipt` ONLY when `applied_log_index >= retirement_log_index`, `scope_lifecycle` reached `Closing` / `Closed`, zero active retention roots remain, and `RetireHoldBatch` retired every bound hold id.
   - `evaluate_shared_hold_retirement` & `reconcile_shared_hold_retirement_with_pg`: queries `ref_cas_projection_cursors` and PG `artifact_holds` in a single read-only bounded transaction and transitions to `RetiredToSafeReclaim` ONLY when ALL referencing groups emit valid receipts, ALL projection cursors are `active` at matching `group_epoch` with `applied_log_index >= retirement_log_index` (and above `truncation_cutoff`), AND zero unreconciled cross-repo sibling holds share `(backend_identity, sha256)` — including holds surviving `DELETE FROM repositories`. Any unreachable peer, unknown outcome, stale snapshot, lagging/resyncing cursor, open barrier, active root, or unreconciled sibling hold fails closed (`Protected`).

## Verification

- **Deterministic Unit Suite (`src/ref_store/core/artifact_hold/bridge_tests.rs`)**: offline `RefCasStateMachine` tests (zero PG/Blob I/O).
- **Live PostgreSQL 17 Acceptance Suite (`tests/ref_store_retention_bridge.rs`)**: real Migration `141` + `149`, `BlobStore`, `PgRefStoreCore`, `PgRefStore`, `PgArtifactHoldStore`, `RefCasStateMachine`, and `replay_page_to_pg` / `complete_cursor_resync_in_tx`.
- **Offline Structural Contract Suite (`tests/test_retention_bridge_contracts.py`)**: validates line caps, `#[serde(deny_unknown_fields)]`, zero `#[allow(`, zero PG/Blob I/O inside `RefCasStateMachine`, and CI workflow pinning.
- **GitHub Actions Workflow (`.github/workflows/retention-bridge.yml`)**: builds and executes clippy, unit tests, and PG17 integration tests with pinned `CargoFork` (`1.101.0`) and `postgres:17`.
