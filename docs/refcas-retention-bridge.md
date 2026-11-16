# Global PG Artifact Hold <-> Ref-CAS Retention Bridge (`#151`)

Status: Delivered alongside `#151` under `src/ref_store/core/artifact_hold/`.

## Design Summary

This bridge connects the global PostgreSQL physical artifact hold ledger
(Migration `141`: `artifact_hold_requests`, `artifact_holds`,
`artifact_hold_consume_receipts`, `artifact_hold_repo_usage`,
`artifact_hold_tenant_usage`) to deterministic Ref-CAS state machines
(`RefCasStateMachine`) and Migration `149` projection cursors
(`ref_cas_projection_cursors`) with strict failure atomicity, opaque capability
boundaries, and fail-closed multi-group safety.

## Implemented Architecture

1. **Contracts & Untrusted DTOs (`src/ref_store/core/artifact_hold/bridge_contract.rs`)**
   - `BridgeBinding`: binds `(tenant_id, repository_id, owner_id, authority_id, authority_generation, authority_epoch, backend_identity, history_incarnation, group_id, group_epoch, issuer_id, lane, sequence, operation_id, operation_digest)` into a canonical `RequestDigest` proof.
   - `GlobalHoldReservationDto` & `BridgeRootRegistrationPlan` carry `#[serde(deny_unknown_fields)]` and are separated from opaque verified capabilities.

2. **Reserve-Before-Publish & Opaque PG Capabilities (`src/ref_store/core/artifact_hold/retention_bridge.rs`)**
   - **`VerifiedGlobalHoldReservation`**: opaque, non-deserializable capability with private fields; minted only after PG `artifact_holds` commits (`reserve_global_hold_first`), recovery verifies live PG `artifact_holds` rows (`recover_global_hold_by_request` / `recover_global_hold_by_operation`), or an untrusted DTO passes PG re-verification (`reverify_reservation_dto_with_pg`).
   - **Phase 2 & 3 (`verify_state_machine_gate_for_binding`, `apply_reserved_hold_to_sm`, `publish_pin_and_root_after_hold`)**: pure Ref-CAS helpers requiring `&VerifiedGlobalHoldReservation` with **zero** PG or Blob I/O; enforce `MissingDurableHold`, `Cancel-before-Register`, `cancel_cutoff`, anti-ABA generation/epoch fences, one-way `Closing` barriers, and non-refunding quotas.

3. **Unforgeable Consensus Proofs & Conservative Barrier (`src/ref_store/core/artifact_hold/reconcile_proof.rs`)**
   - **`VerifiedGroupRetirement` & `VerifiedGroupObservation`**: opaque, non-deserializable proofs minted strictly after verifying `RefCasSnapshot::verify_integrity()` (`observe_group_retirement_from_sm`, `observe_group_retirement_from_snapshot`, `observe_group_retirement_from_snapshot_bytes`, `verify_group_observation_with_snapshot`).
   - **Conservative Barrier**: always derives `barrier_log_index = snap.body.last_applied.index` directly from the verified consensus snapshot (an optional `min_expected_log_index` floor can enforce freshness but can never lower the barrier below `last_applied.index`).
   - Diagnostic DTOs (`GroupRetirementReceiptDto`, `GroupRetirementObservationDto`) are strictly separated and refused unless verified against an authoritative `RefCasSnapshot`.

4. **Multi-Group Retirement & PG Cursor Reconciliation (`src/ref_store/core/artifact_hold/retirement_reconcile.rs`)**
   - `evaluate_shared_hold_retirement` & `reconcile_shared_hold_retirement_with_pg`: accept ONLY `&[VerifiedGroupObservation]`, verify group/artifact/backend binding, read `ref_cas_projection_cursors` and cross-repo `artifact_holds` in a single bounded read-only transaction, and converge to `RetiredToSafeReclaim` ONLY when all referencing groups emit verified retirement proofs, all PG cursors are `active` at matching `group_epoch` with `applied_log_index >= barrier_log_index`, and zero unreconciled cross-repo holds exist.

## Verification

- **Deterministic Unit Suites (`bridge_tests.rs`, `reconcile_fault_tests.rs`)**: offline `RefCasStateMachine` tests covering bridge publish/replay/fencing plus snapshot tamper, forged DTO, cross-artifact substitution, and low-hint lagging PG cursor tests.
- **Live PG17 Acceptance Suite (`tests/ref_store_retention_bridge.rs`)**: Migration `141` + `149`, `BlobStore`, `PgArtifactHoldStore`, `RefCasStateMachine`, `replay_page_to_pg`, `reverify_reservation_dto_with_pg`, and lagging PG cursor refusal.
- **Offline Contract Suite (`tests/test_retention_bridge_contracts.py`)** & **GHA Workflow (`.github/workflows/retention-bridge.yml`)**: `CargoFork 1.101.0` + `postgres:17`.
