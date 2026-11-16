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

3. **Group-Bound Quorum Attestation & Conservative Barrier (`src/ref_store/core/artifact_hold/group_keyring.rs`, `reconcile_proof.rs`)**
   - **`GroupConsensusVerifier` (`ROOTYARD_REFCAS_GROUP_KEYRING` / `0700`/`0600` strict keyring)**: non-deserializable keyring holding per-group majority voter HMAC-SHA256 keys (`zeroize`), with zero default/ambient keys and no public snapshot-promotion shortcuts.
   - **`VerifiedGroupRetirement` & `VerifiedGroupObservation`**: opaque, non-deserializable proofs minted ONLY after `GroupConsensusVerifier::verify_attested_observation` authenticates canonical `group_id` / `history_incarnation` / `group_epoch` / `authority_epoch` / `raft_term` / `committed_log_index` / `snapshot_sha256` against a majority quorum and validates `RefCasSnapshot::verify_integrity()` + matching `last_applied`.
   - **Conservative Barrier**: always derives `barrier_log_index = committed_log_index` (`snap.body.last_applied.index`) from the quorum-signed snapshot; an optional `min_expected_log_index` floor enforces freshness without ever lowering the barrier.

4. **Multi-Group Retirement & PG Cursor Reconciliation (`src/ref_store/core/artifact_hold/retirement_reconcile.rs`)**
   - `reconcile_shared_hold_retirement_with_pg` (sole public reconciliation entrypoint) reads `ref_cas_projection_cursors` and cross-repo `artifact_holds` in one bounded read-only transaction and delegates to internal `pub(super)` `evaluate_shared_hold_retirement` (which fails closed with `RetirementBlockReason::MissingPgEvidence` whenever `pg_holds` is `None`). Converges to `RetiredToSafeReclaim` ONLY when every referencing group carries a quorum-authenticated retirement proof, all PG cursors are `active` at matching `group_epoch` with `applied_log_index >= barrier_log_index`, and zero unreconciled cross-repo holds exist.

## Verification

- **Deterministic Unit Suites (`bridge_tests.rs`, `reconcile_fault_tests.rs`)**: offline `RefCasStateMachine` tests covering bridge publish/replay/fencing plus snapshot tamper, forged DTO, cross-artifact substitution, and low-hint lagging PG cursor tests.
- **Live PG17 Acceptance Suite (`tests/ref_store_retention_bridge.rs`)**: Migration `141` + `149`, `BlobStore`, `PgArtifactHoldStore`, `RefCasStateMachine`, `replay_page_to_pg`, `reverify_reservation_dto_with_pg`, and lagging PG cursor refusal.
- **Offline Contract Suite (`tests/test_retention_bridge_contracts.py`)** & **GHA Workflow (`.github/workflows/retention-bridge.yml`)**: `CargoFork 1.101.0` + `postgres:17`.
