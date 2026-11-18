# Remote-Blob LFS Batch, Verified Streaming Transfer & Pointer Publication Attestation (`Refs #145`)

> **Issue Policy**: `Refs #145` — Issue `#145` (`[State/S4] LFS Batch、传输与发布证明统一走 Blob 并用官方客户端验收`) remains **`OPEN`** while sibling push-stream integration (`#300`) completes on `main`.

This document specifies the S4 remote-Blob Git LFS Batch, Basic Streaming Transfer, Locks, Clean Compute-View Hydration, and Replayable Pointer Publication Attestation slice wired directly into Rootyard's production [`src/lfs.rs`](../src/lfs.rs) router (`crate::lfs::routes()`), [`src/lfs/publication.rs`](../src/lfs/publication.rs) ref-publication validator, and [`src/browse/policy.rs`](../src/browse/policy.rs) native `validate_hook` pre-receive gate.

---

## 1. Production Router, Hook & Module Layout

- [`src/lfs.rs`](../src/lfs.rs), [`src/lfs/routes.rs`](../src/lfs/routes.rs), [`src/lfs/handlers.rs`](../src/lfs/handlers.rs), [`src/lfs/upload.rs`](../src/lfs/upload.rs), [`src/lfs/locks.rs`](../src/lfs/locks.rs), [`src/lfs/publication.rs`](../src/lfs/publication.rs), and [`src/browse/policy.rs`](../src/browse/policy.rs) — production `Router<Arc<AppState>>` and `validate_hook` -> `validate_new_refs_for_hook` -> `prod_validate_and_attest_hook` pre-receive gate delegating to S4 remote-Blob mode (`ROOTYARD_LFS_BLOB_ONLY` / `active_blob_gate()`).
- [`src/lfs/blob_proof_publication.rs`](../src/lfs/blob_proof_publication.rs) — `< 100`-line public facade.
- [`types.rs`](../src/lfs/blob_proof_publication/types.rs) — `LfsProofRejectCode` (`DeleteDisabledByPolicy -> 405 Method Not Allowed`), `LfsBlobError`, `LfsCollaboratorRole` (5-level RBAC), `LfsAccessMode`, `LfsPointerAttestation`, `SharedLfsHoldGrant`, SHA-256 receipt/attestation digests, and Git LFS v1 pointer grammar inspection (`NonPointer` / `Valid` / `Malformed`).
- [`authz.rs`](../src/lfs/blob_proof_publication/authz.rs) — `LfsBlobRuntimeGate` (`503` `remote_blob_unconfigured` / `remote_blob_unreachable`), `SubjectTenantAuthority` + `evaluate_subject_tenant_access`, `extract_stable_operation_id`, tenant-bound `derive_default_upload_operation_id` / `derive_default_push_operation_id`, and `verify_shared_hold_grant`.
- [`pg_schema.rs`](../src/lfs/blob_proof_publication/pg_schema.rs) & [`pg_store.rs`](../src/lfs/blob_proof_publication/pg_store.rs) — PostgreSQL 17 `synchronous_commit = 'on'` durability, `lfs_blob_upload_operations` (`PRIMARY KEY (repository_id, operation_id)`), session-leased `lfs_blob_upload_attempts` (`operation_id`, `lease_until`), `lfs_blob_objects_immutable_trig`, live ownership-transfer-aware `ensure_realm_for_repository`, and `resolve_authoritative_repo_access` querying `repositories JOIN namespaces`, `users`, `organizations`, `organization_memberships`, `organization_teams`, `repository_collaborators`, `repository_teams`, and `repository_transfers` under `FOR SHARE`.
- [`prod_auth_tx.rs`](../src/lfs/blob_proof_publication/prod_auth_tx.rs) — in-transaction write authority (`verify_commit_write_authority_in_tx`), push attestation authority (`verify_push_attestation_authority_in_tx`), publication-window verification, and the deterministic `upload_attempt_advisory_keys` derived from each `attempt_id`.
- [`transfer.rs`](../src/lfs/blob_proof_publication/transfer.rs) & [`hydration_view.rs`](../src/lfs/blob_proof_publication/hydration_view.rs) — `MAX_CONCURRENT_S4_TRANSFERS` `Semaphore` (`acquire_transfer_permit`), OpenDAL `ProtectedUploader` read-back verified upload from chunk-streamed `0600` scratch files (`0` files in `data_dir/lfs`), chunk-streamed `verify_committed_locator_bytes` (`64 KiB` SHA-256 + byte length, zero full-object `Vec<u8>`), `open_verified_remote_download_file`, `DeleteDisabledByPolicy` guard, and `hydrate_clean_compute_view`.
- [`locks_store.rs`](../src/lfs/blob_proof_publication/locks_store.rs) & [`attestation.rs`](../src/lfs/blob_proof_publication/attestation.rs) — queries production `lfs_locks JOIN users` (`LockedPathConflict`), manages cross-owner `SharedLfsHoldGrant`, per-attempt PostgreSQL session advisory locks with a `250 ms` heartbeat and explicit `pg_advisory_unlock`, active-lease-aware restart/cancellation reconciliation (`reconcile_stale_pending_uploads`, `abort_upload_on_cancel`, `InFlightUploadGuard`), and issues/replays/refreshes durable `LfsPointerAttestation` (`refresh_repaired_attestation` after missing-locator repair, `AttestationEquivocation` refusal on conflicting inputs or stale pre-transfer tenants).
- [`prod_routes.rs`](../src/lfs/blob_proof_publication/prod_routes.rs) & [`prod_publication.rs`](../src/lfs/blob_proof_publication/prod_publication.rs) — authorization **before** any realm/`pending` mutation (`auth_and_prepare_prod` STEP 1 transaction, then realm ensure/reconcile), chunk-streamed `prod_upload` (`Body::into_data_stream` + `max_request_bytes` + `InFlightUploadGuard`), and `prod_download` (`Body::from_stream` `64 KiB` chunks + RAII scratch unlink & semaphore permit), plus `prod_validate_and_attest_hook` binding trusted admitted `journal::Operation`.

---

## 2. Core S4 Invariants & Named Failure Semantics

1. **Final Persisted `BlobLocator` Streaming Verification Before ACK & Bounded Concurrency**:
   - Missing or unreachable remote `BlobStore` fails closed (`503 Service Unavailable`: `remote_blob_unconfigured` / `remote_blob_unreachable`) across startup and every production `crate::lfs::routes()` and `browse::policy::validate_hook` endpoint.
   - `prod_upload` streams request chunks directly to an ephemeral `0600` scratch file while enforcing `max_request_bytes` (`413 Payload Too Large`) and computing SHA-256 incrementally; `prod_download` streams verified bytes via `Body::from_stream` (`64 KiB` chunks) under `MAX_CONCURRENT_S4_TRANSFERS`.
   - Batch `upload` skip-ACK, same-`operation_id` upload retry replay, and post-commit concurrent upload/repair winner resolution **all** call `verify_committed_locator_bytes` (provider `verify_receipt` + chunk-streamed `get_to_file` SHA-256 & byte-length check) on the **final persisted `BlobLocator`** in `lfs_blob_objects` before issuing an ACK.
2. **Authoritative Relational Authz & Ownership-Transfer Re-Validation**:
   - `ensure_realm_for_repository`, `begin_or_load_upload_operation`, `prod_verify`, `lfs_pointer_attestations`, and `hydrate_clean_compute_view` re-validate the live `repositories.owner_id` (`tenant_id`) on every request, rejecting stale pre-transfer tenant operations/attestations (`409 attestation_equivocation`) and isolating pre-transfer tenant objects unless an active `SharedLfsHoldGrant` exists.
3. **Stable Same-Operation Retry Identity, Canonical Repair Refresh & No-Delete Policy**:
   - Native receive hooks (`browse::policy::validate_hook` -> `validate_new_refs_for_hook`) bind the admitted `journal::Operation` (`actor_id`, `actor_name`, `idempotency`), replaying identical `LfsPointerAttestation` receipts on retry, refreshing `lfs_pointer_attestations` after canonical missing-locator repair, and rejecting equivocation (`409 attestation_equivocation`).
   - Direct HTTP `DELETE .../info/lfs/objects/{oid}[/{size}]` and `delete_or_retire_lfs_object(..., false)` fail closed with `405 delete_disabled_by_policy` (`BlobDeletePolicy::Disabled`); physical reclamation belongs exclusively to `#122`.
4. **Post-Auth `pending` Isolation & Active Upload Leases**:
   - Authorization runs **before** any realm or `pending` mutation: `auth_and_prepare_prod` verifies token/read-only/repository/RBAC in STEP 1, then `ensure_realm_for_repository` / `reconcile_stale_pending_uploads` run only in STEP 2. Unauthorized Batch/PUT requests create no `lfs_blob_repo_realms` row and cannot touch pre-existing `pending` rows.
   - Every streamed upload acquires a PostgreSQL **session** advisory lock keyed by its `attempt_id`, stamps `lease_until`, and heartbeats both the attempt lease and operation `updated_at` every `250 ms`; the keeper always issues an explicit `pg_advisory_unlock` before returning the connection. Reconciliation reclaims an attempt only when its advisory lock is free and the configured age/lease policy permits (or the lease expired), so a live sibling instance's upload is never stolen while a crashed instance's rows are aborted.
5. **Single Commit Boundary for Live Auth + Durable Publication**:
   - `record_committed_blob_with_auth` re-verifies the live publication window (token lock/re-read, repository generation, effective role, scopes) and writes `lfs_blob_objects`, the `lfs_blob_upload_operations` state, and `lfs_objects` in the **same** `synchronous_commit = 'on'` transaction. Mid-upload write-role revocation fails closed as `403 unauthorized_collaborator`, and token revocation as `401 unauthenticated`, leaving zero durable object rows and no `pending` attempt/operation.
6. **Multi-Instance Restart & Revocation Acceptance**:
   - [`multi_instance_auth_boundary.rs`](../tests/lfs_blob_proof_support/multi_instance_auth_boundary.rs) runs two production server instances over one migrated schema: it proves unauthorized requests leave stale `pending` rows and realm creation untouched, a crashed instance's session-locked rows are reclaimed by the restarted instance while the live instance's gated `65,536`-byte upload stays `pending` and later commits/downloads byte-exactly, the crashed operation is retryable, and mid-stream role/token revocation publishes nothing.
7. **Cancellation Cleanup & Retryable Operations**:
   - `prod_upload` wraps every in-flight stream in `InFlightUploadGuard`; abrupt TCP/client disconnects (`Drop`) and explicit stream/size/upload errors (`abort_now`) unlink the ephemeral scratch file and transition the pending rows in `lfs_blob_upload_attempts` / `lfs_blob_upload_operations` to `'aborted_cancelled'`.
   - A previously `'aborted_cancelled'` / `'aborted_failed'` upload `operation_id` is retryable with identical `(tenant_id, actor_id, oid_sha256, size_bytes)` via `'aborted_cancelled' | 'aborted_failed' -> 'pending'` re-arming inside `begin_or_load_upload_operation`; `'committed'` stays immutable.

---

## 3. Reproducible Verification Gates

- **Authoritative Rust + PostgreSQL 17 + LoopbackS3 + Official `git-lfs` 3.6.1 E2E Suite**:
  [`tests/lfs_blob_proof_publication.rs`](../tests/lfs_blob_proof_publication.rs) drives official `git` (`SHA-1` & `SHA-256`) + official `git-lfs` 3.6.1 through production `rootyard::lfs::routes()` + `rootyard::browse::policy::validate_hook` across personal (`alice/engine`), organization (`acme/org-engine`), ownership-transferred (`alice/xfer-repo` -> `acme/xfer-repo`), collaborator (`bob`/`carol`), and cross-owner fork (`dave/fork-engine`) repositories.
- **Multi-Instance Lease, Restart & Mid-Stream Revocation Coverage**:
  [`tests/lfs_blob_proof_support/multi_instance_auth_boundary.rs`](../tests/lfs_blob_proof_support/multi_instance_auth_boundary.rs) is driven from the same `--ignored` suite: it checks post-auth `pending` isolation for unauthorized actors, session advisory lock + `lease_until` heartbeat semantics, crashed-instance reconciliation versus a live sibling instance, retry of the crashed `operation_id`, and `403`/`401` fail-closed behavior with zero durable publication on mid-upload role/token revocation.
- **Stock-Git Reference Evaluator (`python_reference_model_with_stock_git`)**:
  [`scripts/eval_lfs_blob_proof.py`](../scripts/eval_lfs_blob_proof.py) exercises `SHA-1`/`SHA-256` stock `git` pointer inspection and validates the compiled test binary receipt via `scripts/native_build_receipt.py::validate_receipt` (`covers_rust_pg17_git_lfs_acceptance = false`).

```bash
cargo fmt --all -- --check
python3 scripts/check_design_docs.py
python3 -m unittest tests/test_ci_workflow_triggers.py tests/test_ci_cargo_fork_workflows.py tests/test_lfs_blob_proof_contracts.py
cargo clippy --locked --no-default-features --lib --test lfs_blob_proof_publication -- -D warnings
RUSTFLAGS="-D warnings" cargo test --locked --no-default-features --lib lfs::blob_proof_publication
RUSTFLAGS="-D warnings" cargo test --locked --no-default-features --test lfs_blob_proof_publication
RUSTFLAGS="-D warnings" cargo test --locked --no-default-features --test lfs_blob_proof_publication -- --ignored --test-threads=1
python3 scripts/eval_lfs_blob_proof.py --formats sha1,sha256
```
