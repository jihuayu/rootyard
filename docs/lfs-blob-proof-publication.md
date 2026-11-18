# Remote-Blob LFS Batch, Verified Transfer & Pointer Publication Attestation (`Refs #145`)

> **Issue Policy**: `Refs #145` — Issue `#145` (`[State/S4] LFS Batch、传输与发布证明统一走 Blob 并用官方客户端验收`) remains **`OPEN`** while sibling push-stream integration (`#300`) completes on `main`.

This document specifies the S4 remote-Blob Git LFS Batch, Basic Transfer, Locks, Clean Compute-View Hydration, and Replayable Pointer Publication Attestation slice wired directly into Rootyard's production [`src/lfs.rs`](../src/lfs.rs) router (`crate::lfs::routes()`) and [`src/lfs/publication.rs`](../src/lfs/publication.rs) ref-publication validator.

---

## 1. Production Router & Module Layout

- [`src/lfs.rs`](../src/lfs.rs), [`src/lfs/routes.rs`](../src/lfs/routes.rs), [`src/lfs/handlers.rs`](../src/lfs/handlers.rs), [`src/lfs/upload.rs`](../src/lfs/upload.rs), [`src/lfs/locks.rs`](../src/lfs/locks.rs), and [`src/lfs/publication.rs`](../src/lfs/publication.rs) — production `Router<Arc<AppState>>` and `validate_new_refs_with_client` hooks delegating to [`prod_routes.rs`](../src/lfs/blob_proof_publication/prod_routes.rs) whenever S4 remote-Blob mode (`active_blob_gate()`) is active.
- [`src/lfs/blob_proof_publication.rs`](../src/lfs/blob_proof_publication.rs) — `< 100`-line public facade.
- [`types.rs`](../src/lfs/blob_proof_publication/types.rs) — `LfsProofRejectCode`, `LfsBlobError`, `LfsCollaboratorRole` (5-level RBAC), `LfsAccessMode` (`OwnerTenant`, `OrganizationMember`, `Collaborator`), `LfsPointerAttestation`, `SharedLfsHoldGrant`, SHA-256 receipt/attestation digests, and strict Git LFS v1 pointer grammar inspection (`NonPointer` / `Valid` / `Malformed`).
- [`authz.rs`](../src/lfs/blob_proof_publication/authz.rs) — `LfsBlobRuntimeGate` (`503` `remote_blob_unconfigured` / `remote_blob_unreachable`), `SubjectTenantAuthority` + `evaluate_subject_tenant_access` (relational authority without raw UUID comparison), `extract_stable_operation_id` (`X-Rootyard-Operation-Id` / `Idempotency-Key`), and `verify_shared_hold_grant`.
- [`pg_schema.rs`](../src/lfs/blob_proof_publication/pg_schema.rs) & [`pg_store.rs`](../src/lfs/blob_proof_publication/pg_store.rs) — PostgreSQL 17 `synchronous_commit = 'on'` durability, `lfs_blob_upload_operations` (`PRIMARY KEY (repository_id, operation_id)`), `lfs_blob_objects_immutable_trig` (permitting locator replacement only under verified-missing repair guard or logical retirement), `ensure_realm_for_repository`, and `resolve_authoritative_repo_access` querying `repositories JOIN namespaces`, `users`, `organizations`, `organization_memberships`, `organization_teams`, `repository_collaborators`, `repository_teams`, and `repository_transfers` under `FOR SHARE`.
- [`transfer.rs`](../src/lfs/blob_proof_publication/transfer.rs) & [`hydration_view.rs`](../src/lfs/blob_proof_publication/hydration_view.rs) — OpenDAL `ProtectedUploader` read-back verified upload (ephemeral `0600` scratch file unlinked on drop, leaving `0` files in `data_dir/lfs`), `verify_committed_locator_bytes` verifying BOTH `BlobStore::verify_receipt` AND streamed SHA-256 + byte length on the **final persisted `BlobLocator`** before ACK, missing-remote-locator atomic repair, `DeleteDisabledByPolicy` guard, and `hydrate_clean_compute_view`.
- [`locks_store.rs`](../src/lfs/blob_proof_publication/locks_store.rs) & [`attestation.rs`](../src/lfs/blob_proof_publication/attestation.rs) — queries production `lfs_locks JOIN users` (`LockedPathConflict`) and issues/replays durable `LfsPointerAttestation` (`Issued` vs. `Replayed`, `AttestationEquivocation` refusal).
- [`prod_routes.rs`](../src/lfs/blob_proof_publication/prod_routes.rs) & [`prod_publication.rs`](../src/lfs/blob_proof_publication/prod_publication.rs) — bridges `Arc<AppState>` (`auth::authenticate`, `resolve_authoritative_repo_access`, `auth::authorize_repo_with_role`, `reauthorize_repo`), automatic default `operation_id` propagation (`ensure_default_upload_operation` + `derive_default_push_operation_id`) for unmodified stock `git-lfs` / `git push` clients, and `with_push_attestation_session` / `prod_validate_and_attest_push`.

---

## 2. Core S4 Invariants & Named Failure Semantics

1. **Final Persisted `BlobLocator` Verification Before ACK & Zero Local LFS Disk**:
   - Missing or unreachable remote `BlobStore` fails closed (`503 Service Unavailable`: `remote_blob_unconfigured` / `remote_blob_unreachable`) across startup and every production `crate::lfs::routes()` and ref-publication endpoint.
   - Batch `upload` skip-ACK, same-`operation_id` upload retry replay, and post-commit concurrent upload/repair winner resolution **all** call `verify_committed_locator_bytes` (provider `verify_receipt` + streamed `get_to_file` SHA-256 & byte-length check) on the **final persisted `BlobLocator`** in `lfs_blob_objects` before issuing an ACK.
   - If the previously committed remote `BlobLocator` is missing on the remote provider, Batch refuses fast-path ACK and a subsequent upload atomically repairs `lfs_blob_objects` to the newly verified `BlobLocator`; if the persisted remote `BlobLocator` is corrupted, verification fails closed (`422 size_or_digest_mismatch`) without ACKing.
2. **Authoritative Relational Subject/Tenant/Organization/Collaborator Authz**:
   - `resolve_authoritative_repo_access` verifies personal-namespace ownership (`namespaces(kind='user') JOIN users`), organization roles (`organizations` + `organization_memberships` + `organization_teams`), and repository collaborator roles (`repository_collaborators` + `repository_teams`) under `FOR SHARE`, never comparing raw `actor_id == owner_tenant_id` UUIDs.
   - Cross-owner fork deduplication requires an active `SharedLfsHoldGrant` bound to `source_hold_id == source_blob.hold_id`; revoking the grant immediately blocks subsequent cross-owner pushes, replays, and Batch downloads (`unauthorized_shared_hold`).
3. **Stable Same-Operation Retry Identity & No-Delete Policy**:
   - Retrying an upload (`PUT .../info/lfs/objects/{oid}/{size}`) or push (`git push` -> `publication::validate_new_refs_with_client`) under an identical `X-Rootyard-Operation-Id` / `Idempotency-Key` deterministically replays the committed upload receipt or `LfsPointerAttestation` after verifying live remote `BlobLocator` integrity; reusing an `operation_id` for conflicting inputs fails closed with `409 attestation_equivocation`.
   - Direct HTTP `DELETE .../info/lfs/objects/{oid}` and `delete_or_retire_lfs_object(..., false)` fail closed with `405 delete_disabled_by_policy` (`BlobDeletePolicy::Disabled`); physical reclamation belongs exclusively to `#122`.

---

## 3. Reproducible Verification Gates

- **Authoritative Rust + PostgreSQL 17 + LoopbackS3 + Official `git-lfs` 3.6.1 E2E Suite**:
  [`tests/lfs_blob_proof_publication.rs`](../tests/lfs_blob_proof_publication.rs) drives official `git` (`SHA-1` & `SHA-256`) + official `git-lfs` 3.6.1 through production `rootyard::lfs::routes()` + `rootyard::lfs::publication::validate_new_refs_with_client` across personal (`alice/engine`), organization (`acme/org-engine`), collaborator (`bob`/`carol`), and cross-owner fork (`dave/fork-engine`) repositories.
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
