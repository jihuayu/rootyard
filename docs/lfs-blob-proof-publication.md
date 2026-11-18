# Remote-Blob LFS Batch, Verified Transfer & Pointer Publication Attestation (`Refs #145`)

> **Issue Policy**: `Refs #145` — Issue `#145` (`[State/S4] LFS Batch、传输与发布证明统一走 Blob 并用官方客户端验收`) remains **`OPEN`** while sibling LFS route consolidation PRs (`#259`, `#278`, `#300`) are integrated onto `main`.

This document specifies the standalone remote-Blob LFS Batch, Basic Transfer, Locks, Clean Compute-View Hydration, and Replayable Pointer Publication Attestation slice delivered under [`src/lfs/blob_proof_publication.rs`](../src/lfs/blob_proof_publication.rs).

---

## 1. Non-Overlapping Module Layout

To preserve `0` file overlap with concurrent open PRs touching `src/lfs/{handlers,storage,upload,hydration}.rs` and `src/namespace_service/push_causal_stream/lfs_verify.rs`, the S4 implementation is isolated under:

- [`src/lfs.rs`](../src/lfs.rs) — exports `pub mod blob_proof_publication;` only.
- [`src/lfs/blob_proof_publication.rs`](../src/lfs/blob_proof_publication.rs) — `< 100`-line public facade.
- [`types.rs`](../src/lfs/blob_proof_publication/types.rs) — `LfsProofRejectCode`, `LfsBlobError`, `LfsPointerAttestation`, `SharedLfsHoldGrant`, SHA-256 receipt/attestation digests, and strict Git LFS v1 pointer grammar inspection (`NonPointer` / `Valid` / `Malformed`).
- [`authz.rs`](../src/lfs/blob_proof_publication/authz.rs) — `LfsBlobRuntimeGate` (fail-closed `503` `remote_blob_unconfigured` / `remote_blob_unreachable`), `evaluate_repo_role_access` (zero `caller == tenant` assumption), and `verify_shared_hold_grant`.
- [`pg_schema.rs`](../src/lfs/blob_proof_publication/pg_schema.rs) & [`pg_store.rs`](../src/lfs/blob_proof_publication/pg_store.rs) — PostgreSQL 17 `synchronous_commit = 'on'` durability, immutability trigger `lfs_blob_objects_immutable_trig`, `PgArtifactHoldStore` reservation,upload-attempt crash reconciliation, and cross-owner shared holds.
- [`transfer.rs`](../src/lfs/blob_proof_publication/transfer.rs) & [`hydration_view.rs`](../src/lfs/blob_proof_publication/hydration_view.rs) — OpenDAL `ProtectedUploader` read-back verified upload (ephemeral `0600` scratch file unlinked on drop), remote-byte-verified Batch `upload`/`download`/`verify`, `DeleteDisabledByPolicy` guard, and `hydrate_clean_compute_view`.
- [`locks_store.rs`](../src/lfs/blob_proof_publication/locks_store.rs) — Git LFS v1 locks (`create`, `list`, `verify`, `unlock`) and pre-receive locked-path diff/log inspection (`LockedPathConflict`).
- [`attestation.rs`](../src/lfs/blob_proof_publication/attestation.rs) — `attest_and_authorize_push` durable decision proof (`Issued` vs. `Replayed`, `AttestationEquivocation` refusal).
- [`http_router.rs`](../src/lfs/blob_proof_publication/http_router.rs) & [`git_smart_http.rs`](../src/lfs/blob_proof_publication/git_smart_http.rs) — Axum v1 LFS + `git http-backend` Smart-HTTP server (`SHA-1` & `SHA-256` `Git-Protocol` forwarding, bounded gzip decode, `Connection: close`, and internal `pre-receive` hook callback).

---

## 2. Core S4 Invariants & Named Failure Semantics

1. **Zero Local-Disk Source of Truth**:
   - Missing or unreachable remote `BlobStore` fails closed (`503 Service Unavailable`: `remote_blob_unconfigured` / `remote_blob_unreachable`) across startup and every LFS Batch, transfer, lock, and Git Smart-HTTP endpoint.
   - Batch `upload` emits an idempotent skip-upload ACK (`actions: None`) **only** after `BlobStore::verify_receipt` proves live byte length, SHA-256 metadata, and matching `BackendIdentity` on the remote provider. Removing the remote S3 object immediately forces a fresh upload action even if PostgreSQL metadata exists.
   - Ephemeral upload/download scratch files (`0600`) live strictly for the duration of a single streaming call (`EphemeralScratchGuard`) and leave `0` files on local disk; server restart with an empty scratch directory preserves 100% of committed LFS objects and aborts orphaned `in_flight` attempts (`reconcile_in_flight_uploads`).
2. **Sealed `ArtifactHold` + `ProtectedUploader` Publication**:
   - Every upload reserves a permanent `ArtifactHold` (`ArtifactHoldScope::LfsObject`) via `PgRefStore` + `PgArtifactHoldStore` and streams via `ProtectedUploader::consume_and_upload`, verifying full provider read-back SHA-256 and byte length before minting `BlobReceipt`.
   - Concurrent identical-OID uploads write to distinct attempt-scoped keys while PostgreSQL `lfs_blob_objects` (`ON CONFLICT DO NOTHING` + `lfs_blob_objects_immutable_trig`) preserves the first committed `(locator, hold_id)` monotonically; corrupt or wrong-size retries (`size_or_digest_mismatch`) abort their attempt without deleting or regressing any committed remote blob.
   - Physical deletion through `delete_or_retire_lfs_object(..., allow_logical_retire = false)` calls `BlobStore::delete` and fails closed with `delete_disabled_by_policy` (`BlobDeletePolicy::Disabled`); logical retirement (`allow_logical_retire = true`) marks `retired = TRUE` without deleting remote bytes (physical GC belongs to `#122`).
3. **Replayable `LfsPointerAttestation` & Cross-Owner Authorization**:
   - During the Git `pre-receive` decision phase, `attest_and_authorize_push` inspects touched paths against active locks (`locked_path_conflict`) and inspects all newly reachable candidate Git blobs (`<= 1024` B), rejecting `malformed_lfs_pointer`, `missing_remote_blob`, `size_or_digest_mismatch`, `foreign_backend_mismatch`, `unauthorized_collaborator`, and `unauthorized_shared_hold`.
   - Authorization evaluates explicit repository roles (`Owner`, `Admin`, `Write`, `Read`) without assuming `caller == tenant`, and supports cross-owner fork deduplication exclusively through active `SharedLfsHoldGrant` bindings (`source_hold_id == source_blob.hold_id`). Revoking a `SharedLfsHoldGrant` immediately blocks subsequent cross-owner pushes, replays, and Batch downloads.
   - Replaying the same `(repository_id, operation_id)` with identical `(actor_id, ref_updates_digest)` re-verifies live remote `BlobReceipt` + active hold authorization and deterministically returns `AttestationOutcome::Replayed`; differing actor or ref updates fail closed with `attestation_equivocation`.

---

## 3. Reproducible Verification Gates

- **Authoritative Rust + PostgreSQL 17 + LoopbackS3 + Official `git-lfs` 3.6.1 E2E Suite**:
  [`tests/lfs_blob_proof_publication.rs`](../tests/lfs_blob_proof_publication.rs) runs real `git` (`SHA-1` & `SHA-256`) + official `git-lfs` (`push`, `clone`, `lfs fetch`, `lfs pull`, `lfs lock`, `lfs locks`, `lfs locks --verify`, `lfs unlock`, locked `git rm` refusal, unlocked `git rm` + branch `--delete`, concurrent upload races, named pointer rejections, crash/restart recovery with wiped local disk, `hydrate_clean_compute_view`, and cross-owner `SharedLfsHoldGrant` grant/revocation).
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
