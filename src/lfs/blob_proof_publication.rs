//! Remote-Blob-only LFS Batch, verified streaming transfer, and pointer publication proof (`Refs #145`).

#[path = "blob_proof_publication/attestation.rs"]
pub mod attestation;
#[path = "blob_proof_publication/authz.rs"]
pub mod authz;
#[path = "blob_proof_publication/hydration_view.rs"]
pub mod hydration_view;
#[path = "blob_proof_publication/locks_store.rs"]
pub mod locks_store;
#[path = "blob_proof_publication/pg_schema.rs"]
pub mod pg_schema;
#[path = "blob_proof_publication/pg_store.rs"]
pub mod pg_store;
#[path = "blob_proof_publication/prod_auth_tx.rs"]
pub mod prod_auth_tx;
#[path = "blob_proof_publication/prod_publication.rs"]
pub mod prod_publication;
#[path = "blob_proof_publication/prod_routes.rs"]
pub mod prod_routes;
#[path = "blob_proof_publication/transfer.rs"]
pub mod transfer;
#[path = "blob_proof_publication/types.rs"]
pub mod types;

#[cfg(test)]
#[path = "blob_proof_publication/unit_tests.rs"]
mod unit_tests;

pub use attestation::{LfsPushAttestationRequest, attest_and_authorize_push};
pub use authz::{
    AuthorizedRepoAccess, LfsBlobRuntimeGate, SubjectTenantAuthority, derive_default_push_operation_id,
    derive_default_upload_operation_id, evaluate_subject_tenant_access, extract_credentials_header,
    extract_stable_operation_id, operation_token_to_uuid, verify_shared_hold_grant,
};
pub use locks_store::{InFlightUploadGuard, valid_lfs_lock_path};
pub use pg_store::{LfsRepoRealm, PgLfsBlobStore, ReconcileUploadsReport, UploadOperationRow, init_lfs_blob_proof_tables};
pub use prod_auth_tx::{ProdCommitAuthCheck, PushCommitAuthCheck, upload_attempt_advisory_keys};
pub use prod_routes::{
    PushAttestationSession, active_blob_gate, prod_validate_and_attest_hook, prod_validate_and_attest_push,
    set_runtime_gate_override, with_push_attestation_session,
};
pub use transfer::{
    ComputeViewHydrationReport, LfsTransferContext, MAX_CONCURRENT_S4_TRANSFERS, PreStreamedScratch,
    acquire_transfer_permit, delete_or_retire_lfs_object, download_lfs_object_from_remote, hydrate_clean_compute_view,
    process_batch_request, resolve_and_verify_remote_blob, upload_lfs_object_to_remote,
    upload_streamed_lfs_object_to_remote, verify_committed_locator_bytes, verify_lfs_object_remote,
};
pub use types::{
    AttestationOutcome, AttestedLfsPointer, CommittedLfsBlobRecord, LfsAccessMode, LfsBlobError, LfsCollaboratorRole,
    LfsPointerAttestation, LfsProofRejectCode, LfsRefUpdateSpec, PointerInspection, PointerResolutionSource,
    SharedLfsHoldGrant, StoredBlobLocatorRef, compute_attestation_digest, compute_pointer_receipt_digest,
    compute_ref_updates_digest, inspect_candidate_lfs_pointer,
};
