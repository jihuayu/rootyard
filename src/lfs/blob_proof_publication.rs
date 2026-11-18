//! Unified OpenDAL Blob LFS Batch, Locks, Transfer, and Replayable Pointer Attestation (`Refs #145`).
//!
//! Eliminates node-local durable ACK assumptions for Git LFS: every Batch (`upload`,
//! `download`, `verify`), object transfer, lock check, clean compute-view hydration, and
//! pre-receive LFS pointer publication decision runs strictly through the standalone
//! OpenDAL [`crate::blob_store::opendal::BlobStore`], permanent [`crate::ref_store::core::artifact_hold::PgArtifactHoldStore`]
//! holds, and [`crate::blob_store::protected::ProtectedUploader`] provider read-back receipts.

#[path = "blob_proof_publication/attestation.rs"]
pub mod attestation;
#[path = "blob_proof_publication/authz.rs"]
pub mod authz;
#[path = "blob_proof_publication/git_smart_http.rs"]
pub mod git_smart_http;
#[path = "blob_proof_publication/http_router.rs"]
pub mod http_router;
#[path = "blob_proof_publication/hydration_view.rs"]
pub mod hydration_view;
#[path = "blob_proof_publication/locks_store.rs"]
pub mod locks_store;
#[path = "blob_proof_publication/pg_schema.rs"]
pub mod pg_schema;
#[path = "blob_proof_publication/pg_store.rs"]
pub mod pg_store;
#[path = "blob_proof_publication/transfer.rs"]
pub mod transfer;
#[path = "blob_proof_publication/types.rs"]
pub mod types;

#[cfg(test)]
#[path = "blob_proof_publication/unit_tests.rs"]
mod unit_tests;

pub use attestation::{LfsPushAttestationRequest, attest_and_authorize_push};
pub use authz::{AuthorizedRepoAccess, LfsBlobRuntimeGate, LfsPrincipal};
pub use http_router::{LfsBlobProofService, lfs_blob_proof_router};
pub use locks_store::{LfsLockRecord, LfsVerifyLocksReport};
pub use pg_store::{LfsRepoRealm, PgLfsBlobStore, ReconcileUploadsReport, init_lfs_blob_proof_tables};
pub use transfer::{
    ComputeViewHydrationReport, LfsTransferContext, delete_or_retire_lfs_object, download_lfs_object_from_remote,
    hydrate_clean_compute_view, process_batch_request, upload_lfs_object_to_remote, verify_lfs_object_remote,
};
pub use types::{
    AttestationOutcome, AttestedLfsPointer, CommittedLfsBlobRecord, LfsAccessMode, LfsBlobError, LfsCollaboratorRole,
    LfsPointerAttestation, LfsProofRejectCode, LfsRefUpdateSpec, PointerInspection, PointerResolutionSource,
    SharedLfsHoldGrant, StoredBlobLocatorRef, compute_attestation_digest, inspect_candidate_lfs_pointer,
};
