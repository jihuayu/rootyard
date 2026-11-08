//! Ref-CAS semantic boundary shared by PostgreSQL and future Ref-CAS drivers.
//!
//! This module deliberately does not provide an HTTP commit route. The
//! PostgreSQL adapter implements durable operation identity, digest replay,
//! cancellation tombstones and terminal-result recording. Ref publication
//! still runs through the existing trusted Pando transaction, which validates
//! live authorization, branch/LFS policy and old-OID CAS in that transaction.
//!
//! A2 additionally exposes an internal, metadata-only snapshot/pin contract
//! over the unserved core gate. It is not a Git read snapshot, and existing
//! long read leases remain the read protection for Git objects.
pub mod contract;
pub mod core;
pub mod metadata;
pub mod pg;
pub(crate) mod tx;

pub use core::artifact_hold;

pub use contract::{
    BeginReceipt, CancelReceipt, Capabilities, CommitReceipt, IssuerLane, OperationIdentity, OperationLookup,
    OperationRecord, OperationState, RefStoreError, RequestDigest, SequenceReservation, TerminalOutcome,
    TerminalResult,
};
pub use core::{
    CommitMode, CommitRefsReceipt, CommitRefsRequest, CommitRejectCode, CommitRejection, CommitTerminal, CoreGate,
    CoreGateInit, CoreGateVersion, CreateMetadataSnapshotOutcome, CreateMetadataSnapshotRequest, GitObjectFormat,
    GitOid, HeadUpdate, MAX_PIN_LEASE_SECONDS, MAX_RECEIPT_BODY_BYTES, MAX_SNAPSHOT_LOGICAL_BYTES, MAX_SNAPSHOT_PAGE,
    MAX_SNAPSHOT_REFS, MetadataPinOutcome, MetadataPinReceipt, MetadataReceipt, MetadataReceiptLookup,
    MetadataSnapshotCursor, MetadataSnapshotPage, MetadataSnapshotReceipt, MetadataSnapshotRef, MetadataSnapshotScope,
    PackMembershipDescriptor, PgRefStoreCore, PinReleaseReason, REPO_MAX_LOGICAL_BYTES, REPO_MAX_RECEIPTS,
    REPO_MAX_SNAPSHOT_REFS, REPO_MAX_SNAPSHOTS, ReadMetadataSnapshotPageRequest, RefCommitResult, RefName,
    RefPrecondition, RefPrefix, RefTarget, RefUpdate, ReleaseMetadataPinRequest, RenewMetadataPinRequest,
    TENANT_MAX_LOGICAL_BYTES, TENANT_MAX_RECEIPTS, TENANT_MAX_SNAPSHOT_REFS, TENANT_MAX_SNAPSHOTS, TerminalKind,
    VersionCheck,
};
pub use metadata::{MetadataMutationAction, MetadataPinPurpose, MetadataQuotaResource, MetadataQuotaScope};
pub use pg::PgRefStore;
