//! Ref-CAS semantic boundary shared by PostgreSQL and future Ref-CAS drivers.
//!
//! This module deliberately does not provide an HTTP commit route. The
//! PostgreSQL adapter implements durable operation identity, digest replay,
//! cancellation tombstones and terminal-result recording. Ref publication
//! still runs through the existing trusted Pando transaction, which validates
//! live authorization, branch/LFS policy and old-OID CAS in that transaction.
pub mod contract;
pub mod core;
pub mod pg;
pub(crate) mod tx;

pub use contract::{
    BeginReceipt, CancelReceipt, Capabilities, CommitReceipt, IssuerLane, OperationIdentity, OperationLookup,
    OperationRecord, OperationState, RefStoreError, RequestDigest, SequenceReservation, TerminalOutcome,
    TerminalResult,
};
pub use core::{
    CommitMode, CommitRefsReceipt, CommitRefsRequest, CommitRejectCode, CommitRejection, CommitTerminal, CoreGate,
    CoreGateInit, CoreGateVersion, GitObjectFormat, GitOid, HeadUpdate, PgRefStoreCore, RefCommitResult, RefName,
    RefPrecondition, RefTarget, RefUpdate, TerminalKind, VersionCheck,
};
pub use pg::PgRefStore;
