//! Ref-CAS semantic boundary shared by PostgreSQL and future Ref-CAS drivers.
//!
//! This module deliberately does not provide an HTTP commit route. The
//! PostgreSQL adapter implements durable operation identity, digest replay,
//! cancellation tombstones and terminal-result recording. Ref publication
//! still runs through the existing trusted Pando transaction, which validates
//! live authorization, branch/LFS policy and old-OID CAS in that transaction.
pub mod contract;
pub mod pg;

pub use contract::{
    BeginReceipt, CancelReceipt, Capabilities, CommitReceipt, IssuerLane, OperationIdentity, OperationLookup,
    OperationRecord, OperationState, RefStoreError, RequestDigest, SequenceReservation, TerminalOutcome,
    TerminalResult,
};
pub use pg::PgRefStore;
