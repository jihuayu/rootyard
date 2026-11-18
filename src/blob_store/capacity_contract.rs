//! Multi-layer Blob-only Pando capacity contract, streaming growth, and retention.
//!
//! Eliminates the 16-pack active frontier and 160 MiB verification workspace
//! bottlenecks without weakening closure proofs, authorization, or historical
//! retention guarantees.

pub mod admission;
pub mod admission_types;
pub mod git_ops;
pub mod git_views;
mod growth_cas;
pub mod growth_state;
pub mod growth_types;
pub mod inventory;
pub mod ledger_retention;
pub mod ledger_types;
pub mod limits;
pub mod streaming_growth;

#[cfg(test)]
mod growth_tests;
#[cfg(test)]
mod ledger_tests;

pub use admission::{AdmissionController, AdmissionPermit};
pub use admission_types::{
    AdmissionClass, AdmissionLimits, AdmissionRejection, AdmissionRequest, AdmissionTelemetrySnapshot,
};
pub use git_ops::{GitOpsError, GitProcessLimits, ObjectFormat, PackDownloadRef, UploadScope, UploadedPackPair};
pub use git_views::{CompactViewInput, CompactedViewSummary, VerifiedViewSummary, VerifyViewInput};
pub use growth_types::{
    CompactionOutcome, EngineScope, GrowthEngineError, GrowthEngineSnapshot, IncrementalPushRequest, PushOutcome,
    RefMutation, VerifiedPackRecord,
};
pub use inventory::{ContractFactStatus, LayerLimitFact};
pub use ledger_retention::RetentionLedger;
pub use ledger_types::{
    LedgerBudgetPolicy, LedgerEntry, LedgerEntryKind, LedgerRetentionError, LedgerRetentionSummary, ProtectionHold,
    RetentionClassification,
};
pub use limits::{
    CapacityContractError, GatewayLayerContract, MetadataLedgerContract, PandoCapacityContract,
    StreamingGrowthContract, VerifierLayerContract,
};
pub use streaming_growth::StreamingGrowthEngine;
