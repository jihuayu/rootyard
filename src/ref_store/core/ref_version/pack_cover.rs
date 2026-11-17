//! Causal `have/want` + `ref_version` + tiered compaction cover fetch planner (Issue #184).
//!
//! Combines `#180` causal ref-version closures, `#183` verified pack dependencies, and
//! `#162` non-destructive compaction cover hierarchies to select minimal reusable immutable
//! fetch packs while enforcing strict tenant/per-request authorization, explicit 3-state
//! retention classification, default `StrongSnapshot` read isolation, independent closure
//! proofs, and fail-closed fallback to full verified reads.
pub mod auth;
pub mod blob_verify;
pub mod model;
mod model_codec;
pub mod planner;
mod planner_select;
pub mod retention_class;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_git_blob;
#[cfg(test)]
mod tests_matrix;
pub mod verifier;

pub use auth::{
    AdvertisedRef, AuthorizationContext, FallbackReason, FetchPlanError, ReadIsolationMode, RefVisibilityPolicy,
    StrongSnapshotCut, StrongSnapshotFallback, advertise_authorized_refs,
};
pub use blob_verify::{BlobVerifyError, MaterializedFetchVerification, materialize_and_verify_fetch_plan};
pub use model::{
    CompactionPublishOutcome, CoverArtifactPair, CoverCommitLink, CoverHierarchyIndex, CoverHierarchyRecord,
    CoverHierarchyRecordInput, CoverMembershipDigest, CoverModelError, CoverRecordDigest, CoverTier,
    compute_cover_membership_digest,
};
pub use planner::{
    DEFAULT_COMPACTED_THRESHOLD, FetchPlan, FetchPlanDigest, FetchPlanOutcome, FetchPlanRequest, HaveSpec,
    PlannedCoverEntry, WantTarget, plan_fetch_covers,
};
pub use retention_class::{
    CoverHoldKind, CoverRetentionHold, NonAuthoritativeHint, PHYSICAL_GC_OWNER, PackRetentionClassification,
    PackRetentionState, PhysicalBlobStatus, RetentionClassificationIndex,
};
pub use verifier::{PlanVerifyError, VerifiedFetchPlanProof, verify_fetch_plan_closure};
