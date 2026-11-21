//! Reusable fixed-OID CloneKit pack builder, capability grants, and incremental CI checkout.
//!
//! All state stays explicitly bounded: stock Git fallback remains available by
//! explicit policy, builds never expose unverified pack bytes as valid commits,
//! and exact-OID checkouts never treat a kit's base commit tip as the target OID.

#[path = "clonekit/builder.rs"]
pub mod builder;
#[path = "clonekit/checkout.rs"]
pub mod checkout;
#[path = "clonekit/grants.rs"]
pub mod grants;
#[path = "clonekit/manifest.rs"]
pub mod manifest;
#[path = "clonekit/transfer.rs"]
mod transfer;

pub use builder::{
    BlobHoldPublishContext, BuildCloneKitRequest, BuildFailurePoint, BuiltCloneKitArtifacts, CloneKitPublicationStore,
    CloneKitReadLease, LeasedCloneKitManifest, RetentionPinGuard, RetentionPinLedger, build_clonekit_from_git,
    publish_clonekit_to_blob_store, publish_clonekit_versioned,
};
pub use checkout::{
    CheckoutOutcome, CheckoutPolicy, CheckoutRequest, CheckoutStrategy, CheckoutTelemetry, FallbackReason,
    execute_ci_checkout, run_stock_git_checkout,
};
pub use grants::{
    CloneKitAuthorityOracle, CloneKitDependencyGrants, CloneKitGrantClaims, DependencyVerificationReceipt,
    GrantVerificationContext, InMemoryAuthorityOracle, PgCheckoutAuthorityOracle, RequiredLfsObject, RequiredSubmodule,
    SignedCloneKitGrant, sign_grant, verify_grant, verify_tree_dependencies,
};
pub use manifest::{
    CLONEKIT_MANIFEST_SCHEMA, CloneKitArtifactDigest, CloneKitError, CloneKitManifest, CloneKitObjectFormat,
    CloneKitStatus, StoredBlobLocator,
};
