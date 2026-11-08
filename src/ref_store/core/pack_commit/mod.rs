//! A4a: durable one-time pack registration plus a single short PG transaction
//! that writes refs + HEAD + pack membership + gate revision/mode + operation
//! terminal + event, gated by an actual native closure proof.
//!
//! Delivered path (library only, unserved — **not** completion of #107):
//!
//! 1. [`PackCommitBaseline`] capture of the complete old gate/refs/HEAD/
//!    membership state in one short read transaction;
//! 2. [`PackCommitPlan`] with preallocated operation/pack/registration ids and a
//!    canonical parent digest over known semantic fields only (before A3);
//! 3. `begin_pending` over the migration-138 registry (exact digest, exact
//!    cancellation tombstones) returning an opaque [`PackPendingToken`];
//! 4. A3 acquire → consume → protected upload, then
//!    `register_publication` binding the publication's direct acquire/consume
//!    ids, every hold row and both read-back receipts to the planned content;
//! 5. [`PackClosureContext`] capture at the plan's expected revision with the
//!    same-parent durable registrations, then native verification returning a
//!    [`PackClosureProof`] (minted only inside the private verifier subtree);
//! 6. `commit_verified_pending` reusing the exact 138 lock prefix and writing
//!    every effect in one short transaction, including the one-way
//!    `metadata_only → pack_verified` gate fence.
//!
//! Not implemented here, by design: activation/serving claims, accepted subsets,
//! roots/decisions, GC, snapshot pins, pack-aware pins, bitmap packs, detach/
//! compaction, encryption, Blob-byte backup. No HTTP route, runtime profile or
//! helper replay grant is added.
pub mod artifact;
pub mod closure;
pub mod context;
pub mod contract;
pub mod error;
pub mod plan;
pub mod proof;
pub mod receipt;
pub mod request;

mod pg;
mod pg_commit;
mod registration;
mod sql;
mod usage;

pub use artifact::{ArtifactLocator, ArtifactSetDigest, RegisteredArtifact, RegisteredPack, packs_digest};
pub use closure::PackClosureContext;
pub use context::{CapturedRef, MembershipDigest, PackCommitBaseline, PackMembershipEntry, refs_digest};
pub use contract::{
    ARTIFACTS_PER_PACK, MAX_ACK_BODY_BYTES, MAX_ACTIVE_MEMBERSHIPS, MAX_BATCH_NEW_PACKS, MAX_CAPTURE_REFS,
    MAX_PLAN_REFS, PackArtifactRole, PackMode, REPO_MAX_ARTIFACTS, REPO_MAX_LOGICAL_BYTES, REPO_MAX_MEMBERSHIPS,
    REPO_MAX_RECEIPTS, REPO_MAX_REGISTRATIONS, TENANT_MAX_ARTIFACTS, TENANT_MAX_LOGICAL_BYTES, TENANT_MAX_MEMBERSHIPS,
    TENANT_MAX_RECEIPTS, TENANT_MAX_REGISTRATIONS, VERIFIER_MAX_CONCURRENT, VERIFIER_MAX_OBJECTS, VERIFIER_MAX_PAIRS,
    VERIFIER_MAX_RESULT_REFS, VERIFIER_MAX_TOTAL_BYTES,
};
pub use error::{PackCommitError, PackCommitRejectCode, PackCommitRejection};
pub use pg::PgPackCommit;
pub use plan::{ContentDigest, PackCommitExpectation, PackCommitPlan, PackCommitScope, PlannedArtifact, PlannedPack};
pub use proof::PackClosureProof;
pub use proof::verifier::PackVerifier;
pub use receipt::{
    PackCommitReceipt, PackCommitTerminal, PackRegistrationAck, PackRegistrationReceipt, PackTerminalRegistration,
    ensure_pack_terminal_budget,
};
pub use request::{PAIR_SLOTS, PackPendingToken, PackRegistrationRequest, PairArtifact};
