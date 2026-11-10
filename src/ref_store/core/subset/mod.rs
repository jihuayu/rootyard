//! Accepted-subset publication vocabulary and the private selected projection
//! (feature 3).
//!
//! This module is the shared, deterministic per-ref outcome vocabulary plus the
//! selection hashing/projection used by the publication-decision owner:
//!
//! * [`RefRejectReason`] — exactly the six stable reasons (`cas`, `policy`,
//!   `missing_target`, `bad_object_type`, `prefix_conflict`, `head_dependency`);
//! * [`RefVerdict`] — one final verdict per plan ref, in original plan order, with
//!   the canonical persistence spelling;
//! * [`PolicyVerdict`] — the decisions owner's PG auth/policy input; it can only
//!   reject, never resurrect a deterministic rejection;
//! * [`SubsetSelection`] — canonical selection digest + persisted verdict rows;
//! * [`SelectedPackPlan`] — the opaque, crate-private projection that binds the
//!   ORIGINAL whole-batch identity/parent digest, the exact per-ref selection
//!   digest and the resulting ref-map digest.
//!
//! Nothing here is a proof. `PackClosureProof` remains mintable only by the native
//! verifier over the FULL resulting ref map (`PackVerifier::verify_selected`), and
//! rejected refs never enter that proof.
//!
//! Honest limitations: this slice is same-PG policy evaluation plus local native
//! facts, not the distributed #112 `OPEN/CLOSING` barrier. Local LFS byte
//! verification is not a durable Blob receipt; without a durable byte witness the
//! selection fails every pointer-bearing ref closed.
mod projection;
mod selection;
mod verdict;

pub use projection::SelectedPackPlan;
pub use selection::SubsetSelection;
pub use verdict::{MAX_DETAIL_BYTES, PolicyVerdict, RefRejectReason, RefVerdict};
