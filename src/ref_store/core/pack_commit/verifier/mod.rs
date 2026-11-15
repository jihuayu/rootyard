//! Native pack-closure verifier — the only mint of [`PackClosureProof`], plus the
//! shared private native engine used by A5b materialized reads.
//!
//! This subtree is wired as a **child** of `pack_commit::proof` (`proof.rs`
//! declares `#[path = "verifier/mod.rs"] pub(crate) mod verifier;`), so it can
//! build the private proof fields while every sibling module stays unable to mint
//! one. There is no `pub`/`pub(crate)` proof factory, no `Clone`/`Serialize` proof
//! and no metadata-to-proof shortcut: the only way to obtain a proof is
//! [`PackVerifier::verify`] after a real native validation of the *actual*
//! registered bytes.
//!
//! A5b reuses the same bounded download/Git/view machinery through
//! [`NativeReadEngine`], but that engine never calls `mint::mint`, never builds a
//! `PackCommitPlan`, and cannot produce a [`PackClosureProof`].
//!
//! Frozen public API:
//!
//! * `PackVerifier::new(store: BlobStore, git_binary: PathBuf)
//!   -> Result<Self, PackCommitError>` — no `Default`, no ambient environment
//!   store, no `PATH` lookup: the absolute trusted executable is validated once.
//! * `PackVerifier::verify(&self, plan, context, deadline: Instant)
//!   -> Result<PackClosureProof, PackCommitError>`.
//!
//! One absolute deadline (`min(caller, now + 30 s)`) covers the process-wide
//! concurrency permit, every verified Blob read, all local IO and every native
//! Git command. Failures are fixed `ProofUnavailable` reasons; no caller,
//! provider or Git text is ever part of a public error.
//!
//! Cleanup is bounded separately from that work budget. The process-wide native
//! slot and the 0700 workspace live in one owned `lease::VerificationLease` that
//! is shared with every child this call spawns: a child that is not confirmed
//! reaped *and* group-quiescent keeps the lease, and therefore the slot and the
//! files, alive. Foreground cleanup has its own bounded window; a slower or failed
//! stop hands the child and the lease to one owned reaper task (at most one per
//! lease, at most two native leases process-wide), so retained cleanup keeps
//! capacity reserved instead of pretending a reap.
//!
//! Flow (no PostgreSQL client, pool or lease is reachable from here):
//!
//! 1. [`validate`] — complete plan/context agreement and frozen bounds, all
//!    before any IO;
//! 2. [`download`] — live backend identity/provider equality for *every*
//!    registered artifact, then a verified `BlobStore::get_to_file` of each exact
//!    registered locator plus an independent SHA-256/length re-read and the fixed
//!    12-byte pack-header admission;
//! 3. [`view`] — one owned 0700 bare repository: registered index/pack pairing,
//!    Git-computed canonical pack names, the exact resulting refs/HEAD, branch
//!    object types and full object connectivity;
//! 4. [`mint`] — bind the closure context digest and complete closure identity.
mod binary;
mod budget;
mod budget_metrics;
#[cfg(test)]
mod budget_tests;
mod download;
mod handoff;
#[cfg(test)]
mod handoff_tests;
mod lease;
mod mint;
mod pointer;
mod probe;
mod process;
mod publication;
mod publication_support;
mod read;
mod refs;
mod scratch;
mod validate;
mod view;

pub(super) use budget::{AdmissionClass, NativePermit, ViewPermit, budgets};
pub(crate) use publication::{PublicationFactsEngine, VerifiedPublicationFacts};
pub(crate) use read::{NativeReadClosure, NativeReadEngine, NativeReadRequest};

use super::super::closure::PackClosureContext;
use super::super::contract::{
    VERIFIER_DEADLINE_SECONDS, VERIFIER_MAX_OBJECTS, VERIFIER_MAX_PAIRS, VERIFIER_MAX_RESULT_REFS,
    VERIFIER_MAX_TOTAL_BYTES,
};
use super::super::error::PackCommitError;
use super::super::plan::PackCommitPlan;
use super::PackClosureProof;
use crate::blob_store::opendal::BlobStore;
use crate::ref_store::contract::RequestDigest;
use crate::ref_store::core::pack_commit::context::refs_digest;
use crate::ref_store::core::types::RefUpdate;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Fixed, caller-independent refusal reason.
pub(super) fn refuse(reason: &'static str) -> PackCommitError {
    PackCommitError::ProofUnavailable(reason)
}

/// Native closure verifier.
///
/// Construction grants nothing: a proof exists only after
/// [`Self::verify`] validated the actual bytes of every registered old and new
/// pack against the live Blob backend with native Git.
pub struct PackVerifier {
    store: BlobStore,
    git: PathBuf,
}

impl PackVerifier {
    /// Frozen verifier bound re-exported for callers and tests.
    pub const MAX_PAIRS: usize = VERIFIER_MAX_PAIRS;
    /// Frozen total compressed pack+idx byte bound.
    pub const MAX_TOTAL_BYTES: u64 = VERIFIER_MAX_TOTAL_BYTES;
    /// Frozen total admitted object bound.
    pub const MAX_OBJECTS: u64 = VERIFIER_MAX_OBJECTS;
    /// Frozen resulting-ref bound.
    pub const MAX_RESULT_REFS: usize = VERIFIER_MAX_RESULT_REFS;

    /// Build a verifier for one live Blob store and one absolute trusted Git
    /// binary. There is no `Default` and no ambient store: both are supplied
    /// explicitly, and the binary path is validated before any IO.
    pub fn new(store: BlobStore, git_binary: PathBuf) -> Result<Self, PackCommitError> {
        let git = binary::validate(&git_binary)?;
        Ok(Self { store, git })
    }

    /// Verify one closure and return the sealed proof it authorises.
    ///
    /// The proof binds the context digest, the plan's parent digest, the expected
    /// gate revision/digest, the exact resulting refs and HEAD, the old membership
    /// digest, the complete old and new pack-set digests and the number/bytes of
    /// verified pairs. Cancelling this future never produces a proof, signals the
    /// native process group and keeps the process-wide slot and the private
    /// workspace retained (via `lease::retain_until_stopped`) until the group is
    /// confirmed quiescent and the leader reaped, so an uncertain cleanup can never
    /// admit a third live verification.
    pub async fn verify(
        &self,
        plan: &PackCommitPlan,
        context: &PackClosureContext,
        deadline: Instant,
    ) -> Result<PackClosureProof, PackCommitError> {
        self.verify_with_class(plan, context, AdmissionClass::Foreground, deadline).await
    }

    /// Background/maintenance entry point capped at <= 50% of download, staging,
    /// and native Git slots so maintenance verification cannot starve foreground.
    pub async fn verify_maintenance(
        &self,
        plan: &PackCommitPlan,
        context: &PackClosureContext,
        deadline: Instant,
    ) -> Result<PackClosureProof, PackCommitError> {
        self.verify_with_class(plan, context, AdmissionClass::Maintenance, deadline).await
    }

    /// Current monotonic resource-budget & transfer telemetry serialized for
    /// benchmarks and observability checks.
    pub fn budget_metrics_json() -> serde_json::Value {
        serde_json::to_value(budget::metrics_snapshot()).unwrap_or(serde_json::Value::Null)
    }

    async fn verify_with_class(
        &self,
        plan: &PackCommitPlan,
        context: &PackClosureContext,
        class: AdmissionClass,
        deadline: Instant,
    ) -> Result<PackClosureProof, PackCommitError> {
        if context.selection_digest().is_some() {
            return Err(refuse("atomic verification cannot use a selected closure"));
        }
        let (pairs, bytes) = self.execute(plan, context, class, deadline).await?;
        mint::mint(plan, context, pairs, bytes)
    }

    /// Verify the FULL resulting ref map of an accepted-subset selection and mint
    /// a proof that also binds the private selection digest.
    ///
    /// The original plan is the unchanged whole batch; only `selected.accepted()`
    /// is applied to the captured old refs. Rejected refs are never in the proof,
    /// and the proof is never re-filtered afterwards. The context must bind this
    /// exact selection digest, accepted set and resulting-map digest, so a
    /// selection/proof mismatch is a typed refusal and no proof exists.
    /// Primitive selected verification used by `core::subset`'s opaque
    /// `SelectedPackPlan` wrapper. The caller passes the bound selection digest,
    /// accepted update set and resulting ref-map digest; this method refuses unless
    /// the closure context binds exactly those values, verifies the FULL resulting
    /// ref map and mints a proof that also binds the selection digest.
    pub(crate) async fn verify_selected_parts(
        &self,
        plan: &PackCommitPlan,
        context: &PackClosureContext,
        expected_selection_digest: &RequestDigest,
        expected_accepted: &[RefUpdate],
        expected_resulting_refs_digest: &RequestDigest,
        deadline: Instant,
    ) -> Result<PackClosureProof, PackCommitError> {
        if context.selection_digest() != Some(expected_selection_digest) {
            return Err(refuse("closure context binds another selection digest"));
        }
        if context.accepted() != Some(expected_accepted) {
            return Err(refuse("closure context binds another accepted subset"));
        }
        if refs_digest(context.resulting_refs()) != *expected_resulting_refs_digest {
            return Err(refuse("closure context binds another resulting ref map"));
        }
        let (pairs, bytes) = self.execute(plan, context, AdmissionClass::Foreground, deadline).await?;
        mint::mint(plan, context, pairs, bytes)
    }

    /// Shared two-phase bounded closure run:
    /// Phase 1 acquires staging + Blob download capacity without holding native CPU slots,
    /// then releases the download slot before Phase 2 admits native Git execution.
    async fn execute(
        &self,
        plan: &PackCommitPlan,
        context: &PackClosureContext,
        class: AdmissionClass,
        deadline: Instant,
    ) -> Result<(usize, u64), PackCommitError> {
        let deadline = arm(deadline)?;
        let checked = validate::check(plan, context)?;
        let registered = checked.old.iter().chain(checked.new.iter()).collect::<Vec<_>>();
        download::check_live_backend(&self.store, &registered)?;
        let planned_bytes = download::planned_pair_bytes(&registered)?;
        let initial_staging = planned_bytes.saturating_mul(2);
        let staging = budgets().reserve_staging(initial_staging, class, deadline).await?;
        let download_permit = budgets().acquire_download(class, deadline).await?;
        let lease = lease::VerificationLease::for_verification(staging, download_permit)?;
        let view = view::NativeView::create(&self.git, Arc::clone(&lease), checked.format)?;

        let staged_pairs =
            download::fetch_pairs_staged(&self.store, &registered, view.incoming(), &lease, deadline).await?;
        lease.release_download();

        let native_permit = acquire_slot_with_class(class, deadline).await?;
        lease.admit_native(native_permit);
        view.init(deadline).await?;
        let mut indexed = std::collections::BTreeSet::new();
        let mut cleaned_incoming = 0u64;
        for pair in staged_pairs {
            view.verify_registered_pair(&pair.idx, deadline).await?;
            if indexed.insert(pair.sha256) {
                view.index_pack(&pair.pack, deadline).await?;
            }
            download::remove_pair_files(&pair.pack, &pair.idx, &lease, deadline).await?;
            cleaned_incoming = cleaned_incoming.saturating_add(pair.bytes);
            lease.shrink_staging_to(initial_staging.saturating_sub(cleaned_incoming));
        }
        view.check_pack_directory(indexed.len())?;
        view.attest(&checked, deadline).await?;
        Ok((checked.pairs, checked.bytes))
    }
}

impl std::fmt::Debug for PackVerifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("PackVerifier").field("git", &"<configured>").finish_non_exhaustive()
    }
}

/// The single absolute deadline of one verification.
fn arm(caller: Instant) -> Result<Instant, PackCommitError> {
    let ceiling = Instant::now() + Duration::from_secs(VERIFIER_DEADLINE_SECONDS);
    let deadline = caller.min(ceiling);
    if deadline <= Instant::now() {
        return Err(refuse("verifier deadline already elapsed"));
    }
    Ok(deadline)
}

async fn acquire_slot_with_class(class: AdmissionClass, deadline: Instant) -> Result<NativePermit, PackCommitError> {
    budgets().acquire_native(class, deadline).await
}

async fn acquire_view_budget_with_class(
    class: AdmissionClass,
    deadline: Instant,
) -> Result<ViewPermit, PackCommitError> {
    budgets().acquire_view(class, deadline).await
}
