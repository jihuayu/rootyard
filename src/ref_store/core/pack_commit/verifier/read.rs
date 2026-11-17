//! Shared private native engine for A5b materialized read snapshots.
//!
//! It reuses the same bounded downloader, `GitRunner`, packed-refs writer and
//! `fsck` attestation as the A4 verifier, but it never builds a `PackCommitPlan`
//! and never calls `mint::mint`. Its result is an internal owned workspace with
//! the exact verified local pack/idx copies and the natively attested refs/HEAD;
//! it cannot mint `PackClosureProof`.
//!
//! Ownership: a materialized-view budget is acquired before any native
//! admission and travels with the workspace for the view lifetime. One global
//! native permit is installed only around the native steps and released after
//! every child is confirmed quiescent. Any uncertain cleanup keeps both the
//! native permit and the workspace/view budget.
use super::budget::budgets;
use super::download;
use super::handoff;
use super::lease::VerificationLease;
use super::refs::{self, RefMap};
use super::view::NativeView;
use super::{AdmissionClass, acquire_slot_with_class, acquire_view_budget_with_class, arm, refuse};
use crate::blob_store::opendal::BlobStore;
use crate::ref_store::contract::RequestDigest;
use crate::ref_store::core::pack_commit::artifact::RegisteredPack;
use crate::ref_store::core::pack_commit::context::CapturedRef;
use crate::ref_store::core::pack_commit::contract::{
    PackArtifactRole, VERIFIER_MAX_PAIRS, VERIFIER_MAX_RESULT_REFS, VERIFIER_MAX_TOTAL_BYTES,
    VERIFIER_VIEW_MAX_LOGICAL_BYTES,
};
use crate::ref_store::core::pack_commit::error::PackCommitError;
use crate::ref_store::core::types::{GitObjectFormat, RefName};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;

/// Trusted T1 metadata passed into the native engine. Nothing here is a proof;
/// every value is still revalidated by the native view.
pub(crate) struct NativeReadRequest<'a> {
    pub(crate) format: GitObjectFormat,
    pub(crate) head_ref: &'a str,
    pub(crate) head_oid: Option<&'a str>,
    pub(crate) refs: &'a [CapturedRef],
    pub(crate) packs: &'a [RegisteredPack],
    /// The complete T1 A5b binding digest. The closure must carry exactly this
    /// value so T2 can compare it against its own freshly recomputed digest;
    /// the narrower A5a `read_digest` alone is never sufficient.
    pub(crate) read_digest: &'a str,
}

struct StoredPair {
    pack_path: PathBuf,
    pack_sha256: String,
    idx_path: PathBuf,
    idx_sha256: String,
}

/// Owned native materialization: private workspace + exact verified local files.
pub(crate) struct NativeReadClosure {
    lease: Arc<VerificationLease>,
    pairs: BTreeMap<Uuid, StoredPair>,
    verified_pairs: usize,
    verified_bytes: u64,
    /// The explicit complete T1 binding this closure was materialized for.
    read_digest: RequestDigest,
}

#[cfg(test)]
impl NativeReadClosure {
    /// Test-only stand-in for a native closure (an empty lease, no local files).
    /// Offline unit cases use it to build a materialized view without a Git
    /// workspace; they never read bytes through it.
    pub(in crate::ref_store::core) fn for_test(read_digest: RequestDigest) -> Self {
        Self {
            lease: VerificationLease::for_test(),
            pairs: BTreeMap::new(),
            verified_pairs: 1,
            verified_bytes: 0,
            read_digest,
        }
    }
}

impl NativeReadClosure {
    pub(crate) fn verified_pairs(&self) -> usize {
        self.verified_pairs
    }

    pub(crate) fn verified_bytes(&self) -> u64 {
        self.verified_bytes
    }

    /// The complete T1 A5b binding carried by this opaque closure.
    pub(crate) fn read_digest(&self) -> RequestDigest {
        self.read_digest
    }

    /// Canonical hex of [`Self::read_digest`]; never the incomplete A5a digest.
    pub(crate) fn read_digest_hex(&self) -> String {
        self.read_digest.as_hex()
    }

    /// Conservative retained workspace bytes. The recursive filesystem scan runs
    /// in one owned blocking task that holds a clone of the lease, so a stalled
    /// scratch filesystem can never let the caller release the workspace, the
    /// view budget or the native permit while the scan is still running.
    pub(crate) async fn retained_bytes(&self, deadline: Instant) -> Result<u64, PackCommitError> {
        retained_bytes_bounded(Arc::clone(&self.lease), deadline).await
    }

    /// Read one exact verified local copy (pack or index) of one registered pack.
    ///
    /// The private path is selected here, never by the caller, and the read runs
    /// in one owned blocking task that holds a clone of the `Arc` lease plus the
    /// resolved private path. A timed-out or cancelled join therefore detaches
    /// the task without releasing the workspace, the view budget or the native
    /// permit until the blocking read has actually finished. The task preallocates
    /// only the registered length and reads at most that length plus one byte, so
    /// the local read stays bounded by the registered artifact length.
    pub(crate) async fn read_artifact(
        &self,
        pack_id: Uuid,
        role: PackArtifactRole,
        registered_len: u64,
        deadline: Instant,
    ) -> Result<Vec<u8>, PackCommitError> {
        if deadline <= Instant::now() {
            return Err(refuse("materialized copy read has no remaining deadline"));
        }
        if registered_len > VERIFIER_VIEW_MAX_LOGICAL_BYTES {
            return Err(refuse("materialized copy read exceeds the workspace bound"));
        }
        let (path, expected_sha) = match role {
            PackArtifactRole::Pack => self.pack_entry(pack_id),
            PackArtifactRole::Idx => self.idx_entry(pack_id),
        }
        .ok_or_else(|| refuse("materialized pack copy is unavailable"))?;
        let path = path.to_path_buf();
        let expected_sha = expected_sha.to_owned();
        let lease = Arc::clone(&self.lease);
        let task = tokio::task::spawn_blocking(move || {
            // The task owns the lease until the stream finishes; a detached join
            // never frees the workspace under the running read.
            handoff::read_verified_streamed(&path, registered_len, Some(&expected_sha), lease, deadline)
        });
        match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), task).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(refuse("materialized copy read task failed")),
            Err(_) => Err(refuse("materialized copy read is retained until it exits")),
        }
    }

    fn pack_entry(&self, pack_id: Uuid) -> Option<(&std::path::Path, &str)> {
        self.pairs.get(&pack_id).map(|pair| (pair.pack_path.as_path(), pair.pack_sha256.as_str()))
    }

    fn idx_entry(&self, pack_id: Uuid) -> Option<(&std::path::Path, &str)> {
        self.pairs.get(&pack_id).map(|pair| (pair.idx_path.as_path(), pair.idx_sha256.as_str()))
    }
}

/// Shared private native materializer. Construction validates the absolute
/// trusted Git binary once and grants nothing.
pub(crate) struct NativeReadEngine {
    store: BlobStore,
    git: PathBuf,
}

impl NativeReadEngine {
    pub(crate) fn new(store: BlobStore, git_binary: PathBuf) -> Result<Self, PackCommitError> {
        let git = super::binary::validate(&git_binary)?;
        Ok(Self { store, git })
    }

    /// The actual opened Blob backend identity used by this engine. Callers use
    /// this for an internal serving-lane predicate; it is not a capability.
    pub(crate) fn backend_identity(&self) -> &crate::blob_store::BlobBackendIdentity {
        self.store.backend_identity()
    }

    pub(crate) async fn materialize(
        &self,
        request: &NativeReadRequest<'_>,
        deadline: Instant,
    ) -> Result<NativeReadClosure, PackCommitError> {
        let deadline = arm(deadline)?;
        let (refs, read_digest) = validate(request)?;
        let registered = request.packs.iter().collect::<Vec<_>>();
        download::check_live_backend(&self.store, &registered)?;
        let planned_bytes = download::planned_pair_bytes(&registered)?;
        let class = AdmissionClass::Foreground;
        // Phase 1: view budget, staging reservation, and download slot (no native Git CPU slot yet).
        let view_budget = acquire_view_budget_with_class(class, deadline).await?;
        let staging = budgets().reserve_staging(planned_bytes.saturating_mul(2), class, deadline).await?;
        let download_permit = budgets().acquire_download(class, deadline).await?;
        let lease = VerificationLease::with_view_budget(view_budget, staging, download_permit)?;
        let view = NativeView::create(&self.git, Arc::clone(&lease), request.format)?;
        check_workspace(&lease, deadline).await?;
        preflight_workspace(&lease, planned_bytes.saturating_mul(2), deadline).await?;
        let staged_pairs =
            download::fetch_pairs_staged(&self.store, &registered, view.incoming(), &lease, deadline).await?;
        lease.release_download();
        check_workspace(&lease, deadline).await?;

        // Phase 2: admit native CPU slot strictly for Git verification/attestation.
        let native = acquire_slot_with_class(class, deadline).await?;
        lease.admit_native(native);
        view.init(deadline).await?;
        check_workspace(&lease, deadline).await?;

        let mut pairs = BTreeMap::new();
        let mut indexed = BTreeSet::new();
        let mut bytes = 0u64;
        for (pack, staged) in request.packs.iter().zip(staged_pairs) {
            view.verify_registered_pair(&staged.idx, deadline).await?;
            if indexed.insert(staged.sha256.clone()) {
                // `index-pack` duplicates the verified pack+idx under canonical
                // names while the incoming copy remains. Refuse the projected
                // peak before Git can consume disk beyond the view cap.
                preflight_workspace(&lease, staged.bytes, deadline).await?;
                view.index_pack(&staged.pack, deadline).await?;
                check_workspace(&lease, deadline).await?;
            }
            bytes =
                bytes.checked_add(staged.bytes).ok_or_else(|| refuse("materialized artifact byte count overflowed"))?;
            let idx_sha256 = pack.artifact(PackArtifactRole::Idx).verified_sha256().as_str().to_owned();
            pairs.insert(
                pack.pack_id(),
                StoredPair { pack_path: staged.pack, pack_sha256: staged.sha256, idx_path: staged.idx, idx_sha256 },
            );
        }
        view.check_pack_directory(indexed.len())?;
        view.attest_refs(
            &RefName::new(request.head_ref).map_err(|_| refuse("materialized HEAD is not canonical"))?,
            request.head_oid,
            &refs,
            deadline,
        )
        .await?;
        check_workspace(&lease, deadline).await?;
        // Every child spawned above is confirmed reaped by the runner. Native
        // capacity returns now; reclaim disposable `verify.git/` and shrink
        // staging down to the ~1x retained pair footprint.
        lease.release_native();
        download::remove_directory_tree(&lease.root_path().join("verify.git"), &lease, deadline).await?;
        lease.shrink_staging_to(bytes);
        Ok(NativeReadClosure { lease, pairs, verified_pairs: request.packs.len(), verified_bytes: bytes, read_digest })
    }
}

/// Pure pre-IO bound/identity validation of the T1 metadata.
fn validate(request: &NativeReadRequest<'_>) -> Result<(RefMap, RequestDigest), PackCommitError> {
    let read_digest = request
        .read_digest
        .parse::<RequestDigest>()
        .map_err(|_| refuse("materialized read digest is not canonical sha256 hex"))?;
    if request.packs.is_empty() || request.packs.len() > VERIFIER_MAX_PAIRS {
        return Err(refuse("materialized read pack set exceeds the verifier bound"));
    }
    if request.refs.len() > VERIFIER_MAX_RESULT_REFS {
        return Err(refuse("materialized read ref set exceeds the verifier bound"));
    }
    let mut map = RefMap::new();
    for reference in request.refs {
        refs::validate_ref(reference.name(), reference.oid_hex(), request.format)?;
        if map.insert(reference.name().to_owned(), reference.oid_hex().to_owned()).is_some() {
            return Err(refuse("materialized read repeats a ref name"));
        }
    }
    RefName::new(request.head_ref).map_err(|_| refuse("materialized HEAD is not canonical"))?;
    if let Some(oid) = request.head_oid {
        refs::validate_ref(request.head_ref, oid, request.format)?;
        if map.get(request.head_ref).map(String::as_str) != Some(oid) {
            return Err(refuse("materialized HEAD object id is not one of the captured refs"));
        }
    }
    let mut ids = BTreeSet::new();
    let mut bytes = 0u64;
    for pack in request.packs {
        if !ids.insert(pack.pack_id()) {
            return Err(refuse("materialized read repeats a pack id"));
        }
        bytes = bytes
            .checked_add(download::single_pair_bytes(pack)?)
            .ok_or_else(|| refuse("materialized artifact bytes overflowed"))?;
    }
    if bytes > VERIFIER_MAX_TOTAL_BYTES {
        return Err(refuse("materialized read exceeds the verifier total artifact-byte bound"));
    }
    Ok((map, read_digest))
}

async fn check_workspace(lease: &Arc<VerificationLease>, deadline: Instant) -> Result<(), PackCommitError> {
    if retained_bytes_bounded(Arc::clone(lease), deadline).await? > VERIFIER_VIEW_MAX_LOGICAL_BYTES {
        return Err(refuse("materialized view exceeds its aggregate workspace bound"));
    }
    Ok(())
}

/// Conservative pre-mutation projection: the current retained tree plus the
/// bytes the next native mutation may add must already fit the view cap.
async fn preflight_workspace(
    lease: &Arc<VerificationLease>,
    additional: u64,
    deadline: Instant,
) -> Result<(), PackCommitError> {
    let projected = retained_bytes_bounded(Arc::clone(lease), deadline)
        .await?
        .checked_add(additional)
        .ok_or_else(|| refuse("materialized workspace projection overflowed"))?;
    if projected > VERIFIER_VIEW_MAX_LOGICAL_BYTES {
        return Err(refuse("materialized view would exceed its aggregate workspace bound"));
    }
    Ok(())
}

/// Run the recursive workspace scan on the blocking pool under the caller's
/// absolute deadline. The task owns its own `Arc<VerificationLease>` until it
/// actually exits, so a timed-out or cancelled join can never drop the
/// workspace, the view budget or the native permit while syscalls may still be
/// running against them. Ownership is retained (fail-closed) on timeout.
async fn retained_bytes_bounded(lease: Arc<VerificationLease>, deadline: Instant) -> Result<u64, PackCommitError> {
    if deadline <= Instant::now() {
        return Err(refuse("materialized workspace scan has no remaining deadline"));
    }
    let task = tokio::task::spawn_blocking(move || {
        let lease = lease;
        lease.retained_bytes()
    });
    match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), task).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err(refuse("materialized workspace scan task failed")),
        Err(_) => Err(refuse("materialized workspace scan is retained until it exits")),
    }
}
