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
use super::download;
use super::lease::VerificationLease;
use super::refs::{self, RefMap};
use super::view::NativeView;
use super::{acquire_slot, acquire_view_budget, arm, refuse};
use crate::blob_store::opendal::BlobStore;
use crate::ref_store::contract::RequestDigest;
use crate::ref_store::core::pack_commit::artifact::RegisteredPack;
use crate::ref_store::core::pack_commit::context::CapturedRef;
use crate::ref_store::core::pack_commit::contract::{
    PackArtifactRole, VERIFIER_MAX_OBJECTS, VERIFIER_MAX_PAIRS, VERIFIER_MAX_RESULT_REFS, VERIFIER_MAX_TOTAL_BYTES,
    VERIFIER_VIEW_MAX_LOGICAL_BYTES,
};
use crate::ref_store::core::pack_commit::error::PackCommitError;
use crate::ref_store::core::types::{GitObjectFormat, RefName};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
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

/// Owned native materialization: private workspace + exact verified local files.
pub(crate) struct NativeReadClosure {
    lease: Arc<VerificationLease>,
    pairs: BTreeMap<Uuid, (PathBuf, PathBuf)>,
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
        let path = match role {
            PackArtifactRole::Pack => self.pack_path(pack_id),
            PackArtifactRole::Idx => self.idx_path(pack_id),
        }
        .ok_or_else(|| refuse("materialized pack copy is unavailable"))?
        .to_path_buf();
        let lease = Arc::clone(&self.lease);
        let task = tokio::task::spawn_blocking(move || {
            // The task owns the lease until this closure actually returns; a
            // detached join never frees the workspace under the running read.
            let _lease = lease;
            read_artifact_blocking(&path, registered_len)
        });
        match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), task).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(refuse("materialized copy read task failed")),
            Err(_) => Err(refuse("materialized copy read is retained until it exits")),
        }
    }

    fn pack_path(&self, pack_id: Uuid) -> Option<&Path> {
        self.pairs.get(&pack_id).map(|(pack, _)| pack.as_path())
    }

    fn idx_path(&self, pack_id: Uuid) -> Option<&Path> {
        self.pairs.get(&pack_id).map(|(_, idx)| idx.as_path())
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

    pub(crate) async fn materialize(
        &self,
        request: &NativeReadRequest<'_>,
        deadline: Instant,
    ) -> Result<NativeReadClosure, PackCommitError> {
        let deadline = arm(deadline)?;
        let (refs, read_digest) = validate(request)?;
        let registered = request.packs.iter().collect::<Vec<_>>();
        download::check_live_backend(&self.store, &registered)?;
        // View budget first, then create the owned workspace, then admit native.
        let lease = VerificationLease::with_view_budget(acquire_view_budget(deadline).await?)?;
        // Native admission comes BEFORE `init`, because `init` runs Git. The view
        // budget was acquired first; the native permit stays installed until every
        // child below is confirmed quiescent.
        let native = acquire_slot(deadline).await?;
        lease.admit_native(native);
        let view = NativeView::create(&self.git, Arc::clone(&lease), request.format)?;
        view.init(deadline).await?;
        check_workspace(&lease, deadline).await?;

        let mut pairs = BTreeMap::new();
        let mut indexed = BTreeSet::new();
        let mut bytes = 0u64;
        let mut objects_total = 0u64;
        for (index, pack) in request.packs.iter().enumerate() {
            let pair_bytes = pack_bytes(pack)?;
            // `get_to_file` streams through a staging file and then renames, so the
            // pre-download peak can be two copies of this pair.
            preflight_workspace(&lease, pair_bytes.saturating_mul(2), deadline).await?;
            let download::PairInput { pack: pack_copy, idx, sha256, objects } =
                download::fetch_pair(&self.store, pack, view.incoming(), index, &lease, deadline).await?;
            check_workspace(&lease, deadline).await?;
            let declared = objects;
            objects_total =
                objects_total.checked_add(declared).ok_or_else(|| refuse("materialized object count overflowed"))?;
            if objects_total > VERIFIER_MAX_OBJECTS {
                return Err(refuse("materialized read exceeds the aggregate verifier object bound"));
            }
            view.verify_registered_pair(&idx, deadline).await?;
            if indexed.insert(sha256) {
                // `index-pack` duplicates the verified pack+idx under canonical
                // names while the incoming copy remains. Refuse the projected
                // peak before Git can consume disk beyond the view cap.
                preflight_workspace(&lease, pair_bytes, deadline).await?;
                view.index_pack(&pack_copy, deadline).await?;
                check_workspace(&lease, deadline).await?;
            }
            bytes =
                bytes.checked_add(pair_bytes).ok_or_else(|| refuse("materialized artifact byte count overflowed"))?;
            pairs.insert(pack.pack_id(), (pack_copy, idx));
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
        // capacity returns now; the workspace and view budget stay owned.
        lease.release_native();
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
        bytes = bytes.checked_add(pack_bytes(pack)?).ok_or_else(|| refuse("materialized artifact bytes overflowed"))?;
    }
    if bytes > VERIFIER_MAX_TOTAL_BYTES {
        return Err(refuse("materialized read exceeds the verifier total artifact-byte bound"));
    }
    Ok((map, read_digest))
}

fn pack_bytes(pack: &RegisteredPack) -> Result<u64, PackCommitError> {
    pack.artifact(PackArtifactRole::Pack)
        .verified_length()
        .checked_add(pack.artifact(PackArtifactRole::Idx).verified_length())
        .ok_or_else(|| refuse("materialized artifact bytes overflowed"))
}

/// One owned bounded blocking read of exactly one private local copy.
fn read_artifact_blocking(path: &Path, length: u64) -> Result<Vec<u8>, PackCommitError> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|_| refuse("materialized copy cannot be reopened"))?;
    let metadata = file.metadata().map_err(|_| refuse("materialized copy cannot be inspected"))?;
    if !metadata.is_file() {
        return Err(refuse("materialized copy is not a regular file"));
    }
    if metadata.len() != length {
        return Err(refuse("materialized copy length differs from the registered length"));
    }
    let capacity = usize::try_from(length).map_err(|_| refuse("materialized copy length is not addressable"))?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut reader = file.take(length.saturating_add(1));
    reader.read_to_end(&mut bytes).map_err(|_| refuse("materialized copy cannot be read"))?;
    if bytes.len() as u64 != length {
        return Err(refuse("materialized copy changed length while being read"));
    }
    Ok(bytes)
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
