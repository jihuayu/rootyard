//! Opaque materialized views and the sealed serving proof (#174).
//!
//! Extracted from `materialize.rs` so the materializer transaction flow stays
//! below its line bound. The parent re-exports exactly the same public types and
//! the same `cfg(test)` fixtures.

use super::super::read_snapshot::PackReadSnapshot;
use super::super::serving_proof::{VerifiedReadView, VerifiedReadViewProof};
use super::super::serving_read::ServingReadCapture;
use super::map_native_error;
use crate::ref_store::contract::{RefStoreError, RequestDigest};
use crate::ref_store::core::pack_commit::{CapturedRef, NativeReadClosure, PackArtifactRole, RegisteredPack};
use crate::ref_store::core::snapshot_contract::MetadataSnapshotScope;
use sha2::{Digest, Sha256};
use tokio::time::Instant;
use uuid::Uuid;

/// Opaque owned materialized read view. Not `Clone`, not `Serialize`, no public
/// constructor and no write/publish/serving capability.
///
/// `serving_incarnation` is the view's provenance, not a caller input. Only the
/// transient serving T2 path — after `revalidate_serving_capture` locked
/// `cluster_authority` `FOR SHARE` and compared the live incarnation with the
/// capture's anchor — builds a view with `Some(anchor)`. Legacy/history
/// materialization leaves it `None`, and an unanchored view can never become a
/// serving proof.
pub struct MaterializedPackRead {
    snapshot: PackReadSnapshot,
    native: NativeReadClosure,
    serving_incarnation: Option<Uuid>,
}

/// Pure binding step of the sealed builder: the capture must be the very
/// snapshot T2 revalidated, and the proof is sealed over the view's own A5b
/// binding — which T2 compared with the capture's A5b binding, and which
/// [`VerifiedReadView::of_materialized`] re-checks against the snapshot's
/// recomputed A5b materialization digest. The capture's digest alone is never a
/// proof input.
///
/// The cluster incarnation is likewise not chosen here: the view must carry the
/// very anchor its T2 compared (and the capture must still carry the same one),
/// and [`VerifiedReadView::of_materialized`] reads that value back from the view
/// itself — never from an argument — before sealing it.
pub(crate) fn serving_materialization(
    view: MaterializedPackRead,
    capture: &ServingReadCapture,
) -> Result<MaterializedServingRead, RefStoreError> {
    let (captured, binding, anchor) = capture.registered_parts()?;
    if view.serving_incarnation() != Some(anchor) {
        return Err(RefStoreError::MetadataScopeMismatch("cluster authority incarnation"));
    }
    if *view.snapshot() != captured {
        return Err(RefStoreError::MetadataScopeMismatch("materialized serving read is not its capture"));
    }
    if view.proven_binding() != binding {
        return Err(RefStoreError::MetadataScopeMismatch("materialized serving read binding"));
    }
    let proof = VerifiedReadView::of_materialized(&view)?.seal();
    Ok(MaterializedServingRead { view, proof })
}

/// One proof-producing materialization: the verified native view and the sealed
/// proof of exactly that view travel together and cannot be separated. Not
/// `Clone`, no public constructor; only
/// [`PgPackSnapshotMaterializer::materialize_serving_read_sealed`] builds it.
pub(crate) struct MaterializedServingRead {
    view: MaterializedPackRead,
    proof: VerifiedReadViewProof,
}

impl MaterializedServingRead {
    /// The verified native view (packs, refs, local bytes). Not `Clone`; it must
    /// live as long as the proof describes it.
    pub(crate) fn view(&self) -> &MaterializedPackRead {
        &self.view
    }

    /// The sealed internal materialization proof of [`Self::view`].
    pub(crate) fn proof(&self) -> &VerifiedReadViewProof {
        &self.proof
    }

    /// Production admission of the sealed A5b binding (#174): `true` only when
    /// the proof's sealed A5b [`RequestDigest`] equals the actual
    /// [`MaterializedPackRead::proven_binding`] of **this** value's own view —
    /// the native closure's read digest that T2 compared with its freshly
    /// recomputed materialization digest. Never the narrower A5a read digest, a
    /// bare `i64` revision or a caller-chosen digest. The session issuer calls
    /// this before signing; a `false` answer must fail closed.
    pub(crate) fn admit_sealed_binding(&self) -> bool {
        self.proof.binding() == self.view.proven_binding()
    }
}

/// Test-only: build the production view shape over a fixture snapshot and a
/// stand-in native closure, with an explicit fixed serving anchor
/// (`None` models the unanchored legacy/history view). Never reachable outside
/// this crate's test builds, and never a production seal input.
#[cfg(test)]
pub(crate) fn test_materialized_view(
    snapshot: PackReadSnapshot,
    native: NativeReadClosure,
    serving_incarnation: Option<Uuid>,
) -> MaterializedPackRead {
    assert_eq!(native.read_digest(), snapshot.materialization_digest(), "a test view must bind its own snapshot");
    MaterializedPackRead::sealed(snapshot, native, serving_incarnation)
}

impl MaterializedPackRead {
    /// The one place a view exists: after T2 revalidated `snapshot`, compared
    /// the native closure's A5b digest with its own recomputation and finished
    /// cleanup. The view keeps the single source of truth (`native`); the public
    /// [`Self::read_digest_hex`] is derived from it, never stored separately, so
    /// the A5b binding cannot drift from the bytes it describes.
    ///
    /// `serving_incarnation` is set by the caller that holds the T2 anchor lock
    /// itself ([`Self::materialize_serving_read`]'s T2) and is `None` everywhere
    /// else.
    pub(super) fn sealed(
        snapshot: PackReadSnapshot,
        native: NativeReadClosure,
        serving_incarnation: Option<Uuid>,
    ) -> Self {
        Self { snapshot, native, serving_incarnation }
    }

    /// The cluster authority incarnation T2 locked `FOR SHARE` and compared with
    /// the capture anchor, or `None` for a legacy/history view that never took
    /// that lock. This is the only source the proof factory may seal from.
    pub(in crate::ref_store) fn serving_incarnation(&self) -> Option<Uuid> {
        self.serving_incarnation
    }

    pub(in crate::ref_store) fn snapshot(&self) -> &PackReadSnapshot {
        &self.snapshot
    }
    /// The actual A5b binding: the native closure's digest, which T2 compared
    /// with its freshly recomputed materialization digest before this view
    /// existed. Never the narrower A5a read digest.
    pub(in crate::ref_store) fn proven_binding(&self) -> RequestDigest {
        self.native.read_digest()
    }
    pub fn snapshot_id(&self) -> Uuid {
        self.snapshot.snapshot_id()
    }
    pub fn pin_id(&self) -> Uuid {
        self.snapshot.pin_id()
    }
    pub fn pin_generation(&self) -> i64 {
        self.snapshot.pin_generation()
    }
    pub fn scope(&self) -> &MetadataSnapshotScope {
        self.snapshot.scope()
    }
    pub fn repository_id(&self) -> Uuid {
        self.snapshot.repository_id()
    }
    pub fn tenant_id(&self) -> Uuid {
        self.snapshot.tenant_id()
    }
    pub fn owner_id(&self) -> Uuid {
        self.snapshot.owner_id()
    }
    pub fn gate_revision(&self) -> i64 {
        self.snapshot.gate_revision()
    }
    pub fn gate_digest_hex(&self) -> &str {
        self.snapshot.gate_digest_hex()
    }
    pub fn pack_mode(&self) -> &'static str {
        self.snapshot.pack_mode()
    }
    pub fn head_ref(&self) -> &str {
        self.snapshot.head_ref()
    }
    pub fn head_oid_hex(&self) -> Option<&str> {
        self.snapshot.head_oid_hex()
    }
    pub fn refs(&self) -> &[CapturedRef] {
        self.snapshot.refs()
    }
    pub fn ref_count(&self) -> i64 {
        self.snapshot.ref_count()
    }
    pub fn packs(&self) -> &[RegisteredPack] {
        self.snapshot.packs()
    }
    pub fn pack_count(&self) -> i64 {
        self.snapshot.pack_count()
    }
    pub fn membership_digest_hex(&self) -> &str {
        self.snapshot.membership_digest_hex()
    }
    pub fn snapshot_digest_hex(&self) -> &str {
        self.snapshot.snapshot_digest_hex()
    }
    /// Complete A5b binding: full scope, expiry, pin/generation, refs+HEAD,
    /// membership and full pack identity digests — exactly the native closure's
    /// digest T2 compared with its own recomputation. Never the incomplete A5a
    /// read digest.
    pub fn read_digest_hex(&self) -> String {
        self.native.read_digest_hex()
    }
    pub fn logical_bytes(&self) -> i64 {
        self.snapshot.logical_bytes()
    }
    pub fn expires_at_unix_micros(&self) -> i64 {
        self.snapshot.expires_at_unix_micros()
    }
    pub fn expires_at(&self) -> Result<std::time::SystemTime, RefStoreError> {
        self.snapshot.expires_at()
    }
    pub fn verified_pairs(&self) -> usize {
        self.native.verified_pairs()
    }
    pub fn verified_bytes(&self) -> u64 {
        self.native.verified_bytes()
    }
    pub const fn complete_registered_pack_membership(&self) -> bool {
        true
    }
    pub const fn complete_git_read_snapshot(&self) -> bool {
        true
    }
    pub const fn packs_complete(&self) -> bool {
        true
    }

    /// Read one exact verified local pack copy. This never re-opens the Blob
    /// backend and never exposes the private workspace path.
    pub async fn pack_bytes(&self, pack_id: Uuid, deadline: Instant) -> Result<Vec<u8>, RefStoreError> {
        self.read_local(pack_id, PackArtifactRole::Pack, deadline).await
    }

    /// Read one exact verified local index copy.
    pub async fn idx_bytes(&self, pack_id: Uuid, deadline: Instant) -> Result<Vec<u8>, RefStoreError> {
        self.read_local(pack_id, PackArtifactRole::Idx, deadline).await
    }

    async fn read_local(
        &self,
        pack_id: Uuid,
        role: PackArtifactRole,
        deadline: Instant,
    ) -> Result<Vec<u8>, RefStoreError> {
        if deadline <= Instant::now() {
            return Err(RefStoreError::Timeout);
        }
        let pack = self
            .snapshot
            .packs()
            .iter()
            .find(|pack| pack.pack_id() == pack_id)
            .ok_or(RefStoreError::Unsupported("unknown materialized pack id"))?;
        let artifact = pack.artifact(role);
        // The private workspace path is never exposed: the native closure selects
        // the exact verified copy and runs the read in one owned blocking task
        // that holds the workspace/view lease until the read actually exits, so a
        // timeout/cancel can never reclaim the workspace under a live read.
        let bytes = self
            .native
            .read_artifact(pack_id, role, artifact.verified_length(), deadline.into_std())
            .await
            .map_err(map_native_error)?;
        if bytes.len() as u64 != artifact.verified_length() {
            return Err(RefStoreError::Database("verified local materialized copy changed its length".into()));
        }
        if hex::encode(Sha256::digest(&bytes)) != artifact.verified_sha256().as_str() {
            return Err(RefStoreError::Database("verified local materialized copy changed its digest".into()));
        }
        Ok(bytes)
    }
}
