//! A5b materialized Git read snapshot: T1 sealed metadata, actual Blob/native
//! closure **outside every PostgreSQL lease**, then a fresh-locked T2 recheck at
//! the very end under one absolute effective deadline.
//!
//! The returned [`MaterializedPackRead`] is an opaque owned local read view. It
//! has no `Clone`, no `Serialize`/`Deserialize`, no public constructor and grants
//! no write/publish/serving authority. A public value exists only after:
//!
//! 1. T1 read the sealed registered-membership snapshot under the stored
//!    historical scope/current realm in one short bounded transaction, then
//!    released its pool client/transaction under the same absolute deadline; no
//!    sealed snapshot is yielded unless that cleanup succeeded;
//! 2. the shared private native engine downloaded **every** registered pack/idx
//!    with a verified Blob GET, independently re-read SHA-256/length, proved the
//!    registered pair, computed canonical pack names, wrote the exact sorted
//!    `packed-refs` + HEAD, checked branch object types and ran `fsck`;
//! 3. T2 reacquired PostgreSQL under the *same* effective deadline, re-ran the
//!    full A5a locked validation, compared the complete A5b binding digest (as
//!    carried by the opaque native closure), then read a fresh DB clock under
//!    the still-held pin lock and rechecked expiry / generation / scope.
//!
//! # Read linearization and cleanup ordering
//!
//! The read linearizes at that final fresh-clock/liveness check while the pin
//! `FOR SHARE` lock is held. The sealed owned [`MaterializedPackRead`] is built
//! before the transaction is released, then transaction cleanup runs under the
//! same absolute deadline, and only a *successful* cleanup returns the value. A
//! timeout or failed rollback returns an error and exposes nothing. A pin
//! release/generation change ordered after the linearization point can complete
//! before the caller receives the already-linearized local copy; this is a local
//! disposable read view, not a continuously-live network lease.
//!
//! # Clock boundary
//!
//! PostgreSQL stages use `tokio::time::Instant`; the private native verifier
//! uses `std::time::Instant`. The single effective deadline is converted with
//! `into_std()` at that boundary, so both halves observe the same absolute
//! instant and the budget is never restarted.
use super::super::pack_commit::{
    self, CapturedRef, NativeReadClosure, NativeReadEngine, NativeReadRequest, PackArtifactRole, PackCommitError,
    RegisteredPack,
};
use super::super::snapshot_contract::MetadataSnapshotScope;
use super::contract as pack_contract;
use super::pg::PgPackSnapshot;
use super::read_snapshot::PackReadSnapshot;
use super::request::PackSnapshotRef;
use super::serving_proof::VerifiedReadView;
use super::serving_proof::VerifiedReadViewProof;
use super::serving_read::{RegisteredServingRead, ServingReadCapture, revalidate_serving_capture};
use crate::blob_store::opendal::BlobStore;
use crate::ref_store::contract::{RefStoreError, RequestDigest};
use crate::ref_store::core::snapshot_sql;
use crate::ref_store::pg;
use crate::ref_store::tx::begin_bounded;
use deadpool_postgres::Pool;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use tokio::time::{Instant, timeout_at};
use uuid::Uuid;

/// One absolute effective work deadline for the whole call, including both pool
/// acquisitions. Never restarted between T1, native work and T2.
pub(super) fn effective_deadline(caller: Instant) -> Result<Instant, RefStoreError> {
    let ceiling = Instant::now() + std::time::Duration::from_secs(pack_commit::contract::VERIFIER_DEADLINE_SECONDS);
    let deadline = caller.min(ceiling);
    if deadline <= Instant::now() {
        return Err(RefStoreError::Timeout);
    }
    Ok(deadline)
}

/// Take one pooled client with the caller's exact effective deadline. Both T1 and
/// T2 use this helper; no pool wait is outside the budget.
pub(super) async fn pooled_client(pool: &Pool, deadline: Instant) -> Result<deadpool_postgres::Client, RefStoreError> {
    let pool = pool.clone();
    match timeout_at(deadline, pool.get()).await {
        Ok(Ok(client)) => Ok(client),
        Ok(Err(_)) => Err(RefStoreError::Unsupported("materialized read PostgreSQL pool is unavailable")),
        Err(_) => Err(RefStoreError::Timeout),
    }
}

/// (T1) Sealed metadata capture in one short bounded transaction.
///
/// `read_checked` and the terminal `ROLLBACK` both run under the caller's one
/// effective deadline, the pooled client and its transaction are dropped before
/// any Blob or native Git IO exists, and no sealed metadata is yielded unless
/// cleanup actually succeeded: a timeout or a failed rollback fails closed with
/// no snapshot at all. This materializer-local path leaves the legacy
/// `PgPackSnapshot::read` API (and its unbounded rollback) untouched.
async fn capture_t1(
    pool: &Pool,
    reference: &PackSnapshotRef,
    deadline: Instant,
) -> Result<PackReadSnapshot, RefStoreError> {
    let mut client = pooled_client(pool, deadline).await?;
    let tx = begin_bounded(&mut client, deadline).await?;
    let read = pg::before_deadline(deadline, PgPackSnapshot.read_checked(&tx, reference, deadline)).await;
    let cleanup = match timeout_at(deadline, tx.rollback()).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(RefStoreError::Database("materialized read T1 transaction cleanup failed".into())),
        Err(_) => Err(RefStoreError::Timeout),
    };
    drop(client);
    match (read, cleanup) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(snapshot), Ok(())) => Ok(snapshot),
    }
}

/// T1 sealed metadata plus the complete A5b binding digest.
struct PreparedReadClosure {
    snapshot: PackReadSnapshot,
    binding: RequestDigest,
}

impl PreparedReadClosure {
    fn new(snapshot: PackReadSnapshot) -> Self {
        let binding = snapshot.materialization_digest();
        Self { snapshot, binding }
    }

    fn binding_hex(&self) -> String {
        self.binding.as_hex()
    }
}

/// Frozen A5b adapter. Construction validates the absolute trusted Git binary
/// once; it grants no capability.
pub struct PgPackSnapshotMaterializer {
    engine: NativeReadEngine,
    /// Digest of the Blob backend this materializer actually opened. It is the
    /// only value the serving-read T2 path accepts as "the live backend".
    store_identity: crate::blob_store::BlobBackendIdentity,
}

impl PgPackSnapshotMaterializer {
    /// Build one materializer for a live Blob store and an absolute trusted Git
    /// binary. There is no ambient store and no `PATH` lookup.
    pub fn new(store: BlobStore, git_binary: PathBuf) -> Result<Self, RefStoreError> {
        let store_identity = store.backend_identity().clone();
        let engine = NativeReadEngine::new(store, git_binary).map_err(map_native_error)?;
        Ok(Self { engine, store_identity })
    }

    /// Digest of the Blob backend this materializer holds open. Never a
    /// credential and never a proof on its own.
    pub fn backend_identity_hex(&self) -> &str {
        self.store_identity.as_hex()
    }

    /// Materialize one complete Git read snapshot.
    ///
    /// One call uses exactly one effective deadline for both `pool.get()` waits,
    /// every SQL stage, every verified Blob GET and every native Git child.
    pub async fn read(
        &self,
        pool: &Pool,
        reference: &PackSnapshotRef,
        deadline: Instant,
    ) -> Result<MaterializedPackRead, RefStoreError> {
        reference.validate()?;
        let deadline = effective_deadline(deadline)?;

        // (T1) Sealed metadata only, in one short bounded transaction. The
        // pooled client and its transaction are fully dropped here, before any
        // Blob or native Git IO exists, and the sealed snapshot is yielded only
        // after a successful bounded rollback.
        let sealed = capture_t1(pool, reference, deadline).await?;
        if sealed.pack_mode() != pack_contract::PACK_MODE_VERIFIED
            || !sealed.complete_registered_pack_membership()
            || sealed.pack_count() <= 0
        {
            return Err(RefStoreError::Unsupported("materialized read requires a complete pack-verified snapshot"));
        }
        let prepared = PreparedReadClosure::new(sealed);

        // Actual Blob + native Git closure, outside every PostgreSQL lease.
        // The SQL layer uses `tokio::time::Instant`, the native verifier uses
        // `std::time::Instant`; `into_std()` keeps the SAME absolute instant, so
        // one deadline still bounds T1, every SQL stage, every Blob GET, every
        // native Git child and T2. The complete T1 binding is passed explicitly
        // into the opaque closure.
        let t1_digest = prepared.binding_hex();
        let native = self
            .engine
            .materialize(
                &NativeReadRequest {
                    format: prepared.snapshot.scope().object_format(),
                    head_ref: prepared.snapshot.head_ref(),
                    head_oid: prepared.snapshot.head_oid_hex(),
                    refs: prepared.snapshot.refs(),
                    packs: prepared.snapshot.packs(),
                    read_digest: &t1_digest,
                },
                deadline.into_std(),
            )
            .await
            .map_err(map_native_error)?;
        if i64::try_from(native.verified_pairs()).unwrap_or(i64::MAX) != prepared.snapshot.pack_count() {
            return Err(RefStoreError::Database("native materialization did not cover every registered pack".into()));
        }
        if native.retained_bytes(deadline.into_std()).await.map_err(map_native_error)?
            > pack_commit::contract::VERIFIER_VIEW_MAX_LOGICAL_BYTES
        {
            return Err(RefStoreError::Unsupported("materialized view exceeds its workspace bound"));
        }

        // (T2) Fresh locked revalidation at the very end, still under the one
        // effective deadline. The opaque public value is sealed while the pin
        // lock is held and is returned only after bounded cleanup completed.
        self.revalidate(pool, reference, &prepared, native, deadline).await
    }

    /// Materialize one already-captured bounded serving read.
    ///
    /// `Ok(None)` means the capture was a **checked empty** repository
    /// observation (`metadata_only` gate, no refs, no packs): there is nothing to
    /// verify and the caller initializes an empty private Git view from that
    /// capture. A fabricated [`PackReadSnapshot`] is never returned for it.
    ///
    /// Otherwise the actual shared native engine downloads every registered
    /// pack/idx with a verified Blob GET, re-reads SHA-256/length, proves the
    /// registered pair, writes the exact sorted `packed-refs` + HEAD and runs
    /// `fsck` — all **outside** every PostgreSQL lease. The final (T2) recheck
    /// then reacquires PostgreSQL under the same absolute deadline and re-proves
    /// the migration-146 transient pin (`FOR SHARE`), the captured realm, the
    /// live Blob backend digest, every captured ref and pack descriptor and a
    /// fresh database-clock lease liveness. A released/expired pin, a history or
    /// epoch move, a new authority or a foreign backend is refused before any
    /// public value exists. A later gate *revision* in the same live history is
    /// accepted: the captured bytes are protected by the pin.
    ///
    /// The caller is responsible for [`super::PgServingReads::release`] after the
    /// returned local view has been fully built (or on any error); the pin is
    /// held for the whole Blob/native window.
    pub async fn materialize_serving_read(
        &self,
        pool: &Pool,
        capture: &ServingReadCapture,
        deadline: Instant,
    ) -> Result<Option<MaterializedPackRead>, RefStoreError> {
        if capture.is_empty() {
            return Ok(None);
        }
        let deadline = effective_deadline(deadline)?;
        let (snapshot, binding) = capture.registered_parts()?;
        let registered = RegisteredServingRead { snapshot, binding };
        if !registered.snapshot.complete_transient_pack_read() {
            return Err(RefStoreError::Unsupported(
                "serving read materialization requires a transient complete pack-verified capture",
            ));
        }

        // Actual Blob + native Git closure, outside every PostgreSQL lease and
        // bounded by the same absolute deadline as the capture and T2.
        let binding_hex = registered.binding.as_hex();
        let native = self
            .engine
            .materialize(
                &NativeReadRequest {
                    format: registered.snapshot.scope().object_format(),
                    head_ref: registered.snapshot.head_ref(),
                    head_oid: registered.snapshot.head_oid_hex(),
                    refs: registered.snapshot.refs(),
                    packs: registered.snapshot.packs(),
                    read_digest: &binding_hex,
                },
                deadline.into_std(),
            )
            .await
            .map_err(map_native_error)?;
        if i64::try_from(native.verified_pairs()).unwrap_or(i64::MAX) != registered.snapshot.pack_count() {
            return Err(RefStoreError::Database(
                "native materialization did not cover every captured serving pack".into(),
            ));
        }
        if native.retained_bytes(deadline.into_std()).await.map_err(map_native_error)?
            > pack_commit::contract::VERIFIER_VIEW_MAX_LOGICAL_BYTES
        {
            return Err(RefStoreError::Unsupported("materialized view exceeds its workspace bound"));
        }
        self.revalidate_serving(pool, &registered, native, deadline).await
    }

    /// The proof-producing form of [`Self::materialize_serving_read`] (#174).
    ///
    /// Exactly the same download, verification, native `fsck` and fresh T2
    /// recheck, but the returned value keeps the verified native view and the
    /// sealed [`VerifiedReadViewProof`] alive together. A checked empty capture
    /// still returns `Ok(None)`: no bytes, no proof. This is an internal
    /// materialization proof only; no gateway route consumes it yet (the
    /// `serving_proof` module docs list what a consumer must still enforce).
    pub(crate) async fn materialize_serving_read_sealed(
        &self,
        pool: &Pool,
        capture: &ServingReadCapture,
        deadline: Instant,
    ) -> Result<Option<MaterializedServingRead>, RefStoreError> {
        let Some(view) = self.materialize_serving_read(pool, capture, deadline).await? else {
            return Ok(None);
        };
        serving_materialization(view, capture).map(Some)
    }

    /// T2 for the transient serving read source kind.
    ///
    /// One fresh short transaction, one fresh database clock, the migration-146
    /// pin row `FOR SHARE`. The opaque value is sealed inside that window and is
    /// returned only when the bounded rollback also succeeded.
    async fn revalidate_serving(
        &self,
        pool: &Pool,
        registered: &RegisteredServingRead,
        native: NativeReadClosure,
        deadline: Instant,
    ) -> Result<MaterializedPackRead, RefStoreError> {
        let mut client = pooled_client(pool, deadline).await?;
        let tx = begin_bounded(&mut client, deadline).await?;
        let result = async {
            let fresh = pg::before_deadline(
                deadline,
                revalidate_serving_capture(&tx, registered, self.store_identity.as_hex(), deadline),
            )
            .await?;
            if fresh != registered.snapshot || fresh.materialization_digest() != registered.binding {
                return Err(RefStoreError::MetadataScopeMismatch("serving read changed during materialization"));
            }
            let binding = fresh.materialization_digest();
            if binding != registered.binding {
                return Err(RefStoreError::MetadataScopeMismatch(
                    "serving read binding changed during materialization",
                ));
            }
            // The opaque native closure must carry exactly the digest T2 just
            // recomputed, not merely the digest the capture computed.
            if native.read_digest() != binding {
                return Err(RefStoreError::MetadataScopeMismatch(
                    "materialized native closure binding differs from the revalidated serving read",
                ));
            }
            Ok(fresh)
        }
        .await;
        let sealed = result.map(|fresh| {
            let read_digest = native.read_digest_hex();
            MaterializedPackRead { snapshot: fresh, native, read_digest }
        });
        let cleanup = match tokio::time::timeout_at(deadline, tx.rollback()).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(RefStoreError::Database("serving read transaction cleanup failed".into())),
            Err(_) => Err(RefStoreError::Timeout),
        };
        match (sealed, cleanup) {
            (Ok(view), Ok(())) => Ok(view),
            (Err(error), _) => Err(error),
            (Ok(_dropped), Err(error)) => Err(error),
        }
    }

    /// T2: one fresh short transaction under the retained pin `FOR SHARE`.
    ///
    /// The read linearization point is the final fresh DB-clock/liveness check
    /// under that lock: the sealed owned result is built there, then the
    /// transaction is cleaned up under the same absolute deadline and only a
    /// successful cleanup returns it. A mutation ordered after that point may
    /// complete first; it cannot invalidate the already-linearized local copy.
    /// A failed or unknown cleanup returns no public value at all.
    async fn revalidate(
        &self,
        pool: &Pool,
        reference: &PackSnapshotRef,
        prepared: &PreparedReadClosure,
        native: NativeReadClosure,
        deadline: Instant,
    ) -> Result<MaterializedPackRead, RefStoreError> {
        let mut client = pooled_client(pool, deadline).await?;
        let tx = begin_bounded(&mut client, deadline).await?;
        let result = async {
            let fresh = pg::before_deadline(deadline, PgPackSnapshot.read_checked(&tx, reference, deadline)).await?;
            if fresh != prepared.snapshot || fresh.materialization_digest() != prepared.binding {
                return Err(RefStoreError::MetadataScopeMismatch("pack snapshot changed during materialization"));
            }
            // All potentially slow ledger/ref/pack reads are done. Both terminal
            // statements run under the same transaction (pin FOR SHARE still
            // held), under the SAME absolute deadline as every earlier SQL stage:
            // the fresh pin row and then a fresh DB clock. Neither is unbounded.
            let (pin, now) = pg::before_deadline(deadline, async {
                let pin = snapshot_sql::pin_for_share(&tx, reference.pin_id(), reference.repository_id())
                    .await?
                    .ok_or(RefStoreError::MetadataPinNotFound { pin_id: reference.pin_id() })?;
                let row = tx
                    .query_one("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint", &[])
                    .await
                    .map_err(pg::db_error)?;
                let now: i64 = row.get(0);
                Ok::<_, RefStoreError>((pin, now))
            })
            .await?;
            // Scope/generation/expiry are checked immediately before the public
            // value may exist; the initial `pin_for_share` flag is never trusted
            // on its own.
            pin.ensure_scope(fresh.scope(), fresh.snapshot_id())?;
            pin.ensure_live(reference.expected_generation())?;
            if pin.expires_at_unix_micros <= now {
                return Err(RefStoreError::MetadataPinExpired { pin_id: pin.pin_id, generation: pin.generation });
            }
            Ok(fresh)
        }
        .await;
        // Still under the retained pin `FOR SHARE`: nothing has been rolled back
        // yet, so these pure bindings and the sealed value stay inside the
        // linearization window opened by the final fresh-clock check.
        let sealed = result.and_then(|fresh| {
            let binding = fresh.materialization_digest();
            if binding != prepared.binding {
                return Err(RefStoreError::MetadataScopeMismatch(
                    "pack snapshot binding changed during materialization",
                ));
            }
            // T2 requires the opaque native closure to carry exactly the complete
            // digest it just recomputed, not merely the digest T1 computed.
            if native.read_digest() != binding {
                return Err(RefStoreError::MetadataScopeMismatch(
                    "materialized native closure binding differs from the revalidated read",
                ));
            }
            let read_digest = native.read_digest_hex();
            Ok(MaterializedPackRead { snapshot: fresh, native, read_digest })
        });
        // Bounded cleanup under the SAME absolute deadline. The sealed value is
        // returned only when cleanup succeeded; a timeout or a failed rollback
        // drops it and reports no public result at all.
        let cleanup = match tokio::time::timeout_at(deadline, tx.rollback()).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(RefStoreError::Database("materialized read transaction cleanup failed".into())),
            Err(_) => Err(RefStoreError::Timeout),
        };
        match (sealed, cleanup) {
            (Ok(view), Ok(())) => Ok(view),
            (Err(error), _) => Err(error),
            (Ok(_dropped), Err(error)) => Err(error),
        }
    }
}

/// Opaque owned materialized read view. Not `Clone`, not `Serialize`, no public
/// constructor and no write/publish/serving capability.
pub struct MaterializedPackRead {
    snapshot: PackReadSnapshot,
    native: NativeReadClosure,
    read_digest: String,
}

/// Pure binding step of the sealed builder: the capture must be the very
/// snapshot T2 revalidated, and only the native closure's A5b digest — compared
/// with the capture's own A5b binding — may seal.
fn serving_materialization(
    view: MaterializedPackRead,
    capture: &ServingReadCapture,
) -> Result<MaterializedServingRead, RefStoreError> {
    let (captured, binding) = capture.registered_parts()?;
    if *view.snapshot() != captured {
        return Err(RefStoreError::MetadataScopeMismatch("materialized serving read is not its capture"));
    }
    let proof = VerifiedReadView::of_revalidated(view.snapshot(), binding)?.seal();
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
}

impl MaterializedPackRead {
    pub(super) fn snapshot(&self) -> &PackReadSnapshot {
        &self.snapshot
    }
    /// The actual A5b binding: the native closure's digest, which T2 compared
    /// with its freshly recomputed materialization digest before this view
    /// existed. Never the narrower A5a read digest.
    pub(super) fn proven_binding(&self) -> RequestDigest {
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
    /// membership and full pack identity digests. Never the incomplete A5a
    /// read digest alone.
    pub fn read_digest_hex(&self) -> &str {
        &self.read_digest
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

/// Map the private native refusal into the shared error vocabulary without ever
/// promoting Git text, argv, a path, a locator or provider text.
fn map_native_error(error: PackCommitError) -> RefStoreError {
    match error {
        PackCommitError::RefStore(error) => error,
        PackCommitError::Invalid(_) => RefStoreError::Unsupported("materialized read metadata is not valid"),
        PackCommitError::Capacity { .. } => {
            RefStoreError::Unsupported("materialized read exceeds a fixed verifier bound")
        }
        PackCommitError::Rejected(rejection) => match rejection.code {
            pack_commit::PackCommitRejectCode::TenantMismatch
            | pack_commit::PackCommitRejectCode::ObjectFormatMismatch
            | pack_commit::PackCommitRejectCode::HistoryIncarnationMismatch
            | pack_commit::PackCommitRejectCode::AuthorityEpochMismatch
            | pack_commit::PackCommitRejectCode::GroupEpochMismatch => {
                RefStoreError::MetadataScopeMismatch("materialized read realm")
            }
            _ => RefStoreError::Database("native materialized read ledger was refused".into()),
        },
        PackCommitError::ProofUnavailable(_) => {
            RefStoreError::Unsupported("native materialized read verification is unavailable")
        }
        PackCommitError::CommitUnknown { .. } => RefStoreError::Unsupported("materialized read never commits"),
    }
}

#[cfg(test)]
mod serving_tests;
