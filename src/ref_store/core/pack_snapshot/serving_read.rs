//! Bounded TRANSIENT serving read pins (issue #107/#114/#144).
//!
//! The durable A5a path ([`super::PgPackSnapshot::create`]) is retained,
//! immutable and quota-bounded at 64 snapshots/pins per repository. It is the
//! right shape for a *retained* snapshot, but it is the wrong shape for a
//! per-GET serving read: every GET would append another permanent snapshot, pin,
//! receipt and history row and the gateway would hit that quota after 64 reads.
//!
//! This module adds the second, deliberately disjoint family: one **transient**
//! serving read pin (migration 146) that protects exactly one read, captures the
//! current refs/HEAD/registered membership atomically, is bounded per
//! repository/tenant and is deleted on release or reclaimed after its bounded
//! lease. The retained family, its source kind, its T2 SQL and its counters are
//! untouched.
//!
//! # What one capture proves
//!
//! Under the SAME strict `pg_refstore` serving authority every durable path uses
//! (repository lane + ready durable serving binding + binding realm equal to the
//! locked core gate realm + binding Blob backend digest equal to the identity of
//! the store the caller actually opened) and under the core gate `FOR UPDATE`
//! that `CommitRefs` and the A4 verified commit also take, [`PgServingReads::capture`]:
//!
//! 1. reads the current `pack_mode` (unlocked) only to choose the shape;
//! 2. for a `pack_verified` gate takes the ordered transient usage locks, drains
//!    a bounded batch of expired transient rows, and only then locks the
//!    repository/binding/gate and captures **every** ref, HEAD and **every**
//!    active registered membership through the full A4 validated reader
//!    (`read_membership_set`) — including the complete locator/provider/backend/
//!    verified identity of both artifacts of every pack;
//! 3. writes the header, the captured refs and the complete pack descriptors
//!    (with the full artifact rows a future GC enumerates) in the same
//!    transaction, charges the recomputed bounded counters, and commits;
//! 4. for a `metadata_only` gate with no refs and no pack membership returns a
//!    distinct **typed empty capture** and writes nothing. It never fabricates a
//!    [`PackReadSnapshot`]: that value requires a non-empty verified pack set.
//!
//! No PostgreSQL client, transaction or lease is held while Blob/native Git IO
//! runs: the capture transaction is finished before the caller materializes, and
//! the final T2 recheck ([`super::PgPackSnapshotMaterializer::materialize_serving_read`])
//! reacquires PostgreSQL under one absolute deadline.
//!
//! # What it does not claim
//!
//! A capture is metadata only. It is not a Git read snapshot, not a byte proof,
//! not write authority, and it does not resurrect, refund or renew any durable
//! snapshot, pin, receipt, history row, root or decision row.
//!
//! # Leak and expiry bounds
//!
//! An unacknowledged capture `COMMIT` can leave a transient row behind, but that
//! row is bounded by the same per-repository/tenant lease and byte caps and is
//! reclaimed by later captures after its own bounded lease expires. There is no
//! permanent read receipt and no forever ledger to reconcile.
//!
//! # GC note
//!
//! Physical Blob deletion is disabled by default in this service. Any future GC
//! that deletes pack/idx objects MUST enumerate the active rows of migration-146
//! (`ref_store_core_serving_read_protection(uuid)`) in its protected set; a
//! transient row protects its packs only until `expires_at`.
use super::super::pack_commit::{self, CapturedRef, PackMode};
use super::super::snapshot_contract::{
    MAX_SNAPSHOT_REFS, MetadataSnapshotScope, refs_digest, snapshot_budget_guard, snapshot_logical_bytes,
};
use super::contract as pack_contract;
use super::materialize::{effective_deadline, pooled_client};
use super::read_snapshot::{PackReadSnapshot, ReadSnapshotParts};
use super::serving_read_request::{
    check_admission, check_read_shape, serving_capture_digest, serving_empty_capture_digest,
    serving_read_logical_bytes, validate_lease,
};
use super::serving_read_sql::{self, ServingReadInsert};
use crate::blob_store::BlobBackendIdentity;
use crate::ref_store::contract::{RefStoreError, RequestDigest};
use crate::ref_store::core::snapshot_sql;
use crate::ref_store::pg;
use crate::ref_store::tx::{begin_bounded, commit_bounded};
use deadpool_postgres::Pool;
use tokio::time::{Instant, timeout_at};
use tokio_postgres::Transaction;
use uuid::Uuid;

/// Stateless adapter for the bounded transient serving read pin.
#[derive(Clone, Copy, Debug, Default)]
pub struct PgServingReads;

/// One opaque serving read capture.
///
/// It has no `Clone`, no `Serialize`/`Deserialize`, no public constructor and no
/// caller-chosen identity: the pin/snapshot ids are minted internally and are
/// never reused. A capture is either a checked **empty** repository observation
/// ([`Self::is_empty`]) or a complete registered-pack capture whose
/// [`Self::registered_snapshot`] carries the real
/// [`PackReadSnapshot::source_kind`] = [`super::ReadSnapshotSourceKind::ServingTransient`].
pub struct ServingReadCapture {
    inner: CaptureInner,
}

enum CaptureInner {
    Empty(EmptyRepositoryCapture),
    Registered(Box<RegisteredServingRead>),
}

struct EmptyRepositoryCapture {
    scope: MetadataSnapshotScope,
    gate_revision: i64,
    gate_digest: String,
    head_ref: String,
    capture_digest: RequestDigest,
}

/// The registered (non-empty) capture internals, visible inside this module
/// subtree only so the materializer can run its source-kind-specific T2.
pub(super) struct RegisteredServingRead {
    pub(super) snapshot: PackReadSnapshot,
    pub(super) binding: RequestDigest,
}

impl ServingReadCapture {
    fn empty(
        scope: MetadataSnapshotScope,
        gate_revision: i64,
        gate_digest: String,
        head_ref: String,
        capture_digest: RequestDigest,
    ) -> Self {
        Self {
            inner: CaptureInner::Empty(EmptyRepositoryCapture {
                scope,
                gate_revision,
                gate_digest,
                head_ref,
                capture_digest,
            }),
        }
    }

    fn registered(snapshot: PackReadSnapshot) -> Self {
        let binding = snapshot.materialization_digest();
        Self { inner: CaptureInner::Registered(Box::new(RegisteredServingRead { snapshot, binding })) }
    }

    /// A checked empty repository has no packs and therefore no byte protection
    /// to pin. It is never a [`PackReadSnapshot`].
    pub fn is_empty(&self) -> bool {
        matches!(self.inner, CaptureInner::Empty(_))
    }

    /// The complete registered-pack snapshot, or `None` for a checked empty
    /// repository capture.
    pub fn registered_snapshot(&self) -> Option<&PackReadSnapshot> {
        match &self.inner {
            CaptureInner::Empty(_) => None,
            CaptureInner::Registered(registered) => Some(&registered.snapshot),
        }
    }

    pub fn scope(&self) -> &MetadataSnapshotScope {
        match &self.inner {
            CaptureInner::Empty(empty) => &empty.scope,
            CaptureInner::Registered(registered) => registered.snapshot.scope(),
        }
    }

    pub fn repository_id(&self) -> Uuid {
        self.scope().repository_id()
    }

    pub fn tenant_id(&self) -> Uuid {
        self.scope().tenant_id()
    }

    pub fn head_ref(&self) -> &str {
        match &self.inner {
            CaptureInner::Empty(empty) => &empty.head_ref,
            CaptureInner::Registered(registered) => registered.snapshot.head_ref(),
        }
    }

    /// The captured gate revision; a later refs commit does not invalidate the
    /// captured bytes of a registered capture (they are protected by the pin).
    pub fn gate_revision(&self) -> i64 {
        match &self.inner {
            CaptureInner::Empty(empty) => empty.gate_revision,
            CaptureInner::Registered(registered) => registered.snapshot.gate_revision(),
        }
    }

    pub fn gate_digest_hex(&self) -> &str {
        match &self.inner {
            CaptureInner::Empty(empty) => &empty.gate_digest,
            CaptureInner::Registered(registered) => registered.snapshot.gate_digest_hex(),
        }
    }

    /// The transient pin id; `None` for a checked empty repository capture.
    pub fn pin_id(&self) -> Option<Uuid> {
        match &self.inner {
            CaptureInner::Empty(_) => None,
            CaptureInner::Registered(registered) => Some(registered.snapshot.pin_id()),
        }
    }

    pub fn pin_generation(&self) -> Option<i64> {
        match &self.inner {
            CaptureInner::Empty(_) => None,
            CaptureInner::Registered(registered) => Some(registered.snapshot.pin_generation()),
        }
    }

    /// Database-clock lease expiry of the transient pin, if any.
    pub fn expires_at_unix_micros(&self) -> Option<i64> {
        match &self.inner {
            CaptureInner::Empty(_) => None,
            CaptureInner::Registered(registered) => Some(registered.snapshot.expires_at_unix_micros()),
        }
    }

    /// Canonical digest of this capture.
    ///
    /// Registered captures return the complete A5b materialization digest (which
    /// binds the source kind, scope, both identities, expiry, refs/HEAD,
    /// membership and every full pack identity). Empty captures return their own
    /// dedicated empty-capture digest. Neither value is a byte proof.
    pub fn capture_digest_hex(&self) -> String {
        match &self.inner {
            CaptureInner::Empty(empty) => empty.capture_digest.as_hex(),
            CaptureInner::Registered(registered) => registered.binding.as_hex(),
        }
    }

    /// The registered snapshot (cloned) plus its complete A5b binding digest.
    /// Used by the materializer, which must keep the capture alive so the caller
    /// can release it after the local view is built.
    pub(super) fn registered_parts(&self) -> Result<(PackReadSnapshot, RequestDigest), RefStoreError> {
        match &self.inner {
            CaptureInner::Registered(registered) => Ok((registered.snapshot.clone(), registered.binding)),
            CaptureInner::Empty(_) => Err(RefStoreError::Unsupported(
                "an empty serving read capture has no registered pack bytes to materialize",
            )),
        }
    }

    /// `(pin_id, generation, snapshot, tenant_id, repository_id)` for the release
    /// path; `None` for a checked empty capture, which owns no row.
    fn release_identity(&self) -> Option<(Uuid, i64, &PackReadSnapshot, Uuid, Uuid)> {
        match &self.inner {
            CaptureInner::Empty(_) => None,
            CaptureInner::Registered(registered) => {
                let snapshot = &registered.snapshot;
                Some((
                    snapshot.pin_id(),
                    snapshot.pin_generation(),
                    snapshot,
                    snapshot.tenant_id(),
                    snapshot.repository_id(),
                ))
            }
        }
    }
}

/// Roll one failed short transaction back under the caller's **original**
/// absolute deadline.
///
/// The cleanup wait is bounded by the same instant that bounded the work, so a
/// capture/release failure can never hang on an unresolved server-side lock
/// wait: the caller gets its original error and no rollback is allowed to extend
/// the call past its own deadline. When that instant has already passed,
/// `timeout_at` elapses immediately and dropping the SDK rollback future still
/// queues `ROLLBACK` on the connection (see [`crate::ref_store::tx`]), so the
/// session is never left in an open transaction Rust no longer owns.
async fn rollback_bounded(tx: Transaction<'_>, deadline: Instant) {
    let _ = timeout_at(deadline, tx.rollback()).await;
}

impl PgServingReads {
    /// Capture one bounded transient serving read under the strict serving
    /// authority, minting the pin/snapshot identity internally.
    ///
    /// `lease_seconds` is bounded to `1..=300`. The whole call (pool wait, every
    /// SQL stage and `COMMIT`) is bounded by one absolute `deadline`; it performs
    /// no Blob or Git IO. A changed realm/backend, a non-serving lane, a
    /// `metadata_only` gate that already has refs, or an exhausted transient
    /// bound is a typed refusal with zero rows written.
    pub async fn capture(
        &self,
        pool: &Pool,
        scope: &MetadataSnapshotScope,
        backend: &BlobBackendIdentity,
        lease_seconds: u32,
        deadline: Instant,
    ) -> Result<ServingReadCapture, RefStoreError> {
        let lease_seconds = validate_lease(lease_seconds)?;
        let deadline = effective_deadline(deadline)?;
        // (0) Bounded, SEPARATELY COMMITTED expired-row cleanup before the
        // capture attempt. Admission is decided against counters that include
        // expired-but-not-yet-reclaimed rows, so a reclaim that shares the
        // capture transaction is undone whenever that capture is refused; the
        // tenant would then delete the same oldest batch on every retry and
        // could never drain its backlog. This batch commits on its own.
        let _reclaimed = cleanup_expired_once(pool, scope, deadline).await;
        let mut client = pooled_client(pool, deadline).await?;
        let repository_id = scope.repository_id();
        let tx = begin_bounded(&mut client, deadline).await?;
        let result =
            pg::before_deadline(deadline, capture_checked(&tx, scope, backend.as_hex(), lease_seconds, deadline)).await;
        match result {
            Ok(capture) => {
                commit_bounded(tx, deadline, repository_id, None).await?;
                Ok(capture)
            }
            Err(error) => {
                rollback_bounded(tx, deadline).await;
                Err(error)
            }
        }
    }

    /// Release exactly the transient pin this capture minted.
    ///
    /// Only the exact immutable pin identity/generation and captured realm are
    /// released; the row is then deleted (no permanent read receipt is kept and
    /// no durable counter is refunded or touched). Releasing after the local
    /// materialized view is complete is the intended usage; releasing an
    /// already-released, reclaimed or expired row is an idempotent success
    /// because nothing is protected any more. A checked empty capture owns no
    /// row and always releases successfully.
    ///
    /// Deadline discipline: the database-side `lock_timeout`/`statement_timeout`
    /// are set from the caller's absolute deadline *before* this transaction's
    /// first SQL statement, so a usage-row or pin-row lock wait can never outlive
    /// it, and a failed release is rolled back under that same instant (never
    /// under an extended cleanup budget). Only an acknowledged `COMMIT` (or an
    /// acknowledged absence of the row) is reported as a successful release.
    pub async fn release(
        &self,
        pool: &Pool,
        capture: &ServingReadCapture,
        deadline: Instant,
    ) -> Result<(), RefStoreError> {
        let Some((pin_id, generation, snapshot, tenant_id, repository_id)) = capture.release_identity() else {
            return Ok(());
        };
        let scope = *snapshot.scope();
        let snapshot_id = snapshot.snapshot_id();
        let deadline = effective_deadline(deadline)?;
        let mut client = pooled_client(pool, deadline).await?;
        let tx = begin_bounded(&mut client, deadline).await?;
        let result = pg::before_deadline(deadline, async {
            // Database-side lock/statement budget (from this same absolute
            // deadline) before the first SQL statement of this transaction, so
            // a usage-row lock wait can never outlive the caller's deadline.
            pg::bound(&tx, deadline).await?;
            // Usage rows first: the same tenant -> repository order every A5
            // write path uses, so release can never deadlock with a capture.
            let _ = serving_read_sql::lock_usage(&tx, tenant_id, repository_id).await?;
            let Some(row) = serving_read_sql::load_read(&tx, pin_id, repository_id, Some("update")).await? else {
                // Already released/reclaimed/cascaded away: nothing is protected.
                return Ok(());
            };
            row.ensure_capture_identity(&scope, snapshot_id, generation)?;
            serving_read_sql::delete_read(&tx, pin_id, repository_id, generation).await?;
            serving_read_sql::recompute_usage(&tx, tenant_id, repository_id).await?;
            Ok(())
        })
        .await;
        match result {
            Ok(()) => {
                commit_bounded(tx, deadline, repository_id, None).await?;
                Ok(())
            }
            Err(error) => {
                rollback_bounded(tx, deadline).await;
                Err(error)
            }
        }
    }
}

/// Commit one bounded batch of expired-row reclaim in its **own** transaction
/// *before* the capture attempt, so a later refusal can never roll it back.
///
/// This closes a real liveness bug: `capture_registered` deletes at most
/// `MAX_EXPIRED_SERVING_READ_RECLAIM` expired rows and then admits against the
/// recomputed counters *inside the same transaction*. Because those counters
/// deliberately include the bytes of expired-but-not-yet-reclaimed rows, an
/// admission refusal made the outer rollback undo exactly that reclaim, so every
/// retry deleted the same oldest rows and a tenant whose expired backlog pushed
/// it over the byte bound could never drain it.
///
/// The cleanup is bounded and independent: one transaction, at most
/// `MAX_EXPIRED_SERVING_READ_RECLAIM` rows, the frozen tenant -> repository
/// usage lock order, and no row is ever *created* (the probe runs first, so a
/// scope with nothing to reclaim writes nothing and is simply rolled back). It
/// keeps no receipt, no history and no per-request ledger; the only effect is
/// that an expired row can disappear sooner than the next successful capture.
/// A cleanup failure is never promoted into the caller's capture result.
async fn cleanup_expired_once(pool: &Pool, scope: &MetadataSnapshotScope, deadline: Instant) -> u64 {
    let tenant_id = scope.tenant_id();
    let repository_id = scope.repository_id();
    let Ok(mut client) = pooled_client(pool, deadline).await else {
        return 0;
    };
    let Ok(tx) = begin_bounded(&mut client, deadline).await else {
        return 0;
    };
    let result = pg::before_deadline(deadline, async {
        pg::bound(&tx, deadline).await?;
        if !serving_read_sql::has_expired(&tx, tenant_id).await? {
            return Ok(0_u64);
        }
        // Frozen lock order: tenant usage -> repository usage, exactly like
        // every other A5 write path, so this can never deadlock with a capture
        // or a release.
        let _ = serving_read_sql::lock_usage(&tx, tenant_id, repository_id).await?;
        let reclaimed = serving_read_sql::reclaim_expired(&tx, tenant_id).await?;
        serving_read_sql::recompute_usage(&tx, tenant_id, repository_id).await?;
        Ok::<u64, RefStoreError>(reclaimed)
    })
    .await;
    match result {
        // Only an acknowledged COMMIT is progress. Anything else (including an
        // unknown commit) leaves the rows where they were, which is still
        // consistent because every writer recomputes the counters.
        Ok(reclaimed) => match commit_bounded(tx, deadline, repository_id, None).await {
            Ok(()) => reclaimed,
            Err(_) => 0,
        },
        Err(_) => {
            rollback_bounded(tx, deadline).await;
            0
        }
    }
}

/// The capture decision. Read-only for a checked empty repository; exactly one
/// atomic write set for a registered-pack capture.
async fn capture_checked(
    tx: &Transaction<'_>,
    scope: &MetadataSnapshotScope,
    backend_identity_hex: &str,
    lease_seconds: i64,
    deadline: Instant,
) -> Result<ServingReadCapture, RefStoreError> {
    pg::bound(tx, deadline).await?;
    match serving_read_sql::peek_pack_mode(tx, scope.repository_id()).await? {
        PackMode::MetadataOnly => capture_empty(tx, scope, backend_identity_hex, deadline).await,
        PackMode::PackVerified => capture_registered(tx, scope, backend_identity_hex, lease_seconds, deadline).await,
    }
}

/// A `metadata_only` gate is a repository with no verified pack bytes yet. It is
/// always refused for refs (refs without pack bytes cannot be served) and it must
/// not have any registered membership. The result is a distinct typed empty
/// capture, never a fabricated [`PackReadSnapshot`].
async fn capture_empty(
    tx: &Transaction<'_>,
    scope: &MetadataSnapshotScope,
    backend_identity_hex: &str,
    deadline: Instant,
) -> Result<ServingReadCapture, RefStoreError> {
    let gate = serving_read_sql::lock_serving_realm(tx, scope, backend_identity_hex, true).await?;
    // Re-prove the shape under the locked gate. `metadata_only` never downgrades
    // from `pack_verified`, so a gate that moved to `pack_verified` between the
    // unlocked peek and this lock is a typed "retry the read" signal instead of a
    // stale empty view.
    if snapshot_sql::gate_pack_mode(tx, scope.repository_id()).await? != PackMode::MetadataOnly {
        return Err(RefStoreError::MetadataGateVersionMismatch);
    }
    let refs = snapshot_sql::capture_refs(tx, scope.repository_id()).await?;
    let packs = pack_commit::read_membership_set(tx, &gate, deadline).await.map_err(pack_contract::map_pack_error)?;
    if !refs.is_empty() {
        return Err(RefStoreError::Unsupported("metadata-only serving repository has refs but no verified pack bytes"));
    }
    if !packs.is_empty() {
        return Err(RefStoreError::Database("metadata-only serving gate carries a registered pack membership".into()));
    }
    let head_ref = gate.head_ref().as_str().to_owned();
    let capture_digest =
        serving_empty_capture_digest(scope, backend_identity_hex, gate.revision(), &gate.digest().as_hex(), &head_ref);
    Ok(ServingReadCapture::empty(*scope, gate.revision(), gate.digest().as_hex(), head_ref, capture_digest))
}

/// A `pack_verified` capture: bounded transient admission, then the same atomic
/// capture as A5a (every ref, HEAD and every active registered membership) under
/// the gate `FOR UPDATE`, then one write set that also records the complete pack
/// descriptors a future GC enumerates.
async fn capture_registered(
    tx: &Transaction<'_>,
    scope: &MetadataSnapshotScope,
    backend_identity_hex: &str,
    lease_seconds: i64,
    deadline: Instant,
) -> Result<ServingReadCapture, RefStoreError> {
    // (1) Ordered transient usage locks, bounded reclaim, exact counters.
    let _ = serving_read_sql::lock_usage(tx, scope.tenant_id(), scope.repository_id()).await?;
    serving_read_sql::reclaim_expired(tx, scope.tenant_id()).await?;
    serving_read_sql::recompute_usage(tx, scope.tenant_id(), scope.repository_id()).await?;
    let (tenant_usage, repository_usage) =
        serving_read_sql::read_usage(tx, scope.tenant_id(), scope.repository_id()).await?;

    // (2) Strict serving authority + gate `FOR UPDATE`: refs, HEAD and pack
    // memberships are one revision and cannot race `CommitRefs`/A4.
    let gate = serving_read_sql::lock_serving_realm(tx, scope, backend_identity_hex, true).await?;
    if snapshot_sql::gate_pack_mode(tx, scope.repository_id()).await? != PackMode::PackVerified {
        return Err(RefStoreError::Database("serving read gate changed pack mode while it was locked".into()));
    }
    let refs = snapshot_sql::capture_refs(tx, scope.repository_id()).await?;
    let head_ref = gate.head_ref().as_str().to_owned();
    let head_oid = refs.iter().find(|(name, _)| name == &head_ref).map(|(_, oid)| oid.clone());
    snapshot_budget_guard(snapshot_logical_bytes(&head_ref, head_oid.as_deref(), &refs), refs.len())?;

    // (3) Complete registered membership through the full A4 reader.
    let packs = pack_commit::read_membership_set(tx, &gate, deadline).await.map_err(pack_contract::map_pack_error)?;
    if packs.is_empty() {
        return Err(RefStoreError::Database("pack_verified gate has no active registered pack membership".into()));
    }
    check_read_shape(refs.len(), packs.len())?;
    let entries = pack_contract::membership_entries(&packs)?;
    let membership_hex = pack_contract::membership_digest(&packs)?.as_hex();
    let refs_digest_hex = refs_digest(&refs).as_hex();
    let ref_count = i64::try_from(refs.len()).unwrap_or(i64::MAX);
    let pack_count = i64::try_from(packs.len()).unwrap_or(i64::MAX);
    let logical_bytes = serving_read_logical_bytes(&head_ref, head_oid.as_deref(), &refs, &packs);
    check_admission(repository_usage, tenant_usage, logical_bytes)?;

    // (4) One atomic write set with internally minted, never reused identities.
    let pin_id = Uuid::new_v4();
    let snapshot_id = Uuid::new_v4();
    let gate_digest_hex = gate.digest().as_hex();
    let snapshot_digest_hex = serving_capture_digest(
        scope,
        snapshot_id,
        pin_id,
        1,
        backend_identity_hex,
        gate.revision(),
        &gate_digest_hex,
        &head_ref,
        head_oid.as_deref(),
        ref_count,
        &refs_digest_hex,
        pack_count,
        &membership_hex,
    )
    .as_hex();
    let expires_at_unix_micros = serving_read_sql::insert_read(
        tx,
        &ServingReadInsert {
            pin_id,
            snapshot_id,
            scope,
            backend_identity: backend_identity_hex,
            gate_revision: gate.revision(),
            gate_digest: &gate_digest_hex,
            head_ref: &head_ref,
            head_oid: head_oid.as_deref(),
            refs: &refs,
            packs: &packs,
            entries: &entries,
            refs_digest: &refs_digest_hex,
            membership_digest: &membership_hex,
            snapshot_digest: &snapshot_digest_hex,
            logical_bytes,
            lease_seconds,
        },
    )
    .await?;
    serving_read_sql::recompute_usage(tx, scope.tenant_id(), scope.repository_id()).await?;

    // (5) The sealed value is built from the values that were written, and every
    // ref is revalidated into the shared captured-ref vocabulary.
    let mut captured_refs = Vec::with_capacity(refs.len());
    for (name, oid) in refs {
        captured_refs.push(
            CapturedRef::from_stored(scope.object_format(), name, oid)
                .map_err(|_| RefStoreError::Database("captured serving read ref row is invalid".into()))?,
        );
    }
    let snapshot = PackReadSnapshot::new_serving_transient(ReadSnapshotParts {
        snapshot_id,
        pin_id,
        pin_generation: 1,
        scope: *scope,
        gate_revision: gate.revision(),
        gate_digest: gate_digest_hex,
        head_ref,
        head_oid,
        refs: captured_refs,
        packs,
        membership_digest: membership_hex,
        snapshot_digest: snapshot_digest_hex,
        logical_bytes,
        expires_at_unix_micros,
    })?;
    Ok(ServingReadCapture::registered(snapshot))
}

/// Source-kind-specific T2 for a registered serving read capture.
///
/// It runs in the caller's (materializer-owned) short transaction, holds the
/// transient pin row `FOR SHARE` and re-proves everything the capture proved:
///
/// * the current strict serving authority (repository lane, ready binding,
///   captured realm and the live Blob backend digest of the store the
///   materializer actually holds) — a history-incarnation/authority/group epoch
///   move, a new authority or a foreign backend is refused;
/// * the stored transient row's immutable identity/generation/scope;
/// * every captured ref and the complete captured registered pack set, rebuilt
///   from the stored descriptors (digests re-derived, never trusted);
/// * the stored capture digest and logical-byte accounting;
/// * a fresh database-clock liveness check on the retained lease.
///
/// A later gate *revision* within the same live history is accepted: the captured
/// bytes are protected by this pin, not by the current refs.
pub(super) async fn revalidate_serving_capture(
    tx: &Transaction<'_>,
    registered: &RegisteredServingRead,
    backend_identity_hex: &str,
    deadline: Instant,
) -> Result<PackReadSnapshot, RefStoreError> {
    pg::bound(tx, deadline).await?;
    let expected = &registered.snapshot;
    let scope = expected.scope();
    let pin_id = expected.pin_id();
    let generation = expected.pin_generation();
    let repository_id = scope.repository_id();

    // (1) Same live strict serving realm (gate `FOR SHARE`, no refs write can
    // interleave with this check) and the same live physical backend.
    let _gate = serving_read_sql::lock_serving_realm(tx, scope, backend_identity_hex, false).await?;
    let row = serving_read_sql::load_read(tx, pin_id, repository_id, Some("share"))
        .await?
        .ok_or(RefStoreError::MetadataPinNotFound { pin_id })?;
    row.ensure_capture_identity(scope, expected.snapshot_id(), generation)?;
    if row.backend_identity != backend_identity_hex {
        return Err(RefStoreError::MetadataScopeMismatch("serving read Blob backend identity"));
    }
    if row.expired {
        return Err(RefStoreError::MetadataPinExpired { pin_id, generation });
    }

    // (2) Rebuild and revalidate every captured ref and pack descriptor.
    let refs = serving_read_sql::read_refs(tx, pin_id).await?;
    if refs.len() > MAX_SNAPSHOT_REFS {
        return Err(RefStoreError::MetadataSnapshotTooLarge { ref_count: refs.len(), max_refs: MAX_SNAPSHOT_REFS });
    }
    let head_oid = refs.iter().find(|(name, _)| name == &row.head_ref).map(|(_, oid)| oid.clone());
    if head_oid != row.head_oid {
        return Err(RefStoreError::Database("stored serving read HEAD disagrees with its captured ref rows".into()));
    }
    let packs = serving_read_sql::read_packs(tx, pin_id).await?;
    if i64::try_from(packs.len()).unwrap_or(i64::MAX) != row.pack_count {
        return Err(RefStoreError::Database(
            "stored serving read pack count disagrees with its captured descriptors".into(),
        ));
    }
    let membership_hex = pack_contract::membership_digest(&packs)?.as_hex();
    if membership_hex != row.membership_digest {
        return Err(RefStoreError::Database(
            "stored serving read membership digest disagrees with its captured packs".into(),
        ));
    }
    serving_read_sql::check_capture_digest(&row, scope, &refs, &packs, &membership_hex)?;

    // (3) The sealed value, identical to what the capture produced.
    let mut captured_refs = Vec::with_capacity(refs.len());
    for (name, oid) in refs {
        captured_refs.push(
            CapturedRef::from_stored(scope.object_format(), name, oid)
                .map_err(|_| RefStoreError::Database("stored serving read ref row is invalid".into()))?,
        );
    }
    PackReadSnapshot::new_serving_transient(ReadSnapshotParts {
        snapshot_id: row.snapshot_id,
        pin_id: row.pin_id,
        pin_generation: row.generation,
        scope: *scope,
        gate_revision: row.gate_revision,
        gate_digest: row.gate_digest,
        head_ref: row.head_ref,
        head_oid: row.head_oid,
        refs: captured_refs,
        packs,
        membership_digest: membership_hex,
        snapshot_digest: row.snapshot_digest,
        logical_bytes: row.logical_bytes,
        expires_at_unix_micros: row.expires_at_unix_micros,
    })
}
