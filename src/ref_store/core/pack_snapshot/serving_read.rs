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
//! # Cluster authority anchor (#174)
//!
//! Both the capture and T2 read the global restore incarnation
//! (`public.cluster_authority.incarnation`, migration 085) under `FOR SHARE` as
//! the **first** statement of their short transaction (see
//! `serving_read_sql::lock_cluster_incarnation`). The capture keeps that exact
//! UUID in its opaque [`ServingReadCapture`] (registered and checked-empty
//! alike); T2 locks and re-reads the singleton and refuses with
//! `RefStoreError::MetadataScopeMismatch("cluster authority incarnation")` when
//! it is no longer the captured value. A restore rotation between capture and T2
//! therefore never yields a materialized view or a proof, and the newly rotated
//! UUID is never attached to the old capture.
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
use super::super::pack_commit::PackMode;
use super::super::snapshot_contract::MetadataSnapshotScope;
use super::materialize::{effective_deadline, pooled_client};
use super::read_snapshot::PackReadSnapshot;
use super::serving_read_request::validate_lease;
use super::serving_read_sql;
use crate::blob_store::BlobBackendIdentity;
use crate::ref_store::contract::{RefStoreError, RequestDigest};
use crate::ref_store::pg;
use crate::ref_store::tx::{begin_bounded, commit_bounded};
use deadpool_postgres::Pool;
use tokio::time::{Instant, timeout_at};
use tokio_postgres::Transaction;
use uuid::Uuid;

/// Stateless adapter for the bounded transient serving read pin.
mod sealed;

pub(super) use sealed::revalidate_serving_capture;

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
///
/// Every capture also keeps [`Self::capture_incarnation`]: the global cluster
/// authority incarnation its capture transaction locked `FOR SHARE`. It is only
/// ever set by the DB capture path (test fixtures pass an explicit fixed one),
/// travels with the capture into T2, and — after T2 re-proved it — into the
/// sealed proof.
pub struct ServingReadCapture {
    inner: CaptureInner,
    cluster_incarnation: Uuid,
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
        cluster_incarnation: Uuid,
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
            cluster_incarnation,
        }
    }

    /// Test-only registered capture of an already-built test snapshot and an
    /// explicit fixed cluster incarnation; the binding must be that snapshot's
    /// own A5b digest.
    #[cfg(test)]
    pub(super) fn for_test(snapshot: PackReadSnapshot, binding: RequestDigest, cluster_incarnation: Uuid) -> Self {
        debug_assert_eq!(binding, snapshot.materialization_digest());
        debug_assert!(!cluster_incarnation.is_nil());
        Self {
            inner: CaptureInner::Registered(Box::new(RegisteredServingRead { snapshot, binding })),
            cluster_incarnation,
        }
    }

    fn registered(snapshot: PackReadSnapshot, cluster_incarnation: Uuid) -> Self {
        let binding = snapshot.materialization_digest();
        Self {
            inner: CaptureInner::Registered(Box::new(RegisteredServingRead { snapshot, binding })),
            cluster_incarnation,
        }
    }

    /// The cluster authority incarnation this capture transaction locked and
    /// read `FOR SHARE`; T2 must re-read exactly this value before any sealed
    /// materialization exists.
    pub(crate) fn capture_incarnation(&self) -> Uuid {
        self.cluster_incarnation
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

    /// The registered snapshot (cloned), its complete A5b binding digest and the
    /// capture's cluster incarnation anchor (the value T2 compared and the only
    /// incarnation a sealed proof may carry). Used by the materializer, which
    /// must keep the capture alive so the caller can release it after the local
    /// view is built.
    pub(super) fn registered_parts(&self) -> Result<(PackReadSnapshot, RequestDigest, Uuid), RefStoreError> {
        match &self.inner {
            CaptureInner::Registered(registered) => {
                Ok((registered.snapshot.clone(), registered.binding, self.cluster_incarnation))
            }
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
    // (0) The global restore incarnation is read first, before the unlocked
    // shape peek and before any repository/gate/usage lock, so restore's
    // singleton `UPDATE` is this capture's only conflicting writer and the
    // capture anchor is the incarnation every later read in this short
    // transaction is ordered against.
    let cluster_incarnation = serving_read_sql::lock_cluster_incarnation(tx).await?;
    match serving_read_sql::peek_pack_mode(tx, scope.repository_id()).await? {
        PackMode::MetadataOnly => {
            sealed::capture_empty(tx, cluster_incarnation, scope, backend_identity_hex, deadline).await
        }
        PackMode::PackVerified => {
            sealed::capture_registered(tx, cluster_incarnation, scope, backend_identity_hex, lease_seconds, deadline)
                .await
        }
    }
}
