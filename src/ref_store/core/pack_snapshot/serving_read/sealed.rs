//! Sealed capture/T2 helpers for the #174 cluster-authority anchor.
//!
//! Extracted from `serving_read.rs` to keep that pre-existing module at or
//! below its `origin/main` line count. Only the parent calls these functions;
//! the opaque capture type and its private constructors stay in the parent.

use super::{RegisteredServingRead, ServingReadCapture};
use crate::ref_store::contract::RefStoreError;
use crate::ref_store::core::pack_commit::{self, CapturedRef, PackMode};
use crate::ref_store::core::snapshot_contract::{
    MAX_SNAPSHOT_REFS, MetadataSnapshotScope, refs_digest, snapshot_budget_guard, snapshot_logical_bytes,
};
use crate::ref_store::core::snapshot_sql;
use crate::ref_store::pg;
use tokio::time::Instant;
use tokio_postgres::Transaction;
use uuid::Uuid;

use super::super::contract as pack_contract;
use super::super::read_snapshot::{PackReadSnapshot, ReadSnapshotParts};
use super::super::serving_read_request::{
    check_admission, check_read_shape, serving_capture_digest, serving_empty_capture_digest, serving_read_logical_bytes,
};
use super::super::serving_read_sql::{self, ServingReadInsert};

/// A `metadata_only` gate is a repository with no verified pack bytes yet. It is
/// always refused for refs (refs without pack bytes cannot be served) and it must
/// not have any registered membership. The result is a distinct typed empty
/// capture, never a fabricated [`PackReadSnapshot`].
pub(crate) async fn capture_empty(
    tx: &Transaction<'_>,
    cluster_incarnation: Uuid,
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
    Ok(ServingReadCapture::empty(
        cluster_incarnation,
        *scope,
        gate.revision(),
        gate.digest().as_hex(),
        head_ref,
        capture_digest,
    ))
}

/// A `pack_verified` capture: bounded transient admission, then the same atomic
/// capture as A5a (every ref, HEAD and every active registered membership) under
/// the gate `FOR UPDATE`, then one write set that also records the complete pack
/// descriptors a future GC enumerates.
pub(crate) async fn capture_registered(
    tx: &Transaction<'_>,
    cluster_incarnation: Uuid,
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
    Ok(ServingReadCapture::registered(snapshot, cluster_incarnation))
}

/// Source-kind-specific T2 for a registered serving read capture.
///
/// It runs in the caller's (materializer-owned) short transaction, holds the
/// transient pin row `FOR SHARE` and re-proves everything the capture proved:
///
/// * the global cluster authority incarnation: the singleton is locked `FOR
///   SHARE` first and must still be exactly the capture's anchor, otherwise a
///   typed scope mismatch is returned before any other statement;
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
pub(crate) async fn revalidate_serving_capture(
    tx: &Transaction<'_>,
    registered: &RegisteredServingRead,
    capture_incarnation: Uuid,
    backend_identity_hex: &str,
    deadline: Instant,
) -> Result<PackReadSnapshot, RefStoreError> {
    pg::bound(tx, deadline).await?;
    let expected = &registered.snapshot;
    let scope = expected.scope();
    let pin_id = expected.pin_id();
    let generation = expected.pin_generation();
    let repository_id = scope.repository_id();

    // (0) The restore incarnation is locked and compared first, before any
    // repository/pin/gate lock, in the same global lock order as the capture.
    // `pg::bound` above only sets this transaction's lock/statement budget; it
    // locks no row, so this is still the first row lock taken. A rotation
    // between capture and T2 refuses here; the rotated UUID is never read out
    // and attached to the old capture.
    if serving_read_sql::lock_cluster_incarnation(tx).await? != capture_incarnation {
        return Err(RefStoreError::MetadataScopeMismatch("cluster authority incarnation"));
    }

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
