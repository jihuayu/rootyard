//! SQL-only row helpers for the global artifact-hold adapter (A3).
//!
//! Every function here runs inside the one owned short transaction that
//! `super::pg` starts. They contain no commit/rollback logic and never open a
//! connection, so transaction ownership and the rollback policy live in
//! exactly one place.
//!
//! Lock order of every mutation in this module (the adapter takes the exact
//! migration-138 parent operation/issuer-lane prefix first and the immutable
//! receipt rows last):
//!
//! parent 138 operation advisory key -> repository existence -> issuer lane ->
//! 138 pending operation/cancellation rows -> separate-domain global request
//! advisory key -> global shard row -> tenant usage row -> repository usage row
//! -> repository row `FOR SHARE` -> core gate `FOR SHARE` -> sorted hold rows
//! `FOR UPDATE` -> immutable consume receipts.
//!
//! Quota rows are therefore never taken after the repository/gate rows, and
//! hold rows are always locked in `hold_id` order. All reads are bounded by the
//! caller's absolute deadline through the adapter and by the per-statement
//! timeouts set by `crate::ref_store::pg::bound`.
use super::contract::{ArtifactHoldError, HoldScope, ShardId};
use super::quota::{UsageCounts, UsageDelta};
use super::receipt::AcquireAck;
use crate::ref_store::contract::{OperationIdentity, RequestDigest};
use crate::ref_store::core::contract::CoreGate;
use crate::ref_store::core::sql::gate_from_row;
use crate::ref_store::pg::{self, OPERATION_LOCK_DOMAIN, OPERATION_LOCK_SQL};
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

/// Global request identity is independent from the migration-138 operation
/// advisory domain: replay/query of one request id serializes here without
/// touching the parent operation serialization.
const REQUEST_LOCK_DOMAIN: &str = "rootyard-artifact-hold-request-v1";

/// Ack-durability of hold/consume commits. Single-PostgreSQL durability only;
/// no HA/failover or cross-store atomicity is claimed.
pub(super) async fn set_ack_durability(tx: &Transaction<'_>) -> Result<(), ArtifactHoldError> {
    tx.batch_execute("SET LOCAL synchronous_commit = on").await.map_err(pg::db_error)?;
    Ok(())
}

/// First lock of every acquire/consume: one advisory key in the artifact-hold
/// request domain, derived by hashing the stable global request id so it cannot
/// collide with the snapshot adapter's raw request-id keys.
pub(super) async fn request_lock(tx: &Transaction<'_>, request_id: Uuid) -> Result<(), ArtifactHoldError> {
    let digest = RequestDigest::of(REQUEST_LOCK_DOMAIN, &[request_id.as_bytes()]);
    let bytes = digest.as_bytes();
    let first = i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let second = i32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    tx.execute("SELECT pg_advisory_xact_lock($1::int4,$2::int4)", &[&first, &second]).await.map_err(pg::db_error)?;
    Ok(())
}

/// Exact migration-138 parent prefix: the same operation advisory SQL/key,
/// repository existence check and issuer-lane upsert as
/// `PgRefStore::{begin,cancel,record_terminal}`, in the same order. Reusing the
/// exact prefix (not an independent mutex) keeps cancel/commit-vs-hold
/// serialization intact for one parent operation.
pub(super) async fn lock_parent_prefix(
    tx: &Transaction<'_>,
    operation: &OperationIdentity,
) -> Result<(), ArtifactHoldError> {
    tx.query_one(OPERATION_LOCK_SQL, &[&OPERATION_LOCK_DOMAIN, &operation.repository_id(), &operation.operation_id()])
        .await
        .map_err(pg::db_error)?;
    let exists: bool = tx
        .query_one("SELECT EXISTS(SELECT 1 FROM repositories WHERE id=$1)", &[&operation.repository_id()])
        .await
        .map_err(pg::db_error)?
        .get(0);
    if !exists {
        return Err(ArtifactHoldError::RepositoryNotFound);
    }
    tx.execute(
        "INSERT INTO ref_store_issuer_lanes(repository_id,issuer_id,lane,last_reserved_sequence)
         VALUES($1,$2,$3,$4) ON CONFLICT(repository_id,issuer_id,lane) DO UPDATE
         SET last_reserved_sequence=GREATEST(ref_store_issuer_lanes.last_reserved_sequence,EXCLUDED.last_reserved_sequence),
             updated_at=clock_timestamp()",
        &[
            &operation.repository_id(),
            &operation.issuer_id(),
            &operation.lane().as_str(),
            &operation.sequence(),
        ],
    )
    .await
    .map_err(pg::db_error)?;
    Ok(())
}

/// The parent operation must still be the exact same durable *pending* record
/// and must have no cancellation tombstone. There is no guessed-UUID
/// authorization: a missing row is rejected. This runs for every *new* hold
/// admission and every consume, but not for an immutable ACK replay: a replay
/// returns no authority, exactly like the migration-138 terminal replay.
pub(super) async fn verify_parent_pending(
    tx: &Transaction<'_>,
    operation: &OperationIdentity,
) -> Result<(), ArtifactHoldError> {
    let row = tx
        .query_opt(
            "SELECT issuer_id,lane,sequence,request_digest,state
             FROM ref_store_operations WHERE repository_id=$1 AND operation_id=$2 FOR UPDATE",
            &[&operation.repository_id(), &operation.operation_id()],
        )
        .await
        .map_err(pg::db_error)?;
    let Some(row) = row else {
        return Err(ArtifactHoldError::OperationNotPending { operation_id: operation.operation_id() });
    };
    let issuer: Uuid = row.get(0);
    let lane: String = row.get(1);
    let sequence: i64 = row.get(2);
    let digest: String = row.get(3);
    let state: String = row.get(4);
    if issuer != operation.issuer_id()
        || lane != operation.lane().as_str()
        || sequence != operation.sequence()
        || digest != operation.digest().as_hex()
    {
        return Err(ArtifactHoldError::ScopeMismatch("parent operation identity"));
    }
    if state != "pending" {
        return Err(ArtifactHoldError::OperationNotPending { operation_id: operation.operation_id() });
    }
    let cancelled: bool = tx
        .query_one(
            "SELECT EXISTS(
                 SELECT 1 FROM ref_store_cancellations
                 WHERE repository_id=$1
               AND (operation_id=$2 OR (issuer_id=$3 AND lane=$4 AND sequence=$5))
             )",
            &[
                &operation.repository_id(),
                &operation.operation_id(),
                &operation.issuer_id(),
                &operation.lane().as_str(),
                &operation.sequence(),
            ],
        )
        .await
        .map_err(pg::db_error)?
        .get(0);
    if cancelled {
        return Err(ArtifactHoldError::OperationCancelled { operation_id: operation.operation_id() });
    }
    Ok(())
}

/// One immutable acquire ledger row: the physical primary key, *every*
/// duplicated column of the outer row plus the canonical ACK body. The adapter
/// compares the decoded body against this row instead of trusting either side
/// alone.
pub(super) struct StoredAcquire {
    /// Physical primary key of the row that was actually selected, so a body
    /// can never be accepted for a different `request_id` than the one read.
    pub request_id: Uuid,
    pub request_digest: String,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
    pub purpose: String,
    pub object_format: String,
    pub history_incarnation: Uuid,
    pub authority_epoch: i64,
    pub group_epoch: i64,
    pub operation_issuer_id: Uuid,
    pub operation_lane: String,
    pub operation_sequence: i64,
    pub operation_id: Uuid,
    pub operation_digest: String,
    pub gate_revision: i64,
    pub gate_digest: String,
    pub shard: i32,
    pub backend_identity: String,
    pub consume_request_id: Uuid,
    pub artifact_count: i32,
    pub declared_bytes: i64,
    pub logical_bytes: i64,
    pub body: String,
}

impl StoredAcquire {
    /// The decoded ACK body must equal the whole immutable outer row, including
    /// the canonical encoding, the stable consume id, the backend identity and
    /// the exact parent/purpose/format/history/epoch/gate tuple. Any difference
    /// is durable corruption, not an unknown outcome.
    pub(super) fn ensure_ack(&self, ack: &AcquireAck) -> Result<(), ArtifactHoldError> {
        ack.ensure_batch_shape()?;
        if self.request_id != ack.request_id
            || self.request_digest != ack.request_digest
            || self.repository_id != ack.repository_id
            || self.tenant_id != ack.tenant_id
            || self.owner_id != ack.owner_id
            || self.purpose != ack.purpose.as_str()
            || self.object_format != ack.object_format.as_str()
            || self.history_incarnation != ack.history_incarnation
            || self.authority_epoch != ack.authority_epoch
            || self.group_epoch != ack.group_epoch
            || self.operation_issuer_id != ack.issuer_id
            || self.operation_lane != ack.lane
            || self.operation_sequence != ack.sequence
            || self.operation_id != ack.operation_id
            || self.operation_digest != ack.operation_digest
            || self.gate_revision != ack.gate_revision
            || self.gate_digest != ack.gate_digest
            || self.shard != ack.shard
            || self.backend_identity != ack.backend_identity
            || self.consume_request_id != ack.consume_request_id
            || self.declared_bytes != ack.declared_bytes
            || self.logical_bytes != ack.logical_bytes
            || i32::try_from(ack.artifacts.len()).ok() != Some(self.artifact_count)
        {
            return Err(ArtifactHoldError::LedgerIntegrity("stored ACK body disagrees with its immutable ledger row"));
        }
        if ShardId::of(ack.request_id).as_i32() != ack.shard {
            return Err(ArtifactHoldError::LedgerIntegrity("stored ACK is charged to the wrong global shard"));
        }
        if self.body != ack.encode()? {
            return Err(ArtifactHoldError::LedgerIntegrity("stored ACK body is not the canonical encoding"));
        }
        Ok(())
    }

    /// The immutable row must name exactly the parent operation tuple the
    /// caller provided (`repo, tenant, issuer, lane, sequence, op id, digest`).
    /// This runs before the adapter locks or qualifies any 138 pending row, so a
    /// different pending operation cannot qualify this grant.
    pub(super) fn ensure_parent(&self, operation: &OperationIdentity) -> Result<(), ArtifactHoldError> {
        if self.repository_id != operation.repository_id()
            || self.operation_issuer_id != operation.issuer_id()
            || self.operation_lane != operation.lane().as_str()
            || self.operation_sequence != operation.sequence()
            || self.operation_id != operation.operation_id()
            || self.operation_digest != operation.digest().as_hex()
        {
            return Err(ArtifactHoldError::ScopeMismatch("stored ACK parent operation binding"));
        }
        Ok(())
    }
}

pub(super) async fn stored_acquire(
    tx: &Transaction<'_>,
    request_id: Uuid,
) -> Result<Option<StoredAcquire>, ArtifactHoldError> {
    let row = tx
        .query_opt(
            "SELECT request_digest,repository_id,tenant_id,owner_id,purpose,object_format,
                    history_incarnation,authority_epoch,group_epoch,operation_issuer_id,operation_lane,
                    operation_sequence,operation_id,operation_digest,gate_revision,gate_digest,shard_id,
                    backend_identity,consume_request_id,artifact_count,declared_bytes,logical_bytes,ack_body,request_id
             FROM artifact_hold_requests WHERE request_id=$1",
            &[&request_id],
        )
        .await
        .map_err(pg::db_error)?;
    Ok(row.map(|row| StoredAcquire {
        request_digest: row.get(0),
        repository_id: row.get(1),
        tenant_id: row.get(2),
        owner_id: row.get(3),
        purpose: row.get(4),
        object_format: row.get(5),
        history_incarnation: row.get(6),
        authority_epoch: row.get(7),
        group_epoch: row.get(8),
        operation_issuer_id: row.get(9),
        operation_lane: row.get(10),
        operation_sequence: row.get(11),
        operation_id: row.get(12),
        operation_digest: row.get(13),
        gate_revision: row.get(14),
        gate_digest: row.get(15),
        shard: row.get(16),
        backend_identity: row.get(17),
        consume_request_id: row.get(18),
        artifact_count: row.get(19),
        declared_bytes: row.get(20),
        logical_bytes: row.get(21),
        body: row.get(22),
        // Selected last so no existing column index moves; this is the physical
        // primary key of the row that was read, never a copied body field.
        request_id: row.get(23),
    }))
}

/// Lock the fixed global shard row chosen from the acquire request UUID.
pub(super) async fn lock_shard(tx: &Transaction<'_>, shard: ShardId) -> Result<UsageCounts, ArtifactHoldError> {
    let row = tx
        .query_opt(
            "SELECT hold_count,declared_bytes,logical_bytes,receipt_count
             FROM artifact_hold_shards WHERE shard_id=$1 FOR UPDATE",
            &[&shard.as_i32()],
        )
        .await
        .map_err(pg::db_error)?;
    let Some(row) = row else {
        return Err(ArtifactHoldError::Database("artifact hold shard row is missing".into()));
    };
    Ok(UsageCounts { holds: row.get(0), declared_bytes: row.get(1), logical_bytes: row.get(2), receipts: row.get(3) })
}

/// Lock (or create) the retained tenant usage row and then the repository usage
/// row. This is the quota prefix of the fixed lock order and always runs before
/// the repository/gate rows.
pub(super) async fn lock_usage(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    repository_id: Uuid,
) -> Result<(UsageCounts, UsageCounts), ArtifactHoldError> {
    tx.execute(
        "INSERT INTO artifact_hold_tenant_usage(tenant_id) VALUES($1) ON CONFLICT(tenant_id) DO NOTHING",
        &[&tenant_id],
    )
    .await
    .map_err(pg::db_error)?;
    tx.execute(
        "INSERT INTO artifact_hold_repo_usage(repository_id,tenant_id) VALUES($2,$1)
         ON CONFLICT(repository_id) DO NOTHING",
        &[&tenant_id, &repository_id],
    )
    .await
    .map_err(pg::db_error)?;
    let tenant = tx
        .query_one(
            "SELECT hold_count,declared_bytes,logical_bytes,receipt_count
             FROM artifact_hold_tenant_usage WHERE tenant_id=$1 FOR UPDATE",
            &[&tenant_id],
        )
        .await
        .map_err(pg::db_error)?;
    let repository = tx
        .query_one(
            "SELECT hold_count,declared_bytes,logical_bytes,receipt_count
             FROM artifact_hold_repo_usage WHERE repository_id=$1 FOR UPDATE",
            &[&repository_id],
        )
        .await
        .map_err(pg::db_error)?;
    Ok((usage_from_row(&tenant), usage_from_row(&repository)))
}

fn usage_from_row(row: &Row) -> UsageCounts {
    UsageCounts { holds: row.get(0), declared_bytes: row.get(1), logical_bytes: row.get(2), receipts: row.get(3) }
}

/// Charge the locked counters. The `CHECK` ceilings in migration 141 repeat the
/// exact limits, so a bug cannot oversubscribe a scope even if this arithmetic
/// were wrong; the trigger refuses any decrease.
pub(super) async fn apply_usage(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    repository_id: Uuid,
    shard: ShardId,
    delta: UsageDelta,
) -> Result<(), ArtifactHoldError> {
    tx.execute(
        "UPDATE artifact_hold_tenant_usage
         SET hold_count=hold_count+$2,declared_bytes=declared_bytes+$3,
             logical_bytes=logical_bytes+$4,receipt_count=receipt_count+$5
         WHERE tenant_id=$1",
        &[&tenant_id, &delta.holds, &delta.declared_bytes, &delta.logical_bytes, &delta.receipts],
    )
    .await
    .map_err(pg::db_error)?;
    tx.execute(
        "UPDATE artifact_hold_repo_usage
         SET hold_count=hold_count+$2,declared_bytes=declared_bytes+$3,
             logical_bytes=logical_bytes+$4,receipt_count=receipt_count+$5
         WHERE repository_id=$1",
        &[&repository_id, &delta.holds, &delta.declared_bytes, &delta.logical_bytes, &delta.receipts],
    )
    .await
    .map_err(pg::db_error)?;
    tx.execute(
        "UPDATE artifact_hold_shards
         SET hold_count=hold_count+$2,declared_bytes=declared_bytes+$3,
             logical_bytes=logical_bytes+$4,receipt_count=receipt_count+$5,
             updated_at=clock_timestamp()
         WHERE shard_id=$1",
        &[&shard.as_i32(), &delta.holds, &delta.declared_bytes, &delta.logical_bytes, &delta.receipts],
    )
    .await
    .map_err(pg::db_error)?;
    Ok(())
}

/// Repository row `FOR SHARE` + the current unserved core gate `FOR SHARE`.
///
/// The unserved predicate is the same one A1/A2 use: explicitly unserved
/// `provisioning` repository on `gitfs`, `stable` transition, no Pando
/// authority and no legacy ref projection. A transition writer needs the
/// exclusive row lock, so it cannot race an admitted hold.
pub(super) async fn lock_scope_gate(tx: &Transaction<'_>, scope: &HoldScope) -> Result<CoreGate, ArtifactHoldError> {
    let row = tx
        .query_opt(
            "SELECT r.owner_id,r.object_format,r.state,r.storage_backend,r.transition_state,
                    EXISTS(SELECT 1 FROM pando_repository_states s WHERE s.repository_id=r.id),
                    EXISTS(SELECT 1 FROM repository_ref_projection p WHERE p.repository_id=r.id)
             FROM repositories r WHERE r.id=$1 FOR SHARE",
            &[&scope.repository_id()],
        )
        .await
        .map_err(pg::db_error)?;
    let Some(row) = row else {
        return Err(ArtifactHoldError::RepositoryNotFound);
    };
    let owner: Uuid = row.get(0);
    let object_format: String = row.get(1);
    if owner != scope.tenant_id() {
        return Err(ArtifactHoldError::RepositoryNotFound);
    }
    let state: String = row.get(2);
    let storage_backend: String = row.get(3);
    let transition_state: String = row.get(4);
    let pando_authority: bool = row.get(5);
    let legacy_refs: bool = row.get(6);
    if state != "provisioning" || storage_backend != "gitfs" || transition_state != "stable" {
        return Err(ArtifactHoldError::Unsupported(
            "repository is no longer an explicitly unserved stable gitfs core repository",
        ));
    }
    if pando_authority || legacy_refs {
        return Err(ArtifactHoldError::Unsupported(
            "repository has a live legacy Pando authority or legacy ref projection",
        ));
    }
    if object_format != scope.object_format().as_str() {
        return Err(ArtifactHoldError::ScopeMismatch("repository object format"));
    }
    let gate_row = tx
        .query_opt(
            "SELECT tenant_id,object_format,history_incarnation,authority_epoch,group_epoch,head_ref,revision
             FROM ref_store_core_gates WHERE repository_id=$1 FOR SHARE",
            &[&scope.repository_id()],
        )
        .await
        .map_err(pg::db_error)?;
    let Some(gate_row) = gate_row else {
        return Err(ArtifactHoldError::Unsupported("repository has no initialized core gate"));
    };
    let gate = gate_from_row(scope.repository_id(), &gate_row).map_err(ArtifactHoldError::Registry)?;
    if gate.tenant_id() != scope.tenant_id() {
        return Err(ArtifactHoldError::RepositoryNotFound);
    }
    if gate.object_format() != scope.object_format() {
        return Err(ArtifactHoldError::ScopeMismatch("gate object format"));
    }
    if gate.history_incarnation() != scope.history_incarnation() {
        return Err(ArtifactHoldError::ScopeMismatch("gate history incarnation"));
    }
    if gate.authority_epoch() != scope.authority_epoch() {
        return Err(ArtifactHoldError::ScopeMismatch("gate authority epoch"));
    }
    if gate.group_epoch() != scope.group_epoch() {
        return Err(ArtifactHoldError::ScopeMismatch("gate group epoch"));
    }
    Ok(gate)
}
