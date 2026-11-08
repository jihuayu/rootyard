//! The single bounded, fully verified stored-registration reader.
//!
//! Both the fresh-registration replay check and the read-only historical
//! `query_registration` path go through this module. A missing row is `None`; a
//! partial, multi-row, rewritten or A3-inconsistent registration is a typed
//! `LedgerIntegrity`/`RegistrationConflict` refusal and **never** "found".
//! Nothing here grants authority, opens a nested transaction or performs IO.
use super::artifact::RegisteredPack;
use super::contract::{MAX_ACTIVE_MEMBERSHIPS, PackArtifactRole};
use super::error::{PackCommitError, PackCommitRejectCode, PackCommitRejection};
use super::plan::PackCommitScope;
use super::receipt::{PackRegistrationAck, PackRegistrationReceipt};
use super::sql;
use crate::ref_store::core::CoreGate;
use crate::ref_store::core::artifact_hold::{
    ArtifactHoldPurpose, HoldScope, RegistrationLedger, read_registration_ledger,
};
use crate::ref_store::core::types::GitObjectFormat;
use crate::ref_store::pg;
use tokio::time::Instant;
use tokio_postgres::Transaction;
use uuid::Uuid;

/// Fully validated durable registration: the immutable ACK plus the exact
/// registered pack with complete read-only locator identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct StoredRegistration {
    pub ack: PackRegistrationAck,
    pub pack: RegisteredPack,
}

impl StoredRegistration {
    pub(super) fn replay(&self) -> PackRegistrationReceipt {
        PackRegistrationReceipt { ack: self.ack.clone(), replayed: true }
    }
}

fn integrity(detail: &'static str) -> PackCommitError {
    PackCommitError::Rejected(PackCommitRejection::new(PackCommitRejectCode::LedgerIntegrity, detail))
}

fn conflict(detail: &'static str) -> PackCommitError {
    PackCommitError::Rejected(PackCommitRejection::new(PackCommitRejectCode::RegistrationConflict, detail))
}

const OUTER_SELECT: &str = "SELECT registration_id,pack_id,repository_id,tenant_id,owner_id,purpose,object_format,
        history_incarnation,authority_epoch,group_epoch,plan_operation_id,parent_digest,gate_revision,gate_digest,
        backend_identity,planned_pack_sha256,planned_pack_length,planned_idx_sha256,planned_idx_length,
        artifact_set_digest,acquire_request_id,consume_request_id,logical_bytes,ack_body
     FROM ref_store_core_pack_publications";

/// Reads by global registration id (historical query path).
pub(super) async fn by_registration_id(
    tx: &Transaction<'_>,
    scope: &PackCommitScope,
    registration_id: Uuid,
    deadline: Instant,
) -> Result<Option<StoredRegistration>, PackCommitError> {
    let query = format!("{OUTER_SELECT} WHERE registration_id=$1 LIMIT 3");
    let rows =
        pg::before_deadline(deadline, async { tx.query(&query, &[&registration_id]).await.map_err(pg::db_error) })
            .await?;
    finish(tx, scope, rows, deadline).await
}

/// Reads the registration that owns this exact A3 acquire/consume pair (fresh
/// path replay and post-lock re-check).
pub(super) async fn by_request(
    tx: &Transaction<'_>,
    scope: &PackCommitScope,
    acquire_request_id: Uuid,
    consume_request_id: Uuid,
    registration_id: Uuid,
    deadline: Instant,
) -> Result<Option<StoredRegistration>, PackCommitError> {
    let query =
        format!("{OUTER_SELECT} WHERE acquire_request_id=$1 OR consume_request_id=$2 OR registration_id=$3 LIMIT 3");
    let rows = pg::before_deadline(deadline, async {
        tx.query(&query, &[&acquire_request_id, &consume_request_id, &registration_id]).await.map_err(pg::db_error)
    })
    .await?;
    finish(tx, scope, rows, deadline).await
}

async fn finish(
    tx: &Transaction<'_>,
    scope: &PackCommitScope,
    rows: Vec<tokio_postgres::Row>,
    deadline: Instant,
) -> Result<Option<StoredRegistration>, PackCommitError> {
    match rows.len() {
        0 => Ok(None),
        1 => Ok(Some(validate(tx, scope, &rows[0], deadline).await?)),
        _ => Err(conflict("several durable registrations match this identity")),
    }
}

async fn validate(
    tx: &Transaction<'_>,
    scope: &PackCommitScope,
    row: &tokio_postgres::Row,
    deadline: Instant,
) -> Result<StoredRegistration, PackCommitError> {
    let registration_id: Uuid = row.get(0);
    let pack_id: Uuid = row.get(1);
    let repository_id: Uuid = row.get(2);
    let tenant_id: Uuid = row.get(3);
    let owner_id: Uuid = row.get(4);
    let purpose: String = row.get(5);
    let object_format: String = row.get(6);
    let history_incarnation: Uuid = row.get(7);
    let authority_epoch: i64 = row.get(8);
    let group_epoch: i64 = row.get(9);
    let plan_operation_id: Uuid = row.get(10);
    let parent_digest: String = row.get(11);
    let gate_revision: i64 = row.get(12);
    let gate_digest: String = row.get(13);
    let backend_identity: String = row.get(14);
    let planned_pack_sha256: String = row.get(15);
    let planned_pack_length: i64 = row.get(16);
    let planned_idx_sha256: String = row.get(17);
    let planned_idx_length: i64 = row.get(18);
    let artifact_set_digest: String = row.get(19);
    let acquire_request_id: Uuid = row.get(20);
    let consume_request_id: Uuid = row.get(21);
    let logical_bytes: i64 = row.get(22);
    let body: String = row.get(23);

    // Historical scope bound: the stored realm must equal the caller's expected
    // scope exactly; a foreign scope is never returned as a receipt.
    if repository_id != scope.repository_id()
        || tenant_id != scope.tenant_id()
        || owner_id != scope.owner_id()
        || object_format != scope.object_format().as_str()
        || history_incarnation != scope.history_incarnation()
        || authority_epoch != scope.authority_epoch()
        || group_epoch != scope.group_epoch()
        || purpose != ArtifactHoldPurpose::RefPublication.as_str()
        || gate_revision <= 0
        || logical_bytes <= 0
        || planned_pack_length <= 0
        || planned_idx_length <= 0
    {
        return Err(conflict("registration id/request belongs to another durable realm"));
    }
    let ack = PackRegistrationAck::decode(&body)?;
    ack.ensure_one_pair().map_err(|_| integrity("stored ACK is not a single pair"))?;
    let pack_ok = ack.registration_id == registration_id
        && ack.pack_id == pack_id
        && ack.repository_id == repository_id
        && ack.tenant_id == tenant_id
        && ack.owner_id == owner_id
        && ack.purpose == purpose
        && ack.object_format == object_format
        && ack.history_incarnation == history_incarnation
        && ack.authority_epoch == authority_epoch
        && ack.group_epoch == group_epoch
        && ack.plan_operation_id == plan_operation_id
        && ack.parent_digest == parent_digest
        && ack.gate_revision == gate_revision
        && ack.gate_digest == gate_digest
        && ack.backend_identity == backend_identity
        && ack.planned_pack_sha256 == planned_pack_sha256
        && ack.planned_pack_length == u64::try_from(planned_pack_length).unwrap_or(0)
        && ack.planned_idx_sha256 == planned_idx_sha256
        && ack.planned_idx_length == u64::try_from(planned_idx_length).unwrap_or(0)
        && ack.artifact_set_digest == artifact_set_digest
        && ack.acquire_request_id == acquire_request_id
        && ack.consume_request_id == consume_request_id
        && ack.logical_bytes == logical_bytes;
    if !pack_ok {
        return Err(integrity("stored registration body does not match its outer row"));
    }

    let rows = sql::artifacts_for(tx, registration_id, Some(pack_id)).await?;
    if rows.len() != super::contract::ARTIFACTS_PER_PACK {
        return Err(integrity("stored registration does not have exactly two artifact rows"));
    }
    let pack = sql::build_pack(pack_id, registration_id, &artifact_set_digest, rows, None)
        .map_err(|_| integrity("stored registration artifact rows are inconsistent"))?;
    let pack_artifact = pack.artifact(PackArtifactRole::Pack);
    let idx_artifact = pack.artifact(PackArtifactRole::Idx);
    if pack_artifact.locator().sha256().as_str() != planned_pack_sha256
        || pack_artifact.locator().length() != u64::try_from(planned_pack_length).unwrap_or(0)
        || idx_artifact.locator().sha256().as_str() != planned_idx_sha256
        || idx_artifact.locator().length() != u64::try_from(planned_idx_length).unwrap_or(0)
        || ack.hold_ids.iter().copied().collect::<std::collections::BTreeSet<_>>()
            != pack.artifacts().iter().map(|artifact| artifact.hold_id()).collect()
    {
        return Err(integrity("stored artifacts do not match the planned pair"));
    }

    // A3 ledger cross-check of the full physical identity. Read-only and bounded;
    // the caller's absolute deadline still applies.
    pg::bound(tx, deadline).await?;
    let hold_scope = HoldScope::new(
        scope.repository_id(),
        scope.tenant_id(),
        scope.owner_id(),
        ArtifactHoldPurpose::RefPublication,
        scope.object_format(),
        scope.history_incarnation(),
        scope.authority_epoch(),
        scope.group_epoch(),
    )
    .map_err(|_| integrity("stored realm cannot form a hold scope"))?;
    let ledger: RegistrationLedger = read_registration_ledger(tx, &hold_scope, acquire_request_id, consume_request_id)
        .await
        .map_err(|_| integrity("A3 ledger read refused for a stored registration"))?;
    let acquire = ledger.acquire_ack();
    if acquire.operation_id != plan_operation_id
        || acquire.operation_digest != parent_digest
        || acquire.gate_revision != gate_revision
        || acquire.gate_digest != gate_digest
        || acquire.backend_identity != backend_identity
        || acquire.consume_request_id != consume_request_id
        || acquire.artifact_count() != super::contract::ARTIFACTS_PER_PACK
    {
        return Err(integrity("stored registration parent/gate/backend differs from the A3 ledger"));
    }
    let receipts = ledger.consume_receipts();
    if receipts.len() != super::contract::ARTIFACTS_PER_PACK {
        return Err(integrity("A3 consume receipt set is not a pair"));
    }
    for receipt in receipts {
        let role = match receipt.slot {
            0 => PackArtifactRole::Pack,
            1 => PackArtifactRole::Idx,
            _ => return Err(integrity("A3 receipt slot is not a pair slot")),
        };
        let artifact = pack.artifact(role);
        if receipt.hold_id != artifact.hold_id()
            || receipt.consume_request_id != consume_request_id
            || receipt.operation_digest != parent_digest
            || receipt.gate_revision != gate_revision
            || receipt.gate_digest != gate_digest
            || receipt.artifact.sha256 != artifact.locator().sha256().as_str()
            || receipt.artifact.length != artifact.locator().length()
            || receipt.artifact.provider != artifact.provider()
            || receipt.artifact.backend_identity != artifact.backend_identity()
            || receipt.artifact.namespace != artifact.locator().namespace()
        {
            return Err(integrity("stored artifact identity differs from its A3 receipt"));
        }
    }
    Ok(StoredRegistration { ack, pack })
}

/// Full lineage validation of every old active membership.
///
/// Owner nuance (confirmed): the stored publication `owner_id` is an *internal
/// producer identity*, not the tenant and not necessarily the producer of the new
/// operation. The historical expected scope is therefore built from the CURRENT
/// captured gate repository/tenant/format/history/epochs plus the STORED publisher
/// owner and `ref_publication` purpose; the A3 ledger + ACK must be self-consistent
/// with that scope. Only a *new* registration binds the current producer owner.
///
/// Rejected as `LedgerIntegrity`: a publication whose realm differs from the
/// current gate, a non-nil/foreign purpose, a membership joined after the current
/// revision, or `joined_revision != publication.gate_revision + 1`.
pub(super) async fn old_memberships(
    tx: &Transaction<'_>,
    gate: &CoreGate,
    deadline: Instant,
) -> Result<Vec<RegisteredPack>, PackCommitError> {
    crate::ref_store::pg::bound(tx, deadline).await?;
    let rows = crate::ref_store::pg::before_deadline(deadline, async {
        tx.query(
            "SELECT m.pack_id,m.registration_id,m.joined_revision,
                    p.repository_id,p.tenant_id,p.object_format,p.history_incarnation,p.authority_epoch,
                    p.group_epoch,p.gate_revision,p.owner_id,p.purpose
             FROM ref_store_core_pack_memberships m
             JOIN ref_store_core_pack_publications p
               ON p.registration_id=m.registration_id AND p.pack_id=m.pack_id
             WHERE m.repository_id=$1 ORDER BY m.pack_id LIMIT $2",
            &[&gate.repository_id(), &(MAX_ACTIVE_MEMBERSHIPS + 1)],
        )
        .await
        .map_err(pg::db_error)
    })
    .await?;
    if rows.len() as i64 > MAX_ACTIVE_MEMBERSHIPS {
        return Err(PackCommitError::Rejected(PackCommitRejection::new(
            PackCommitRejectCode::CaptureOverflow,
            "membership capture exceeds the fixed 16-pack bound",
        )));
    }
    let mut packs = Vec::with_capacity(rows.len());
    for row in rows {
        let pack_id: Uuid = row.get(0);
        let registration_id: Uuid = row.get(1);
        let joined_revision: i64 = row.get(2);
        let repository_id: Uuid = row.get(3);
        let tenant_id: Uuid = row.get(4);
        let object_format: String = row.get(5);
        let history_incarnation: Uuid = row.get(6);
        let authority_epoch: i64 = row.get(7);
        let group_epoch: i64 = row.get(8);
        let publication_gate_revision: i64 = row.get(9);
        let stored_owner: Uuid = row.get(10);
        let purpose: String = row.get(11);
        if repository_id != gate.repository_id()
            || tenant_id != gate.tenant_id()
            || object_format != gate.object_format().as_str()
            || history_incarnation != gate.history_incarnation()
            || authority_epoch != gate.authority_epoch()
            || group_epoch != gate.group_epoch()
            || stored_owner.is_nil()
            || purpose != ArtifactHoldPurpose::RefPublication.as_str()
        {
            return Err(integrity("old membership publication realm differs from the current gate"));
        }
        if joined_revision <= 0
            || joined_revision > gate.revision()
            || publication_gate_revision <= 0
            || joined_revision != publication_gate_revision.saturating_add(1)
        {
            return Err(integrity("old membership joined revision is not publication.gate_revision + 1"));
        }
        let format = GitObjectFormat::parse(&object_format).map_err(|_| integrity("old membership format"))?;
        let historical_scope = PackCommitScope::new(
            gate.repository_id(),
            gate.tenant_id(),
            stored_owner,
            format,
            gate.history_incarnation(),
            gate.authority_epoch(),
            gate.group_epoch(),
        )
        .map_err(|_| integrity("old membership historical scope is invalid"))?;
        let Some(stored) = by_registration_id(tx, &historical_scope, registration_id, deadline).await? else {
            return Err(integrity("old membership has no durable registration"));
        };
        if stored.pack.pack_id() != pack_id {
            return Err(integrity("old membership pack id differs from its registration"));
        }
        packs.push(
            RegisteredPack::new(
                pack_id,
                registration_id,
                stored.pack.artifact_set_digest(),
                stored.pack.artifacts().to_vec(),
                Some(joined_revision),
            )
            .map_err(|_| integrity("old membership registered pack is inconsistent"))?,
        );
    }
    Ok(packs)
}
