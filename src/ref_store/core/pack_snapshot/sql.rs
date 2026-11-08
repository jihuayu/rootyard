//! SQL-only helpers for the A5a pack snapshot adapter.
//!
//! Every function runs inside the one owned short transaction that
//! `super::pg` (or `super::super::pin_pg` for a pack-aware renew/release) starts.
//! Nothing here opens a connection, commits, rolls back, performs Blob/Git IO or
//! mints a proof/credential: rows in, data out.
//!
//! Lock order of the helpers in this module: none of them takes a lock beyond the
//! gate `FOR UPDATE`/`FOR SHARE` the caller already holds. `gate_pack_mode` reads
//! the already-locked gate row, `stored_history` is a plain immutable-row read,
//! and the inserts append to the rows their caller already admitted.
use super::super::pack_commit::PackMembershipEntry;
use super::super::pin::{self, SnapshotHeader};
use super::super::snapshot_contract::{MAX_SNAPSHOT_PACKS, MetadataSnapshotScope};
use super::super::snapshot_receipt::MetadataReceipt;
use super::super::snapshot_sql::StoredReceipt;
use crate::ref_store::contract::{MetadataMutationAction, RefStoreError};
use crate::ref_store::pg;
use tokio_postgres::Transaction;
use uuid::Uuid;

/// Permanent history kinds. They mirror the A2 receipt action one-for-one.
pub(crate) const HISTORY_CREATED: &str = "created";
pub(crate) const HISTORY_RENEWED: &str = "renewed";
pub(crate) const HISTORY_RELEASED: &str = "released";

/// Append the immutable snapshot -> registered pack bindings.
///
/// Each row is bound by composite foreign key to the exact
/// `(repository_id, registration_id, pack_id, artifact_set_digest)` membership
/// tuple, so a binding can never point at a pack that was not the active
/// membership of this repository at capture time.
pub(crate) async fn insert_bindings(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    snapshot_id: Uuid,
    entries: &[PackMembershipEntry],
) -> Result<(), RefStoreError> {
    if entries.is_empty() || entries.len() > MAX_SNAPSHOT_PACKS {
        return Err(RefStoreError::MetadataSnapshotTooLarge { ref_count: entries.len(), max_refs: MAX_SNAPSHOT_PACKS });
    }
    let pack_ids = entries.iter().map(PackMembershipEntry::pack_id).collect::<Vec<_>>();
    let registration_ids = entries.iter().map(PackMembershipEntry::registration_id).collect::<Vec<_>>();
    let digests = entries.iter().map(|entry| entry.artifact_set_digest().as_hex()).collect::<Vec<_>>();
    let joined = entries.iter().map(PackMembershipEntry::joined_revision).collect::<Vec<_>>();
    tx.execute(
        "INSERT INTO ref_store_core_snapshot_packs(
             repository_id,snapshot_id,pack_id,registration_id,artifact_set_digest,joined_revision)
         SELECT $1,$2,b.pack_id,b.registration_id,b.artifact_set_digest,b.joined_revision
         FROM unnest($3::uuid[],$4::uuid[],$5::text[],$6::bigint[])
              AS b(pack_id,registration_id,artifact_set_digest,joined_revision)",
        &[&repository_id, &snapshot_id, &pack_ids, &registration_ids, &digests, &joined],
    )
    .await
    .map_err(pg::db_error)?;
    Ok(())
}

/// The stored bindings of one snapshot, byte-ordered by pack id and bounded to
/// `16 + 1` rows so an overflow is a typed refusal instead of a truncation.
pub(crate) async fn snapshot_bindings(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    snapshot_id: Uuid,
) -> Result<Vec<PackMembershipEntry>, RefStoreError> {
    let rows = tx
        .query(
            "SELECT pack_id,registration_id,artifact_set_digest,joined_revision
             FROM ref_store_core_snapshot_packs
             WHERE repository_id=$1 AND snapshot_id=$2 ORDER BY pack_id LIMIT $3",
            &[&repository_id, &snapshot_id, &(MAX_SNAPSHOT_PACKS as i64 + 1)],
        )
        .await
        .map_err(pg::db_error)?;
    if rows.len() > MAX_SNAPSHOT_PACKS {
        return Err(RefStoreError::MetadataSnapshotTooLarge { ref_count: rows.len(), max_refs: MAX_SNAPSHOT_PACKS });
    }
    let mut entries = Vec::with_capacity(rows.len());
    for row in rows {
        let digest: String = row.get(2);
        let parsed: crate::ref_store::contract::RequestDigest = digest
            .parse()
            .map_err(|_| RefStoreError::Database("stored binding artifact-set digest is not sha256 hex".into()))?;
        entries.push(
            PackMembershipEntry::new(
                row.get(0),
                row.get(1),
                super::super::pack_commit::ArtifactSetDigest::from_digest(parsed),
                row.get(3),
            )
            .map_err(|_| RefStoreError::Database("stored pack binding identity is invalid".into()))?,
        );
    }
    Ok(entries)
}

/// A retained *create* binding of one pack snapshot/pin pair.
pub(crate) struct CreatedBinding {
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
}

/// Whether a retained create binding already owns this snapshot id or pin id.
///
/// Only `kind='created'` rows are considered: renew/release rows legitimately
/// repeat the same pair, so they must never be treated as a reused identity. A
/// returned value names the colliding identity; the caller turns it into a typed
/// conflict before any write or charge.
pub(crate) async fn retained_create_identity(
    tx: &Transaction<'_>,
    snapshot_id: Uuid,
    pin_id: Uuid,
) -> Result<Option<&'static str>, RefStoreError> {
    let row = tx
        .query_opt(
            "SELECT snapshot_id,pin_id FROM ref_store_core_pack_snapshot_history
             WHERE kind=$3 AND (snapshot_id=$1 OR pin_id=$2) LIMIT 1",
            &[&snapshot_id, &pin_id, &HISTORY_CREATED],
        )
        .await
        .map_err(pg::db_error)?;
    Ok(row.map(|row| {
        let stored_snapshot: Uuid = row.get(0);
        if stored_snapshot == snapshot_id { "snapshot" } else { "pin" }
    }))
}

/// The retained create binding of one pack snapshot/pin pair, if any. This is the
/// permanent identity a lifecycle (renew/release) history row is validated
/// against, so a reused snapshot/pin pair can never gain a lifecycle entry under a
/// different repository/tenant/owner.
pub(crate) async fn created_binding(
    tx: &Transaction<'_>,
    snapshot_id: Uuid,
    pin_id: Uuid,
) -> Result<Option<CreatedBinding>, RefStoreError> {
    let row = tx
        .query_opt(
            "SELECT repository_id,tenant_id,owner_id
             FROM ref_store_core_pack_snapshot_history
             WHERE kind=$3 AND snapshot_id=$1 AND pin_id=$2 LIMIT 2",
            &[&snapshot_id, &pin_id, &HISTORY_CREATED],
        )
        .await
        .map_err(pg::db_error)?;
    let Some(row) = row else { return Ok(None) };
    Ok(Some(CreatedBinding { repository_id: row.get(0), tenant_id: row.get(1), owner_id: row.get(2) }))
}

/// Prove that a fresh lifecycle mutation names the original retained create
/// binding of its pack snapshot/pin pair in the same realm. A missing binding or a
/// different repository/tenant/owner is refused, so no history row and no
/// permanent charge is written for a foreign lifecycle entry.
pub(crate) async fn ensure_lifecycle_binding(
    tx: &Transaction<'_>,
    snapshot_id: Uuid,
    pin_id: Uuid,
    repository_id: Uuid,
    tenant_id: Uuid,
    owner_id: Uuid,
) -> Result<(), RefStoreError> {
    let binding = created_binding(tx, snapshot_id, pin_id)
        .await?
        .ok_or_else(|| RefStoreError::Database("pack snapshot pin has no retained create binding".into()))?;
    if binding.repository_id != repository_id || binding.tenant_id != tenant_id || binding.owner_id != owner_id {
        return Err(RefStoreError::IdentityConflict);
    }
    Ok(())
}

/// Whether the business repository row still exists. Only the receipt-lookup path
/// needs it: while the repository exists, a permanent history row without its A2
/// receipt partner is a ledger-integrity error, never a replay.
pub(crate) async fn repository_exists(tx: &Transaction<'_>, repository_id: Uuid) -> Result<bool, RefStoreError> {
    let row = tx
        .query_one("SELECT EXISTS(SELECT 1 FROM repositories WHERE id=$1)", &[&repository_id])
        .await
        .map_err(pg::db_error)?;
    Ok(row.get(0))
}

/// One permanent history row to append. Every digest/gate field is copied from
/// the immutable snapshot header, so a history row always describes the snapshot
/// it belongs to, never the current gate.
pub(crate) struct HistoryInsert<'a> {
    pub request_id: Uuid,
    pub scope: &'a MetadataSnapshotScope,
    pub snapshot_id: Uuid,
    pub pin_id: Uuid,
    pub kind: &'a str,
    /// The exact canonical request digest of the admitted operation.
    pub request_digest: &'a str,
    pub header: &'a SnapshotHeader,
    pub body: &'a str,
}

pub(crate) async fn insert_history(tx: &Transaction<'_>, insert: &HistoryInsert<'_>) -> Result<(), RefStoreError> {
    let membership_digest = insert
        .header
        .membership_digest
        .as_deref()
        .ok_or_else(|| RefStoreError::Database("pack snapshot header has no membership digest".into()))?;
    let snapshot_digest = insert
        .header
        .snapshot_digest
        .as_deref()
        .ok_or_else(|| RefStoreError::Database("pack snapshot header has no snapshot digest".into()))?;
    let pack_count = i32::try_from(insert.header.pack_count)
        .map_err(|_| RefStoreError::Database("pack snapshot pack_count does not fit INTEGER".into()))?;
    let ref_count = i32::try_from(insert.header.ref_count)
        .map_err(|_| RefStoreError::Database("pack snapshot ref_count does not fit INTEGER".into()))?;
    tx.execute(
        "INSERT INTO ref_store_core_pack_snapshot_history(
             history_id,request_id,repository_id,tenant_id,owner_id,snapshot_id,pin_id,kind,gate_revision,
             gate_digest,pack_mode,refs_digest,membership_digest,pack_count,snapshot_digest,ref_count,
             logical_bytes,body,request_digest)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)",
        &[
            &Uuid::new_v4(),
            &insert.request_id,
            &insert.scope.repository_id(),
            &insert.scope.tenant_id(),
            &insert.scope.owner_id(),
            &insert.snapshot_id,
            &insert.pin_id,
            &insert.kind,
            &insert.header.gate_revision,
            &insert.header.gate_digest,
            &super::contract::PACK_MODE_VERIFIED,
            &insert.header.refs_digest,
            &membership_digest,
            &pack_count,
            &snapshot_digest,
            &ref_count,
            &insert.header.logical_bytes,
            &insert.body,
            &insert.request_digest,
        ],
    )
    .await
    .map_err(pg::db_error)?;
    Ok(())
}

/// Require the permanent history partner of one A2 receipt ledger row.
///
/// A pack-aware receipt is two immutable rows written in one transaction: the A2
/// ledger row and the permanent history row carrying the **same canonical body**.
/// An exact replay (or a historical lookup) must therefore see both, and they must
/// agree; a missing or mismatched partner is a ledger-integrity error and never a
/// successful replay. `owner_id` comes from the immutable snapshot header, which is
/// the only row that stores the snapshot producer identity.
pub(crate) async fn ensure_history_partner(
    tx: &Transaction<'_>,
    stored: &StoredReceipt,
    owner_id: Uuid,
    kind: &str,
) -> Result<(), RefStoreError> {
    let history = stored_history(tx, stored.request_id)
        .await?
        .ok_or_else(|| RefStoreError::Database("pack snapshot receipt has no permanent history partner".into()))?;
    if history.request_id != stored.request_id
        || history.repository_id != stored.repository_id
        || history.tenant_id != stored.tenant_id
        || history.owner_id != owner_id
        || history.snapshot_id != stored.snapshot_id
        || history.pin_id != stored.pin_id
        || history.kind != kind
        || history.body != stored.body
        || history.request_digest != stored.request_digest
    {
        return Err(RefStoreError::Database(
            "permanent pack snapshot history disagrees with its receipt partner".into(),
        ));
    }
    Ok(())
}

/// One stored permanent history row, read without any lock or current authority.
pub(crate) struct StoredHistory {
    pub request_id: Uuid,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
    pub snapshot_id: Uuid,
    pub pin_id: Uuid,
    pub kind: String,
    pub gate_revision: i64,
    pub gate_digest: String,
    pub refs_digest: String,
    pub membership_digest: String,
    pub pack_count: i64,
    pub snapshot_digest: String,
    pub ref_count: i64,
    pub logical_bytes: i64,
    pub body: String,
    /// The canonical request digest the operation was permanently admitted with.
    pub request_digest: String,
}

pub(crate) async fn stored_history(
    tx: &Transaction<'_>,
    request_id: Uuid,
) -> Result<Option<StoredHistory>, RefStoreError> {
    let row = tx
        .query_opt(
            "SELECT request_id,repository_id,tenant_id,owner_id,snapshot_id,pin_id,kind,gate_revision,
                    gate_digest,refs_digest,membership_digest,pack_count,snapshot_digest,ref_count,
                    logical_bytes,body,request_digest
             FROM ref_store_core_pack_snapshot_history WHERE request_id=$1",
            &[&request_id],
        )
        .await
        .map_err(pg::db_error)?;
    let Some(row) = row else { return Ok(None) };
    let pack_count: i32 = row.get(11);
    let ref_count: i32 = row.get(13);
    Ok(Some(StoredHistory {
        request_id: row.get(0),
        repository_id: row.get(1),
        tenant_id: row.get(2),
        owner_id: row.get(3),
        snapshot_id: row.get(4),
        pin_id: row.get(5),
        kind: row.get(6),
        gate_revision: row.get(7),
        gate_digest: row.get(8),
        refs_digest: row.get(9),
        membership_digest: row.get(10),
        pack_count: i64::from(pack_count),
        snapshot_digest: row.get(12),
        ref_count: i64::from(ref_count),
        logical_bytes: row.get(14),
        body: row.get::<_, String>(15),
        request_digest: row.get::<_, String>(16),
    }))
}

/// The retained identity a caller must name to reuse one permanent A5 request id.
///
/// After a legitimate repository delete cascades the A2 receipt away, the
/// permanent history row is the only surviving identity of the operation, so
/// every fresh mutation resolves the reservation here, under the shared request
/// advisory lock and *before* any quota admission or business write.
pub(crate) struct ReservationLookup<'a> {
    pub request_id: Uuid,
    pub scope: &'a MetadataSnapshotScope,
    /// The exact permanent history kind this request would have written.
    pub kind: &'a str,
    /// `None` for an A2 pin lifecycle request, which names no snapshot id.
    pub snapshot_id: Option<Uuid>,
    pub pin_id: Uuid,
    /// The caller's FULL canonical request digest. The retained row is an exact
    /// replay only when this equals the digest it was permanently admitted with,
    /// which covers every request field (ids, scope, lease, release reason,
    /// expected gate revision/digest) instead of a partial field projection.
    pub request_digest: &'a str,
}

/// One permanent reservation named exactly, with its decoded body.
pub(crate) struct Reservation {
    pub receipt: MetadataReceipt,
    pub history: StoredHistory,
}

/// Resolve the permanent A5 reservation of one request id.
///
/// `Ok(None)` means the id is free. `Ok(Some(_))` is the *exact* historical
/// operation: the retained scope, kind, snapshot/pin identity and the full
/// canonical request digest all agree with the caller, so the caller replays that
/// immutable receipt and writes nothing (and never mints a new live lease). Any
/// other retained row is a typed conflict with zero writes: `IdentityConflict`
/// for another repository/tenant/owner/snapshot/pin, `DigestConflict` for another
/// action or another canonical request digest.
pub(crate) async fn reserved_history(
    tx: &Transaction<'_>,
    lookup: &ReservationLookup<'_>,
) -> Result<Option<Reservation>, RefStoreError> {
    let Some(history) = stored_history(tx, lookup.request_id).await? else { return Ok(None) };
    if history.repository_id != lookup.scope.repository_id()
        || history.tenant_id != lookup.scope.tenant_id()
        || history.owner_id != lookup.scope.owner_id()
    {
        return Err(RefStoreError::IdentityConflict);
    }
    if history.pin_id != lookup.pin_id || lookup.snapshot_id.is_some_and(|id| id != history.snapshot_id) {
        return Err(RefStoreError::IdentityConflict);
    }
    if history.kind != lookup.kind || history.request_digest != lookup.request_digest {
        return Err(RefStoreError::DigestConflict);
    }
    let action = match lookup.kind {
        HISTORY_CREATED => MetadataMutationAction::Create,
        HISTORY_RENEWED => MetadataMutationAction::Renew,
        HISTORY_RELEASED => MetadataMutationAction::Release,
        _ => return Err(RefStoreError::Database("permanent reservation names no known kind".into())),
    };
    // While the repository still exists its A2 receipt must exist too: a missing
    // partner is ledger integrity, never a historical replay.
    if repository_exists(tx, lookup.scope.repository_id()).await? {
        return Err(RefStoreError::Database(
            "permanent pack snapshot history has no A2 receipt while its repository exists".into(),
        ));
    }
    // Outer scope/ids/body integrity of the retained row and its canonical body.
    let receipt = pin::decode_receipt(action, &history.body)?;
    pin::ensure_receipt_scope(&receipt, lookup.scope)?;
    if receipt.request_id() != history.request_id
        || receipt.snapshot_id() != history.snapshot_id
        || receipt.pin_id() != history.pin_id
    {
        return Err(RefStoreError::Database("permanent pack snapshot history body disagrees with its row".into()));
    }
    let gate_mismatch = match &receipt {
        MetadataReceipt::Snapshot(snapshot) => snapshot.gate_digest_hex() != history.gate_digest,
        MetadataReceipt::Pin(_) => false,
    };
    if gate_mismatch {
        return Err(RefStoreError::Database(
            "permanent pack snapshot history gate digest disagrees with its body".into(),
        ));
    }
    Ok(Some(Reservation { receipt, history }))
}
