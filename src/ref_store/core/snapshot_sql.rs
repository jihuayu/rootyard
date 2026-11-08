//! SQL-only row helpers for the metadata snapshot adapter.
//!
//! Every function here is called inside the one owned short transaction that
//! `super::snapshot_pg` starts. They contain no commit/rollback logic and never
//! open a connection, so transaction ownership and the rollback policy live in
//! exactly one place.
//!
//! Lock order of every helper in this module (the adapter additionally takes an
//! advisory request-id key first and the successful receipt last):
//!
//! tenant usage row -> repository usage row -> repository row `FOR SHARE` ->
//! core gate -> immutable snapshot/pin row -> immutable receipt.
//!
//! A1 `CommitRefs` keeps operation -> lane -> repository -> gate; no path here
//! takes a quota row after the gate. Page reads take repository/gate `FOR
//! SHARE` and then the pin `FOR SHARE`, so a release `FOR UPDATE` orders after
//! an admitted page.
use super::super::contract::{MetadataMutationAction, MetadataPinPurpose, RefStoreError};
use super::super::pg;
use super::contract::CoreGate;
use super::pack_commit::PackMode;
use super::pin::{PinIdentity, PinRow, PinState, SnapshotHeader};
use super::snapshot_contract::{MAX_SNAPSHOT_REFS, MetadataSnapshotScope};
use super::snapshot_receipt::MetadataReceipt;
use super::snapshot_request::PinReleaseReason;
use super::types::{GitObjectFormat, RefName};
use tokio::time::Instant;
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

/// Force durable commit in the one owned write transaction: hosted policy may set
/// `synchronous_commit=off`, and only an explicitly durable `COMMIT` may be
/// acknowledged. Called by write paths only, and bounded by the caller's absolute
/// deadline like every other SQL stage after `BEGIN`.
pub(super) async fn durable_write(tx: &Transaction<'_>, deadline: Instant) -> Result<(), RefStoreError> {
    pg::before_deadline(deadline, async {
        tx.execute("SET LOCAL synchronous_commit = 'on'", &[]).await.map_err(pg::db_error)
    })
    .await?;
    Ok(())
}

/// First lock of every metadata mutation: one advisory key derived from the
/// request id. It serializes concurrent attempts of the *same* request so the
/// receipt ledger cannot race itself, before any quota row is touched.
pub(super) async fn advisory_request_lock(tx: &Transaction<'_>, request_id: Uuid) -> Result<(), RefStoreError> {
    let bytes = request_id.as_bytes();
    let first = i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let second = i32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    tx.execute("SELECT pg_advisory_xact_lock($1::int4,$2::int4)", &[&first, &second]).await.map_err(pg::db_error)?;
    Ok(())
}

/// A stored ledger row for one request id. The whole immutable ledger key is
/// carried so a replayed body can be checked against it instead of being
/// trusted on its own, and a historical receipt is never compared with the
/// live pin generation/expiry.
pub(super) struct StoredReceipt {
    pub request_id: Uuid,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub action: MetadataMutationAction,
    pub request_digest: String,
    pub pin_id: Uuid,
    pub snapshot_id: Uuid,
    pub pin_generation: i64,
    pub body: String,
}

pub(super) async fn stored_receipt(
    tx: &Transaction<'_>,
    request_id: Uuid,
) -> Result<Option<StoredReceipt>, RefStoreError> {
    let row = tx
        .query_opt(
            "SELECT request_id,repository_id,tenant_id,action,request_digest,pin_id,snapshot_id,pin_generation,body
             FROM ref_store_core_receipts WHERE request_id=$1",
            &[&request_id],
        )
        .await
        .map_err(pg::db_error)?;
    let Some(row) = row else { return Ok(None) };
    let action: String = row.get(3);
    Ok(Some(StoredReceipt {
        request_id: row.get(0),
        repository_id: row.get(1),
        tenant_id: row.get(2),
        action: MetadataMutationAction::parse(&action)?,
        request_digest: row.get(4),
        pin_id: row.get(5),
        snapshot_id: row.get(6),
        pin_generation: row.get(7),
        body: row.get(8),
    }))
}

/// Repository row `FOR SHARE` plus the current gate row.
///
/// `require_unserved` rechecks the A1 unserved predicate: provisioning/gitfs/
/// stable, no Pando authority and no legacy ref projection, with the same
/// tenant and object format. Pages and renewals require it; an exact release
/// does not, so a repository transition cannot strand a pin.
pub(super) async fn lock_scope(
    tx: &Transaction<'_>,
    scope: &MetadataSnapshotScope,
    require_unserved: bool,
    gate_for_update: bool,
) -> Result<CoreGate, RefStoreError> {
    let row = tx
        .query_opt(
            "SELECT r.owner_id,r.object_format,r.state,r.storage_backend,r.transition_state,
                    EXISTS(SELECT 1 FROM pando_repository_states s WHERE s.repository_id=r.id),
                    EXISTS(SELECT 1 FROM repository_ref_projection p WHERE p.repository_id=r.id)
             FROM repositories r WHERE r.id=$1 FOR SHARE",
            &[&scope.repository_id()],
        )
        .await
        .map_err(pg::db_error)?
        .ok_or(RefStoreError::RepositoryNotFound)?;
    let owner: Uuid = row.get(0);
    let object_format: String = row.get(1);
    if owner != scope.tenant_id() {
        return Err(RefStoreError::RepositoryNotFound);
    }
    if require_unserved {
        let state: String = row.get(2);
        let storage_backend: String = row.get(3);
        let transition_state: String = row.get(4);
        let pando_authority: bool = row.get(5);
        let legacy_refs: bool = row.get(6);
        if state != "provisioning" || storage_backend != "gitfs" || transition_state != "stable" {
            return Err(RefStoreError::Unsupported(
                "repository is no longer an explicitly unserved stable gitfs core repository",
            ));
        }
        if pando_authority || legacy_refs {
            return Err(RefStoreError::Unsupported(
                "repository has a live legacy Pando authority or legacy ref projection",
            ));
        }
        if GitObjectFormat::parse(&object_format)? != scope.object_format() {
            return Err(RefStoreError::MetadataScopeMismatch("repository object format"));
        }
    }
    let query = format!(
        "SELECT tenant_id,object_format,history_incarnation,authority_epoch,group_epoch,head_ref,revision
         FROM ref_store_core_gates WHERE repository_id=$1{}",
        if gate_for_update { " FOR UPDATE" } else { " FOR SHARE" }
    );
    let gate = tx
        .query_opt(&query, &[&scope.repository_id()])
        .await
        .map_err(pg::db_error)?
        .ok_or(RefStoreError::Unsupported("repository has no initialized core gate"))?;
    let gate = super::sql::gate_from_row(scope.repository_id(), &gate)?;
    if gate.tenant_id() != scope.tenant_id() {
        return Err(RefStoreError::RepositoryNotFound);
    }
    if require_unserved {
        if gate.object_format() != scope.object_format() {
            return Err(RefStoreError::MetadataScopeMismatch("gate object format"));
        }
        if gate.history_incarnation() != scope.history_incarnation() {
            return Err(RefStoreError::MetadataScopeMismatch("gate history incarnation"));
        }
        if gate.authority_epoch() != scope.authority_epoch() {
            return Err(RefStoreError::MetadataScopeMismatch("gate authority epoch"));
        }
        if gate.group_epoch() != scope.group_epoch() {
            return Err(RefStoreError::MetadataScopeMismatch("gate group epoch"));
        }
    }
    Ok(gate)
}

/// The pack mode of the already gate-locked row: `lock_scope` holds it `FOR
/// UPDATE`/`FOR SHARE`, so this read adds no lock. A2 fresh writes require
/// `metadata_only`; A5 fresh capture and reads require `pack_verified`.
pub(super) async fn gate_pack_mode(tx: &Transaction<'_>, repository_id: Uuid) -> Result<PackMode, RefStoreError> {
    let row = tx
        .query_opt("SELECT pack_mode FROM ref_store_core_gates WHERE repository_id=$1", &[&repository_id])
        .await
        .map_err(pg::db_error)?
        .ok_or(RefStoreError::Unsupported("repository has no initialized core gate"))?;
    let mode: String = row.get(0);
    PackMode::parse(&mode)
}

/// Read the current refs of the gate-locked repository. The caller holds the
/// gate `FOR UPDATE`, so `CommitRefs` cannot interleave and refs/HEAD/version
/// are one revision.
///
/// The query is bounded to `MAX_SNAPSHOT_REFS + 1` rows: one ref per commit
/// does not bound the total, so an unbounded materialization before the guard
/// would be a DoS. The extra row proves oversize; only then is the exact total
/// counted for the error (a 4097-row tail is a lower bound, not a total).
/// Ordering is explicit `COLLATE "C"` so the captured order and canonical
/// digest are byte-stable regardless of the database default collation.
pub(super) async fn capture_refs(
    tx: &Transaction<'_>,
    repository_id: Uuid,
) -> Result<Vec<(String, String)>, RefStoreError> {
    let limit = (MAX_SNAPSHOT_REFS + 1) as i64;
    let rows = tx
        .query(
            r#"SELECT ref_name,oid FROM ref_store_core_refs WHERE repository_id=$1
             ORDER BY ref_name COLLATE "C" LIMIT $2"#,
            &[&repository_id, &limit],
        )
        .await
        .map_err(pg::db_error)?;
    if rows.len() > MAX_SNAPSHOT_REFS {
        let total: i64 = tx
            .query_one("SELECT count(*) FROM ref_store_core_refs WHERE repository_id=$1", &[&repository_id])
            .await
            .map_err(pg::db_error)?
            .get(0);
        let ref_count = usize::try_from(total).unwrap_or(MAX_SNAPSHOT_REFS + 1);
        return Err(RefStoreError::MetadataSnapshotTooLarge { ref_count, max_refs: MAX_SNAPSHOT_REFS });
    }
    Ok(rows.into_iter().map(|row| (row.get(0), row.get(1))).collect())
}

/// Header fields captured under the gate lock; the creation receipt (which
/// also carries the pin expiry) is built after the pin row exists.
pub(super) struct SnapshotInsert<'a> {
    pub snapshot_id: Uuid,
    pub scope: &'a MetadataSnapshotScope,
    pub gate_revision: i64,
    pub gate_digest: &'a str,
    pub head_ref: &'a str,
    pub head_oid: Option<&'a str>,
    pub ref_count: i64,
    pub refs_digest: &'a str,
    pub logical_bytes: i64,
    /// `Some` only for an A5 pack-aware snapshot; `None` is the exact A2 shape.
    pub pack: Option<PackHeaderInsert<'a>>,
}

/// Additive pack columns of one snapshot header row.
pub(super) struct PackHeaderInsert<'a> {
    pub pack_count: i64,
    pub membership_digest: &'a str,
    pub snapshot_digest: &'a str,
}

/// The stored `ref_count` column is `INTEGER` (`int4`) in migration 140 while
/// the retained receipt/count contract stays `i64`. PostgreSQL widens `int4` to
/// `bigint` on request, but tokio-postgres never coerces Rust parameter or
/// column types, so both boundaries convert explicitly and the write side is
/// *checked*: an out-of-range count is a typed error, never a silent truncation.
fn ref_count_param(ref_count: i64) -> Result<i32, RefStoreError> {
    i32::try_from(ref_count).map_err(|_| {
        RefStoreError::Database(format!(
            "metadata snapshot ref_count {ref_count} does not fit the stored INTEGER ref_count column"
        ))
    })
}

pub(super) async fn insert_snapshot(tx: &Transaction<'_>, insert: &SnapshotInsert<'_>) -> Result<(), RefStoreError> {
    let scope = insert.scope;
    let ref_count = ref_count_param(insert.ref_count)?;
    let (pack_mode, pack_state, pack_count, membership_digest, snapshot_digest) = match &insert.pack {
        None => ("metadata_only", "unavailable", 0i32, None, None),
        Some(pack) => (
            "pack_verified",
            "complete",
            i32::try_from(pack.pack_count)
                .map_err(|_| RefStoreError::Database("pack snapshot pack_count does not fit INTEGER".into()))?,
            Some(pack.membership_digest),
            Some(pack.snapshot_digest),
        ),
    };
    tx.execute(
        "INSERT INTO ref_store_core_snapshots(
             snapshot_id,repository_id,tenant_id,owner_id,purpose,object_format,history_incarnation,
             authority_epoch,group_epoch,gate_revision,gate_digest,head_ref,head_oid,ref_count,
             refs_digest,logical_bytes,pack_membership_state,pack_mode,pack_count,membership_digest,
             snapshot_digest)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)",
        &[
            &insert.snapshot_id,
            &scope.repository_id(),
            &scope.tenant_id(),
            &scope.owner_id(),
            &scope.purpose().as_str(),
            &scope.object_format().as_str(),
            &scope.history_incarnation(),
            &scope.authority_epoch(),
            &scope.group_epoch(),
            &insert.gate_revision,
            &insert.gate_digest,
            &insert.head_ref,
            &insert.head_oid,
            &ref_count,
            &insert.refs_digest,
            &insert.logical_bytes,
            &pack_state,
            &pack_mode,
            &pack_count,
            &membership_digest,
            &snapshot_digest,
        ],
    )
    .await
    .map_err(pg::db_error)?;
    Ok(())
}

pub(super) async fn insert_snapshot_refs(
    tx: &Transaction<'_>,
    snapshot_id: Uuid,
    refs: &[(String, String)],
) -> Result<(), RefStoreError> {
    let names = refs.iter().map(|(name, _)| name.clone()).collect::<Vec<_>>();
    let oids = refs.iter().map(|(_, oid)| oid.clone()).collect::<Vec<_>>();
    tx.execute(
        "INSERT INTO ref_store_core_snapshot_refs(snapshot_id,ref_name,oid)
         SELECT $1,ref_name,oid FROM unnest($2::text[],$3::text[]) AS captured(ref_name,oid)",
        &[&snapshot_id, &names, &oids],
    )
    .await
    .map_err(pg::db_error)?;
    Ok(())
}

/// Immutable snapshot header, read without a lock (rows never change).
pub(super) async fn snapshot_header(
    tx: &Transaction<'_>,
    snapshot_id: Uuid,
    repository_id: Uuid,
) -> Result<Option<SnapshotHeader>, RefStoreError> {
    let row = tx
        .query_opt(
            "SELECT snapshot_id,repository_id,tenant_id,owner_id,purpose,object_format,
                    history_incarnation,authority_epoch,group_epoch,gate_revision,gate_digest,
                    head_ref,head_oid,ref_count,refs_digest,logical_bytes,pack_membership_state,
                    pack_mode,pack_count,membership_digest,snapshot_digest
             FROM ref_store_core_snapshots WHERE snapshot_id=$1 AND repository_id=$2",
            &[&snapshot_id, &repository_id],
        )
        .await
        .map_err(pg::db_error)?;
    let Some(row) = row else { return Ok(None) };
    let purpose: String = row.get(4);
    let object_format: String = row.get(5);
    let head_ref: String = row.get(11);
    let pack_mode = PackMode::parse(&row.get::<_, String>(17))?;
    let expected_state = if pack_mode == PackMode::PackVerified { "complete" } else { "unavailable" };
    if row.get::<_, String>(16) != expected_state {
        return Err(RefStoreError::Database(
            "stored snapshot pack_membership_state disagrees with its pack_mode".into(),
        ));
    }
    Ok(Some(SnapshotHeader {
        snapshot_id: row.get(0),
        repository_id: row.get(1),
        tenant_id: row.get(2),
        owner_id: row.get(3),
        purpose: MetadataPinPurpose::parse(&purpose)?,
        object_format: GitObjectFormat::parse(&object_format)?,
        history_incarnation: row.get(6),
        authority_epoch: row.get(7),
        group_epoch: row.get(8),
        gate_revision: row.get(9),
        gate_digest: row.get(10),
        head_ref: RefName::new(head_ref)?.as_str().to_owned(),
        head_oid: row.get(12),
        // `ref_count` is `INTEGER` (migration 140) and the public count stays
        // `i64`; decode the stored width explicitly instead of asking
        // tokio-postgres to deserialize int4 straight into i64.
        ref_count: i64::from(row.get::<_, i32>(13)),
        refs_digest: row.get(14),
        logical_bytes: row.get(15),
        pack_mode,
        pack_count: i64::from(row.get::<_, i32>(18)),
        membership_digest: row.get(19),
        snapshot_digest: row.get(20),
    }))
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn insert_pin(
    tx: &Transaction<'_>,
    pin_id: Uuid,
    scope: &MetadataSnapshotScope,
    snapshot_id: Uuid,
    request_id: Uuid,
    request_digest: &str,
    lease_seconds: i64,
) -> Result<i64, RefStoreError> {
    let row = tx
        .query_one(
            "INSERT INTO ref_store_core_pins(
                 pin_id,repository_id,tenant_id,snapshot_id,owner_id,purpose,create_request_id,
                 create_digest,generation,state,expires_at)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,1,'active',clock_timestamp()+$9::bigint*interval '1 second')
             RETURNING (extract(epoch FROM expires_at)*1000000)::bigint",
            &[
                &pin_id,
                &scope.repository_id(),
                &scope.tenant_id(),
                &snapshot_id,
                &scope.owner_id(),
                &scope.purpose().as_str(),
                &request_id,
                &request_digest,
                &lease_seconds,
            ],
        )
        .await
        .map_err(pg::db_error)?;
    Ok(row.get(0))
}

const PIN_COLUMNS: &str = "pin_id,repository_id,tenant_id,snapshot_id,owner_id,purpose,generation,state,
    (extract(epoch FROM expires_at)*1000000)::bigint,
    (extract(epoch FROM released_at)*1000000)::bigint,
    release_reason,expires_at <= clock_timestamp()";

fn pin_from_row(row: &Row) -> Result<PinRow, RefStoreError> {
    let purpose: String = row.get(5);
    let state: String = row.get(7);
    let reason: Option<String> = row.get(10);
    Ok(PinRow {
        pin_id: row.get(0),
        repository_id: row.get(1),
        tenant_id: row.get(2),
        snapshot_id: row.get(3),
        owner_id: row.get(4),
        purpose: MetadataPinPurpose::parse(&purpose)?,
        generation: row.get(6),
        state: PinState::parse(&state)?,
        expires_at_unix_micros: row.get(8),
        released_at_unix_micros: row.get(9),
        release_reason: reason.as_deref().map(PinReleaseReason::parse).transpose()?,
        expired: row.get(11),
    })
}

/// A page holds the pin `FOR SHARE`, so a concurrent release `FOR UPDATE`
/// waits for admitted pages to finish.
pub(super) async fn pin_for_share(
    tx: &Transaction<'_>,
    pin_id: Uuid,
    repository_id: Uuid,
) -> Result<Option<PinRow>, RefStoreError> {
    let query =
        format!("SELECT {} FROM ref_store_core_pins WHERE pin_id=$1 AND repository_id=$2 FOR SHARE", PIN_COLUMNS);
    let row = tx.query_opt(&query, &[&pin_id, &repository_id]).await.map_err(pg::db_error)?;
    row.as_ref().map(pin_from_row).transpose()
}

/// Renew/release lock the exact pin row (`FOR UPDATE`) and CAS its generation.
pub(super) async fn pin_for_update(
    tx: &Transaction<'_>,
    pin_id: Uuid,
    repository_id: Uuid,
) -> Result<Option<PinRow>, RefStoreError> {
    let query =
        format!("SELECT {} FROM ref_store_core_pins WHERE pin_id=$1 AND repository_id=$2 FOR UPDATE", PIN_COLUMNS);
    let row = tx.query_opt(&query, &[&pin_id, &repository_id]).await.map_err(pg::db_error)?;
    row.as_ref().map(pin_from_row).transpose()
}

/// Stable pin identity without reading or locking generation/expiry. Receipt
/// replay uses this to prove a historical receipt still names the same
/// immutable pin scope; it must never compare the receipt generation with the
/// live one, because a legitimate renewal/release advances the pin.
pub(super) async fn pin_identity(
    tx: &Transaction<'_>,
    pin_id: Uuid,
    repository_id: Uuid,
) -> Result<Option<PinIdentity>, RefStoreError> {
    let row = tx
        .query_opt(
            "SELECT pin_id,repository_id,tenant_id,snapshot_id,owner_id,purpose
             FROM ref_store_core_pins WHERE pin_id=$1 AND repository_id=$2",
            &[&pin_id, &repository_id],
        )
        .await
        .map_err(pg::db_error)?;
    let Some(row) = row else { return Ok(None) };
    let purpose: String = row.get(5);
    Ok(Some(PinIdentity {
        pin_id: row.get(0),
        repository_id: row.get(1),
        tenant_id: row.get(2),
        snapshot_id: row.get(3),
        owner_id: row.get(4),
        purpose: MetadataPinPurpose::parse(&purpose)?,
    }))
}

/// CAS renewal: generation advances by exactly one and the lease is re-based on
/// the database clock. The expiry predicate is evaluated in this same UPDATE
/// (the linearization point), so a pin that expires after the `FOR UPDATE`
/// read but before the write cannot be silently revived.
pub(super) async fn renew_pin(
    tx: &Transaction<'_>,
    pin_id: Uuid,
    repository_id: Uuid,
    expected_generation: i64,
    lease_seconds: i64,
) -> Result<Option<(i64, i64)>, RefStoreError> {
    let row = tx
        .query_opt(
            "UPDATE ref_store_core_pins
             SET generation=generation+1,renewed_at=clock_timestamp(),updated_at=clock_timestamp(),
                 expires_at=clock_timestamp()+$4::bigint*interval '1 second'
             WHERE pin_id=$1 AND repository_id=$2 AND generation=$3 AND state='active'
               AND expires_at > clock_timestamp()
             RETURNING generation,(extract(epoch FROM expires_at)*1000000)::bigint",
            &[&pin_id, &repository_id, &expected_generation, &lease_seconds],
        )
        .await
        .map_err(pg::db_error)?;
    Ok(row.map(|row| (row.get(0), row.get(1))))
}

/// Explicit terminal release of exactly this generation. Release does not
/// advance the generation and never refunds retained usage.
pub(super) async fn release_pin(
    tx: &Transaction<'_>,
    pin_id: Uuid,
    repository_id: Uuid,
    expected_generation: i64,
    request_id: Uuid,
    reason: PinReleaseReason,
) -> Result<Option<(i64, i64, i64)>, RefStoreError> {
    let row = tx
        .query_opt(
            "UPDATE ref_store_core_pins
             SET state='released',released_at=clock_timestamp(),release_request_id=$4,
                 release_reason=$5,updated_at=clock_timestamp()
             WHERE pin_id=$1 AND repository_id=$2 AND generation=$3 AND state='active'
             RETURNING generation,(extract(epoch FROM released_at)*1000000)::bigint,
                       (extract(epoch FROM expires_at)*1000000)::bigint",
            &[&pin_id, &repository_id, &expected_generation, &request_id, &reason.as_str()],
        )
        .await
        .map_err(pg::db_error)?;
    Ok(row.map(|row| (row.get(0), row.get(1), row.get(2))))
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn insert_receipt(
    tx: &Transaction<'_>,
    request_id: Uuid,
    scope: &MetadataSnapshotScope,
    action: MetadataMutationAction,
    request_digest: &str,
    receipt: &MetadataReceipt,
    body: &str,
) -> Result<(), RefStoreError> {
    tx.execute(
        "INSERT INTO ref_store_core_receipts(
             request_id,repository_id,tenant_id,action,request_digest,pin_id,snapshot_id,pin_generation,body)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        &[
            &request_id,
            &scope.repository_id(),
            &scope.tenant_id(),
            &action.as_str(),
            &request_digest,
            &receipt.pin_id(),
            &receipt.snapshot_id(),
            &receipt.pin_generation(),
            &body,
        ],
    )
    .await
    .map_err(pg::db_error)?;
    Ok(())
}

/// Strict byte-ordered keyset page: `limit + 1` rows, literal prefix compare.
/// The prefix length is measured in characters (`char_length`) because
/// PostgreSQL `left` counts characters, not bytes; `octet_length` would slice
/// the wrong amount for a multi-byte UTF-8 prefix. The compare stays literal
/// (no `LIKE` wildcards) and is forced to the byte (`"C"`) collation, matching
/// the primary key `(snapshot_id, ref_name)` order.
pub(super) async fn page_refs(
    tx: &Transaction<'_>,
    snapshot_id: Uuid,
    after: Option<&str>,
    prefix: Option<&str>,
    limit_plus_one: i64,
) -> Result<Vec<(String, String)>, RefStoreError> {
    let rows = tx
        .query(
            r#"SELECT ref_name,oid FROM ref_store_core_snapshot_refs
             WHERE snapshot_id=$1
               AND ref_name > (COALESCE($2::text,'') COLLATE "C")
               AND ($3::text IS NULL OR left(ref_name,char_length($3::text)) = ($3::text COLLATE "C"))
             ORDER BY ref_name COLLATE "C"
             LIMIT $4"#,
            &[&snapshot_id, &after, &prefix, &limit_plus_one],
        )
        .await
        .map_err(pg::db_error)?;
    Ok(rows.into_iter().map(|row| (row.get(0), row.get(1))).collect())
}
