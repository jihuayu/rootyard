//! SQL-only row helpers for the bounded TRANSIENT serving read pin (migration
//! 146).
//!
//! Every function here runs inside the one owned short transaction that
//! `super::serving_read` starts. Nothing opens a connection, commits, rolls back,
//! performs Blob/Git IO or mints a proof; rows in, data out.
//!
//! Lock order of the serving read write path (shared with every other A5 write
//! so the two families cannot deadlock):
//!
//! serving tenant usage -> serving repository usage -> repository row
//! `FOR SHARE` -> durable serving binding `FOR SHARE` -> core gate `FOR UPDATE`
//!
//! The read/T2 path takes repository -> binding -> gate `FOR SHARE` -> the
//! transient pin row `FOR SHARE`, and the release path takes the usage rows then
//! the transient pin row `FOR UPDATE`. No path here ever locks a durable
//! `ref_store_core_pins` row or writes any migration-140/143/144/145 row.
use super::super::pack_commit::{
    ArtifactLocator, ArtifactSetDigest, ContentDigest, PackArtifactRole, PackCommitError, PackMembershipEntry,
    PackMode, RegisteredArtifact, RegisteredPack,
};
use super::super::serving_scope::{LockedScope, ScopeRefusal};
use super::super::snapshot_contract::{MAX_SNAPSHOT_PACKS, MAX_SNAPSHOT_REFS, MetadataSnapshotScope};
use super::super::snapshot_sql;
use super::serving_read_request::{
    MAX_EXPIRED_SERVING_READ_RECLAIM, ServingReadUsage, check_read_shape, serving_capture_digest,
    serving_read_logical_bytes,
};
use crate::ref_store::contract::RefStoreError;
use crate::ref_store::pg;
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

/// Map the shared serving-scope refusal into this adapter's typed errors.
///
/// A tenant/not-serving/legacy refusal never discloses more than
/// `RepositoryNotFound`/`Unsupported`; a realm disagreement is a scope mismatch,
/// and a stored-vs-live backend disagreement is refused explicitly instead of
/// being promoted into a byte/proof success.
pub(super) fn map_scope_refusal(refusal: ScopeRefusal) -> RefStoreError {
    match refusal {
        ScopeRefusal::Tenant | ScopeRefusal::NotServing | ScopeRefusal::MissingBinding => {
            RefStoreError::Unsupported(refusal.reason())
        }
        ScopeRefusal::Realm(field) => RefStoreError::MetadataScopeMismatch(match field {
            super::super::serving_scope::RealmField::ObjectFormat => "repository object format",
            super::super::serving_scope::RealmField::HistoryIncarnation => "repository history incarnation",
            super::super::serving_scope::RealmField::AuthorityEpoch => "repository authority epoch",
            super::super::serving_scope::RealmField::GroupEpoch => "repository group epoch",
        }),
        ScopeRefusal::BackendIdentity => RefStoreError::MetadataScopeMismatch("live Blob backend identity"),
        ScopeRefusal::Inconsistent(reason) => RefStoreError::Database(reason.into()),
        other => RefStoreError::Unsupported(other.reason()),
    }
}

/// Lock and classify the strict `pg_refstore` serving realm of the caller scope
/// and return the current (locked) core gate.
///
/// This goes through the one shared authority predicate twice on purpose:
/// `snapshot_sql::lock_scope` proves the repository lane, the durable serving
/// binding readiness and the full stored-vs-requested realm, and
/// `LockedScope::require_serving` additionally compares the binding's stored
/// Blob backend digest with the identity of the store the caller actually holds
/// open. A ready row or a stored hex string alone is never authority.
pub(super) async fn lock_serving_realm(
    tx: &Transaction<'_>,
    scope: &MetadataSnapshotScope,
    backend_identity_hex: &str,
    gate_for_update: bool,
) -> Result<super::super::contract::CoreGate, RefStoreError> {
    let gate = snapshot_sql::lock_scope(tx, scope, true, gate_for_update).await?;
    let locked = LockedScope::lock(tx, scope.repository_id(), false).await?.ok_or(RefStoreError::RepositoryNotFound)?;
    locked.require_serving(scope.tenant_id(), backend_identity_hex).map_err(map_scope_refusal)?;
    Ok(gate)
}

/// The current gate pack mode without taking a lock.
///
/// Only used to decide the *shape* of the capture before the ordered usage locks
/// are taken. The decision is always re-proved under the gate `FOR UPDATE`
/// afterwards, so this read grants nothing.
pub(super) async fn peek_pack_mode(tx: &Transaction<'_>, repository_id: Uuid) -> Result<PackMode, RefStoreError> {
    let row = tx
        .query_opt("SELECT pack_mode FROM ref_store_core_gates WHERE repository_id=$1", &[&repository_id])
        .await
        .map_err(pg::db_error)?;
    match row {
        Some(row) => PackMode::parse(&row.get::<_, String>(0)),
        None => Err(RefStoreError::Unsupported("repository has no initialized core gate")),
    }
}

/// Decode one transient usage `(active_count,logical_bytes)` pair.
///
/// Both columns are `BIGINT`; a missing/typed-wrong column is a typed row-shape
/// failure instead of a panic (an indexing or decode panic would escape the
/// request task). The column order is `SELECT active_count,logical_bytes`.
fn usage_row(row: &Row, what: &'static str) -> Result<ServingReadUsage, RefStoreError> {
    let active = row
        .try_get::<_, i64>(0)
        .map_err(|_| RefStoreError::Database(format!("serving read {what} usage row has no bigint active_count")))?;
    let logical_bytes = row
        .try_get::<_, i64>(1)
        .map_err(|_| RefStoreError::Database(format!("serving read {what} usage row has no bigint logical_bytes")))?;
    Ok(ServingReadUsage::new(active, logical_bytes))
}

/// Lock (or create) and read both transient usage counter/mutex rows.
///
/// Order is tenant then repository, matching every other A5 write path. The
/// repository row's stored tenant is compared after the lock, so a re-created
/// repository id can never inherit another tenant's transient budget.
pub(super) async fn lock_usage(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    repository_id: Uuid,
) -> Result<(ServingReadUsage, ServingReadUsage), RefStoreError> {
    tx.execute(
        "INSERT INTO ref_store_core_serving_read_tenant_usage(tenant_id) VALUES($1)
         ON CONFLICT(tenant_id) DO NOTHING",
        &[&tenant_id],
    )
    .await
    .map_err(pg::db_error)?;
    tx.execute(
        "INSERT INTO ref_store_core_serving_read_repo_usage(repository_id,tenant_id) VALUES($1,$2)
         ON CONFLICT(repository_id) DO NOTHING",
        &[&repository_id, &tenant_id],
    )
    .await
    .map_err(pg::db_error)?;
    let tenant = tx
        .query_one(
            "SELECT active_count,logical_bytes FROM ref_store_core_serving_read_tenant_usage
             WHERE tenant_id=$1 FOR UPDATE",
            &[&tenant_id],
        )
        .await
        .map_err(pg::db_error)?;
    let repository = tx
        .query_one(
            "SELECT tenant_id,active_count,logical_bytes FROM ref_store_core_serving_read_repo_usage
             WHERE repository_id=$1 FOR UPDATE",
            &[&repository_id],
        )
        .await
        .map_err(pg::db_error)?;
    let stored_tenant: Uuid = repository
        .try_get(0)
        .map_err(|_| RefStoreError::Database("serving read repository usage row has no uuid tenant_id".into()))?;
    if stored_tenant != tenant_id {
        return Err(RefStoreError::IdentityConflict);
    }
    // The repository row is `tenant_id,active_count,logical_bytes`.
    let repository_usage = ServingReadUsage::new(
        repository.try_get::<_, i64>(1).map_err(|_| {
            RefStoreError::Database("serving read repository usage row has no bigint active_count".into())
        })?,
        repository.try_get::<_, i64>(2).map_err(|_| {
            RefStoreError::Database("serving read repository usage row has no bigint logical_bytes".into())
        })?,
    );
    // The tenant row is exactly `active_count,logical_bytes`.
    Ok((usage_row(&tenant, "tenant")?, repository_usage))
}

/// Delete at most [`MAX_EXPIRED_SERVING_READ_RECLAIM`] expired transient reads of
/// one tenant. Bounded, ordered by expiry and serialized by the tenant usage row
/// lock the caller already holds.
pub(super) async fn reclaim_expired(tx: &Transaction<'_>, tenant_id: Uuid) -> Result<u64, RefStoreError> {
    let rows = tx
        .query(
            "DELETE FROM ref_store_core_serving_reads
             WHERE pin_id IN (
                 SELECT pin_id FROM ref_store_core_serving_reads
                 WHERE tenant_id=$1 AND expires_at <= clock_timestamp()
                 ORDER BY expires_at
                 LIMIT $2
             )
             RETURNING pin_id",
            &[&tenant_id, &MAX_EXPIRED_SERVING_READ_RECLAIM],
        )
        .await
        .map_err(pg::db_error)?;
    Ok(rows.len() as u64)
}

/// Cheap tenant-scoped probe: is there at least one expired transient row?
///
/// Used by the separately committed bounded cleanup so a scope with nothing to
/// reclaim does not take the usage locks and writes no row at all. The probe and
/// the `DELETE` that follows it are both index probes on
/// `(tenant_id, expires_at)`; the `DELETE` re-evaluates `clock_timestamp()`
/// itself, so a stale `true` can only produce an empty (still committed) batch.
pub(super) async fn has_expired(tx: &Transaction<'_>, tenant_id: Uuid) -> Result<bool, RefStoreError> {
    let row = tx
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM ref_store_core_serving_reads
             WHERE tenant_id=$1 AND expires_at <= clock_timestamp())",
            &[&tenant_id],
        )
        .await
        .map_err(pg::db_error)?;
    Ok(row.get(0))
}

/// Read the locked transient usage counters without taking the locks again.
/// The caller must already hold both `FOR UPDATE` rows (via [`lock_usage`]).
pub(super) async fn read_usage(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    repository_id: Uuid,
) -> Result<(ServingReadUsage, ServingReadUsage), RefStoreError> {
    let tenant = tx
        .query_one(
            "SELECT active_count,logical_bytes FROM ref_store_core_serving_read_tenant_usage WHERE tenant_id=$1",
            &[&tenant_id],
        )
        .await
        .map_err(pg::db_error)?;
    let repository = tx
        .query_one(
            "SELECT active_count,logical_bytes FROM ref_store_core_serving_read_repo_usage WHERE repository_id=$1",
            &[&repository_id],
        )
        .await
        .map_err(pg::db_error)?;
    // Both queries select `active_count,logical_bytes` only.
    Ok((usage_row(&tenant, "tenant")?, usage_row(&repository, "repository")?))
}

/// Recompute both transient counters from the actual rows of this scope.
///
/// Recomputation (instead of a blind increment) keeps the bounds honest even
/// when a legitimate repository delete cascades transient rows away without
/// touching these counter rows, and it can only ever *under*-count a concurrent
/// writer because every writer holds the same tenant usage row.
pub(super) async fn recompute_usage(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    repository_id: Uuid,
) -> Result<(), RefStoreError> {
    tx.execute(
        "UPDATE ref_store_core_serving_read_tenant_usage u
         SET active_count=s.active_count,logical_bytes=s.logical_bytes
         FROM (
             SELECT (count(*) FILTER (WHERE expires_at > clock_timestamp()))::bigint AS active_count,
                    COALESCE(sum(logical_bytes),0)::bigint AS logical_bytes
             FROM ref_store_core_serving_reads WHERE tenant_id=$1
         ) s
         WHERE u.tenant_id=$1",
        &[&tenant_id],
    )
    .await
    .map_err(pg::db_error)?;
    tx.execute(
        "UPDATE ref_store_core_serving_read_repo_usage u
         SET active_count=s.active_count,logical_bytes=s.logical_bytes
         FROM (
             SELECT (count(*) FILTER (WHERE expires_at > clock_timestamp()))::bigint AS active_count,
                    COALESCE(sum(logical_bytes),0)::bigint AS logical_bytes
             FROM ref_store_core_serving_reads WHERE repository_id=$1
         ) s
         WHERE u.repository_id=$1",
        &[&repository_id],
    )
    .await
    .map_err(pg::db_error)?;
    Ok(())
}

/// One complete transient serving read header to insert.
pub(super) struct ServingReadInsert<'a> {
    pub pin_id: Uuid,
    pub snapshot_id: Uuid,
    pub scope: &'a MetadataSnapshotScope,
    pub backend_identity: &'a str,
    pub gate_revision: i64,
    pub gate_digest: &'a str,
    pub head_ref: &'a str,
    pub head_oid: Option<&'a str>,
    pub refs: &'a [(String, String)],
    pub packs: &'a [RegisteredPack],
    pub entries: &'a [PackMembershipEntry],
    pub refs_digest: &'a str,
    pub membership_digest: &'a str,
    pub snapshot_digest: &'a str,
    pub logical_bytes: i64,
    pub lease_seconds: i64,
}

fn int4(value: i64, what: &'static str) -> Result<i32, RefStoreError> {
    i32::try_from(value).map_err(|_| RefStoreError::Database(format!("serving read {what} does not fit INTEGER")))
}

/// Insert the header row, its refs, its complete pack descriptors and every
/// artifact row, and return the stored lease expiry (database clock micros).
pub(super) async fn insert_read(tx: &Transaction<'_>, insert: &ServingReadInsert<'_>) -> Result<i64, RefStoreError> {
    check_read_shape(insert.refs.len(), insert.packs.len())?;
    if insert.packs.len() != insert.entries.len() {
        return Err(RefStoreError::Database("serving read pack/entry counts disagree".into()));
    }
    let ref_count = int4(insert.refs.len() as i64, "ref_count")?;
    let pack_count = int4(insert.packs.len() as i64, "pack_count")?;
    let lease_seconds = int4(insert.lease_seconds, "lease_seconds")?;
    let row = tx
        .query_one(
            "INSERT INTO ref_store_core_serving_reads(
                 pin_id,snapshot_id,generation,repository_id,tenant_id,owner_id,purpose,object_format,
                 history_incarnation,authority_epoch,group_epoch,backend_identity,gate_revision,gate_digest,
                 head_ref,head_oid,ref_count,refs_digest,pack_count,membership_digest,snapshot_digest,
                 logical_bytes,lease_seconds,expires_at)
             VALUES($1,$2,1,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,
                    clock_timestamp()+$22::integer*interval '1 second')
             RETURNING (extract(epoch FROM expires_at)*1000000)::bigint",
            &[
                &insert.pin_id,
                &insert.snapshot_id,
                &insert.scope.repository_id(),
                &insert.scope.tenant_id(),
                &insert.scope.owner_id(),
                &insert.scope.purpose().as_str(),
                &insert.scope.object_format().as_str(),
                &insert.scope.history_incarnation(),
                &insert.scope.authority_epoch(),
                &insert.scope.group_epoch(),
                &insert.backend_identity,
                &insert.gate_revision,
                &insert.gate_digest,
                &insert.head_ref,
                &insert.head_oid,
                &ref_count,
                &insert.refs_digest,
                &pack_count,
                &insert.membership_digest,
                &insert.snapshot_digest,
                &insert.logical_bytes,
                &lease_seconds,
            ],
        )
        .await
        .map_err(pg::db_error)?;
    if !insert.refs.is_empty() {
        let names = insert.refs.iter().map(|(name, _)| name.clone()).collect::<Vec<_>>();
        let oids = insert.refs.iter().map(|(_, oid)| oid.clone()).collect::<Vec<_>>();
        tx.execute(
            "INSERT INTO ref_store_core_serving_read_refs(pin_id,ref_name,oid)
             SELECT $1,ref_name,oid FROM unnest($2::text[],$3::text[]) AS captured(ref_name,oid)",
            &[&insert.pin_id, &names, &oids],
        )
        .await
        .map_err(pg::db_error)?;
    }
    insert_pack_descriptors(tx, insert).await?;
    Ok(row.get(0))
}

/// Insert every captured pack descriptor and the full physical identity of both
/// of its artifacts. The rows are what a future GC enumerates as protected.
async fn insert_pack_descriptors(tx: &Transaction<'_>, insert: &ServingReadInsert<'_>) -> Result<(), RefStoreError> {
    let pack_ids = insert.packs.iter().map(RegisteredPack::pack_id).collect::<Vec<_>>();
    let registration_ids = insert.packs.iter().map(RegisteredPack::registration_id).collect::<Vec<_>>();
    let digests = insert.entries.iter().map(|entry| entry.artifact_set_digest().as_hex()).collect::<Vec<_>>();
    let joined = insert.entries.iter().map(PackMembershipEntry::joined_revision).collect::<Vec<_>>();
    tx.execute(
        "INSERT INTO ref_store_core_serving_read_packs(
             pin_id,pack_id,registration_id,artifact_set_digest,joined_revision)
         SELECT $1,p.pack_id,p.registration_id,p.artifact_set_digest,p.joined_revision
         FROM unnest($2::uuid[],$3::uuid[],$4::text[],$5::bigint[])
              AS p(pack_id,registration_id,artifact_set_digest,joined_revision)",
        &[&insert.pin_id, &pack_ids, &registration_ids, &digests, &joined],
    )
    .await
    .map_err(pg::db_error)?;

    let mut artifact_pack_ids: Vec<Uuid> = Vec::new();
    let mut roles: Vec<String> = Vec::new();
    let mut slots: Vec<i32> = Vec::new();
    let mut hold_ids: Vec<Uuid> = Vec::new();
    let mut locator_tenants: Vec<Uuid> = Vec::new();
    let mut authority_ids: Vec<Uuid> = Vec::new();
    let mut authority_generations: Vec<i64> = Vec::new();
    let mut attempt_ids: Vec<Uuid> = Vec::new();
    let mut namespaces: Vec<String> = Vec::new();
    let mut locator_sha256: Vec<String> = Vec::new();
    let mut locator_lengths: Vec<i64> = Vec::new();
    let mut providers: Vec<String> = Vec::new();
    let mut backends: Vec<String> = Vec::new();
    let mut verified_sha256: Vec<String> = Vec::new();
    let mut verified_lengths: Vec<i64> = Vec::new();
    for pack in insert.packs {
        for artifact in pack.artifacts() {
            let locator = artifact.locator();
            artifact_pack_ids.push(pack.pack_id());
            roles.push(artifact.role().as_str().to_owned());
            slots.push(artifact.slot());
            hold_ids.push(artifact.hold_id());
            locator_tenants.push(locator.tenant_id());
            authority_ids.push(locator.authority_id());
            authority_generations.push(locator.authority_generation());
            attempt_ids.push(locator.attempt_id());
            namespaces.push(locator.namespace().to_owned());
            locator_sha256.push(locator.sha256().as_str().to_owned());
            locator_lengths.push(
                i64::try_from(locator.length())
                    .map_err(|_| RefStoreError::Database("serving read artifact length overflows".into()))?,
            );
            providers.push(artifact.provider().to_owned());
            backends.push(artifact.backend_identity().to_owned());
            verified_sha256.push(artifact.verified_sha256().as_str().to_owned());
            verified_lengths.push(
                i64::try_from(artifact.verified_length())
                    .map_err(|_| RefStoreError::Database("serving read verified length overflows".into()))?,
            );
        }
    }
    tx.execute(
        "INSERT INTO ref_store_core_serving_read_artifacts(
             pin_id,pack_id,role,slot,hold_id,locator_tenant_id,locator_authority_id,
             locator_authority_generation,locator_attempt_id,locator_namespace,locator_sha256,
             locator_length,provider,backend_identity,verified_sha256,verified_length)
         SELECT $1,a.pack_id,a.role,a.slot,a.hold_id,a.locator_tenant_id,a.locator_authority_id,
                a.locator_authority_generation,a.locator_attempt_id,a.locator_namespace,
                a.locator_sha256,a.locator_length,a.provider,a.backend_identity,a.verified_sha256,
                a.verified_length
         FROM unnest($2::uuid[],$3::text[],$4::int[],$5::uuid[],$6::uuid[],$7::uuid[],$8::bigint[],
                     $9::uuid[],$10::text[],$11::text[],$12::bigint[],$13::text[],$14::text[],
                     $15::text[],$16::bigint[])
              AS a(pack_id,role,slot,hold_id,locator_tenant_id,locator_authority_id,
                   locator_authority_generation,locator_attempt_id,locator_namespace,locator_sha256,
                   locator_length,provider,backend_identity,verified_sha256,verified_length)",
        &[
            &insert.pin_id,
            &artifact_pack_ids,
            &roles,
            &slots,
            &hold_ids,
            &locator_tenants,
            &authority_ids,
            &authority_generations,
            &attempt_ids,
            &namespaces,
            &locator_sha256,
            &locator_lengths,
            &providers,
            &backends,
            &verified_sha256,
            &verified_lengths,
        ],
    )
    .await
    .map_err(pg::db_error)?;
    Ok(())
}

const READ_COLUMNS: &str = "pin_id,snapshot_id,generation,repository_id,tenant_id,owner_id,purpose,object_format,
    history_incarnation,authority_epoch,group_epoch,backend_identity,gate_revision,gate_digest,head_ref,head_oid,
    ref_count,refs_digest,pack_count,membership_digest,snapshot_digest,logical_bytes,lease_seconds,
    (extract(epoch FROM expires_at)*1000000)::bigint,expires_at <= clock_timestamp()";

/// One stored transient serving read header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ServingReadRow {
    pub pin_id: Uuid,
    pub snapshot_id: Uuid,
    pub generation: i64,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
    pub purpose: String,
    pub object_format: String,
    pub history_incarnation: Uuid,
    pub authority_epoch: i64,
    pub group_epoch: i64,
    pub backend_identity: String,
    pub gate_revision: i64,
    pub gate_digest: String,
    pub head_ref: String,
    pub head_oid: Option<String>,
    pub ref_count: i64,
    pub refs_digest: String,
    pub pack_count: i64,
    pub membership_digest: String,
    pub snapshot_digest: String,
    pub logical_bytes: i64,
    pub expires_at_unix_micros: i64,
    pub expired: bool,
}

fn read_row(row: &Row) -> ServingReadRow {
    ServingReadRow {
        pin_id: row.get(0),
        snapshot_id: row.get(1),
        generation: row.get(2),
        repository_id: row.get(3),
        tenant_id: row.get(4),
        owner_id: row.get(5),
        purpose: row.get(6),
        object_format: row.get(7),
        history_incarnation: row.get(8),
        authority_epoch: row.get(9),
        group_epoch: row.get(10),
        backend_identity: row.get(11),
        gate_revision: row.get(12),
        gate_digest: row.get(13),
        head_ref: row.get(14),
        head_oid: row.get(15),
        ref_count: i64::from(row.get::<_, i32>(16)),
        refs_digest: row.get(17),
        pack_count: i64::from(row.get::<_, i32>(18)),
        membership_digest: row.get(19),
        snapshot_digest: row.get(20),
        logical_bytes: row.get(21),
        expires_at_unix_micros: row.get(23),
        expired: row.get(24),
    }
}

/// Read one transient header row, optionally holding it `FOR SHARE`/`FOR UPDATE`.
///
/// The `FOR SHARE` read is the T2 linearization lock: a concurrent release
/// deletes the row `FOR UPDATE` and therefore waits until the revalidation
/// transaction has finished.
pub(super) async fn load_read(
    tx: &Transaction<'_>,
    pin_id: Uuid,
    repository_id: Uuid,
    lock: Option<&str>,
) -> Result<Option<ServingReadRow>, RefStoreError> {
    let suffix = match lock {
        Some("share") => " FOR SHARE",
        Some("update") => " FOR UPDATE",
        _ => "",
    };
    let query =
        format!("SELECT {READ_COLUMNS} FROM ref_store_core_serving_reads WHERE pin_id=$1 AND repository_id=$2{suffix}");
    let row = tx.query_opt(&query, &[&pin_id, &repository_id]).await.map_err(pg::db_error)?;
    Ok(row.as_ref().map(read_row))
}

/// The captured refs of one transient read, bounded to `4096 + 1` rows so an
/// overflow is a typed refusal instead of a truncation.
pub(super) async fn read_refs(tx: &Transaction<'_>, pin_id: Uuid) -> Result<Vec<(String, String)>, RefStoreError> {
    let rows = tx
        .query(
            r#"SELECT ref_name,oid FROM ref_store_core_serving_read_refs
             WHERE pin_id=$1 ORDER BY ref_name COLLATE "C" LIMIT $2"#,
            &[&pin_id, &((MAX_SNAPSHOT_REFS + 1) as i64)],
        )
        .await
        .map_err(pg::db_error)?;
    if rows.len() > MAX_SNAPSHOT_REFS {
        return Err(RefStoreError::MetadataSnapshotTooLarge { ref_count: rows.len(), max_refs: MAX_SNAPSHOT_REFS });
    }
    Ok(rows.into_iter().map(|row| (row.get(0), row.get(1))).collect())
}

fn pack_error(what: &'static str) -> impl Fn(PackCommitError) -> RefStoreError {
    move |_| RefStoreError::Database(format!("stored serving read pack {what} is invalid"))
}

/// Rebuild the complete captured registered pack set from its stored descriptors
/// and artifact rows.
///
/// Every value is reconstructed and revalidated: `RegisteredArtifact::new` and
/// `RegisteredPack::new` re-derive the artifact-set digest from the stored
/// physical identity and refuse a disagreement, so a stored digest (or a
/// metadata flag) can never be promoted into a byte proof.
pub(super) async fn read_packs(tx: &Transaction<'_>, pin_id: Uuid) -> Result<Vec<RegisteredPack>, RefStoreError> {
    let pack_rows = tx
        .query(
            "SELECT pack_id,registration_id,artifact_set_digest,joined_revision
             FROM ref_store_core_serving_read_packs WHERE pin_id=$1 ORDER BY pack_id LIMIT $2",
            &[&pin_id, &((MAX_SNAPSHOT_PACKS + 1) as i64)],
        )
        .await
        .map_err(pg::db_error)?;
    if pack_rows.is_empty() || pack_rows.len() > MAX_SNAPSHOT_PACKS {
        return Err(RefStoreError::MetadataSnapshotTooLarge {
            ref_count: pack_rows.len(),
            max_refs: MAX_SNAPSHOT_PACKS,
        });
    }
    let artifact_rows = tx
        .query(
            "SELECT pack_id,role,slot,hold_id,locator_tenant_id,locator_authority_id,
                    locator_authority_generation,locator_attempt_id,locator_namespace,locator_sha256,
                    locator_length,provider,backend_identity,verified_sha256,verified_length
             FROM ref_store_core_serving_read_artifacts WHERE pin_id=$1 ORDER BY pack_id,slot
             LIMIT $2",
            &[&pin_id, &((MAX_SNAPSHOT_PACKS * 2 + 1) as i64)],
        )
        .await
        .map_err(pg::db_error)?;
    if artifact_rows.len() > MAX_SNAPSHOT_PACKS * 2 {
        return Err(RefStoreError::MetadataSnapshotTooLarge {
            ref_count: artifact_rows.len(),
            max_refs: MAX_SNAPSHOT_PACKS * 2,
        });
    }
    let mut artifacts: Vec<(Uuid, RegisteredArtifact)> = Vec::with_capacity(artifact_rows.len());
    for row in artifact_rows {
        let pack_id: Uuid = row.get(0);
        let role = PackArtifactRole::parse(&row.get::<_, String>(1))?;
        let slot: i32 = row.get(2);
        let hold_id: Uuid = row.get(3);
        let locator = ArtifactLocator::new(
            row.get(4),
            row.get(5),
            row.get(6),
            row.get(7),
            row.get::<_, String>(8),
            ContentDigest::parse(row.get::<_, String>(9)).map_err(pack_error("locator digest"))?,
            u64::try_from(row.get::<_, i64>(10))
                .map_err(|_| RefStoreError::Database("stored serving read locator length is negative".into()))?,
        )
        .map_err(pack_error("locator"))?;
        let artifact = RegisteredArtifact::new(
            role,
            slot,
            hold_id,
            locator,
            row.get::<_, String>(11),
            row.get::<_, String>(12),
            ContentDigest::parse(row.get::<_, String>(13)).map_err(pack_error("verified digest"))?,
            u64::try_from(row.get::<_, i64>(14))
                .map_err(|_| RefStoreError::Database("stored serving read verified length is negative".into()))?,
        )
        .map_err(pack_error("artifact"))?;
        artifacts.push((pack_id, artifact));
    }
    let mut packs = Vec::with_capacity(pack_rows.len());
    for row in pack_rows {
        let pack_id: Uuid = row.get(0);
        let registration_id: Uuid = row.get(1);
        let digest_hex: String = row.get(2);
        let joined_revision: i64 = row.get(3);
        let parsed: crate::ref_store::contract::RequestDigest = digest_hex
            .parse()
            .map_err(|_| RefStoreError::Database("stored serving read artifact-set digest is not sha256 hex".into()))?;
        let mut pack_artifacts = Vec::with_capacity(2);
        for (artifact_pack_id, artifact) in &artifacts {
            if *artifact_pack_id == pack_id {
                pack_artifacts.push(artifact.clone());
            }
        }
        let pack = RegisteredPack::new(
            pack_id,
            registration_id,
            ArtifactSetDigest::from_digest(parsed),
            pack_artifacts,
            Some(joined_revision),
        )
        .map_err(pack_error("identity"))?;
        packs.push(pack);
    }
    Ok(packs)
}

/// Delete exactly one transient pin row at its exact generation. Returns `false`
/// when it is already gone (released, reclaimed or cascaded away), which the
/// release path treats as an idempotent success: nothing is protected any more.
pub(super) async fn delete_read(
    tx: &Transaction<'_>,
    pin_id: Uuid,
    repository_id: Uuid,
    generation: i64,
) -> Result<bool, RefStoreError> {
    let row = tx
        .query_opt(
            "DELETE FROM ref_store_core_serving_reads
             WHERE pin_id=$1 AND repository_id=$2 AND generation=$3
             RETURNING pin_id",
            &[&pin_id, &repository_id, &generation],
        )
        .await
        .map_err(pg::db_error)?;
    Ok(row.is_some())
}

impl ServingReadRow {
    /// The stored row must be exactly the immutable capture identity the caller
    /// holds: same repository/tenant/owner/purpose/format/history/epochs, same
    /// snapshot and the same pin generation. Anything else is a scope mismatch
    /// (or a generation mismatch for an explicit release), never a success.
    pub(super) fn ensure_capture_identity(
        &self,
        scope: &MetadataSnapshotScope,
        snapshot_id: Uuid,
        generation: i64,
    ) -> Result<(), RefStoreError> {
        if self.repository_id != scope.repository_id() || self.tenant_id != scope.tenant_id() {
            return Err(RefStoreError::MetadataScopeMismatch("serving read repository/tenant"));
        }
        if self.snapshot_id != snapshot_id {
            return Err(RefStoreError::MetadataScopeMismatch("serving read snapshot"));
        }
        if self.owner_id != scope.owner_id() {
            return Err(RefStoreError::MetadataScopeMismatch("serving read owner"));
        }
        if self.purpose != scope.purpose().as_str() {
            return Err(RefStoreError::MetadataScopeMismatch("serving read purpose"));
        }
        if self.object_format != scope.object_format().as_str() {
            return Err(RefStoreError::MetadataScopeMismatch("serving read object format"));
        }
        if self.history_incarnation != scope.history_incarnation() {
            return Err(RefStoreError::MetadataScopeMismatch("serving read history incarnation"));
        }
        if self.authority_epoch != scope.authority_epoch() {
            return Err(RefStoreError::MetadataScopeMismatch("serving read authority epoch"));
        }
        if self.group_epoch != scope.group_epoch() {
            return Err(RefStoreError::MetadataScopeMismatch("serving read group epoch"));
        }
        if self.generation != generation {
            return Err(RefStoreError::MetadataPinGenerationMismatch {
                pin_id: self.pin_id,
                expected: generation,
                actual: self.generation,
            });
        }
        Ok(())
    }
}

/// Recompute the stored capture digest of one row from that row's own immutable
/// columns and the supplied backend identity, and compare it with the stored
/// value. A disagreement is database corruption, never a read success.
pub(super) fn check_capture_digest(
    row: &ServingReadRow,
    scope: &MetadataSnapshotScope,
    refs: &[(String, String)],
    packs: &[RegisteredPack],
    membership_digest_hex: &str,
) -> Result<(), RefStoreError> {
    let refs_digest_hex = super::super::snapshot_contract::refs_digest(refs).as_hex();
    if refs_digest_hex != row.refs_digest || i64::try_from(refs.len()).unwrap_or(i64::MAX) != row.ref_count {
        return Err(RefStoreError::Database(
            "stored serving read refs digest/count disagree with its captured ref rows".into(),
        ));
    }
    let recomputed = serving_capture_digest(
        scope,
        row.snapshot_id,
        row.pin_id,
        row.generation,
        &row.backend_identity,
        row.gate_revision,
        &row.gate_digest,
        &row.head_ref,
        row.head_oid.as_deref(),
        row.ref_count,
        &row.refs_digest,
        row.pack_count,
        membership_digest_hex,
    )
    .as_hex();
    if recomputed != row.snapshot_digest {
        return Err(RefStoreError::Database(
            "stored serving read capture digest disagrees with its captured identity".into(),
        ));
    }
    let recomputed_bytes = serving_read_logical_bytes(&row.head_ref, row.head_oid.as_deref(), refs, packs);
    if recomputed_bytes != row.logical_bytes {
        return Err(RefStoreError::Database(
            "stored serving read logical byte accounting disagrees with its captured rows".into(),
        ));
    }
    Ok(())
}
