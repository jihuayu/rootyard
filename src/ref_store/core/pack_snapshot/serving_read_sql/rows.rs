//! Read/validate/delete side of the transient serving-read pin.

use super::sealed;
use crate::ref_store::contract::RefStoreError;
use crate::ref_store::core::pack_commit::{
    ArtifactLocator, ArtifactSetDigest, ContentDigest, PackArtifactRole, RegisteredArtifact, RegisteredPack,
};
use crate::ref_store::core::pack_snapshot::serving_read_request::{serving_capture_digest, serving_read_logical_bytes};
use crate::ref_store::core::snapshot_contract::{MAX_SNAPSHOT_PACKS, MAX_SNAPSHOT_REFS, MetadataSnapshotScope};
use crate::ref_store::pg;
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

const READ_COLUMNS: &str = "pin_id,snapshot_id,generation,repository_id,tenant_id,owner_id,purpose,object_format,
    history_incarnation,authority_epoch,group_epoch,backend_identity,gate_revision,gate_digest,head_ref,head_oid,
    ref_count,refs_digest,pack_count,membership_digest,snapshot_digest,logical_bytes,lease_seconds,
    (extract(epoch FROM expires_at)*1000000)::bigint,expires_at <= clock_timestamp()";

/// One stored transient serving read header.
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
pub(crate) async fn load_read(
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
pub(crate) async fn read_refs(tx: &Transaction<'_>, pin_id: Uuid) -> Result<Vec<(String, String)>, RefStoreError> {
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

/// Rebuild the complete captured registered pack set from its stored descriptors
/// and artifact rows.
///
/// Every value is reconstructed and revalidated: `RegisteredArtifact::new` and
/// `RegisteredPack::new` re-derive the artifact-set digest from the stored
/// physical identity and refuse a disagreement, so a stored digest (or a
/// metadata flag) can never be promoted into a byte proof.
pub(crate) async fn read_packs(tx: &Transaction<'_>, pin_id: Uuid) -> Result<Vec<RegisteredPack>, RefStoreError> {
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
            ContentDigest::parse(row.get::<_, String>(9)).map_err(sealed::pack_error("locator digest"))?,
            u64::try_from(row.get::<_, i64>(10))
                .map_err(|_| RefStoreError::Database("stored serving read locator length is negative".into()))?,
        )
        .map_err(sealed::pack_error("locator"))?;
        let artifact = RegisteredArtifact::new(
            role,
            slot,
            hold_id,
            locator,
            row.get::<_, String>(11),
            row.get::<_, String>(12),
            ContentDigest::parse(row.get::<_, String>(13)).map_err(sealed::pack_error("verified digest"))?,
            u64::try_from(row.get::<_, i64>(14))
                .map_err(|_| RefStoreError::Database("stored serving read verified length is negative".into()))?,
        )
        .map_err(sealed::pack_error("artifact"))?;
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
        .map_err(sealed::pack_error("identity"))?;
        packs.push(pack);
    }
    Ok(packs)
}

/// Delete exactly one transient pin row at its exact generation. Returns `false`
/// when it is already gone (released, reclaimed or cascaded away), which the
/// release path treats as an idempotent success: nothing is protected any more.
pub(crate) async fn delete_read(
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
    pub(crate) fn ensure_capture_identity(
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
pub(crate) fn check_capture_digest(
    row: &ServingReadRow,
    scope: &MetadataSnapshotScope,
    refs: &[(String, String)],
    packs: &[RegisteredPack],
    membership_digest_hex: &str,
) -> Result<(), RefStoreError> {
    let refs_digest_hex = crate::ref_store::core::snapshot_contract::refs_digest(refs).as_hex();
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
