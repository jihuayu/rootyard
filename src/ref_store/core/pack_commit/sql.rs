//! SQL-only helpers for the A4a pack commit adapter.
//!
//! Every function is called inside one already-owned short transaction. No
//! function opens a connection, commits, rolls back or performs Blob/Git IO, so
//! transaction ownership and rollback policy stay in `super::pg`.
use super::artifact::{ArtifactLocator, ArtifactSetDigest, RegisteredArtifact, RegisteredPack};
use super::context::CapturedRef;
use super::contract::{ARTIFACTS_PER_PACK, PackArtifactRole, PackMode};
use super::plan::{ContentDigest, PackCommitPlan};
use crate::ref_store::contract::{RefStoreError, RequestDigest};
use crate::ref_store::core::contract::CoreGate;
use crate::ref_store::core::sql::gate_from_row;
use crate::ref_store::core::types::GitObjectFormat;
use crate::ref_store::pg;
use tokio_postgres::Transaction;
use uuid::Uuid;

/// Gate row plus the persistent pack mode, locked `FOR UPDATE`.
pub(super) async fn gate_locked(
    tx: &Transaction<'_>,
    repository_id: Uuid,
) -> Result<Option<(CoreGate, PackMode)>, RefStoreError> {
    let row = tx
        .query_opt(
            "SELECT tenant_id,object_format,history_incarnation,authority_epoch,group_epoch,head_ref,revision,pack_mode
             FROM ref_store_core_gates WHERE repository_id=$1 FOR UPDATE",
            &[&repository_id],
        )
        .await
        .map_err(pg::db_error)?;
    let Some(row) = row else { return Ok(None) };
    let gate = gate_from_row(repository_id, &row)?;
    let mode: String = row.get(7);
    Ok(Some((gate, PackMode::parse(&mode)?)))
}

/// Complete ref capture. Counts first so an overflow is a typed refusal instead
/// of a silently truncated page.
pub(super) async fn capture_refs(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    format: GitObjectFormat,
    max_refs: i64,
) -> Result<Vec<CapturedRef>, RefStoreError> {
    let count: i64 = tx
        .query_one("SELECT count(*) FROM ref_store_core_refs WHERE repository_id=$1", &[&repository_id])
        .await
        .map_err(pg::db_error)?
        .get(0);
    if count > max_refs {
        return Err(RefStoreError::Unsupported("ref capture exceeds the fixed 4096-ref bound"));
    }
    let rows = tx
        .query(
            "SELECT ref_name,oid FROM ref_store_core_refs WHERE repository_id=$1 ORDER BY ref_name",
            &[&repository_id],
        )
        .await
        .map_err(pg::db_error)?;
    rows.into_iter()
        .map(|row| {
            CapturedRef::from_stored(format, row.get(0), row.get(1))
                .map_err(|_| RefStoreError::Database("stored ref row is invalid".into()))
        })
        .collect()
}

/// Durable registrations of exactly this parent/operation with complete
/// read-only artifact data. Only a pack that was registered under this parent
/// and operation is returned.
pub(super) async fn registered_for_parent(
    tx: &Transaction<'_>,
    plan: &PackCommitPlan,
) -> Result<Vec<RegisteredPack>, RefStoreError> {
    let rows = tx
        .query(
            "SELECT registration_id,pack_id,artifact_set_digest
             FROM ref_store_core_pack_publications
             WHERE repository_id=$1 AND parent_digest=$2 AND plan_operation_id=$3
             ORDER BY pack_id",
            &[&plan.repository_id(), &plan.parent_digest().as_hex(), &plan.identity().operation_id()],
        )
        .await
        .map_err(pg::db_error)?;
    let mut packs = Vec::with_capacity(rows.len());
    for row in rows {
        let registration_id: Uuid = row.get(0);
        let pack_id: Uuid = row.get(1);
        let stored: String = row.get(2);
        let artifacts = artifacts_for(tx, registration_id, Some(pack_id)).await?;
        packs.push(build_pack(pack_id, registration_id, &stored, artifacts, None)?);
    }
    Ok(packs)
}

/// Full immutable artifact rows of one registration.
pub(super) type ArtifactRow = (PackArtifactRole, i32, Uuid, Uuid, Uuid, i64, Uuid, String, String, String, String, u64);

pub(super) async fn artifacts_for(
    tx: &Transaction<'_>,
    registration_id: Uuid,
    pack_id: Option<Uuid>,
) -> Result<Vec<ArtifactRow>, RefStoreError> {
    let rows = match pack_id {
        Some(pack_id) => {
            tx.query(
                "SELECT a.role,a.slot,a.hold_id,h.storage_tenant_id,h.authority_id,h.authority_generation,
                        h.attempt_id,a.namespace,a.sha256,a.provider,a.backend_identity,a.content_length
                 FROM ref_store_core_pack_artifacts a
                 JOIN artifact_holds h ON h.request_id=a.acquire_request_id AND h.hold_id=a.hold_id
                 WHERE a.registration_id=$1 AND a.pack_id=$2 ORDER BY a.role",
                &[&registration_id, &pack_id],
            )
            .await
        }
        None => {
            tx.query(
                "SELECT a.role,a.slot,a.hold_id,h.storage_tenant_id,h.authority_id,h.authority_generation,
                        h.attempt_id,a.namespace,a.sha256,a.provider,a.backend_identity,a.content_length
                 FROM ref_store_core_pack_artifacts a
                 JOIN artifact_holds h ON h.request_id=a.acquire_request_id AND h.hold_id=a.hold_id
                 WHERE a.registration_id=$1 ORDER BY a.role",
                &[&registration_id],
            )
            .await
        }
    }
    .map_err(pg::db_error)?;
    rows.into_iter()
        .map(|row| {
            let role: String = row.get(0);
            Ok((
                PackArtifactRole::parse(&role)?,
                row.get(1),
                row.get(2),
                row.get(3),
                row.get(4),
                row.get(5),
                row.get(6),
                row.get(7),
                row.get(8),
                row.get(9),
                row.get(10),
                u64::try_from(row.get::<_, i64>(11))
                    .map_err(|_| RefStoreError::Database("negative stored artifact length".into()))?,
            ))
        })
        .collect()
}

pub(super) fn build_pack(
    pack_id: Uuid,
    registration_id: Uuid,
    stored_digest: &str,
    rows: Vec<ArtifactRow>,
    joined_revision: Option<i64>,
) -> Result<RegisteredPack, RefStoreError> {
    if rows.len() != ARTIFACTS_PER_PACK {
        return Err(RefStoreError::Database("stored registration does not have exactly two artifacts".into()));
    }
    let mut artifacts = Vec::with_capacity(rows.len());
    for (role, slot, hold_id, tenant, authority, generation, attempt, namespace, sha, provider, backend, length) in rows
    {
        let digest = |value: &str| {
            ContentDigest::parse(value.to_owned())
                .map_err(|_| RefStoreError::Database("stored sha256 is invalid".into()))
        };
        let locator = ArtifactLocator::new(tenant, authority, generation, attempt, namespace, digest(&sha)?, length)
            .map_err(|_| RefStoreError::Database("stored locator is invalid".into()))?;
        artifacts.push(
            RegisteredArtifact::new(
                role,
                slot,
                hold_id,
                locator.clone(),
                provider,
                backend,
                locator.sha256().clone(),
                length,
            )
            .map_err(|_| RefStoreError::Database("stored artifact identity is invalid".into()))?,
        );
    }
    let stored = parse_digest(stored_digest)?;
    if ArtifactSetDigest::of(&artifacts) != stored {
        return Err(RefStoreError::Database("stored artifact-set digest does not match its artifact rows".into()));
    }
    RegisteredPack::new(pack_id, registration_id, stored, artifacts, joined_revision)
        .map_err(|_| RefStoreError::Database("stored registered pack is invalid".into()))
}

pub(super) fn parse_digest(value: &str) -> Result<ArtifactSetDigest, RefStoreError> {
    let digest: RequestDigest =
        value.parse().map_err(|_| RefStoreError::Database("stored artifact-set digest is not sha256 hex".into()))?;
    Ok(ArtifactSetDigest::from_digest(digest))
}

/// Append-only membership insert for one newly committed pack.
pub(super) async fn insert_membership(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    pack: &RegisteredPack,
    joined_revision: i64,
) -> Result<(), RefStoreError> {
    tx.execute(
        "INSERT INTO ref_store_core_pack_memberships(repository_id,pack_id,registration_id,artifact_set_digest,joined_revision)
         VALUES($1,$2,$3,$4,$5)",
        &[
            &repository_id,
            &pack.pack_id(),
            &pack.registration_id(),
            &pack.artifact_set_digest().as_hex(),
            &joined_revision,
        ],
    )
    .await
    .map_err(pg::db_error)?;
    Ok(())
}

/// Permanent ledger row for one pack authority transition.
pub(super) async fn insert_history(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    tenant_id: Uuid,
    kind: &str,
    pack: &RegisteredPack,
    parent_digest: &RequestDigest,
    revision: i64,
    operation_id: Uuid,
    body: &str,
) -> Result<(), RefStoreError> {
    tx.execute(
        "INSERT INTO ref_store_core_pack_history(history_id,repository_id,tenant_id,kind,registration_id,pack_id,
             parent_digest,revision,operation_id,artifact_set_digest,body)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        &[
            &Uuid::new_v4(),
            &repository_id,
            &tenant_id,
            &kind,
            &pack.registration_id(),
            &pack.pack_id(),
            &parent_digest.as_hex(),
            &revision,
            &operation_id,
            &pack.artifact_set_digest().as_hex(),
            &body,
        ],
    )
    .await
    .map_err(pg::db_error)?;
    Ok(())
}
