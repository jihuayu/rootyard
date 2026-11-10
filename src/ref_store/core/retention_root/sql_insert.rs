//! Insert statements for one immutable root capture (header + refs + selector OIDs + pack identities).
//!
//! All of these run in the same short transaction as the head/tombstone/quota/receipt writes, after the fresh
//! source revalidation and after the quota charge. None of them reads Blob bytes or runs Git.
use super::candidate::RootCandidate;
use super::error::RootError;
use crate::ref_store::core::pack_commit::{CapturedRef, PackArtifactRole, RegisteredPack, packs_digest, refs_digest};
use crate::ref_store::pg;
use tokio_postgres::Transaction;
use uuid::Uuid;

/// Insert the immutable capture header. `request_id` is the receipted register request.
pub(super) async fn insert_capture(
    tx: &Transaction<'_>,
    candidate: &RootCandidate,
    request_id: Uuid,
    roots_revision: i64,
) -> Result<(), RootError> {
    let scope = &candidate.scope;
    let refs_digest = refs_digest(&candidate.captured_refs);
    let pack_set_digest = packs_digest(&candidate.packs);
    let ref_count = i32::try_from(candidate.captured_refs.len())
        .map_err(|_| RootError::RootSelectorInvalid("root ref count is not addressable".into()))?;
    let oid_count = i32::try_from(candidate.oids.len())
        .map_err(|_| RootError::RootSelectorInvalid("root oid count is not addressable".into()))?;
    let pack_count = i32::try_from(candidate.packs.len())
        .map_err(|_| RootError::RootSelectorInvalid("root pack count is not addressable".into()))?;
    tx.execute(
        "INSERT INTO ref_store_core_roots(repository_id,root_id,generation,tenant_id,owner_id,purpose,
             business_intent_digest,operation_id,operation_digest,request_id,selector_kind,object_format,
             history_incarnation,authority_epoch,group_epoch,source_snapshot_id,source_pin_id,source_pin_generation,
             source_read_digest,gate_revision,gate_digest,head_ref,head_oid,refs_digest,ref_count,membership_digest,
             pack_set_digest,pack_count,oid_count,native_binding_digest,roots_revision,register_digest)
         VALUES($1,$2,1,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,
             $26,$27,$28,$29,$30,$31)",
        &[
            &scope.repository_id(),
            &candidate.root_id,
            &scope.tenant_id(),
            &scope.owner_id(),
            &scope.purpose().as_str(),
            &scope.business_intent_hex(),
            &candidate.operation_id,
            &candidate.operation_digest.as_hex(),
            &request_id,
            &candidate.selector_kind.as_str(),
            &scope.object_format().as_str(),
            &scope.history_incarnation(),
            &scope.authority_epoch(),
            &scope.group_epoch(),
            &candidate.source_snapshot_id(),
            &candidate.source_pin_id(),
            &candidate.source_pin_generation(),
            &candidate.source_read_digest_hex(),
            &candidate.gate_revision,
            &candidate.gate_digest,
            &candidate.head_ref,
            &candidate.head_oid,
            &refs_digest.as_hex(),
            &ref_count,
            &candidate.source_membership_digest,
            &pack_set_digest.as_hex(),
            &pack_count,
            &oid_count,
            &candidate.binding_digest.as_hex(),
            &roots_revision,
            &candidate.register_digest.as_hex(),
        ],
    )
    .await
    .map_err(pg::db_error)?;
    Ok(())
}

/// Insert the complete captured ref set in one statement (`<= 4096` rows).
pub(super) async fn insert_refs(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    root_id: Uuid,
    refs: &[CapturedRef],
) -> Result<(), RootError> {
    if refs.is_empty() {
        return Ok(());
    }
    let names = refs.iter().map(|reference| reference.name().to_owned()).collect::<Vec<_>>();
    let oids = refs.iter().map(|reference| reference.oid_hex().to_owned()).collect::<Vec<_>>();
    tx.execute(
        "INSERT INTO ref_store_core_root_refs(repository_id,root_id,generation,ref_name,oid)
         SELECT $1,$2,1,name,oid FROM unnest($3::text[],$4::text[]) AS refs(name,oid)",
        &[&repository_id, &root_id, &names, &oids],
    )
    .await
    .map_err(pg::db_error)?;
    Ok(())
}

/// Insert the exact selector OIDs with their canonical ordinal (`0..=255`).
pub(super) async fn insert_oids(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    root_id: Uuid,
    oids: &[String],
) -> Result<(), RootError> {
    if oids.is_empty() {
        return Ok(());
    }
    let ordinals = (0..oids.len()).map(|ordinal| i32::try_from(ordinal).unwrap_or(i32::MAX)).collect::<Vec<_>>();
    tx.execute(
        "INSERT INTO ref_store_core_root_oids(repository_id,root_id,generation,ordinal,oid)
         SELECT $1,$2,1,ordinal,oid FROM unnest($3::int[],$4::text[]) AS oids(ordinal,oid)",
        &[&repository_id, &root_id, &ordinals, &oids],
    )
    .await
    .map_err(pg::db_error)?;
    Ok(())
}

/// Insert every complete pack identity as one self-contained binding row (`<= 16` rows).
pub(super) async fn insert_packs(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    root_id: Uuid,
    packs: &[RegisteredPack],
) -> Result<(), RootError> {
    for pack in packs {
        let pack_artifact = pack.artifact(PackArtifactRole::Pack);
        let idx_artifact = pack.artifact(PackArtifactRole::Idx);
        let joined_revision = pack
            .joined_revision()
            .ok_or(RootError::RootSourceChanged("a captured pack has no joined membership revision"))?;
        let pack_locator = pack_artifact.locator();
        let idx_locator = idx_artifact.locator();
        tx.execute(
            "INSERT INTO ref_store_core_root_packs(repository_id,root_id,generation,pack_id,registration_id,
                 artifact_set_digest,joined_revision,pack_slot,pack_hold_id,pack_storage_tenant_id,
                 pack_authority_id,pack_authority_generation,pack_attempt_id,pack_namespace,pack_sha256,pack_length,
                 pack_provider,pack_backend_identity,pack_verified_sha256,pack_verified_length,idx_slot,idx_hold_id,
                 idx_storage_tenant_id,idx_authority_id,idx_authority_generation,idx_attempt_id,idx_namespace,
                 idx_sha256,idx_length,idx_provider,idx_backend_identity,idx_verified_sha256,idx_verified_length)
             VALUES($1,$2,1,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,
                 $26,$27,$28,$29,$30,$31,$32)",
            &[
                &repository_id,
                &root_id,
                &pack.pack_id(),
                &pack.registration_id(),
                &pack.artifact_set_digest().as_hex(),
                &joined_revision,
                &pack_artifact.slot(),
                &pack_artifact.hold_id(),
                &pack_locator.tenant_id(),
                &pack_locator.authority_id(),
                &pack_locator.authority_generation(),
                &pack_locator.attempt_id(),
                &pack_locator.namespace(),
                &pack_locator.sha256().as_str(),
                &artifact_length(pack_locator.length())?,
                &pack_artifact.provider(),
                &pack_artifact.backend_identity(),
                &pack_artifact.verified_sha256().as_str(),
                &artifact_length(pack_artifact.verified_length())?,
                &idx_artifact.slot(),
                &idx_artifact.hold_id(),
                &idx_locator.tenant_id(),
                &idx_locator.authority_id(),
                &idx_locator.authority_generation(),
                &idx_locator.attempt_id(),
                &idx_locator.namespace(),
                &idx_locator.sha256().as_str(),
                &artifact_length(idx_locator.length())?,
                &idx_artifact.provider(),
                &idx_artifact.backend_identity(),
                &idx_artifact.verified_sha256().as_str(),
                &artifact_length(idx_artifact.verified_length())?,
            ],
        )
        .await
        .map_err(pg::db_error)?;
    }
    Ok(())
}

fn artifact_length(length: u64) -> Result<i64, RootError> {
    i64::try_from(length).map_err(|_| RootError::RootSourceChanged("registered artifact length is not addressable"))
}
