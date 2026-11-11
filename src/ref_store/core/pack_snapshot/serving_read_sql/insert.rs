//! Insert side of the transient serving-read pin (header, refs, packs, artifacts).

use super::super::serving_read_request::check_read_shape;
use crate::ref_store::contract::RefStoreError;
use crate::ref_store::core::pack_commit::{PackMembershipEntry, RegisteredPack};
use crate::ref_store::core::snapshot_contract::MetadataSnapshotScope;
use crate::ref_store::pg;
use tokio_postgres::Transaction;
use uuid::Uuid;

/// One complete transient serving read header to insert.
pub(crate) struct ServingReadInsert<'a> {
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
pub(crate) async fn insert_read(tx: &Transaction<'_>, insert: &ServingReadInsert<'_>) -> Result<i64, RefStoreError> {
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
