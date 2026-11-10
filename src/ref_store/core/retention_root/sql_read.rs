//! Read statements for retained roots. Data only: these never lock a source pin, never consult the source
//! snapshot and never require the business repository to still exist.
use super::capture::RawCapture;
use super::error::RootError;
use super::handle::RootRef;
use super::rows::{CaptureRow, PackRow};
use crate::ref_store::core::pack_commit::CapturedRef;
use crate::ref_store::core::types::GitObjectFormat;
use crate::ref_store::pg;
use tokio_postgres::GenericClient;

const CAPTURE_COLUMNS: &str = "repository_id,root_id,generation,tenant_id,owner_id,purpose,business_intent_digest,
    operation_id,operation_digest,request_id,selector_kind,object_format,history_incarnation,authority_epoch,
    group_epoch,source_snapshot_id,source_pin_id,source_pin_generation,source_read_digest,gate_revision,gate_digest,
    head_ref,head_oid,refs_digest,ref_count,membership_digest,pack_set_digest,pack_count,oid_count,
    native_binding_digest,roots_revision,register_digest";

const PACK_COLUMNS: &str = "pack_id,registration_id,artifact_set_digest,joined_revision,
    pack_slot,pack_hold_id,pack_storage_tenant_id,pack_authority_id,pack_authority_generation,pack_attempt_id,
    pack_namespace,pack_sha256,pack_length,pack_provider,pack_backend_identity,pack_verified_sha256,
    pack_verified_length,idx_slot,idx_hold_id,idx_storage_tenant_id,idx_authority_id,idx_authority_generation,
    idx_attempt_id,idx_namespace,idx_sha256,idx_length,idx_provider,idx_backend_identity,idx_verified_sha256,
    idx_verified_length";

/// Read one complete retained capture (header + refs + oids + packs) without any lock, on the caller's own
/// transaction or connection. The caller owns its deadline; a [`GenericClient`] exposes no clock.
pub(super) async fn read_capture(
    tx: &(impl GenericClient + Sync),
    root: RootRef,
) -> Result<Option<RawCapture>, RootError> {
    let query = format!(
        "SELECT {CAPTURE_COLUMNS} FROM ref_store_core_roots
         WHERE repository_id=$1 AND root_id=$2 AND generation=$3"
    );
    let row = tx
        .query_opt(&query, &[&root.repository_id(), &root.root_id(), &root.generation()])
        .await
        .map_err(pg::db_error)?;
    let Some(row) = row else { return Ok(None) };
    let header = CaptureRow::from_row(&row)?;
    read_rows(tx, header).await.map(Some)
}

/// Read the complete capture row set for an already decoded header (used by T2 revalidation).
pub(super) async fn read_rows(tx: &(impl GenericClient + Sync), header: CaptureRow) -> Result<RawCapture, RootError> {
    let repository_id = header.repository_id;
    let root_id = header.root_id;
    let generation = header.generation;
    let format: GitObjectFormat = header.object_format;

    let ref_rows = tx
        .query(
            "SELECT ref_name,oid FROM ref_store_core_root_refs
             WHERE repository_id=$1 AND root_id=$2 AND generation=$3 ORDER BY ref_name",
            &[&repository_id, &root_id, &generation],
        )
        .await
        .map_err(pg::db_error)?;
    let mut refs = Vec::with_capacity(ref_rows.len());
    for row in ref_rows {
        let name: String = row.get(0);
        let oid: String = row.get(1);
        refs.push(CapturedRef::from_stored(format, name, oid)?);
    }

    let oid_rows = tx
        .query(
            "SELECT oid FROM ref_store_core_root_oids
             WHERE repository_id=$1 AND root_id=$2 AND generation=$3 ORDER BY ordinal",
            &[&repository_id, &root_id, &generation],
        )
        .await
        .map_err(pg::db_error)?;
    let oids = oid_rows.into_iter().map(|row| row.get(0)).collect::<Vec<String>>();

    let query = format!(
        "SELECT {PACK_COLUMNS} FROM ref_store_core_root_packs
         WHERE repository_id=$1 AND root_id=$2 AND generation=$3 ORDER BY pack_id"
    );
    let pack_rows = tx.query(&query, &[&repository_id, &root_id, &generation]).await.map_err(pg::db_error)?;
    let mut packs = Vec::with_capacity(pack_rows.len());
    for row in pack_rows {
        packs.push(PackRow::from_row(&row)?.registered()?);
    }
    Ok(RawCapture { header, refs, oids, packs })
}
