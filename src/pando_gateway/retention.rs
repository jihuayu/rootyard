//! Authority-scoped remote artifact retention foundation.
//!
//! A Pando pack's encrypted bytes are usable only through a committed
//! `pando_pack_manifests` row. Pre-132 manifests address tenant-only keys and
//! have no globally tracked reference set, so this module never registers them
//! as deletable. New publications reserve a key scoped to this database's
//! singleton storage authority *before* upload. Only registered, authority
//! scoped artifacts can ever become deletion candidates, and resurrection of a
//! retired content address bumps the authority generation onto a fresh path.
use super::pack_store::PackManifest;
use crate::storage::remote_objects::ObjectKey;
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use tokio_postgres::GenericClient;
use uuid::Uuid;

pub const NAMESPACE_CIPHER: &str = "pando-cipher";
pub const NAMESPACE_ENVELOPE: &str = "pando-envelope";
const RESERVATION_SECONDS: i64 = 300;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Authority {
    pub id: Uuid,
    pub generation: i64,
}

/// A successful reservation is either a reuse of a currently active immutable
/// object or a fresh generation path that must be uploaded by the caller.
#[derive(Clone, Debug)]
pub enum Slot {
    Reuse(ObjectKey),
    Reserved { key: ObjectKey, owner: Uuid },
}

impl Slot {
    pub fn key(&self) -> &ObjectKey {
        match self {
            Self::Reuse(key) | Self::Reserved { key, .. } => key,
        }
    }
}

pub async fn authority<C: GenericClient + Sync>(client: &C) -> Result<Authority> {
    let row = client
        .query_one("SELECT authority_id,generation FROM pando_storage_authorities WHERE singleton", &[])
        .await
        .context("load Pando storage authority")?;
    Ok(Authority { id: row.get(0), generation: row.get(1) })
}

/// Reserve both encrypted objects of a publication inside the caller's
/// transaction. The authority row is updated first, so concurrent publishers
/// serialize and never share an in-flight generation.
pub async fn reserve_pair<C: GenericClient + Sync>(
    client: &C,
    tenant_id: Uuid,
    ciphertext_sha256: &str,
    envelope_sha256: &str,
) -> Result<(Slot, Slot)> {
    let cipher = reserve(client, tenant_id, NAMESPACE_CIPHER, ciphertext_sha256).await?;
    let envelope = reserve(client, tenant_id, NAMESPACE_ENVELOPE, envelope_sha256).await?;
    Ok((cipher, envelope))
}

async fn reserve<C: GenericClient + Sync>(client: &C, tenant_id: Uuid, namespace: &str, sha256: &str) -> Result<Slot> {
    // Serialize reservations for this authority for the duration of the tx.
    let auth = client
        .query_one("SELECT authority_id,generation FROM pando_storage_authorities WHERE singleton FOR UPDATE", &[])
        .await
        .context("lock Pando storage authority")?;
    let authority_id: Uuid = auth.get(0);
    let generation: i64 = auth.get(1);
    let existing = client
        .query_opt(
            "SELECT state,object_generation FROM pando_remote_artifacts \
             WHERE authority_id=$1 AND tenant_id=$2 AND namespace=$3 AND sha256=$4 FOR UPDATE",
            &[&authority_id, &tenant_id, &namespace, &sha256],
        )
        .await?;
    let had_existing = existing.is_some();
    if let Some(row) = &existing {
        let state: String = row.get(0);
        let object_generation: i64 = row.get(1);
        if state == "active" {
            return Ok(Slot::Reuse(ObjectKey::scoped(tenant_id, authority_id, object_generation, namespace, sha256)?));
        }
    }
    // A retired/deleting/deleted artifact must be recreated at a new path so a
    // stale deleter holding the old claim can only remove abandoned bytes.
    let next = if had_existing {
        client
            .query_one(
                "UPDATE pando_storage_authorities SET generation=generation+1,rotated_at=clock_timestamp() \
                 WHERE singleton RETURNING generation",
                &[],
            )
            .await?
            .get::<_, i64>(0)
    } else {
        generation
    };
    let key = ObjectKey::scoped(tenant_id, authority_id, next, namespace, sha256)?;
    let owner = Uuid::new_v4();
    client
        .execute(
            "INSERT INTO pando_remote_artifacts(authority_id,tenant_id,namespace,sha256,object_generation,remote_path,state,reserved_owner,lease_until) \
             VALUES($1,$2,$3,$4,$5,$6,'reserved',$7,clock_timestamp()+make_interval(secs=>$8)) \
             ON CONFLICT(authority_id,tenant_id,namespace,sha256) DO UPDATE SET \
                 object_generation=EXCLUDED.object_generation,remote_path=EXCLUDED.remote_path,state='reserved', \
                 reserved_owner=EXCLUDED.reserved_owner,lease_until=EXCLUDED.lease_until,claimed_by=NULL, \
                 delete_after=NULL,deleted_at=NULL,last_error=NULL,updated_at=clock_timestamp()",
            &[
                &authority_id,
                &tenant_id,
                &namespace,
                &sha256,
                &next,
                &key.path(),
                &owner,
                &RESERVATION_SECONDS,
            ],
        )
        .await?;
    Ok(Slot::Reserved { key, owner })
}

/// Mark a previously uploaded reservation active. Returns false when another
/// publisher superseded this reservation; the caller must re-reserve/upload.
pub async fn activate<C: GenericClient + Sync>(
    client: &C,
    tenant_id: Uuid,
    namespace: &str,
    sha256: &str,
    size: u64,
    slot: &Slot,
) -> Result<bool> {
    let Slot::Reserved { key, owner } = slot else { return Ok(true) };
    let Some((authority_id, generation)) = key.authority else {
        anyhow::bail!("reserved artifact lost its authority scope");
    };
    let changed = client
        .execute(
            "UPDATE pando_remote_artifacts SET state='active',size=$5,reserved_owner=NULL,lease_until=NULL, \
             updated_at=clock_timestamp() \
             WHERE authority_id=$1 AND tenant_id=$2 AND namespace=$3 AND sha256=$4 \
               AND state='reserved' AND reserved_owner=$6 AND object_generation=$7 AND remote_path=$8",
            &[&authority_id, &tenant_id, &namespace, &sha256, &(size as i64), owner, &generation, &key.path()],
        )
        .await?;
    Ok(changed == 1)
}

/// Record the immutable manifest -> artifact links in the same transaction as
/// the ready manifest row. A manifest is never acknowledged without them.
pub async fn record_manifest<C: GenericClient + Sync>(
    client: &C,
    manifest: &PackManifest,
    authority_id: Uuid,
) -> Result<()> {
    let rows = [
        ("pack-cipher", NAMESPACE_CIPHER, &manifest.pack.ciphertext_sha256),
        ("pack-envelope", NAMESPACE_ENVELOPE, &manifest.pack.envelope_sha256),
        ("index-cipher", NAMESPACE_CIPHER, &manifest.index.ciphertext_sha256),
        ("index-envelope", NAMESPACE_ENVELOPE, &manifest.index.envelope_sha256),
    ];
    for (role, namespace, sha256) in rows {
        client
            .execute(
                "INSERT INTO pando_manifest_artifacts(manifest_id,repository_id,authority_id,tenant_id,namespace,sha256,artifact_role) \
                 VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(manifest_id,artifact_role) DO NOTHING",
                &[
                    &manifest.id,
                    &manifest.repository_id,
                    &authority_id,
                    &manifest.tenant_id,
                    &namespace,
                    &sha256,
                    &role,
                ],
            )
            .await?;
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct Resolved {
    pub key: ObjectKey,
    /// True when this database's authority registered the artifact; false for
    /// legacy PackManifest v1 tenant-only objects that must never be deleted.
    pub registered: bool,
}

/// Resolve the exact remote key for a manifest receipt. Legacy objects fall
/// back to the tenant-only path and are permanently excluded from deletion.
pub async fn resolve_artifact<C: GenericClient + Sync>(
    client: &C,
    tenant_id: Uuid,
    namespace: &str,
    sha256: &str,
) -> Result<Resolved> {
    let auth = authority(client).await?;
    let row = client
        .query_opt(
            "SELECT object_generation,state FROM pando_remote_artifacts \
             WHERE authority_id=$1 AND tenant_id=$2 AND namespace=$3 AND sha256=$4",
            &[&auth.id, &tenant_id, &namespace, &sha256],
        )
        .await?;
    match row {
        Some(row) => {
            let state: String = row.get(1);
            ensure!(state != "deleted", "Pando remote artifact was deleted while still referenced");
            let generation: i64 = row.get(0);
            Ok(Resolved {
                key: ObjectKey::scoped(tenant_id, auth.id, generation, namespace, sha256)?,
                registered: true,
            })
        }
        None => Ok(Resolved { key: ObjectKey::new(tenant_id, namespace, sha256)?, registered: false }),
    }
}

/// Restore-time authority reset: the restored database must not inherit the
/// source installation's deletable namespace, or two databases sharing one
/// bucket could delete each other's bytes. Called before the serving closure is
/// re-imported under the fresh authority.
pub async fn reset_authority(client: &mut tokio_postgres::Client) -> Result<Authority> {
    client
        .batch_execute(
            "BEGIN;
             DELETE FROM pando_manifest_artifacts;
             DELETE FROM pando_remote_artifacts;
             UPDATE pando_storage_authorities
                SET authority_id=gen_random_uuid(),generation=1,
                    created_at=clock_timestamp(),rotated_at=clock_timestamp()
                WHERE singleton;
             COMMIT;",
        )
        .await?;
    authority(client).await
}

#[derive(Debug, Serialize)]
pub struct RetentionCounts {
    pub reserved: i64,
    pub active: i64,
    pub retired: i64,
    pub deleting: i64,
    pub deleted: i64,
}

pub async fn counts<C: GenericClient + Sync>(client: &C, tenant_id: Uuid) -> Result<RetentionCounts> {
    let auth = authority(client).await?;
    let mut result = RetentionCounts { reserved: 0, active: 0, retired: 0, deleting: 0, deleted: 0 };
    let rows = client
        .query(
            "SELECT state,count(*) FROM pando_remote_artifacts \
             WHERE authority_id=$1 AND tenant_id=$2 GROUP BY state",
            &[&auth.id, &tenant_id],
        )
        .await?;
    for row in rows {
        let state: String = row.get(0);
        let count: i64 = row.get(1);
        match state.as_str() {
            "reserved" => result.reserved = count,
            "active" => result.active = count,
            "retired" => result.retired = count,
            "deleting" => result.deleting = count,
            "deleted" => result.deleted = count,
            _ => {}
        }
    }
    Ok(result)
}
