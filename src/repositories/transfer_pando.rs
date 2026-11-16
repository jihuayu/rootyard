//! Authority-scoped Pando artifact reservation, copy, rekey verification,
//! incremental persistence, and rollback cleanup for ownership transfers (#85).
use super::{
    purge_exec::{delete_pando_artifact_states, retire_pando_artifact_states},
    remote_copy::copy_object_if_present,
    transfer_exec::parse_tenant_key,
    transfer_model::{CopiedRemoteObject, plan_pando_copy},
};
use crate::{
    pando_gateway::retention,
    storage::remote_objects::{ObjectKey, RemoteObjectStore},
};
use anyhow::{Context, Result, ensure};
use deadpool_postgres::{Pool, Transaction};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
use tokio::time::Instant;
use uuid::Uuid;

/// Parameters for copying Pando pack/envelope artifacts into a transfer destination tenant.
pub(super) struct PandoTransferCopy<'a> {
    pub transfer_lease: Option<(Uuid, &'a str, i64)>,
    pub repo_id: Uuid,
    pub from_owner: Uuid,
    pub to_owner: Uuid,
    pub stage_dir: &'a Path,
    pub deadline: Instant,
}

struct LinkedPandoSource {
    manifest_ids: Vec<Uuid>,
    auth_id: Uuid,
    ns: String,
    sha: String,
    obj_gen: i64,
    remote_path: String,
    size: i64,
    src_state: String,
}

async fn verify_copy_lease(tx: &Transaction<'_>, transfer_id: Uuid, lease_owner: &str, lease_epoch: i64) -> Result<()> {
    let active: bool = tx
        .query_one(
            "SELECT EXISTS( \
                 SELECT 1 FROM repository_transfers \
                 WHERE id = $1 AND state = 'copying_remote' AND lease_owner = $2 AND lease_epoch = $3 \
                   AND lease_until > clock_timestamp() \
             )",
            &[&transfer_id, &lease_owner, &lease_epoch],
        )
        .await?
        .get(0);
    ensure!(active, "transfer lease lost during Pando remote object copy");
    Ok(())
}

pub(super) async fn persist_copied_objects_tx(
    tx: &Transaction<'_>,
    transfer_id: Uuid,
    lease_owner: &str,
    lease_epoch: i64,
    copied: &[CopiedRemoteObject],
) -> Result<()> {
    let val = serde_json::to_value(copied)?;
    let changed = tx
        .execute(
            "UPDATE repository_transfers SET copied_objects = $2, updated_at = clock_timestamp() \
             WHERE id = $1 AND state = 'copying_remote' AND lease_owner = $3 AND lease_epoch = $4",
            &[&transfer_id, &val, &lease_owner, &lease_epoch],
        )
        .await?;
    ensure!(changed == 1, "transfer lease lost while persisting copied remote objects");
    Ok(())
}

pub(super) async fn persist_copied_objects_pool(
    pool: &Pool,
    transfer_id: Uuid,
    lease_owner: &str,
    lease_epoch: i64,
    copied: &[CopiedRemoteObject],
) -> Result<()> {
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    persist_copied_objects_tx(&tx, transfer_id, lease_owner, lease_epoch, copied).await?;
    tx.commit().await?;
    Ok(())
}

pub(super) fn upsert_copied_artifact(
    copied: &mut Vec<CopiedRemoteObject>,
    seen: &mut BTreeSet<(String, String, String)>,
    item: CopiedRemoteObject,
) {
    copied.retain(|existing| {
        if existing.kind == item.kind && existing.from_key == item.from_key {
            seen.remove(&(existing.kind.clone(), existing.from_key.clone(), existing.to_key.clone()));
            false
        } else {
            true
        }
    });
    seen.insert((item.kind.clone(), item.from_key.clone(), item.to_key.clone()));
    copied.push(item);
}

pub(super) fn remove_copied_artifact(
    copied: &mut Vec<CopiedRemoteObject>,
    seen: &mut BTreeSet<(String, String, String)>,
    kind: &str,
    from_key: &str,
) {
    copied.retain(|existing| {
        if existing.kind == kind && existing.from_key == from_key {
            seen.remove(&(existing.kind.clone(), existing.from_key.clone(), existing.to_key.clone()));
            false
        } else {
            true
        }
    });
}

async fn copy_single_linked_pando(
    pool: &Pool,
    store: &RemoteObjectStore,
    req: &PandoTransferCopy<'_>,
    item: &LinkedPandoSource,
    src: &ObjectKey,
    copied: &mut Vec<CopiedRemoteObject>,
    seen: &mut BTreeSet<(String, String, String)>,
) -> Result<()> {
    let expected = u64::try_from(item.size).ok().filter(|&s| s > 0);
    for _ in 0..3 {
        let slot = {
            let mut client = pool.get().await?;
            let tx = client.transaction().await?;
            if let Some((xfer_id, owner, epoch)) = req.transfer_lease {
                verify_copy_lease(&tx, xfer_id, owner, epoch).await?;
            }
            let auth = retention::authority(&*tx).await?;
            ensure!(auth.id == item.auth_id, "Pando storage authority rotated during transfer copy");
            let slot = retention::reserve(&*tx, req.to_owner, Some(item.manifest_ids[0]), &item.ns, &item.sha).await?;
            for &mid in &item.manifest_ids[1..] {
                retention::fence_publication(&*tx, mid, item.auth_id, req.to_owner, &item.ns, &item.sha).await?;
            }
            upsert_copied_artifact(
                copied,
                seen,
                CopiedRemoteObject {
                    kind: item.ns.clone(),
                    from_key: src.path(),
                    to_key: slot.key().path(),
                    size: expected.unwrap_or(0),
                    sha256: Some(item.sha.clone()),
                },
            );
            if let Some((xfer_id, owner, epoch)) = req.transfer_lease {
                persist_copied_objects_tx(&tx, xfer_id, owner, epoch, copied).await?;
            }
            tx.commit().await?;
            slot
        };

        let rec = copy_object_if_present(store, req.stage_dir, &item.ns, src, slot.key(), expected, req.deadline)
            .await?
            .with_context(|| format!("source Pando artifact {} missing during transfer", src.path()))?;

        let active = {
            let mut client = pool.get().await?;
            let tx = client.transaction().await?;
            if let Some((xfer_id, owner, epoch)) = req.transfer_lease {
                verify_copy_lease(&tx, xfer_id, owner, epoch).await?;
            }
            let locked_auth: Uuid = tx
                .query_one("SELECT authority_id FROM pando_storage_authorities WHERE singleton FOR UPDATE", &[])
                .await?
                .get(0);
            ensure!(locked_auth == item.auth_id, "Pando storage authority rotated before transfer activation");
            let ok = retention::activate(&*tx, req.to_owner, &item.ns, &item.sha, rec.size, &slot).await?;
            if !ok {
                tx.rollback().await?;
                false
            } else {
                for &mid in &item.manifest_ids {
                    retention::renew_publication(&*tx, mid).await?;
                }
                upsert_copied_artifact(copied, seen, rec);
                if let Some((xfer_id, owner, epoch)) = req.transfer_lease {
                    persist_copied_objects_tx(&tx, xfer_id, owner, epoch, copied).await?;
                }
                tx.commit().await?;
                true
            }
        };
        if active {
            return Ok(());
        }
    }
    anyhow::bail!("destination Pando artifact {} reservation was repeatedly superseded", item.sha)
}

/// Copy linked Pando artifacts through the destination authority's
/// `reserve -> upload -> activate` + `pando_publication_fences` protocol,
/// persisting every reserved/activated entry incrementally so interruption
/// or second-object failures always retain a recoverable rollback prefix.
pub(super) async fn copy_pando_objects_with_store(
    pool: &Pool,
    store: &RemoteObjectStore,
    req: &PandoTransferCopy<'_>,
    copied: &mut Vec<CopiedRemoteObject>,
    seen: &mut BTreeSet<(String, String, String)>,
) -> Result<()> {
    let (grouped, unlinked_manifests) = {
        let client = pool.get().await?;
        let linked = client
            .query(
                "SELECT m.manifest_id, m.authority_id, m.namespace, m.sha256, \
                        a.object_generation, a.remote_path, a.size, a.state \
                 FROM pando_manifest_artifacts m \
                 LEFT JOIN pando_remote_artifacts a \
                   ON a.authority_id = m.authority_id AND a.tenant_id = m.tenant_id \
                  AND a.namespace = m.namespace AND a.sha256 = m.sha256 \
                 WHERE m.repository_id = $1 AND m.tenant_id = $2 \
                 ORDER BY m.authority_id, m.namespace, m.sha256, m.manifest_id",
                &[&req.repo_id, &req.from_owner],
            )
            .await?;
        let unlinked = client
            .query(
                "SELECT m.manifest FROM pando_pack_manifests m \
                 WHERE m.repository_id = $1 AND m.tenant_id = $2 \
                   AND NOT EXISTS (SELECT 1 FROM pando_manifest_artifacts a WHERE a.manifest_id = m.id)",
                &[&req.repo_id, &req.from_owner],
            )
            .await?;
        let mut map: BTreeMap<(Uuid, String, String), LinkedPandoSource> = BTreeMap::new();
        for row in linked {
            let manifest_id: Uuid = row.get(0);
            let auth_id: Uuid = row.get(1);
            let ns: String = row.get(2);
            let sha: String = row.get(3);
            let obj_gen: i64 =
                row.get::<_, Option<i64>>(4).with_context(|| format!("missing source Pando artifact {sha}"))?;
            let remote_path: String =
                row.get::<_, Option<String>>(5).with_context(|| format!("missing source Pando path {sha}"))?;
            let size: i64 = row.get::<_, Option<i64>>(6).unwrap_or(0);
            let src_state: String =
                row.get::<_, Option<String>>(7).with_context(|| format!("missing source Pando state {sha}"))?;
            ensure!(
                src_state != "deleting" && src_state != "deleted",
                "source Pando artifact {sha} is {src_state}; refusing transfer"
            );
            let entry = map.entry((auth_id, ns.clone(), sha.clone())).or_insert_with(|| LinkedPandoSource {
                manifest_ids: Vec::new(),
                auth_id,
                ns,
                sha,
                obj_gen,
                remote_path,
                size,
                src_state,
            });
            if !entry.manifest_ids.contains(&manifest_id) {
                entry.manifest_ids.push(manifest_id);
            }
        }
        (map, unlinked)
    };

    if grouped.is_empty() && unlinked_manifests.is_empty() {
        return Ok(());
    }

    let scoped_prefix = format!("tenants/{}/authorities/", req.from_owner);
    for item in grouped.into_values() {
        ensure!(item.src_state != "reserved", "source Pando artifact {} still reserved", item.sha);
        let src = if item.remote_path.starts_with(&scoped_prefix) {
            ObjectKey::scoped(req.from_owner, item.auth_id, item.obj_gen, &item.ns, &item.sha)?
        } else {
            ObjectKey::new(req.from_owner, &item.ns, &item.sha)?
        };
        copy_single_linked_pando(pool, store, req, &item, &src, copied, seen).await?;
    }

    for row in unlinked_manifests {
        let manifest: Value = row.get(0);
        for (field, ns) in [
            ("pack_cipher", retention::NAMESPACE_CIPHER),
            ("pack_envelope", retention::NAMESPACE_ENVELOPE),
            ("index_cipher", retention::NAMESPACE_CIPHER),
            ("index_envelope", retention::NAMESPACE_ENVELOPE),
        ] {
            if let Some(sha) = manifest.get(field).and_then(|v| v.get("sha256")).and_then(Value::as_str) {
                let expected = manifest.get(field).and_then(|v| v.get("size")).and_then(Value::as_u64);
                let (src, dst) =
                    plan_pando_copy(req.from_owner, req.to_owner, None, ns, sha).map_err(|e| anyhow::anyhow!(e))?;
                if let Some(rec) =
                    copy_object_if_present(store, req.stage_dir, ns, &src, &dst, expected, req.deadline).await?
                {
                    upsert_copied_artifact(copied, seen, rec);
                    if let Some((xfer_id, owner, epoch)) = req.transfer_lease {
                        persist_copied_objects_pool(pool, xfer_id, owner, epoch, copied).await?;
                    }
                }
            }
        }
    }
    Ok(())
}

/// Lock the storage authority and every destination `pando_remote_artifacts`
/// row needed by this repository's `pando_manifest_artifacts` inside `rekeying_db`,
/// refusing to cascade manifest ownership to any non-`active` or wrong-generation row.
pub(super) async fn verify_pando_rekey_ready_tx(
    tx: &Transaction<'_>,
    repo_id: Uuid,
    from_owner: Uuid,
    to_owner: Uuid,
    copied_objects: &[CopiedRemoteObject],
) -> Result<bool> {
    let rows = tx
        .query(
            "SELECT DISTINCT authority_id, namespace, sha256 \
             FROM pando_manifest_artifacts \
             WHERE repository_id = $1 AND tenant_id = $2 \
             ORDER BY authority_id, namespace, sha256",
            &[&repo_id, &from_owner],
        )
        .await?;
    if rows.is_empty() {
        return Ok(false);
    }
    let live_auth: Uuid = tx
        .query_one("SELECT authority_id FROM pando_storage_authorities WHERE singleton FOR UPDATE", &[])
        .await
        .context("lock Pando storage authority during transfer rekey")?
        .get(0);

    let mut copied_map: BTreeMap<(String, String), (Uuid, i64, String)> = BTreeMap::new();
    for item in copied_objects {
        if matches!(item.kind.as_str(), "pando-cipher" | "pando-envelope")
            && let Some(key) = parse_tenant_key(to_owner, &item.to_key)
            && let Some((auth_id, obj_gen)) = key.authority
        {
            copied_map.insert((key.namespace, key.sha256), (auth_id, obj_gen, item.to_key.clone()));
        }
    }

    for row in rows {
        let (auth_id, ns, sha): (Uuid, String, String) = (row.get(0), row.get(1), row.get(2));
        ensure!(auth_id == live_auth, "Pando storage authority rotated before transfer rekey");
        let (copied_auth, copied_gen, copied_path) = copied_map
            .get(&(ns.clone(), sha.clone()))
            .with_context(|| format!("missing verified destination Pando copy for {ns}/{sha}"))?;
        ensure!(*copied_auth == auth_id, "copied Pando artifact authority mismatch for {ns}/{sha}");

        let target = tx
            .query_opt(
                "SELECT state, object_generation, remote_path \
                 FROM pando_remote_artifacts \
                 WHERE authority_id = $1 AND tenant_id = $2 AND namespace = $3 AND sha256 = $4 FOR UPDATE",
                &[&auth_id, &to_owner, &ns, &sha],
            )
            .await?
            .with_context(|| format!("destination Pando artifact missing during rekey for {ns}/{sha}"))?;
        let state: String = target.get(0);
        let obj_gen: i64 = target.get(1);
        let remote_path: String = target.get(2);
        ensure!(state == "active", "destination Pando artifact {ns}/{sha} is '{state}' during rekey; refusing link");
        ensure!(
            obj_gen == *copied_gen && remote_path == *copied_path,
            "destination Pando artifact {ns}/{sha} generation changed during rekey"
        );
    }
    Ok(true)
}

/// Remove only this repository's transfer fences on `to_owner` matching the
/// repository's live manifest owner (before rekey: `from_owner`; after rekey: `to_owner`),
/// leaving all other publishers' pending fences intact.
pub(super) async fn clear_transfer_pando_fences_tx(tx: &Transaction<'_>, repo_id: Uuid, to_owner: Uuid) -> Result<()> {
    tx.execute(
        "DELETE FROM pando_publication_fences f \
         USING pando_pack_manifests m \
         WHERE f.manifest_id = m.id AND m.repository_id = $1 \
           AND m.tenant_id = (SELECT owner_id FROM repositories WHERE id = $1) \
           AND f.tenant_id = $2",
        &[&repo_id, &to_owner],
    )
    .await?;
    Ok(())
}

/// Delete or retire an authority-scoped destination Pando artifact during rollback
/// (including crashed `reserved` reservations) and fail closed if it remains
/// uncleaned without an active sibling manifest reference or pending fence.
pub(super) async fn rollback_cleanup_pando_artifact(
    pool: &Pool,
    pando_remote_allowed: Option<&RemoteObjectStore>,
    authority_id: Uuid,
    key: &ObjectKey,
    obj_gen: i64,
    deadline: Instant,
) -> Result<()> {
    let cleaned = if let Some(store) = pando_remote_allowed {
        delete_pando_artifact_states(pool, store, authority_id, key, Some(obj_gen), true, deadline).await?
    } else {
        retire_pando_artifact_states(pool, authority_id, key, Some(obj_gen), true).await?
    };
    if cleaned {
        return Ok(());
    }
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT a.state, a.object_generation, \
                    EXISTS(SELECT 1 FROM pando_manifest_artifacts m \
                           WHERE m.authority_id = a.authority_id AND m.tenant_id = a.tenant_id \
                             AND m.namespace = a.namespace AND m.sha256 = a.sha256), \
                    EXISTS(SELECT 1 FROM pando_publication_fences f \
                           WHERE f.authority_id = a.authority_id AND f.tenant_id = a.tenant_id \
                             AND f.namespace = a.namespace AND f.sha256 = a.sha256 \
                             AND f.lease_until > clock_timestamp()) \
             FROM pando_remote_artifacts a \
             WHERE a.authority_id = $1 AND a.tenant_id = $2 AND a.namespace = $3 AND a.sha256 = $4",
            &[&authority_id, &key.tenant_id, &key.namespace, &key.sha256],
        )
        .await?;
    let Some(r) = row else {
        return Ok(());
    };
    let (state, row_gen, has_manifest, has_fence): (String, i64, bool, bool) = (r.get(0), r.get(1), r.get(2), r.get(3));
    if row_gen != obj_gen
        || state == "deleted"
        || (pando_remote_allowed.is_none() && state == "retired")
        || has_manifest
        || has_fence
    {
        return Ok(());
    }
    anyhow::bail!(
        "rollback failed to clean unreferenced Pando artifact {}/{} (state={state}, gen={row_gen})",
        key.namespace,
        key.sha256
    )
}
