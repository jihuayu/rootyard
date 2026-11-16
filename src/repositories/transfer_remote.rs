//! Tenant-scoped remote object copy and rollback cleanup for ownership transfer.
use super::{
    remote_copy::{copy_and_rekey_workspace_checkpoint, copy_object_if_present},
    transfer_exec::plan_rollback_cleanup_keys,
    transfer_model::{CopiedRemoteObject, plan_lfs_copy, plan_pando_copy, plan_workspace_blob_copy},
};
use crate::{
    AppState,
    pando_gateway::pitr_fence,
    storage::remote_objects::{ObjectKey, RemoteObjectStore},
    storage_lifecycle::pando_delete_gate,
};
use anyhow::{Context, Result};
use serde_json::Value;
use std::{collections::BTreeSet, path::Path};
use tokio::{fs, time::Instant};
use uuid::Uuid;

async fn persist_copied_objects(state: &AppState, transfer_id: Uuid, copied: &[CopiedRemoteObject]) -> Result<()> {
    let client = state.pool.get().await?;
    let val = serde_json::to_value(copied)?;
    client
        .execute(
            "UPDATE repository_transfers SET copied_objects = $2, updated_at = clock_timestamp() WHERE id = $1",
            &[&transfer_id, &val],
        )
        .await?;
    Ok(())
}

fn push_unique(
    copied: &mut Vec<CopiedRemoteObject>,
    seen: &mut BTreeSet<(String, String, String)>,
    item: CopiedRemoteObject,
) {
    let sig = (item.kind.clone(), item.from_key.clone(), item.to_key.clone());
    if seen.insert(sig) {
        copied.push(item);
    }
}

pub async fn copy_repository_remote_objects(
    state: &AppState,
    transfer_id: Uuid,
    repo_id: Uuid,
    from_owner: Uuid,
    to_owner: Uuid,
    deadline: Instant,
) -> Result<Vec<CopiedRemoteObject>> {
    let client = state.pool.get().await?;
    let existing_val: Value = client
        .query_one("SELECT copied_objects FROM repository_transfers WHERE id = $1", &[&transfer_id])
        .await?
        .get(0);
    let mut copied: Vec<CopiedRemoteObject> = serde_json::from_value(existing_val).unwrap_or_default();
    let mut seen: BTreeSet<(String, String, String)> =
        copied.iter().map(|c| (c.kind.clone(), c.from_key.clone(), c.to_key.clone())).collect();

    let stage_dir = state.storage.root.join("tmp");
    fs::create_dir_all(&stage_dir).await?;

    copy_lfs_objects(state, &client, repo_id, from_owner, to_owner, &stage_dir, &mut copied, &mut seen, deadline)
        .await?;
    copy_workspace_objects(state, &client, repo_id, from_owner, to_owner, &stage_dir, &mut copied, &mut seen, deadline)
        .await?;
    copy_pando_objects(state, &client, repo_id, from_owner, to_owner, &stage_dir, &mut copied, &mut seen, deadline)
        .await?;

    persist_copied_objects(state, transfer_id, &copied).await?;
    Ok(copied)
}

async fn copy_lfs_objects(
    state: &AppState,
    client: &tokio_postgres::Client,
    repo_id: Uuid,
    from_owner: Uuid,
    to_owner: Uuid,
    stage_dir: &Path,
    copied: &mut Vec<CopiedRemoteObject>,
    seen: &mut BTreeSet<(String, String, String)>,
    deadline: Instant,
) -> Result<()> {
    if std::env::var_os("ROOTYARD_OBJECT_STORE_ENDPOINT").is_none() {
        return Ok(());
    }
    let rows = client
        .query(
            "SELECT oid, size FROM lfs_objects WHERE repository_id = $1 AND tenant_id = $2 AND state = 'ready'",
            &[&repo_id, &from_owner],
        )
        .await?;
    if rows.is_empty() {
        return Ok(());
    }
    let store = RemoteObjectStore::from_env(state.storage.root.join("remote-objects"))?;
    for row in rows {
        let oid: String = row.get(0);
        let size: i64 = row.get(1);
        let (src, dst) = plan_lfs_copy(from_owner, to_owner, &oid).map_err(|e| anyhow::anyhow!(e))?;
        let expected = u64::try_from(size).ok();
        if let Some(rec) = copy_object_if_present(&store, stage_dir, "lfs", &src, &dst, expected, deadline).await? {
            push_unique(copied, seen, rec);
        }
    }
    Ok(())
}

async fn copy_workspace_objects(
    state: &AppState,
    client: &tokio_postgres::Client,
    repo_id: Uuid,
    from_owner: Uuid,
    to_owner: Uuid,
    stage_dir: &Path,
    copied: &mut Vec<CopiedRemoteObject>,
    seen: &mut BTreeSet<(String, String, String)>,
    deadline: Instant,
) -> Result<()> {
    let manifests: Vec<String> = client
        .query(
            "SELECT DISTINCT manifest_digest FROM workspace_checkpoints \
             WHERE repository_id = $1 AND manifest_digest IS NOT NULL",
            &[&repo_id],
        )
        .await?
        .into_iter()
        .map(|r| r.get(0))
        .collect();
    let staged = client
        .query(
            "SELECT DISTINCT s.digest, s.size FROM workspace_remote_staging_objects s \
             JOIN workspace_checkpoints c ON c.id = s.checkpoint_id \
             WHERE c.repository_id = $1 AND s.tenant_id = $2",
            &[&repo_id, &from_owner],
        )
        .await?;
    if manifests.is_empty() && staged.is_empty() {
        return Ok(());
    }
    let store = RemoteObjectStore::from_env(state.storage.root.join("workspace-service/local-object-cache"))?;
    for digest in manifests {
        let src_manifest = ObjectKey::new(from_owner, "workspace", &digest)?;
        if let Some(head) = store.head(&src_manifest, deadline).await? {
            let (_, _, recs) = copy_and_rekey_workspace_checkpoint(
                &store, stage_dir, from_owner, to_owner, &digest, head.size, deadline,
            )
            .await?;
            for rec in recs {
                push_unique(copied, seen, rec);
            }
        }
    }
    for row in staged {
        let digest: String = row.get(0);
        let size: i64 = row.get(1);
        let (src, dst) = plan_workspace_blob_copy(from_owner, to_owner, &digest).map_err(|e| anyhow::anyhow!(e))?;
        let expected = u64::try_from(size).ok();
        if let Some(rec) =
            copy_object_if_present(&store, stage_dir, "workspace", &src, &dst, expected, deadline).await?
        {
            push_unique(copied, seen, rec);
        }
    }
    Ok(())
}

async fn copy_pando_objects(
    state: &AppState,
    client: &tokio_postgres::Client,
    repo_id: Uuid,
    from_owner: Uuid,
    to_owner: Uuid,
    stage_dir: &Path,
    copied: &mut Vec<CopiedRemoteObject>,
    seen: &mut BTreeSet<(String, String, String)>,
    deadline: Instant,
) -> Result<()> {
    let linked = client
        .query(
            "SELECT DISTINCT a.authority_id, a.namespace, a.sha256, a.object_generation, a.remote_path, a.size \
             FROM pando_manifest_artifacts m \
             JOIN pando_remote_artifacts a ON a.authority_id = m.authority_id AND a.tenant_id = m.tenant_id \
              AND a.namespace = m.namespace AND a.sha256 = m.sha256 \
             WHERE m.repository_id = $1 AND m.tenant_id = $2",
            &[&repo_id, &from_owner],
        )
        .await?;
    let unlinked_manifests = client
        .query(
            "SELECT m.manifest FROM pando_pack_manifests m \
             WHERE m.repository_id = $1 AND m.tenant_id = $2 \
               AND NOT EXISTS (SELECT 1 FROM pando_manifest_artifacts a WHERE a.manifest_id = m.id)",
            &[&repo_id, &from_owner],
        )
        .await?;
    if linked.is_empty() && unlinked_manifests.is_empty() {
        return Ok(());
    }

    let store = RemoteObjectStore::from_env(state.storage.root.join("pando-pack-work"))?;
    let scoped_prefix = format!("tenants/{from_owner}/authorities/");
    for row in linked {
        let auth_id: Uuid = row.get(0);
        let ns: String = row.get(1);
        let sha: String = row.get(2);
        let obj_gen: i64 = row.get(3);
        let remote_path: String = row.get(4);
        let size: i64 = row.get(5);
        let src = if remote_path.starts_with(&scoped_prefix) {
            ObjectKey::scoped(from_owner, auth_id, obj_gen, &ns, &sha)?
        } else {
            ObjectKey::new(from_owner, &ns, &sha)?
        };
        let dst = ObjectKey::scoped(to_owner, auth_id, obj_gen, &ns, &sha)?;
        let expected = u64::try_from(size).ok().filter(|&s| s > 0);
        if let Some(rec) = copy_object_if_present(&store, stage_dir, &ns, &src, &dst, expected, deadline).await? {
            push_unique(copied, seen, rec);
        }
        let dst_path = dst.path();
        client
            .execute(
                "INSERT INTO pando_remote_artifacts \
                 (authority_id, tenant_id, namespace, sha256, object_generation, remote_path, size, state) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, 'active') \
                 ON CONFLICT (authority_id, tenant_id, namespace, sha256) DO UPDATE \
                 SET remote_path = EXCLUDED.remote_path, object_generation = EXCLUDED.object_generation, \
                     size = EXCLUDED.size, state = 'active', retired_at = NULL, delete_after = NULL, deleted_at = NULL",
                &[&auth_id, &to_owner, &ns, &sha, &obj_gen, &dst_path, &size],
            )
            .await
            .context("register destination Pando artifact row prior to rekey")?;
    }

    for row in unlinked_manifests {
        let manifest: Value = row.get(0);
        for (field, ns) in [
            ("pack_cipher", crate::pando_gateway::retention::NAMESPACE_CIPHER),
            ("pack_envelope", crate::pando_gateway::retention::NAMESPACE_ENVELOPE),
            ("index_cipher", crate::pando_gateway::retention::NAMESPACE_CIPHER),
            ("index_envelope", crate::pando_gateway::retention::NAMESPACE_ENVELOPE),
        ] {
            if let Some(sha) = manifest.get(field).and_then(|v| v.get("sha256")).and_then(Value::as_str) {
                let expected = manifest.get(field).and_then(|v| v.get("size")).and_then(Value::as_u64);
                let (src, dst) =
                    plan_pando_copy(from_owner, to_owner, None, ns, sha).map_err(|e| anyhow::anyhow!(e))?;
                if let Some(rec) = copy_object_if_present(&store, stage_dir, ns, &src, &dst, expected, deadline).await?
                {
                    push_unique(copied, seen, rec);
                }
            }
        }
    }
    Ok(())
}

pub async fn cleanup_rollback_remote_objects(
    state: &AppState,
    repo_id: Uuid,
    to_owner: Uuid,
    copied: &[CopiedRemoteObject],
    deadline: Instant,
) -> Result<()> {
    if copied.is_empty() {
        return Ok(());
    }
    let client = state.pool.get().await?;
    let mut preserved = BTreeSet::new();
    for row in client
        .query("SELECT oid FROM lfs_objects WHERE tenant_id = $1 AND repository_id <> $2", &[&to_owner, &repo_id])
        .await?
    {
        if let Ok(key) = ObjectKey::new(to_owner, "lfs", row.get::<_, &str>(0)) {
            preserved.insert(key.path());
        }
    }
    for row in client
        .query(
            "SELECT DISTINCT c.manifest_digest FROM workspace_checkpoints c \
             JOIN repositories r ON r.id = c.repository_id \
             WHERE r.owner_id = $1 AND c.repository_id <> $2 AND c.manifest_digest IS NOT NULL",
            &[&to_owner, &repo_id],
        )
        .await?
    {
        if let Ok(key) = ObjectKey::new(to_owner, "workspace", row.get::<_, &str>(0)) {
            preserved.insert(key.path());
        }
    }
    for row in client
        .query(
            "SELECT DISTINCT a.remote_path FROM pando_manifest_artifacts m \
             JOIN pando_remote_artifacts a ON a.authority_id = m.authority_id AND a.tenant_id = m.tenant_id \
              AND a.namespace = m.namespace AND a.sha256 = m.sha256 \
             WHERE m.tenant_id = $1 AND m.repository_id <> $2",
            &[&to_owner, &repo_id],
        )
        .await?
    {
        preserved.insert(row.get(0));
    }

    let targets = plan_rollback_cleanup_keys(to_owner, copied, &preserved);
    let lfs_store = if std::env::var_os("ROOTYARD_OBJECT_STORE_ENDPOINT").is_some() {
        Some(RemoteObjectStore::from_env(state.storage.root.join("remote-objects"))?)
    } else {
        None
    };
    let ws_store = RemoteObjectStore::from_env(state.storage.root.join("workspace-service/local-object-cache"))?;
    let pando_remote_allowed = if pando_delete_gate::remote_delete_env_enabled().unwrap_or(false) {
        let store = RemoteObjectStore::from_env(state.storage.root.join("pando-pack-work"))?;
        match pitr_fence::verify_or_attest(&state.pool, &state.storage.root, &store, deadline, "attest").await {
            Ok(auth) if !auth.remote_delete_fenced => Some(store),
            _ => None,
        }
    } else {
        None
    };

    for (kind, key) in targets {
        match kind.as_str() {
            "lfs" => {
                if let Some(store) = lfs_store.as_ref() {
                    let _ = store.delete(&key, deadline).await;
                }
            }
            "workspace" | "workspace_manifest" => {
                let _ = ws_store.delete(&key, deadline).await;
            }
            "pando-cipher" | "pando-envelope" => {
                let path = key.path();
                if let Some(store) = pando_remote_allowed.as_ref() {
                    if store.delete(&key, deadline).await.is_ok() {
                        let _ = client
                            .execute(
                                "UPDATE pando_remote_artifacts SET state = 'deleted', deleted_at = clock_timestamp() \
                                 WHERE tenant_id = $1 AND remote_path = $2 \
                                   AND NOT EXISTS (SELECT 1 FROM pando_manifest_artifacts m \
                                                   WHERE m.authority_id = pando_remote_artifacts.authority_id \
                                                     AND m.tenant_id = pando_remote_artifacts.tenant_id \
                                                     AND m.namespace = pando_remote_artifacts.namespace \
                                                     AND m.sha256 = pando_remote_artifacts.sha256)",
                                &[&to_owner, &path],
                            )
                            .await;
                    }
                } else {
                    let _ = client
                        .execute(
                            "UPDATE pando_remote_artifacts SET state = 'retired', retired_at = COALESCE(retired_at, clock_timestamp()) \
                             WHERE tenant_id = $1 AND remote_path = $2 AND state = 'active' \
                               AND NOT EXISTS (SELECT 1 FROM pando_manifest_artifacts m \
                                               WHERE m.authority_id = pando_remote_artifacts.authority_id \
                                                 AND m.tenant_id = pando_remote_artifacts.tenant_id \
                                                 AND m.namespace = pando_remote_artifacts.namespace \
                                                 AND m.sha256 = pando_remote_artifacts.sha256)",
                            &[&to_owner, &path],
                        )
                        .await;
                }
            }
            _ => {}
        }
    }
    Ok(())
}
