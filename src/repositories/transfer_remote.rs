//! Tenant-scoped remote object copy and rollback cleanup for ownership transfer.
use super::{
    remote_copy::{copy_and_rekey_workspace_checkpoint, copy_object_if_present},
    transfer_exec::plan_rollback_cleanup_keys,
    transfer_model::{CopiedRemoteObject, plan_lfs_copy, plan_workspace_blob_copy},
    transfer_pando::{
        PandoTransferCopy, clear_transfer_pando_fences_tx, copy_pando_objects_with_store, persist_copied_objects_pool,
        remove_copied_artifact, rollback_cleanup_pando_artifact, upsert_copied_artifact,
    },
};
use crate::{
    AppState,
    pando_gateway::pitr_fence,
    storage::{
        remote_key_claims::{
            DEFAULT_DELETE_CLAIM_LEASE_SECS, claim_if_unreferenced, execute_locked_claimed_delete, lock_object_key,
        },
        remote_objects::{ObjectKey, RemoteObjectStore},
    },
    storage_lifecycle::pando_delete_gate,
};
use anyhow::{Context, Result, ensure};
use deadpool_postgres::Pool;
use serde_json::Value;
use std::collections::BTreeSet;
use tokio::{fs, time::Instant};
use tokio_postgres::GenericClient;
use uuid::Uuid;

async fn verify_rollback_lease_with<C: GenericClient + Sync>(
    client: &C,
    transfer_id: Uuid,
    lease_owner: &str,
    lease_epoch: i64,
) -> Result<()> {
    let active: bool = client
        .query_one(
            "SELECT EXISTS( \
                 SELECT 1 FROM repository_transfers \
                 WHERE id = $1 AND state = 'rolling_back' AND lease_owner = $2 AND lease_epoch = $3 \
                   AND lease_until > clock_timestamp() \
             )",
            &[&transfer_id, &lease_owner, &lease_epoch],
        )
        .await?
        .get(0);
    ensure!(active, "transfer rollback lease lost before remote delete");
    Ok(())
}

async fn verify_rollback_lease(pool: &Pool, transfer_id: Uuid, lease_owner: &str, lease_epoch: i64) -> Result<()> {
    let client = pool.get().await?;
    verify_rollback_lease_with(&**client, transfer_id, lease_owner, lease_epoch).await
}

pub async fn copy_repository_remote_objects(
    state: &AppState,
    transfer_id: Uuid,
    lease_owner: &str,
    lease_epoch: i64,
    repo_id: Uuid,
    from_owner: Uuid,
    to_owner: Uuid,
    deadline: Instant,
) -> Result<Vec<CopiedRemoteObject>> {
    let mut copied: Vec<CopiedRemoteObject> = {
        let client = state.pool.get().await?;
        let row = client
            .query_one(
                "SELECT copied_objects FROM repository_transfers \
                 WHERE id = $1 AND state = 'copying_remote' AND lease_owner = $2 AND lease_epoch = $3",
                &[&transfer_id, &lease_owner, &lease_epoch],
            )
            .await
            .context("transfer lease lost before remote object copy")?;
        let existing_val: Value = row.get(0);
        serde_json::from_value(existing_val).unwrap_or_default()
    };
    let mut seen: BTreeSet<(String, String, String)> =
        copied.iter().map(|c| (c.kind.clone(), c.from_key.clone(), c.to_key.clone())).collect();

    let stage_dir = state.storage.root.join("tmp");
    fs::create_dir_all(&stage_dir).await?;
    let pando_req = PandoTransferCopy {
        transfer_lease: Some((transfer_id, lease_owner, lease_epoch)),
        repo_id,
        from_owner,
        to_owner,
        stage_dir: &stage_dir,
        deadline,
    };

    copy_lfs_objects(state, &pando_req, &mut copied, &mut seen).await?;
    copy_workspace_objects(state, &pando_req, &mut copied, &mut seen).await?;
    let pando_store = RemoteObjectStore::from_env(state.storage.root.join("pando-pack-work"))?;
    copy_pando_objects_with_store(&state.pool, &pando_store, &pando_req, &mut copied, &mut seen).await?;

    persist_copied_objects_pool(&state.pool, transfer_id, lease_owner, lease_epoch, &copied).await?;
    Ok(copied)
}

async fn copy_lfs_objects(
    state: &AppState,
    req: &PandoTransferCopy<'_>,
    copied: &mut Vec<CopiedRemoteObject>,
    seen: &mut BTreeSet<(String, String, String)>,
) -> Result<()> {
    if std::env::var_os("ROOTYARD_OBJECT_STORE_ENDPOINT").is_none() {
        return Ok(());
    }
    let (transfer_id, lease_owner, lease_epoch) = req.transfer_lease.context("missing transfer lease for LFS copy")?;
    let rows = {
        let client = state.pool.get().await?;
        client
            .query(
                "SELECT oid, size FROM lfs_objects WHERE repository_id = $1 AND tenant_id = $2 AND state = 'ready'",
                &[&req.repo_id, &req.from_owner],
            )
            .await?
    };
    if rows.is_empty() {
        return Ok(());
    }
    let store = RemoteObjectStore::from_env(state.storage.root.join("remote-objects"))?;
    for row in rows {
        let oid: String = row.get(0);
        let size: i64 = row.get(1);
        let (src, dst) = plan_lfs_copy(req.from_owner, req.to_owner, &oid).map_err(|e| anyhow::anyhow!(e))?;
        let expected = u64::try_from(size).ok();
        let src_path = src.path();
        upsert_copied_artifact(
            copied,
            seen,
            CopiedRemoteObject {
                kind: "lfs".into(),
                from_key: src_path.clone(),
                to_key: dst.path(),
                size: expected.unwrap_or(0),
                sha256: Some(oid.clone()),
            },
        );
        persist_copied_objects_pool(&state.pool, transfer_id, lease_owner, lease_epoch, copied).await?;
        if let Some(rec) =
            copy_object_if_present(&store, req.stage_dir, "lfs", &src, &dst, expected, req.deadline).await?
        {
            upsert_copied_artifact(copied, seen, rec);
        } else {
            remove_copied_artifact(copied, seen, "lfs", &src_path);
        }
        persist_copied_objects_pool(&state.pool, transfer_id, lease_owner, lease_epoch, copied).await?;
    }
    Ok(())
}

async fn copy_workspace_objects(
    state: &AppState,
    req: &PandoTransferCopy<'_>,
    copied: &mut Vec<CopiedRemoteObject>,
    seen: &mut BTreeSet<(String, String, String)>,
) -> Result<()> {
    let (transfer_id, lease_owner, lease_epoch) =
        req.transfer_lease.context("missing transfer lease for workspace copy")?;
    let (manifests, staged) = {
        let client = state.pool.get().await?;
        let manifests: Vec<String> = client
            .query(
                "SELECT DISTINCT manifest_digest FROM workspace_checkpoints \
                 WHERE repository_id = $1 AND manifest_digest IS NOT NULL",
                &[&req.repo_id],
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
                &[&req.repo_id, &req.from_owner],
            )
            .await?;
        (manifests, staged)
    };
    if manifests.is_empty() && staged.is_empty() {
        return Ok(());
    }
    let store = RemoteObjectStore::from_env(state.storage.root.join("workspace-service/local-object-cache"))?;
    for digest in manifests {
        let src_manifest = ObjectKey::new(req.from_owner, "workspace", &digest)?;
        if let Some(head) = store.head(&src_manifest, req.deadline).await? {
            let (_, _, recs) = copy_and_rekey_workspace_checkpoint(
                &store,
                req.stage_dir,
                req.from_owner,
                req.to_owner,
                &digest,
                head.size,
                req.deadline,
            )
            .await?;
            for rec in recs {
                upsert_copied_artifact(copied, seen, rec);
            }
            persist_copied_objects_pool(&state.pool, transfer_id, lease_owner, lease_epoch, copied).await?;
        }
    }
    for row in staged {
        let digest: String = row.get(0);
        let size: i64 = row.get(1);
        let (src, dst) =
            plan_workspace_blob_copy(req.from_owner, req.to_owner, &digest).map_err(|e| anyhow::anyhow!(e))?;
        let expected = u64::try_from(size).ok();
        let src_path = src.path();
        upsert_copied_artifact(
            copied,
            seen,
            CopiedRemoteObject {
                kind: "workspace".into(),
                from_key: src_path.clone(),
                to_key: dst.path(),
                size: expected.unwrap_or(0),
                sha256: Some(digest),
            },
        );
        persist_copied_objects_pool(&state.pool, transfer_id, lease_owner, lease_epoch, copied).await?;
        if let Some(rec) =
            copy_object_if_present(&store, req.stage_dir, "workspace", &src, &dst, expected, req.deadline).await?
        {
            upsert_copied_artifact(copied, seen, rec);
        } else {
            remove_copied_artifact(copied, seen, "workspace", &src_path);
        }
        persist_copied_objects_pool(&state.pool, transfer_id, lease_owner, lease_epoch, copied).await?;
    }
    Ok(())
}

async fn rollback_cleanup_claim_key(
    pool: &Pool,
    store: &RemoteObjectStore,
    transfer_id: Uuid,
    lease_owner: &str,
    lease_epoch: i64,
    key: &ObjectKey,
    deadline: Instant,
) -> Result<()> {
    let claim = {
        let mut client = pool.get().await?;
        let tx = client.transaction().await?;
        verify_rollback_lease_with(&*tx, transfer_id, lease_owner, lease_epoch).await?;
        lock_object_key(&tx, key.tenant_id, &key.namespace, &key.sha256).await.map_err(|e| anyhow::anyhow!(e.1))?;
        let claim =
            claim_if_unreferenced(&tx, key.tenant_id, &key.namespace, &key.sha256, DEFAULT_DELETE_CLAIM_LEASE_SECS)
                .await
                .map_err(|e| anyhow::anyhow!(e.1))?;
        tx.commit().await?;
        claim
    };
    if let Some(claim) = claim {
        execute_locked_claimed_delete(pool, store, &claim, deadline).await?;
    }
    Ok(())
}

pub(super) async fn cleanup_rollback_objects_with_stores(
    pool: &Pool,
    transfer_id: Uuid,
    lease_owner: &str,
    lease_epoch: i64,
    repo_id: Uuid,
    to_owner: Uuid,
    copied: &[CopiedRemoteObject],
    lfs_store: Option<&RemoteObjectStore>,
    ws_store: &RemoteObjectStore,
    pando_remote_allowed: Option<&RemoteObjectStore>,
    deadline: Instant,
) -> Result<()> {
    if copied.is_empty() {
        return Ok(());
    }
    let mut preserved = BTreeSet::new();
    {
        let client = pool.get().await?;
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
    }

    let targets = plan_rollback_cleanup_keys(to_owner, copied, &preserved);
    let mut cleared_pando_fences = false;
    for (kind, key) in targets {
        match kind.as_str() {
            "lfs" => {
                if let Some(store) = lfs_store {
                    rollback_cleanup_claim_key(pool, store, transfer_id, lease_owner, lease_epoch, &key, deadline)
                        .await?;
                }
            }
            "workspace" | "workspace_manifest" => {
                rollback_cleanup_claim_key(pool, ws_store, transfer_id, lease_owner, lease_epoch, &key, deadline)
                    .await?;
            }
            "pando-cipher" | "pando-envelope" => {
                // Un-fenced legacy tenant-only Pando keys (`authority = None`) are never deleted.
                let Some((authority_id, obj_gen)) = key.authority else {
                    continue;
                };
                if !cleared_pando_fences {
                    let mut c = pool.get().await?;
                    let tx = c.transaction().await?;
                    verify_rollback_lease_with(&*tx, transfer_id, lease_owner, lease_epoch).await?;
                    clear_transfer_pando_fences_tx(&tx, repo_id, to_owner).await?;
                    tx.commit().await?;
                    cleared_pando_fences = true;
                } else {
                    verify_rollback_lease(pool, transfer_id, lease_owner, lease_epoch).await?;
                }
                rollback_cleanup_pando_artifact(pool, pando_remote_allowed, authority_id, &key, obj_gen, deadline)
                    .await?;
            }
            _ => {}
        }
    }
    Ok(())
}

pub async fn cleanup_rollback_remote_objects(
    state: &AppState,
    transfer_id: Uuid,
    lease_owner: &str,
    lease_epoch: i64,
    repo_id: Uuid,
    to_owner: Uuid,
    copied: &[CopiedRemoteObject],
    deadline: Instant,
) -> Result<()> {
    if copied.is_empty() {
        return Ok(());
    }
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
    cleanup_rollback_objects_with_stores(
        &state.pool,
        transfer_id,
        lease_owner,
        lease_epoch,
        repo_id,
        to_owner,
        copied,
        lfs_store.as_ref(),
        &ws_store,
        pando_remote_allowed.as_ref(),
        deadline,
    )
    .await
}
