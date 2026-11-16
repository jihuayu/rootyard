//! Safe final purge execution for unshared remote objects and local git dirs (#85).
use super::purge_safety::RemoteDeletePlan;
use crate::storage::remote_objects::{ObjectKey, RemoteObjectStore};
use anyhow::{Result, ensure};
use std::collections::BTreeSet;
use std::path::Path;
use tokio::{fs, time::Instant};
use uuid::Uuid;

/// Delete only the strictly unshared LFS and workspace remote object keys
/// returned by [`super::purge_safety::plan_safe_remote_cleanup`]. Never deletes
/// any shared key, legacy Pando key, or external-tenant key.
pub async fn execute_safe_remote_deletes(
    tenant_id: Uuid,
    lfs_store: Option<&RemoteObjectStore>,
    workspace_store: Option<&RemoteObjectStore>,
    plan: &RemoteDeletePlan,
    preserved_shared_lfs_oids: &BTreeSet<String>,
    preserved_shared_workspace_digests: &BTreeSet<String>,
    deadline: Instant,
) -> Result<(usize, usize)> {
    let mut deleted_lfs = 0usize;
    if let Some(store) = lfs_store {
        for key_path in &plan.deletable_lfs_keys {
            let oid = key_path.rsplit('/').next().unwrap_or_default();
            ensure!(!preserved_shared_lfs_oids.contains(oid), "refusing to delete shared LFS object {oid}");
            let key = ObjectKey::new(tenant_id, "lfs", oid)?;
            ensure!(key.path() == *key_path, "LFS delete key path mismatch: {key_path}");
            store.delete(&key, deadline).await?;
            deleted_lfs += 1;
        }
    }
    let mut deleted_workspace = 0usize;
    if let Some(store) = workspace_store {
        for key_path in &plan.deletable_workspace_keys {
            let digest = key_path.rsplit('/').next().unwrap_or_default();
            ensure!(
                !preserved_shared_workspace_digests.contains(digest),
                "refusing to delete shared workspace object {digest}"
            );
            let key = ObjectKey::new(tenant_id, "workspace", digest)?;
            ensure!(key.path() == *key_path, "workspace delete key path mismatch: {key_path}");
            store.delete(&key, deadline).await?;
            deleted_workspace += 1;
        }
    }
    Ok((deleted_lfs, deleted_workspace))
}

/// Remove the local bare repository directory only when contained strictly inside
/// `storage_root` (no symlink traversal outside storage root).
pub async fn remove_local_repo_dir(storage_root: &Path, repo_path: &Path) -> Result<()> {
    let Ok(meta) = fs::symlink_metadata(repo_path).await else {
        return Ok(());
    };
    ensure!(!meta.file_type().is_symlink(), "refusing to follow symlink while purging local repository directory");
    let canonical_root = fs::canonicalize(storage_root).await?;
    let canonical_repo = fs::canonicalize(repo_path).await?;
    ensure!(
        canonical_repo != canonical_root && canonical_repo.starts_with(&canonical_root),
        "repository directory escapes configured storage root"
    );
    fs::remove_dir_all(&canonical_repo).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repositories::purge_safety::plan_safe_remote_cleanup;
    use sha2::{Digest, Sha256};

    #[tokio::test]
    async fn execute_safe_remote_deletes_removes_unique_keys_and_preserves_shared() {
        let dir = std::env::temp_dir().join(format!("rootyard-purge-test-{}", Uuid::new_v4()));
        let stage = dir.join("stage");
        fs::create_dir_all(&stage).await.unwrap();
        let lfs_store = RemoteObjectStore::Local(dir.join("lfs-remote"));
        let ws_store = RemoteObjectStore::Local(dir.join("ws-remote"));
        let deadline = Instant::now() + std::time::Duration::from_secs(30);
        let tenant = Uuid::new_v4();

        async fn seed(stage: &Path, name: &str, bytes: &[u8]) -> (std::path::PathBuf, String, u64) {
            let p = stage.join(name);
            fs::write(&p, bytes).await.unwrap();
            (p, hex::encode(Sha256::digest(bytes)), bytes.len() as u64)
        }
        let (p_shared, shared_oid, sz_s) = seed(&stage, "shared.bin", b"shared-lfs").await;
        let (p_uniq, uniq_oid, sz_u) = seed(&stage, "uniq.bin", b"unique-lfs").await;
        let (p_ws_s, ws_shared_oid, sz_ws) = seed(&stage, "ws-shared.bin", b"shared-ws").await;
        let (p_ws_u, ws_uniq_oid, sz_wu) = seed(&stage, "ws-uniq.bin", b"unique-ws").await;

        let l_shared_key = ObjectKey::new(tenant, "lfs", &shared_oid).unwrap();
        let l_uniq_key = ObjectKey::new(tenant, "lfs", &uniq_oid).unwrap();
        let w_shared_key = ObjectKey::new(tenant, "workspace", &ws_shared_oid).unwrap();
        let w_uniq_key = ObjectKey::new(tenant, "workspace", &ws_uniq_oid).unwrap();
        lfs_store.put_file(&l_shared_key, &p_shared, sz_s, deadline).await.unwrap();
        lfs_store.put_file(&l_uniq_key, &p_uniq, sz_u, deadline).await.unwrap();
        ws_store.put_file(&w_shared_key, &p_ws_s, sz_ws, deadline).await.unwrap();
        ws_store.put_file(&w_uniq_key, &p_ws_u, sz_wu, deadline).await.unwrap();

        let shared_lfs = BTreeSet::from([shared_oid.clone()]);
        let shared_ws = BTreeSet::from([ws_shared_oid.clone()]);
        let plan = plan_safe_remote_cleanup(
            tenant,
            &[shared_oid, uniq_oid],
            &shared_lfs,
            &[ws_shared_oid, ws_uniq_oid],
            &shared_ws,
            &[],
        );

        let (dl, dw) = execute_safe_remote_deletes(
            tenant,
            Some(&lfs_store),
            Some(&ws_store),
            &plan,
            &shared_lfs,
            &shared_ws,
            deadline,
        )
        .await
        .unwrap();
        assert_eq!((dl, dw), (1, 1));
        assert!(lfs_store.head(&l_shared_key, deadline).await.unwrap().is_some());
        assert!(lfs_store.head(&l_uniq_key, deadline).await.unwrap().is_none());
        assert!(ws_store.head(&w_shared_key, deadline).await.unwrap().is_some());
        assert!(ws_store.head(&w_uniq_key, deadline).await.unwrap().is_none());
        let _ = fs::remove_dir_all(&dir).await;
    }
}
