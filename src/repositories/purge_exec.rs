//! Safe final purge execution for unshared remote objects and local git dirs (#85).
use super::purge_safety::RemoteDeletePlan;
use crate::{
    AppState, Error,
    storage::{
        remote_key_claims::{DeleteClaim, execute_locked_claimed_delete},
        remote_objects::{ObjectKey, RemoteObjectStore},
    },
    workspaces::remote::RemoteManifest,
};
use anyhow::{Result, bail, ensure};
use deadpool_postgres::{Pool, Transaction};
use std::collections::BTreeSet;
use std::path::Path;
use tokio::{fs, time::Instant};
use uuid::Uuid;

#[derive(Clone)]
pub(super) struct PandoArtifactCandidate {
    pub(super) authority_id: Uuid,
    pub(super) tenant_id: Uuid,
    pub(super) namespace: String,
    pub(super) sha256: String,
    pub(super) object_generation: i64,
    pub(super) remote_path: String,
    pub(super) authority_scoped_unshared: bool,
}

async fn collect_strings(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
) -> Result<Vec<String>, Error> {
    Ok(tx.query(sql, params).await.map_err(Error::internal)?.into_iter().map(|r| r.get(0)).collect())
}

async fn workspace_manifest_blob_digests(
    store: &RemoteObjectStore,
    tenant_id: Uuid,
    manifest_digest: &str,
    stage_dir: &Path,
    deadline: Instant,
) -> Vec<String> {
    let Ok(key) = ObjectKey::new(tenant_id, "workspace", manifest_digest) else {
        return Vec::new();
    };
    let Ok(Some(head)) = store.head(&key, deadline).await else {
        return Vec::new();
    };
    let tmp = stage_dir.join(format!("ws-manifest-{}.json", Uuid::new_v4()));
    if store.get_to_file(&key, &tmp, head.size, deadline).await.is_err() {
        let _ = fs::remove_file(&tmp).await;
        return Vec::new();
    }
    let parsed = fs::read(&tmp).await.ok().and_then(|bytes| serde_json::from_slice::<RemoteManifest>(&bytes).ok());
    let _ = fs::remove_file(&tmp).await;
    parsed
        .map(|m| m.entries.into_iter().filter(|e| e.kind == "file" && !e.sha256.is_empty()).map(|e| e.sha256).collect())
        .unwrap_or_default()
}

pub(super) async fn gather_remote_inventory(
    state: &AppState,
    tx: &Transaction<'_>,
    repo_id: Uuid,
    owner_id: Uuid,
    ws_store: Option<&RemoteObjectStore>,
    deadline: Instant,
) -> Result<(Vec<String>, BTreeSet<String>, Vec<String>, BTreeSet<String>, Vec<PandoArtifactCandidate>), Error> {
    let repo_lfs_oids = collect_strings(
        tx,
        "SELECT oid FROM lfs_objects WHERE repository_id = $1 AND tenant_id = $2",
        &[&repo_id, &owner_id],
    )
    .await?;
    let shared_lfs_oids: BTreeSet<String> = collect_strings(
        tx,
        "SELECT DISTINCT oid FROM lfs_objects WHERE tenant_id = $1 AND repository_id <> $2",
        &[&owner_id, &repo_id],
    )
    .await?
    .into_iter()
    .collect();
    let repo_manifests = collect_strings(
        tx,
        "SELECT DISTINCT manifest_digest FROM workspace_checkpoints WHERE repository_id = $1 AND manifest_digest IS NOT NULL",
        &[&repo_id],
    )
    .await?;
    let repo_staged = collect_strings(
        tx,
        "SELECT DISTINCT s.digest FROM workspace_remote_staging_objects s JOIN workspace_checkpoints c ON c.id = s.checkpoint_id WHERE c.repository_id = $1 AND s.tenant_id = $2",
        &[&repo_id, &owner_id],
    )
    .await?;
    let other_manifests = collect_strings(
        tx,
        "SELECT DISTINCT c.manifest_digest FROM workspace_checkpoints c JOIN repositories r ON r.id = c.repository_id WHERE r.owner_id = $1 AND c.repository_id <> $2 AND c.manifest_digest IS NOT NULL",
        &[&owner_id, &repo_id],
    )
    .await?;
    let other_staged = collect_strings(
        tx,
        "SELECT DISTINCT s.digest FROM workspace_remote_staging_objects s JOIN workspace_checkpoints c ON c.id = s.checkpoint_id WHERE s.tenant_id = $1 AND c.repository_id <> $2",
        &[&owner_id, &repo_id],
    )
    .await?;

    let mut repo_ws_digests = repo_manifests.clone();
    repo_ws_digests.extend(repo_staged);
    let mut shared_ws_digests: BTreeSet<String> = other_manifests.iter().cloned().collect();
    shared_ws_digests.extend(other_staged);

    if let Some(store) = ws_store {
        let stage_dir = state.storage.root.join("tmp");
        let _ = fs::create_dir_all(&stage_dir).await;
        for m in &repo_manifests {
            repo_ws_digests.extend(workspace_manifest_blob_digests(store, owner_id, m, &stage_dir, deadline).await);
        }
        for m in &other_manifests {
            shared_ws_digests.extend(workspace_manifest_blob_digests(store, owner_id, m, &stage_dir, deadline).await);
        }
    }

    let pando_rows = tx
        .query(
            "SELECT DISTINCT a.authority_id, a.tenant_id, a.namespace, a.sha256, a.object_generation, a.remote_path, \
                    EXISTS (SELECT 1 FROM pando_manifest_artifacts other \
                            WHERE other.authority_id = a.authority_id AND other.tenant_id = a.tenant_id \
                              AND other.namespace = a.namespace AND other.sha256 = a.sha256 \
                              AND other.repository_id <> $1) \
             FROM pando_manifest_artifacts m \
             JOIN pando_remote_artifacts a ON a.authority_id = m.authority_id AND a.tenant_id = m.tenant_id \
              AND a.namespace = m.namespace AND a.sha256 = m.sha256 \
             WHERE m.repository_id = $1",
            &[&repo_id],
        )
        .await
        .map_err(Error::internal)?;

    let scoped_prefix = format!("tenants/{owner_id}/authorities/");
    let pando_candidates = pando_rows
        .into_iter()
        .map(|row| {
            let tenant_id: Uuid = row.get(1);
            let remote_path: String = row.get(5);
            let shared_elsewhere: bool = row.get(6);
            PandoArtifactCandidate {
                authority_id: row.get(0),
                tenant_id,
                namespace: row.get(2),
                sha256: row.get(3),
                object_generation: row.get(4),
                authority_scoped_unshared: !shared_elsewhere
                    && tenant_id == owner_id
                    && remote_path.starts_with(&scoped_prefix),
                remote_path,
            }
        })
        .collect();

    Ok((repo_lfs_oids, shared_lfs_oids, repo_ws_digests, shared_ws_digests, pando_candidates))
}

/// Delete claimed unshared LFS and workspace remote object keys while proving
/// each key's lease generation is still valid before `store.delete`, then clear `deleting`.
pub async fn execute_claimed_remote_deletes(
    pool: &Pool,
    tenant_id: Uuid,
    lfs_store: Option<&RemoteObjectStore>,
    workspace_store: Option<&RemoteObjectStore>,
    plan: &RemoteDeletePlan,
    preserved_shared_lfs_oids: &BTreeSet<String>,
    preserved_shared_workspace_digests: &BTreeSet<String>,
    claims: &[DeleteClaim],
    deadline: Instant,
) -> Result<(usize, usize)> {
    let claim_map: std::collections::BTreeMap<(&str, &str), &DeleteClaim> =
        claims.iter().map(|c| ((c.namespace.as_str(), c.digest.as_str()), c)).collect();
    let mut deleted_lfs = 0usize;
    if let Some(store) = lfs_store {
        for key_path in &plan.deletable_lfs_keys {
            let oid = key_path.rsplit('/').next().unwrap_or_default();
            ensure!(!preserved_shared_lfs_oids.contains(oid), "refusing to delete shared LFS object {oid}");
            let Some(claim) = claim_map.get(&("lfs", oid)).copied() else {
                bail!("missing delete claim for LFS object {oid}");
            };
            let key = ObjectKey::new(tenant_id, "lfs", oid)?;
            ensure!(key.path() == *key_path, "LFS delete key path mismatch: {key_path}");
            execute_locked_claimed_delete(pool, store, claim, deadline).await?;
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
            let Some(claim) = claim_map.get(&("workspace", digest)).copied() else {
                bail!("missing delete claim for workspace object {digest}");
            };
            let key = ObjectKey::new(tenant_id, "workspace", digest)?;
            ensure!(key.path() == *key_path, "workspace delete key path mismatch: {key_path}");
            execute_locked_claimed_delete(pool, store, claim, deadline).await?;
            deleted_workspace += 1;
        }
    }
    Ok((deleted_lfs, deleted_workspace))
}

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

async fn lock_unreferenced_pando_artifact(
    tx: &Transaction<'_>,
    authority_id: Uuid,
    tenant_id: Uuid,
    namespace: &str,
    sha256: &str,
    expected_generation: Option<i64>,
    allowed_states: &[&str],
) -> Result<Option<i64>> {
    let locked_auth: Uuid = tx
        .query_one("SELECT authority_id FROM pando_storage_authorities WHERE singleton FOR UPDATE", &[])
        .await?
        .get(0);
    if locked_auth != authority_id {
        return Ok(None);
    }
    let Some(row) = tx
        .query_opt(
            "SELECT state, object_generation FROM pando_remote_artifacts \
             WHERE authority_id = $1 AND tenant_id = $2 AND namespace = $3 AND sha256 = $4 FOR UPDATE",
            &[&authority_id, &tenant_id, &namespace, &sha256],
        )
        .await?
    else {
        return Ok(None);
    };
    let state: String = row.get(0);
    let obj_gen: i64 = row.get(1);
    if expected_generation.is_some_and(|exp| exp != obj_gen) || !allowed_states.contains(&state.as_str()) {
        return Ok(None);
    }
    let referenced: bool = tx
        .query_one(
            "SELECT EXISTS( \
                 SELECT 1 FROM pando_manifest_artifacts \
                 WHERE authority_id = $1 AND tenant_id = $2 AND namespace = $3 AND sha256 = $4 \
             ) OR EXISTS( \
                 SELECT 1 FROM pando_publication_fences \
                 WHERE authority_id = $1 AND tenant_id = $2 AND namespace = $3 AND sha256 = $4 \
                   AND lease_until > clock_timestamp() \
             )",
            &[&authority_id, &tenant_id, &namespace, &sha256],
        )
        .await?
        .get(0);
    if referenced {
        return Ok(None);
    }
    Ok(Some(obj_gen))
}

/// Delete an authority-scoped Pando artifact only after serializing with the
/// authority/artifact publisher fence, rechecking live links and fences, and
/// committing `state = 'deleting'` before remote `store.delete`.
pub(super) async fn delete_pando_artifact_fenced(
    pool: &Pool,
    store: &RemoteObjectStore,
    authority_id: Uuid,
    tenant_id: Uuid,
    namespace: &str,
    sha256: &str,
    expected_generation: Option<i64>,
    deadline: Instant,
) -> Result<bool> {
    let obj_gen = {
        let mut client = pool.get().await?;
        let tx = client.transaction().await?;
        let Some(locked_gen) = lock_unreferenced_pando_artifact(
            &tx,
            authority_id,
            tenant_id,
            namespace,
            sha256,
            expected_generation,
            &["active", "retired"],
        )
        .await?
        else {
            tx.commit().await?;
            return Ok(false);
        };
        let marked = tx
            .execute(
                "UPDATE pando_remote_artifacts SET state = 'deleting', updated_at = clock_timestamp() \
                 WHERE authority_id = $1 AND tenant_id = $2 AND namespace = $3 AND sha256 = $4 \
                   AND object_generation = $5 AND state IN ('active', 'retired')",
                &[&authority_id, &tenant_id, &namespace, &sha256, &locked_gen],
            )
            .await?;
        ensure!(marked == 1, "Pando remote artifact state/generation changed before delete fence");
        tx.commit().await?;
        locked_gen
    };

    let key = ObjectKey::scoped(tenant_id, authority_id, obj_gen, namespace, sha256)?;
    store.delete(&key, deadline).await?;
    let client = pool.get().await?;
    let _ = client
        .execute(
            "UPDATE pando_remote_artifacts \
             SET state = 'deleted', deleted_at = clock_timestamp(), updated_at = clock_timestamp() \
             WHERE authority_id = $1 AND tenant_id = $2 AND namespace = $3 AND sha256 = $4 \
               AND object_generation = $5 AND state = 'deleting'",
            &[&authority_id, &tenant_id, &namespace, &sha256, &obj_gen],
        )
        .await?;
    Ok(true)
}

/// Retire an unreferenced authority-scoped Pando artifact under the publisher lock
/// when remote deletion is disabled or PITR-fenced.
pub(super) async fn retire_pando_artifact_fenced(
    pool: &Pool,
    authority_id: Uuid,
    tenant_id: Uuid,
    namespace: &str,
    sha256: &str,
    expected_generation: Option<i64>,
) -> Result<bool> {
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    let Some(locked_gen) = lock_unreferenced_pando_artifact(
        &tx,
        authority_id,
        tenant_id,
        namespace,
        sha256,
        expected_generation,
        &["active"],
    )
    .await?
    else {
        tx.commit().await?;
        return Ok(false);
    };
    let updated = tx
        .execute(
            "UPDATE pando_remote_artifacts \
             SET state = 'retired', retired_at = COALESCE(retired_at, clock_timestamp()), updated_at = clock_timestamp() \
             WHERE authority_id = $1 AND tenant_id = $2 AND namespace = $3 AND sha256 = $4 \
               AND object_generation = $5 AND state = 'active'",
            &[&authority_id, &tenant_id, &namespace, &sha256, &locked_gen],
        )
        .await?;
    ensure!(updated == 1, "Pando remote artifact generation changed during fenced retire");
    tx.commit().await?;
    Ok(true)
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
