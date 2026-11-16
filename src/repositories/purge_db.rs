//! Database evaluation, exclusive lease quiescence, safe remote object cleanup,
//! and local directory teardown for final repository purge.
use super::{
    lifecycle::{PurgeRepoInput, validate_purge_confirmation},
    lifecycle_ops::{PurgeBlockedResponse, PurgeRepoResponse, json_no_store},
    purge_exec::{execute_safe_remote_deletes, remove_local_repo_dir},
    purge_safety::{PurgeHoldKind, PurgePreconditions, evaluate_purge_holds, plan_safe_remote_cleanup},
};
use crate::{
    AppState, Error,
    db::Identity,
    pando_gateway::{pack_store::PackStore, pitr_fence},
    storage::{
        read_leases,
        remote_objects::{ObjectKey, RemoteObjectStore},
    },
    storage_lifecycle::pando_delete_gate,
    workspaces::remote::RemoteManifest,
};
use axum::{http::StatusCode, response::Response};
use deadpool_postgres::Transaction;
use serde_json::json;
use std::{collections::BTreeSet, path::Path, time::Duration};
use tokio::{fs, time::Instant};
use uuid::Uuid;

#[derive(Clone)]
struct PandoArtifactCandidate {
    authority_id: Uuid,
    tenant_id: Uuid,
    namespace: String,
    sha256: String,
    object_generation: i64,
    remote_path: String,
    authority_scoped_unshared: bool,
}

async fn count_hold(tx: &Transaction<'_>, sql: &str, repo_id: Uuid) -> Result<usize, Error> {
    let count: i64 = tx.query_one(sql, &[&repo_id]).await.map_err(Error::internal)?.get(0);
    Ok(usize::try_from(count).unwrap_or(usize::MAX))
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

pub async fn collect_purge_preconditions(
    state: &AppState,
    tx: &Transaction<'_>,
    repo_id: Uuid,
) -> Result<(PurgePreconditions, Uuid, String, String, i64), Error> {
    let repo_row = tx
        .query_opt(
            "SELECT r.owner_id, n.slug, r.name, r.storage_backend, r.storage_generation, r.version, \
                    r.deleted_at IS NOT NULL AS deleted, \
                    (r.deleted_at IS NOT NULL AND r.purge_after IS NOT NULL AND clock_timestamp() >= r.purge_after) AS window_elapsed, \
                    (r.gc_owner IS NOT NULL AND r.gc_lease_until IS NOT NULL AND r.gc_lease_until > clock_timestamp()) AS gc_fenced \
             FROM repositories r JOIN namespaces n ON n.id = r.owner_id WHERE r.id = $1 FOR UPDATE OF r",
            &[&repo_id],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;

    let owner_id: Uuid = repo_row.get(0);
    let owner_slug: String = repo_row.get(1);
    let repo_name: String = repo_row.get(2);
    let backend: String = repo_row.get(3);
    let storage_generation: i64 = repo_row.get(4);
    let version: i64 = repo_row.get(5);
    let deleted: bool = repo_row.get(6);
    let recovery_window_elapsed: bool = repo_row.get(7);
    let physical_gc_fenced: bool = repo_row.get(8);

    let active_transfer_count = count_hold(
        tx,
        "SELECT count(*) FROM repository_transfers WHERE repository_id = $1 AND state NOT IN ('completed', 'rolled_back', 'failed')",
        repo_id,
    )
    .await?;
    let backup_retention_roots = count_hold(
        tx,
        "SELECT count(DISTINCT r.id) FROM pando_retention_roots r \
         WHERE r.state = 'active' AND (r.repository_id = $1 OR EXISTS (SELECT 1 FROM pando_retention_root_manifests rm WHERE rm.root_id = r.id AND rm.repository_id = $1))",
        repo_id,
    )
    .await?;
    let active_read_leases = count_hold(
        tx,
        "SELECT count(*) FROM ref_store_core_serving_reads WHERE repository_id = $1 AND expires_at > clock_timestamp()",
        repo_id,
    )
    .await?;
    let active_write_admissions = count_hold(
        tx,
        "SELECT count(*) FROM storage_write_admissions WHERE repository_id = $1 AND state = 'active'",
        repo_id,
    )
    .await?;
    let active_maintenance_jobs = count_hold(
        tx,
        "SELECT count(*) FROM storage_maintenance_jobs WHERE repository_id = $1 AND state IN ('queued', 'running')",
        repo_id,
    )
    .await?;
    let active_ci_checkout_leases = count_hold(
        tx,
        "SELECT ((SELECT count(*) FROM ci_checkout_jobs WHERE repository_id = $1 AND NOT cancelled AND NOT revoked AND (expires_unix IS NULL OR expires_unix > (extract(epoch FROM clock_timestamp()))::bigint)) \
               + (SELECT count(*) FROM ci_integration_checkout_jobs WHERE repository_id = $1 AND expires_unix > (extract(epoch FROM clock_timestamp()))::bigint) \
               + (SELECT count(*) FROM ci_checkout_delegations WHERE repository_id = $1 AND expires_unix > (extract(epoch FROM clock_timestamp()))::bigint))",
        repo_id,
    )
    .await?;
    let active_artifact_holds =
        count_hold(tx, "SELECT count(*) FROM artifact_holds WHERE repository_id = $1 AND state = 'active'", repo_id)
            .await?;
    let pending_publication_fences = count_hold(
        tx,
        "SELECT count(*) FROM pando_publication_fences f JOIN pando_pack_manifests m ON m.id = f.manifest_id WHERE m.repository_id = $1 AND f.lease_until > clock_timestamp()",
        repo_id,
    )
    .await?;
    let recovery_resolutions = count_hold(
        tx,
        "SELECT (SELECT count(*) FROM recovery_resolutions WHERE repository_id = $1) + (SELECT count(*) FROM operation_resolutions WHERE repository_id = $1)",
        repo_id,
    )
    .await?;
    let refstore_ledger_rows = count_hold(
        tx,
        "SELECT (SELECT count(*) FROM ref_store_serving_repositories WHERE repository_id = $1) \
              + (SELECT count(*) FROM ref_store_core_protocol_repos WHERE repository_id = $1) \
              + (SELECT count(*) FROM ref_store_operations WHERE repository_id = $1) \
              + (SELECT count(*) FROM ref_store_core_gates WHERE repository_id = $1) \
              + (SELECT count(*) FROM ref_store_core_snapshots WHERE repository_id = $1) \
              + (SELECT count(*) FROM ref_store_core_pins WHERE repository_id = $1)",
        repo_id,
    )
    .await?;
    let active_ci_pins =
        crate::ci_pins::active_pinned_oids(state, repo_id, storage_generation).await.map_err(Error::internal)?.len();

    let pre = PurgePreconditions {
        deleted,
        recovery_window_elapsed,
        is_pg_refstore: backend == "pg_refstore" || refstore_ledger_rows > 0,
        active_transfer_count,
        backup_retention_roots,
        active_read_leases,
        active_write_admissions,
        active_maintenance_jobs,
        physical_gc_fenced,
        active_ci_pins,
        active_ci_checkout_leases,
        active_artifact_holds,
        pending_publication_fences,
        recovery_resolutions,
    };
    Ok((pre, owner_id, owner_slug, repo_name, version))
}

async fn gather_remote_inventory(
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

pub async fn execute_purge(
    state: &AppState,
    actor: &Identity,
    owner: &str,
    name: &str,
    repo_id: Uuid,
    input: &PurgeRepoInput,
) -> Result<Response, Error> {
    validate_purge_confirmation(owner, name, input)?;
    let deadline = Instant::now() + Duration::from_secs(60);
    let _maint_guard = state.storage.maintenance_exclusive(repo_id).await;
    let _read_lease = match read_leases::exclusive(&state.pool, repo_id, deadline).await {
        Ok(lease) => lease,
        Err(_) => {
            let blocked = PurgeBlockedResponse {
                error: "active read leases block purge".to_owned(),
                holds: vec![super::purge_safety::PurgeHold {
                    kind: PurgeHoldKind::ActiveReadLease,
                    detail: "active repository read lease could not quiesce before purge deadline".into(),
                    blocking_count: 1,
                }],
            };
            return json_no_store(StatusCode::CONFLICT, &blocked);
        }
    };

    let lfs_store = if std::env::var_os("ROOTYARD_OBJECT_STORE_ENDPOINT").is_some() {
        Some(RemoteObjectStore::from_env(state.storage.root.join("remote-objects")).map_err(Error::internal)?)
    } else {
        None
    };
    let ws_store = Some(
        RemoteObjectStore::from_env(state.storage.root.join("workspace-service/local-object-cache"))
            .map_err(Error::internal)?,
    );

    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;

    let (pre, owner_id, owner_slug, repo_name, version) = collect_purge_preconditions(state, &tx, repo_id).await?;
    super::lifecycle::check_cas_version(version, input.expected_version)?;

    let evaluation = evaluate_purge_holds(&pre);
    if !evaluation.allowed {
        let blocked = PurgeBlockedResponse {
            error: "repository purge blocked by active holds".to_owned(),
            holds: evaluation.holds,
        };
        return json_no_store(StatusCode::CONFLICT, &blocked);
    }

    let (repo_lfs_oids, shared_lfs_oids, repo_ws_digests, shared_ws_digests, pando_candidates) =
        gather_remote_inventory(state, &tx, repo_id, owner_id, ws_store.as_ref(), deadline).await?;

    let pando_remote_enabled = pando_delete_gate::remote_delete_env_enabled().unwrap_or(false)
        && pando_candidates.iter().any(|c| c.authority_scoped_unshared);
    let pando_store = if pando_remote_enabled {
        let remote =
            RemoteObjectStore::from_env(state.storage.root.join("pando-pack-work")).map_err(Error::internal)?;
        match pitr_fence::verify_or_attest(&state.pool, &state.storage.root, &remote, deadline, "attest").await {
            Ok(auth_state) if !auth_state.remote_delete_fenced => Some(remote),
            _ => None,
        }
    } else {
        None
    };

    let pando_flags: Vec<(String, bool)> = pando_candidates
        .iter()
        .map(|c| (c.remote_path.clone(), c.authority_scoped_unshared && pando_store.is_some()))
        .collect();
    let delete_plan = plan_safe_remote_cleanup(
        owner_id,
        &repo_lfs_oids,
        &shared_lfs_oids,
        &repo_ws_digests,
        &shared_ws_digests,
        &pando_flags,
    );

    if tx.query_opt("SELECT 1 FROM organizations WHERE id = $1", &[&owner_id]).await.map_err(Error::internal)?.is_some()
    {
        crate::organizations::handlers::audit(
            &tx,
            owner_id,
            actor.id,
            "repository.purged",
            &format!("{owner_slug}/{repo_name}"),
            json!({
                "repository_id": repo_id,
                "deleted_lfs_count": delete_plan.deletable_lfs_keys.len(),
                "preserved_shared_lfs_count": delete_plan.preserved_shared_lfs_keys.len(),
                "deleted_workspace_count": delete_plan.deletable_workspace_keys.len(),
                "preserved_shared_workspace_count": delete_plan.preserved_shared_workspace_keys.len(),
            }),
        )
        .await?;
    }

    tx.execute("DELETE FROM pando_retention_roots WHERE repository_id = $1 AND state = 'released'", &[&repo_id])
        .await
        .map_err(Error::internal)?;
    tx.execute("DELETE FROM repositories WHERE id = $1", &[&repo_id]).await.map_err(Error::internal)?;
    crate::auth::finish_tx(tx, actor, true).await?;

    let (deleted_lfs_keys, deleted_workspace_keys) = execute_safe_remote_deletes(
        owner_id,
        lfs_store.as_ref(),
        ws_store.as_ref(),
        &delete_plan,
        &shared_lfs_oids,
        &shared_ws_digests,
        deadline,
    )
    .await
    .map_err(Error::internal)?;

    if let Some(store) = pando_store.as_ref() {
        for cand in pando_candidates.iter().filter(|c| c.authority_scoped_unshared) {
            let key = ObjectKey::scoped(
                cand.tenant_id,
                cand.authority_id,
                cand.object_generation,
                &cand.namespace,
                &cand.sha256,
            )
            .map_err(Error::internal)?;
            store.delete(&key, deadline).await.map_err(Error::internal)?;
            let _ = client
                .execute(
                    "UPDATE pando_remote_artifacts SET state = 'deleted', deleted_at = clock_timestamp() \
                     WHERE authority_id = $1 AND tenant_id = $2 AND namespace = $3 AND sha256 = $4",
                    &[&cand.authority_id, &cand.tenant_id, &cand.namespace, &cand.sha256],
                )
                .await;
        }
    }

    remove_local_repo_dir(&state.storage.root, &state.storage.repo_path(repo_id)).await.map_err(Error::internal)?;
    let _ = remove_local_repo_dir(&state.storage.root, &PackStore::cache_dir(&state.storage.root, repo_id)).await;
    let _ = remove_local_repo_dir(&state.storage.root, &state.storage.root.join("lfs").join(repo_id.to_string())).await;
    let _ =
        remove_local_repo_dir(&state.storage.root, &state.storage.root.join("ci-pins").join(repo_id.to_string())).await;

    let body = PurgeRepoResponse {
        purged: true,
        repository_id: repo_id,
        deleted_lfs_keys,
        preserved_shared_lfs_keys: delete_plan.preserved_shared_lfs_keys.len(),
        deleted_workspace_keys,
        preserved_shared_workspace_keys: delete_plan.preserved_shared_workspace_keys.len(),
        retired_pando_paths: delete_plan.retirable_pando_paths.len(),
        preserved_shared_pando_paths: delete_plan.preserved_shared_pando_paths.len(),
    };
    json_no_store(StatusCode::OK, &body)
}
