//! Database evaluation, exclusive lease quiescence, safe remote object cleanup,
//! and local directory teardown for final repository purge.
use super::{
    lifecycle::{PurgeRepoInput, validate_purge_confirmation},
    lifecycle_ops::{PurgeBlockedResponse, PurgeRepoResponse, json_no_store},
    purge_exec::{
        delete_pando_artifact_fenced, execute_claimed_remote_deletes, gather_remote_inventory, remove_local_repo_dir,
    },
    purge_safety::{PurgeHoldKind, PurgePreconditions, evaluate_purge_holds, plan_safe_remote_cleanup},
};
use crate::{
    AppState, Error,
    db::Identity,
    pando_gateway::{pack_store::PackStore, pitr_fence},
    storage::{
        read_leases,
        remote_key_claims::{DEFAULT_DELETE_CLAIM_LEASE_SECS, DeleteClaim, lock_object_key, upsert_delete_claim},
        remote_objects::RemoteObjectStore,
    },
    storage_lifecycle::pando_delete_gate,
};
use axum::{http::StatusCode, response::Response};
use deadpool_postgres::Transaction;
use serde_json::json;
use std::{collections::BTreeSet, time::Duration};
use tokio::time::Instant;
use uuid::Uuid;

async fn count_hold(tx: &Transaction<'_>, sql: &str, repo_id: Uuid) -> Result<usize, Error> {
    let count: i64 = tx.query_one(sql, &[&repo_id]).await.map_err(Error::internal)?.get(0);
    Ok(usize::try_from(count).unwrap_or(usize::MAX))
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

    let (repo_lfs_oids, _initial_shared_lfs, repo_ws_digests, shared_ws_digests, pando_candidates) =
        gather_remote_inventory(state, &tx, repo_id, owner_id, ws_store.as_ref(), deadline).await?;

    let is_hex64 = |s: &str| s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    let mut locked_keys: BTreeSet<(&str, &str)> = BTreeSet::new();
    for oid in &repo_lfs_oids {
        if is_hex64(oid) {
            locked_keys.insert(("lfs", oid.as_str()));
        }
    }
    for digest in &repo_ws_digests {
        if is_hex64(digest) {
            locked_keys.insert(("workspace", digest.as_str()));
        }
    }
    for (ns, digest) in locked_keys {
        lock_object_key(&tx, owner_id, ns, digest).await?;
    }

    tx.execute("DELETE FROM pando_retention_roots WHERE repository_id = $1 AND state = 'released'", &[&repo_id])
        .await
        .map_err(Error::internal)?;
    tx.execute("DELETE FROM repositories WHERE id = $1", &[&repo_id]).await.map_err(Error::internal)?;

    let mut post_shared_lfs: BTreeSet<String> = BTreeSet::new();
    if !repo_lfs_oids.is_empty() {
        let rows = tx
            .query(
                "SELECT DISTINCT oid FROM lfs_objects WHERE tenant_id = $1 AND oid = ANY($2)",
                &[&owner_id, &repo_lfs_oids],
            )
            .await
            .map_err(Error::internal)?;
        post_shared_lfs.extend(rows.into_iter().map(|r| r.get::<_, String>(0)));
    }
    let mut post_shared_ws = shared_ws_digests;
    if !repo_ws_digests.is_empty() {
        let rows = tx
            .query(
                "SELECT DISTINCT digest FROM ( \
                    SELECT s.digest FROM workspace_remote_staging_objects s \
                    WHERE s.tenant_id = $1 AND s.digest = ANY($2) \
                    UNION \
                    SELECT c.manifest_digest AS digest FROM workspace_checkpoints c \
                    JOIN repositories r ON r.id = c.repository_id \
                    WHERE r.owner_id = $1 AND c.manifest_digest = ANY($2) \
                 ) live",
                &[&owner_id, &repo_ws_digests],
            )
            .await
            .map_err(Error::internal)?;
        post_shared_ws.extend(rows.into_iter().map(|r| r.get::<_, String>(0)));
    }

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
        &post_shared_lfs,
        &repo_ws_digests,
        &post_shared_ws,
        &pando_flags,
    );

    let mut claims: Vec<DeleteClaim> = Vec::new();
    if lfs_store.is_some() {
        for key_path in &delete_plan.deletable_lfs_keys {
            let oid = key_path.rsplit('/').next().unwrap_or_default();
            claims.push(upsert_delete_claim(&tx, owner_id, "lfs", oid, DEFAULT_DELETE_CLAIM_LEASE_SECS).await?);
        }
    }
    if ws_store.is_some() {
        for key_path in &delete_plan.deletable_workspace_keys {
            let digest = key_path.rsplit('/').next().unwrap_or_default();
            claims
                .push(upsert_delete_claim(&tx, owner_id, "workspace", digest, DEFAULT_DELETE_CLAIM_LEASE_SECS).await?);
        }
    }

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

    crate::auth::finish_tx(tx, actor, true).await?;

    let (deleted_lfs_keys, deleted_workspace_keys) = execute_claimed_remote_deletes(
        &state.pool,
        owner_id,
        lfs_store.as_ref(),
        ws_store.as_ref(),
        &delete_plan,
        &post_shared_lfs,
        &post_shared_ws,
        &claims,
        deadline,
    )
    .await
    .map_err(Error::internal)?;

    if let Some(store) = pando_store.as_ref() {
        for cand in pando_candidates.iter().filter(|c| c.authority_scoped_unshared) {
            delete_pando_artifact_fenced(
                &state.pool,
                store,
                cand.authority_id,
                cand.tenant_id,
                &cand.namespace,
                &cand.sha256,
                Some(cand.object_generation),
                deadline,
            )
            .await
            .map_err(Error::internal)?;
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
