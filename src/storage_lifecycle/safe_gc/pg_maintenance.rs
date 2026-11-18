//! Real `storage_lifecycle` scheduler & worker integration for `pg_refstore` Safe GC (#122).

use std::{
    env,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    AppState,
    blob_store::{config::BlobProfile, disposable_view::DisposableViewRoot, opendal::BlobStore},
};

use super::super::{
    fence,
    models::{Job, JobOutcome, Policy},
    scheduler,
};
use super::{
    SafeGcError,
    compaction::{CompactionFault, SafeGcCompactionRequest, execute_two_phase_compaction},
    executor::{
        DeleteFaultHook, SafeGcSweepRequest, execute_safe_gc_sweep_with_external_fence,
        reclaim_abandoned_compaction_staging, reconcile_pending_delete_after_restart,
    },
    model::{AuthorityLane, GcMode, SafeGcArmReceipt},
    pg_reconcile::reconcile_pg_refstore_authority,
    provider_delete::OpenDalS3GcProvider,
    store::DurableSafeGcAuthority,
};

pub const ENV_BLOB_SAFE_GC_DESTRUCTIVE: &str = "ROOTYARD_BLOB_SAFE_GC_DESTRUCTIVE";

/// Strictly parse `ROOTYARD_BLOB_SAFE_GC_DESTRUCTIVE`: unset or `"false"` keeps
/// destructive Blob GC disabled by default; `"true"` opts in subject to arming,
/// fence, reader quiescence, and unified `DeletionProof` verification.
pub fn safe_gc_destructive_env_enabled() -> Result<bool> {
    match env::var(ENV_BLOB_SAFE_GC_DESTRUCTIVE) {
        Err(env::VarError::NotPresent) => Ok(false),
        Ok(val) if val == "false" => Ok(false),
        Ok(val) if val == "true" => Ok(true),
        Ok(_) | Err(env::VarError::NotUnicode(_)) => bail!("{ENV_BLOB_SAFE_GC_DESTRUCTIVE} must be true or false"),
    }
}

pub fn safe_gc_journal_path(storage_root: &Path, repo_id: Uuid) -> PathBuf {
    storage_root.join("safe-gc").join(format!("{repo_id}.json"))
}

pub async fn schedule_pg_refstore(state: &AppState, policy: &Policy) -> Result<usize> {
    let destructive_env = safe_gc_destructive_env_enabled()?;
    let safe_gc_dir = state.storage.root.join("safe-gc");
    if !safe_gc_dir.is_dir() {
        return Ok(0);
    }
    let client = state.pool.get().await?;
    let rows = client
        .query(
            "SELECT r.id, r.owner_id, r.storage_generation \
             FROM repositories r \
             JOIN ref_store_serving_repositories b ON b.repository_id = r.id \
             LEFT JOIN storage_maintenance_repo_state s ON s.repository_id = r.id \
             WHERE r.state = 'ready' AND r.storage_backend = 'pg_refstore' AND b.state = 'ready' \
               AND (s.last_scan_at IS NULL \
                    OR COALESCE((s.last_scan->>'safe_gc_queued')::boolean, false) = false \
                    AND s.last_scan_at < clock_timestamp() - make_interval(secs => ($1::bigint)::double precision)) \
             ORDER BY s.last_scan_at NULLS FIRST, r.id LIMIT 16",
            &[&policy.scan_period_seconds],
        )
        .await?;

    let mut scheduled = 0;
    for row in rows {
        let (repo_id, tenant_id, generation): (Uuid, Uuid, i64) = (row.get(0), row.get(1), row.get(2));
        let journal = safe_gc_journal_path(&state.storage.root, repo_id);
        if !journal.is_file() || !scheduler::check_local_primary(state, repo_id).await? {
            continue;
        }
        let auth = DurableSafeGcAuthority::open_with_journal(&journal, None)
            .map_err(|e| anyhow::anyhow!("open safe_gc journal failed: {e}"))?;
        let snap = auth.snapshot();
        let need_compact = snap.active_packs.len() >= policy.pack_threshold as usize;
        let need_staging =
            snap.staged_uploads.iter().any(|u| u.state == super::domain::StagedUploadState::AbandonedPendingCleanup);
        let need_reconcile = snap.pending_delete.is_some();
        let need_sweep =
            destructive_env && matches!(snap.gc_mode, GcMode::ArmedDestructive(_)) && !snap.retired_packs.is_empty();
        let queued = need_compact || need_staging || need_reconcile || need_sweep;
        let scan_meta = json!({
            "source": "pg_refstore_safe_gc",
            "safe_gc_queued": queued,
            "need_compact": need_compact,
            "need_staging": need_staging,
            "need_reconcile": need_reconcile,
            "need_sweep": need_sweep,
        });
        let updated = client
            .execute(
                "INSERT INTO storage_maintenance_repo_state(repository_id,tenant_id,last_scan_at,last_scan_generation,loose_count,pack_count,last_scan) \
                 SELECT id, owner_id, clock_timestamp(), storage_generation, 0, $3, $4 FROM repositories \
                 WHERE id=$1 AND owner_id=$2 AND storage_generation=$5 AND state='ready' AND storage_backend='pg_refstore' \
                 ON CONFLICT(repository_id) DO UPDATE SET last_scan_at=EXCLUDED.last_scan_at, \
                   last_scan_generation=EXCLUDED.last_scan_generation, pack_count=EXCLUDED.pack_count, \
                   last_scan=EXCLUDED.last_scan \
                 WHERE storage_maintenance_repo_state.tenant_id=EXCLUDED.tenant_id",
                &[&repo_id, &tenant_id, &(snap.active_packs.len() as i64), &scan_meta, &generation],
            )
            .await?;
        if updated == 1 && queued {
            scheduled += 1;
        }
    }
    Ok(scheduled)
}

pub async fn run_claimed_safe_gc_once(
    state: &Arc<AppState>,
    policy: &Policy,
    owner: Uuid,
) -> Result<Option<JobOutcome>> {
    let safe_gc_dir = state.storage.root.join("safe-gc");
    if !safe_gc_dir.is_dir() {
        return Ok(None);
    }
    let client = state.pool.get().await?;
    let Some(claimed_row) = client
        .query_opt(
            "UPDATE storage_maintenance_repo_state s \
             SET last_scan = jsonb_set(s.last_scan, '{safe_gc_queued}', 'false'::jsonb) \
             FROM repositories r \
             WHERE s.repository_id = r.id AND s.tenant_id = r.owner_id \
               AND r.state = 'ready' AND r.storage_backend = 'pg_refstore' \
               AND COALESCE((s.last_scan->>'safe_gc_queued')::boolean, false) = true \
             RETURNING r.id, r.owner_id, r.storage_generation, s.last_scan",
            &[],
        )
        .await?
    else {
        return Ok(None);
    };
    drop(client);

    let repo_id: Uuid = claimed_row.get(0);
    let tenant_id: Uuid = claimed_row.get(1);
    let generation: i64 = claimed_row.get(2);
    let scan_json: Value = claimed_row.get(3);
    let want_delete = scan_json.get("need_sweep").and_then(Value::as_bool).unwrap_or(false)
        || scan_json.get("need_reconcile").and_then(Value::as_bool).unwrap_or(false);
    let job_kind = if want_delete { "pando_tombstone_delete" } else { "pando_repack" };
    let job_id = Uuid::new_v4();

    let job_client = state.pool.get().await?;
    job_client
        .execute(
            "INSERT INTO storage_maintenance_jobs(id,repository_id,tenant_id,kind,state,repository_generation,attempt,claim_generation,lease_owner,lease_until,progress) \
             VALUES($1,$2,$3,$4,'running',$5,1,1,$6,clock_timestamp()+make_interval(secs=>($7::bigint)::double precision),$8)",
            &[&job_id, &repo_id, &tenant_id, &job_kind, &generation, &owner, &policy.lease_seconds, &json!({"phase":"safe_gc_executing"})],
        )
        .await?;
    drop(job_client);

    let job = Job {
        id: job_id,
        repository_id: repo_id,
        tenant_id,
        kind: job_kind.into(),
        repository_generation: generation,
        attempt: 1,
        claim_generation: 1,
        lease_owner: owner,
    };

    match execute_claimed_pg_refstore_job(state, &job, policy).await {
        Ok(res_val) => {
            finish_safe_gc_job_row(state, job_id, "succeeded", res_val, None).await?;
            Ok(Some(JobOutcome {
                job_id,
                kind: job.kind,
                repository_id: repo_id,
                attempt: 1,
                state: "succeeded".into(),
            }))
        }
        Err(err) => {
            let msg = format!("{err:#}");
            finish_safe_gc_job_row(state, job_id, "failed", json!({}), Some(&msg)).await?;
            Ok(Some(JobOutcome { job_id, kind: job.kind, repository_id: repo_id, attempt: 1, state: "failed".into() }))
        }
    }
}

async fn finish_safe_gc_job_row(
    state: &AppState,
    job_id: Uuid,
    status: &str,
    result: Value,
    err_msg: Option<&str>,
) -> Result<()> {
    let truncated = err_msg.map(|m| m.chars().take(1024).collect::<String>());
    let client = state.pool.get().await?;
    client
        .execute(
            "UPDATE storage_maintenance_jobs SET state=$2, lease_owner=NULL, lease_until=NULL, \
               result=$3, last_error=$4, completed_at=clock_timestamp(), updated_at=clock_timestamp() \
             WHERE id=$1",
            &[&job_id, &status, &result, &truncated],
        )
        .await?;
    Ok(())
}

async fn execute_claimed_pg_refstore_job(state: &Arc<AppState>, job: &Job, policy: &Policy) -> Result<Value> {
    let destructive_env = safe_gc_destructive_env_enabled()?;
    let mut barrier_conn = state.pool.get().await?;
    let barrier_tx = barrier_conn.transaction().await?;
    let backup_ok: bool = barrier_tx.query_one("SELECT pg_try_advisory_xact_lock_shared(738390103)", &[]).await?.get(0);
    ensure!(backup_ok, "backup or migration barrier is active");

    let lease = crate::storage::read_leases::exclusive(
        &state.pool,
        job.repository_id,
        tokio::time::Instant::now() + state.config.git_timeout,
    )
    .await
    .map_err(|_| anyhow::anyhow!("repository reader barrier unavailable"))?;
    lease.ensure_active().map_err(|_| anyhow::anyhow!("repository reader barrier lost"))?;
    let _readers = state.storage.maintenance_exclusive(job.repository_id).await;
    let _write = state.storage.write_lock(job.repository_id).await;

    let pg_fence = fence::acquire_blob_safe_gc(state, job, &lease, policy).await?;
    let fence_epoch = pg_fence.epoch().max(1) as u64;

    let run_res = run_safe_gc_phases(state, job, policy, (destructive_env, fence_epoch), (&lease, &pg_fence)).await;
    pg_fence.release().await;
    let out = run_res?;
    lease.ensure_active().map_err(|_| anyhow::anyhow!("repository reader barrier lost"))?;
    barrier_tx.commit().await?;
    Ok(out)
}

async fn run_safe_gc_phases(
    state: &AppState,
    job: &Job,
    policy: &Policy,
    flags: (bool, u64),
    barriers: (&crate::storage::read_leases::Lease, &fence::Fence),
) -> Result<Value> {
    let (destructive_env, fence_epoch) = flags;
    let (lease, pg_fence) = barriers;
    let journal = safe_gc_journal_path(&state.storage.root, job.repository_id);
    let authority = DurableSafeGcAuthority::open_with_journal(&journal, None)
        .map_err(|e| anyhow::anyhow!("open safe_gc journal: {e}"))?;
    let blob_store =
        BlobStore::open(BlobProfile::from_env().context("BlobProfile::from_env")?).context("BlobStore::open")?;
    let provider =
        OpenDalS3GcProvider::open_from_env(&blob_store).map_err(|e| anyhow::anyhow!("OpenDalS3GcProvider: {e}"))?;

    let pg_client = state.pool.get().await?;
    let reconciled =
        reconcile_pg_refstore_authority(&**pg_client, job.repository_id, &blob_store, &authority, Some(fence_epoch))
            .await
            .map_err(|e| anyhow::anyhow!("reconcile_pg_refstore_authority: {e}"))?;
    drop(pg_client);

    let deadline = Instant::now() + Duration::from_secs(120);
    let ext_guard = || -> std::result::Result<(), SafeGcError> {
        lease.ensure_active().map_err(|_| SafeGcError::StaleDeleterFenced("PG exclusive reader lease lost"))?;
        pg_fence.ensure_active().map_err(|_| SafeGcError::StaleDeleterFenced("PG gc_epoch fence heartbeat lost"))
    };

    let mut compacted = false;
    if authority.snapshot().active_packs.len() >= policy.pack_threshold as usize {
        let views_dir = state.storage.root.join("safe-gc-views");
        let views = DisposableViewRoot::open(&views_dir, 8, 64 * 1024 * 1024, Duration::from_secs(120))
            .map_err(|e| anyhow::anyhow!("DisposableViewRoot: {e}"))?;
        execute_two_phase_compaction(
            &authority,
            &blob_store,
            &provider,
            SafeGcCompactionRequest {
                op_id: job.id,
                group_id: "g-main",
                blob_generation: job.repository_generation,
                target_pack_ids: Vec::new(),
                view_root: &views,
                deadline,
                fault: CompactionFault::None,
            },
        )
        .await
        .map_err(|e| anyhow::anyhow!("two-phase compaction failed: {e}"))?;
        compacted = true;
    }

    let staging = reclaim_abandoned_compaction_staging(&authority, &provider, Some(&ext_guard), deadline)
        .await
        .map_err(|e| anyhow::anyhow!("staging cleanup failed: {e}"))?;

    let mut deleted_keys = Vec::new();
    let mut already_absent_keys = Vec::new();
    let snap = authority.snapshot();
    if snap.pending_delete.is_some() {
        ensure!(destructive_env, "{ENV_BLOB_SAFE_GC_DESTRUCTIVE} is disabled; refusing pending destructive batch");
        if let Some(rep) = reconcile_pending_delete_after_restart(
            &authority,
            &provider,
            snap.authority.incarnation_id,
            snap.authority.incarnation_epoch,
            snap.authority.lease_epoch,
            deadline,
        )
        .await
        .map_err(|e| anyhow::anyhow!("reconcile_pending_delete_after_restart: {e}"))?
        {
            deleted_keys.extend(rep.deleted_keys);
            already_absent_keys.extend(rep.already_absent_keys);
        }
    }

    let snap_after = authority.snapshot();
    if destructive_env
        && !snap_after.retired_packs.is_empty()
        && let GcMode::ArmedDestructive(existing_arm) = snap_after.gc_mode
    {
        let upgraded_lane = match existing_arm.lane {
            AuthorityLane::SingleNodePg { pg_authority_id, pg_tx_seq, .. } => AuthorityLane::SingleNodePg {
                pg_authority_id,
                pg_tx_seq: pg_tx_seq.max(reconciled.gate_revision),
                pg_gc_fence_epoch: fence_epoch,
                reader_barrier_epoch: fence_epoch,
            },
            other => other,
        };
        let live_arm = SafeGcArmReceipt::seal(
            snap_after.authority.tenant_id,
            snap_after.authority.repo_id,
            snap_after.authority.history_id,
            snap_after.authority.incarnation_id,
            snap_after.authority.incarnation_epoch,
            true,
            upgraded_lane,
        )
        .map_err(|e| anyhow::anyhow!("re-seal live PG arm: {e}"))?;
        authority.set_gc_mode(GcMode::ArmedDestructive(live_arm.clone())).map_err(|e| anyhow::anyhow!("{e}"))?;
        let proof = authority
            .build_authoritative_deletion_proof(live_arm, &[])
            .map_err(|e| anyhow::anyhow!("build_authoritative_deletion_proof: {e}"))?;
        let rep = execute_safe_gc_sweep_with_external_fence(
            &authority,
            &provider,
            SafeGcSweepRequest {
                batch_id: Uuid::new_v4(),
                deleter_incarnation_id: snap_after.authority.incarnation_id,
                deleter_incarnation_epoch: snap_after.authority.incarnation_epoch,
                deleter_lease_epoch: snap_after.authority.lease_epoch,
                proof,
                deadline,
                fault: DeleteFaultHook::None,
            },
            Some(&ext_guard),
        )
        .await
        .map_err(|e| anyhow::anyhow!("execute_safe_gc_sweep: {e}"))?;
        deleted_keys.extend(rep.deleted_keys);
        already_absent_keys.extend(rep.already_absent_keys);
    }

    Ok(json!({
        "compacted": compacted,
        "destructive_env_enabled": destructive_env,
        "staging_cleaned": staging.deleted_keys.len() + staging.already_absent_keys.len(),
        "deleted_keys": deleted_keys,
        "already_absent_keys": already_absent_keys,
        "gc_epoch": fence_epoch,
    }))
}
