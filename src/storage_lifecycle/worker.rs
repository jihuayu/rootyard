//! Native-volume worker. The global backup barrier precedes repository locks;
//! a claimed job is revalidated only after all local admission barriers are held.
use super::{
    fence, gc, gitfs, jobs,
    models::{JobOutcome, Policy},
    scheduler,
};
use crate::{AppState, db};
use anyhow::{Context, Result, bail};
use serde_json::json;
use std::{sync::Arc, time::Duration};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub async fn run_once(state: &Arc<AppState>, policy: &Policy, owner: Uuid) -> Result<Option<JobOutcome>> {
    let Some(job) = jobs::claim(&state.pool, owner, policy).await? else {
        return Ok(None);
    };
    match run_claimed(state, policy, &job).await {
        Ok(outcome) => Ok(Some(outcome)),
        Err(error) => {
            let accepted = jobs::finish(&state.pool, &job, json!({}), Some(&error.to_string()), policy).await?;
            let status = if !accepted {
                "superseded"
            } else if job.attempt < policy.max_attempts {
                "queued"
            } else {
                "failed"
            };
            Ok(Some(JobOutcome {
                job_id: job.id,
                kind: job.kind.clone(),
                repository_id: job.repository_id,
                attempt: job.attempt,
                state: status.into(),
            }))
        }
    }
}

async fn run_claimed(state: &Arc<AppState>, policy: &Policy, job: &super::models::Job) -> Result<JobOutcome> {
    // Backup and migration hold the exclusive variant. A short claim transaction
    // never holds this lock, so backup cannot deadlock on a worker claim.
    let mut barrier = state.pool.get().await?;
    let tx = barrier.transaction().await?;
    let granted: bool = tx.query_one("SELECT pg_try_advisory_xact_lock_shared(738390103)", &[]).await?.get(0);
    if !granted {
        bail!("backup or migration barrier is active");
    }
    let lease = crate::storage::read_leases::exclusive(
        &state.pool,
        job.repository_id,
        Instant::now() + state.config.git_timeout,
    )
    .await
    .map_err(|_| anyhow::anyhow!("repository reader barrier unavailable"))?;
    lease.ensure_active().map_err(|_| anyhow::anyhow!("repository reader barrier lost"))?;
    if matches!(job.kind.as_str(), "gitfs_tombstone_delete" | "gitfs_cache_evict") {
        // A remote reader may lose its PostgreSQL session just before its
        // watcher notices and reaps the native Git child. The exclusive lock
        // excludes new readers; allow the old ones to quiesce before unlink.
        let grace = tokio::time::sleep(Duration::from_secs(5));
        tokio::pin!(grace);
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                _=&mut grace => break,
                _=tick.tick() => {
                    lease.ensure_active().map_err(|_| anyhow::anyhow!("repository reader barrier lost"))?;
                    let renewed=tokio::time::timeout(Duration::from_millis(750),
                        jobs::renew(&state.pool,job,policy)).await;
                    let backup_ping=tokio::time::timeout(Duration::from_millis(750),
                        tx.query_one("SELECT 1",&[])).await;
                    if !matches!(renewed,Ok(Ok(true))) || !matches!(backup_ping,Ok(Ok(_))) {
                        bail!("maintenance lease or backup barrier lost during reader grace");
                    }
                }
            }
        }
        lease.ensure_active().map_err(|_| anyhow::anyhow!("repository reader barrier lost"))?;
    }
    let _readers = state.storage.maintenance_exclusive(job.repository_id).await;
    // A push may hold a shared transfer gate while waiting for the writer
    // mutex at final CAS. Taking this exclusive gate first lets it finish.
    let _write = state.storage.write_lock(job.repository_id).await;
    lease.ensure_active().map_err(|_| anyhow::anyhow!("repository reader barrier lost"))?;
    if !jobs::current(&state.pool, job).await? {
        bail!("maintenance claim or repository generation changed");
    }
    if !scheduler::check_local_primary(state, job.repository_id).await? {
        bail!("repository is not assigned to this primary");
    }
    let client = state.pool.get().await?;
    let row = client.query_one(&format!("{} WHERE r.id=$1", db::REPO_SELECT), &[&job.repository_id]).await?;
    let repo = db::Repository::from_row(&row);
    crate::sharding::fencing::check_before_push(state, &repo)
        .await
        .map_err(|_| anyhow::anyhow!("repository storage fence denies maintenance"))?;
    if !matches!(
        tokio::time::timeout(Duration::from_millis(750), jobs::progress(&state.pool, job, "executing")).await,
        Ok(Ok(true))
    ) {
        bail!("maintenance progress claim was superseded");
    }

    let cancel = CancellationToken::new();
    let mut fence = if job.kind == "gitfs_tombstone_delete" {
        if !gc::PHYSICAL_DELETE_ENABLED {
            bail!("physical deletion requires complete reader lease coverage");
        }
        Some(fence::acquire(state, job, &lease, policy, &cancel).await?)
    } else {
        None
    };
    let result = {
        let task = async {
            if job.kind == "gitfs_unreachable_mark" {
                gc::mark(state, job.repository_id, job.tenant_id, job.repository_generation, policy, &cancel).await
            } else if job.kind == "gitfs_tombstone_delete" {
                if !gc::PHYSICAL_DELETE_ENABLED {
                    bail!("physical deletion requires complete reader lease coverage");
                }
                gc::delete_due(state, job, &lease, fence.as_ref().context("physical GC fence missing")?, &cancel).await
            } else if job.kind == "gitfs_cache_evict" {
                if !gc::PHYSICAL_DELETE_ENABLED {
                    bail!("cache eviction requires complete reader lease coverage");
                }
                gitfs::execute(state, job.repository_id, &job.kind, policy, &cancel).await
            } else {
                gitfs::execute(state, job.repository_id, &job.kind, policy, &cancel).await
            }
        };
        tokio::pin!(task);
        let mut safety = tokio::time::interval(Duration::from_millis(200));
        safety.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut renew = tokio::time::interval(Duration::from_secs((policy.lease_seconds / 3).max(1) as u64));
        renew.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                done=&mut task => break done,
                _=safety.tick() => {
                    if lease.ensure_active().is_err()
                        || fence.as_ref().is_some_and(|fence| fence.ensure_active().is_err()) {
                        cancel.cancel();
                        let _=task.await;
                        bail!("repository reader barrier or physical GC fence lost during maintenance");
                    }
                }
                _=renew.tick() => {
                    let renewed=tokio::time::timeout(Duration::from_millis(750),jobs::renew(&state.pool,job,policy)).await;
                    let backup_ping=tokio::time::timeout(Duration::from_millis(750),tx.query_one("SELECT 1",&[])).await;
                    if !matches!(renewed,Ok(Ok(true))) || !matches!(backup_ping,Ok(Ok(_))) {
                        cancel.cancel();
                        let _=task.await;
                        bail!("maintenance lease or backup barrier lost");
                    }
                }
            }
        }
    };
    let result = result?;
    lease.ensure_active().map_err(|_| anyhow::anyhow!("repository reader barrier lost"))?;
    if let Some(fence) = &fence {
        fence.verify(job, &lease, &cancel).await?;
    }
    if !jobs::current(&state.pool, job).await? {
        bail!("maintenance lease expired before result publication");
    }
    if job.kind == "gitfs_repack" {
        let counts = gitfs::count(state, job.repository_id, &CancellationToken::new()).await?;
        let client = state.pool.get().await?;
        client
            .execute(
                "UPDATE storage_maintenance_repo_state SET last_repack_at=clock_timestamp(), \
             last_repack_loose_count=$3,last_repack_pack_count=$4 WHERE repository_id=$1 \
             AND tenant_id=$2 AND last_scan_generation=$5",
                &[&job.repository_id, &job.tenant_id, &counts.loose, &counts.packs, &job.repository_generation],
            )
            .await?;
    }
    let accepted = jobs::finish(&state.pool, job, result, None, policy).await?;
    if let Some(fence) = fence.take() {
        fence.release().await;
    }
    lease.ensure_active().map_err(|_| anyhow::anyhow!("repository reader barrier lost"))?;
    tx.commit().await?;
    Ok(JobOutcome {
        job_id: job.id,
        kind: job.kind.clone(),
        repository_id: job.repository_id,
        attempt: job.attempt,
        state: if accepted { "succeeded" } else { "superseded" }.into(),
    })
}
