//! Native-volume worker. The global backup barrier precedes repository locks;
//! a claimed job is revalidated only after all local admission barriers are held.
use super::{gitfs, jobs, models::{JobOutcome,Policy}, scheduler};
use crate::{AppState, db};
use anyhow::{Result, bail};
use serde_json::json;
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub async fn run_once(state: &Arc<AppState>, policy: &Policy, owner: Uuid) -> Result<Option<JobOutcome>> {
    let Some(job)=jobs::claim(&state.pool,owner,policy).await? else { return Ok(None) };
    match run_claimed(state,policy,&job).await {
        Ok(outcome) => Ok(Some(outcome)),
        Err(error) => {
            let accepted=jobs::finish(&state.pool,&job,json!({}),Some(&error.to_string()),policy).await?;
            let status=if !accepted { "superseded" } else if job.attempt<policy.max_attempts { "queued" } else { "failed" };
            Ok(Some(JobOutcome {job_id:job.id,kind:job.kind.clone(),repository_id:job.repository_id,
                attempt:job.attempt,state:status.into()}))
        }
    }
}

async fn run_claimed(state: &Arc<AppState>, policy: &Policy, job: &super::models::Job) -> Result<JobOutcome> {
    // Backup and migration hold the exclusive variant. A short claim transaction
    // never holds this lock, so backup cannot deadlock on a worker claim.
    let mut barrier=state.pool.get().await?;
    let tx=barrier.transaction().await?;
    let granted:bool=tx.query_one("SELECT pg_try_advisory_xact_lock_shared(738390103)",&[]).await?.get(0);
    if !granted { bail!("backup or migration barrier is active"); }
    // The durable per-repository reader lease will be acquired here before
    // the local locks once storage::read_leases lands. Until then, this worker
    // permits only nonpruning operations.
    let _write=state.storage.write_lock(job.repository_id).await;
    let _readers=state.storage.maintenance_exclusive(job.repository_id).await;
    if !jobs::current(&state.pool,job).await? { bail!("maintenance claim or repository generation changed"); }
    if !scheduler::check_local_primary(state,job.repository_id).await? { bail!("repository is not assigned to this primary"); }
    let client=state.pool.get().await?;
    let row=client.query_one(&format!("{} WHERE r.id=$1",db::REPO_SELECT),&[&job.repository_id]).await?;
    let repo=db::Repository::from_row(&row);
    crate::sharding::fencing::check_before_push(state,&repo).await
        .map_err(|_| anyhow::anyhow!("repository storage fence denies maintenance"))?;

    let cancel=CancellationToken::new();
    let task=gitfs::execute(state,job.repository_id,&job.kind,policy,&cancel);
    tokio::pin!(task);
    let mut tick=tokio::time::interval(Duration::from_secs((policy.lease_seconds/3).max(1) as u64));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let result=loop {
        tokio::select! {
            done=&mut task => break done,
            _=tick.tick() => {
                if !jobs::renew(&state.pool,job,policy).await.unwrap_or(false)
                    || tx.query_one("SELECT 1",&[]).await.is_err() {
                    cancel.cancel();
                    break task.await;
                }
            }
        }
    };
    let result=result?;
    if !jobs::current(&state.pool,job).await? { bail!("maintenance lease expired before result publication"); }
    if job.kind=="gitfs_repack" {
        let counts=gitfs::count(state,job.repository_id,&CancellationToken::new()).await?;
        let client=state.pool.get().await?;
        client.execute(
            "UPDATE storage_maintenance_repo_state SET last_repack_at=clock_timestamp(), \
             last_repack_loose_count=$3,last_repack_pack_count=$4 WHERE repository_id=$1 \
             AND tenant_id=$2 AND last_scan_generation=$5",
            &[&job.repository_id,&job.tenant_id,&counts.loose,&counts.packs,&job.repository_generation],
        ).await?;
    }
    let accepted=jobs::finish(&state.pool,job,result,None,policy).await?;
    tx.commit().await?;
    Ok(JobOutcome {job_id:job.id,kind:job.kind.clone(),repository_id:job.repository_id,
        attempt:job.attempt,state:if accepted {"succeeded"} else {"superseded"}.into()})
}
