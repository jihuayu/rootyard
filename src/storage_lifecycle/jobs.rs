//! Durable, generation-fenced claims. All state changes compare both claim owner
//! and claim generation; an expired worker cannot publish a late result.
use super::models::{Job, Policy};
use anyhow::Result;
use deadpool_postgres::Pool;
use serde_json::Value;
use uuid::Uuid;

pub async fn enqueue(pool: &Pool, repo: Uuid, tenant: Uuid, generation: i64, kind: &str) -> Result<bool> {
    let client = pool.get().await?;
    let n = client.execute(
        "INSERT INTO storage_maintenance_jobs(id,repository_id,tenant_id,kind,repository_generation) \
         VALUES($1,$2,$3,$4,$5) ON CONFLICT (repository_id,kind) \
         WHERE state IN ('queued','running') DO NOTHING",
        &[&Uuid::new_v4(), &repo, &tenant, &kind, &generation],
    ).await?;
    Ok(n == 1)
}

pub async fn claim(pool: &Pool, owner: Uuid, policy: &Policy) -> Result<Option<Job>> {
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    tx.execute(
        "UPDATE storage_maintenance_jobs SET state='failed',lease_owner=NULL,lease_until=NULL, \
         last_error='lease expired after maximum attempts',completed_at=clock_timestamp(), \
         updated_at=clock_timestamp() WHERE state='running' AND lease_until<clock_timestamp() \
         AND attempt >= $1",
        &[&policy.max_attempts],
    ).await?;
    let row = tx.query_opt(
        "WITH candidate AS ( \
           SELECT id FROM storage_maintenance_jobs \
           WHERE not_before <= clock_timestamp() AND attempt < $3 \
             AND (state='queued' OR (state='running' AND lease_until < clock_timestamp())) \
           ORDER BY not_before,created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED \
         ) UPDATE storage_maintenance_jobs j SET state='running', \
             attempt=j.attempt+1, claim_generation=j.claim_generation+1, \
             lease_owner=$1, lease_until=clock_timestamp()+make_interval(secs=>$2), \
             updated_at=clock_timestamp() \
         FROM candidate WHERE j.id=candidate.id RETURNING j.*",
        &[&owner, &policy.lease_seconds, &policy.max_attempts],
    ).await?;
    tx.commit().await?;
    Ok(row.as_ref().map(Job::row))
}

pub async fn renew(pool: &Pool, job: &Job, policy: &Policy) -> Result<bool> {
    let client = pool.get().await?;
    Ok(client.execute(
        "UPDATE storage_maintenance_jobs SET lease_until=clock_timestamp()+make_interval(secs=>$5), \
         updated_at=clock_timestamp() WHERE id=$1 AND state='running' AND lease_owner=$2 \
         AND claim_generation=$3 AND attempt=$4 AND lease_until > clock_timestamp()",
        &[&job.id, &job.lease_owner, &job.claim_generation, &job.attempt, &policy.lease_seconds],
    ).await? == 1)
}

pub async fn current(pool: &Pool, job: &Job) -> Result<bool> {
    let client = pool.get().await?;
    Ok(client.query_opt(
        "SELECT 1 FROM storage_maintenance_jobs j JOIN repositories r ON r.id=j.repository_id \
         WHERE j.id=$1 AND j.state='running' AND j.lease_owner=$2 AND \
         j.claim_generation=$3 AND j.attempt=$4 AND j.lease_until>clock_timestamp() \
         AND j.repository_generation=r.storage_generation AND j.tenant_id=r.owner_id \
         AND r.state='ready' AND r.storage_backend='gitfs'",
        &[&job.id, &job.lease_owner, &job.claim_generation, &job.attempt],
    ).await?.is_some())
}

pub async fn finish(pool: &Pool, job: &Job, result: Value, error: Option<&str>, policy: &Policy) -> Result<bool> {
    let client = pool.get().await?;
    let retry = error.is_some() && job.attempt < policy.max_attempts;
    let state = if retry { "queued" } else if error.is_some() { "failed" } else { "succeeded" };
    let message = error.map(|e| e.chars().take(1024).collect::<String>());
    let delay = (1_i64 << job.attempt.min(10)).min(900);
    Ok(client.execute(
        "UPDATE storage_maintenance_jobs SET state=$5, lease_owner=NULL,lease_until=NULL, \
         result=$6,last_error=$7,not_before=clock_timestamp()+make_interval(secs=>$8), \
         completed_at=CASE WHEN $5='queued' THEN NULL ELSE clock_timestamp() END, \
         updated_at=clock_timestamp() WHERE id=$1 AND state='running' AND lease_owner=$2 \
         AND claim_generation=$3 AND attempt=$4 AND lease_until>clock_timestamp()",
        &[&job.id, &job.lease_owner, &job.claim_generation, &job.attempt,
          &state, &result, &message, &delay],
    ).await? == 1)
}
