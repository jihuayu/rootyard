//! Automatic, tenant-scoped job admission based on observed GitFS thresholds.
use super::{gitfs, jobs, models::Policy};
use crate::AppState;
use anyhow::{Result, bail};
use serde_json::json;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

async fn local_primary(state: &AppState, repo: Uuid) -> Result<bool> {
    let client=state.pool.get().await?;
    let local=std::env::var("ROOTYARD_NODE_ID").ok();
    if local.as_ref().is_some_and(|id| !crate::sharding::models::valid_node_id(id)) {
        bail!("invalid local node identity");
    }
    let row=client.query_opt(
        "SELECT primary_node_id FROM repository_shard_routes WHERE repository_id=$1",
        &[&repo],
    ).await?;
    match (local,row) {
        (Some(id),Some(row)) => Ok(id==row.get::<_,String>(0)),
        (Some(id),None) => Ok(id==crate::sharding::models::DEFAULT_NODE_ID),
        (None,_) => {
            let count:i64=client.query_one("SELECT count(*) FROM shard_nodes",&[]).await?.get(0);
            Ok(count<=1)
        }
    }
}

pub async fn schedule_once(state: &AppState, policy: &Policy) -> Result<usize> {
    let client=state.pool.get().await?;
    let rows=client.query(
        "SELECT r.id,r.owner_id,r.storage_generation, \
         COALESCE(s.last_repack_loose_count,0) AS base_loose, \
         COALESCE(s.last_repack_pack_count,0) AS base_packs, \
         s.last_repack_at::text AS last_repack_at \
         FROM repositories r LEFT JOIN storage_maintenance_repo_state s ON s.repository_id=r.id \
         WHERE r.state='ready' AND r.storage_backend='gitfs' AND \
           (s.last_scan_at IS NULL OR s.last_scan_at < clock_timestamp()-make_interval(secs=>($1::bigint)::double precision)) \
         ORDER BY s.last_scan_at NULLS FIRST,r.id LIMIT 16",
        &[&policy.scan_period_seconds],
    ).await?;
    let mut scheduled=0;
    for row in rows {
        let repo:Uuid=row.get("id");
        let tenant:Uuid=row.get("owner_id");
        let generation:i64=row.get("storage_generation");
        if !local_primary(state,repo).await? { continue; }
        let cancel=CancellationToken::new();
        let counts=gitfs::count(state,repo,&cancel).await?;
        let client=state.pool.get().await?;
        let updated=client.execute(
            "INSERT INTO storage_maintenance_repo_state(repository_id,tenant_id,last_scan_at,last_scan_generation,loose_count,pack_count,last_scan) \
             SELECT id,owner_id,clock_timestamp(),storage_generation,$3,$4,$5 FROM repositories \
             WHERE id=$1 AND owner_id=$2 AND storage_generation=$6 AND state='ready' AND storage_backend='gitfs' \
             ON CONFLICT(repository_id) DO UPDATE SET last_scan_at=EXCLUDED.last_scan_at, \
             last_scan_generation=EXCLUDED.last_scan_generation,loose_count=EXCLUDED.loose_count, \
             pack_count=EXCLUDED.pack_count,last_scan=EXCLUDED.last_scan \
             WHERE storage_maintenance_repo_state.tenant_id=EXCLUDED.tenant_id",
            &[&repo,&tenant,&counts.loose,&counts.packs,&json!({"source":"git-count-objects-v"}),&generation],
        ).await?;
        if updated==0 { continue; }
        if jobs::enqueue(&state.pool,repo,tenant,generation,"gitfs_stage_cleanup").await? { scheduled+=1; }
        let prior:Option<String>=row.get("last_repack_at");
        let new_loose=counts.loose-row.get::<_,i64>("base_loose");
        let new_packs=counts.packs-row.get::<_,i64>("base_packs");
        let repack=if prior.is_none() {
            counts.loose>=policy.loose_threshold || counts.packs>=policy.pack_threshold
        } else {
            new_loose>=policy.loose_threshold || new_packs>=policy.pack_threshold
        };
        if repack && jobs::enqueue(&state.pool,repo,tenant,generation,"gitfs_repack").await? { scheduled+=1; }
        if jobs::enqueue(&state.pool,repo,tenant,generation,"gitfs_unreachable_mark").await? { scheduled+=1; }
    }
    Ok(scheduled)
}

pub async fn check_local_primary(state: &AppState, repo: Uuid) -> Result<bool> { local_primary(state,repo).await }
