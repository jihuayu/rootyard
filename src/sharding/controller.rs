//! Recoverable local-host takeover. The trusted process fence is a prerequisite,
//! not a user-supplied receipt or a substitute for a verified Git snapshot.
use crate::{AppState, journal, storage::read_leases::Lease, sharding::{local_fence, locks, migration,
    models::{self, REPO_ROUTE_FIELDS, RepoShardRoute, VolumeFenceMarker}, transitions}};
use anyhow::{Context, Result, ensure};
use std::sync::Arc;
use uuid::Uuid;

struct Candidate {
    repo_id: Uuid,
    old_node: String,
    route_epoch: i64,
    operation_id: Uuid,
    refs_sha256: String,
    journal_sequence: i64,
}

async fn heartbeat(state: &AppState, node_id: &str) -> Result<()> {
    let client = state.pool.get().await?;
    let now = models::unix_now();
    client.execute(
        "UPDATE shard_nodes SET lease_expires_unix=$2, updated_at=clock_timestamp() \
         WHERE node_id=$1 AND status='healthy' AND role IN ('primary','replica') \
         AND lease_epoch > fenced_epoch",
        &[&node_id, &(now + 5)],
    ).await?;
    Ok(())
}

async fn candidates(state: &AppState, node_id: &str) -> Result<Vec<Candidate>> {
    let client = state.pool.get().await?;
    let rows = client.query(
        "SELECT DISTINCT ON (r.repository_id) r.repository_id,r.primary_node_id,r.route_epoch, \
            o.id,o.refs_sha256,o.journal_sequence \
         FROM repository_shard_routes r \
         JOIN repositories p ON p.id=r.repository_id \
         JOIN shard_nodes old ON old.node_id=r.primary_node_id \
         JOIN shard_replication_operations o ON o.repository_id=r.repository_id \
         JOIN shard_nodes candidate ON candidate.node_id=o.target_node_id \
         WHERE old.lease_expires_unix>0 AND old.lease_expires_unix<$2 \
           AND o.target_node_id=$1 AND o.state='verified' \
           AND o.source_node_id=r.primary_node_id AND o.source_route_epoch=r.route_epoch \
           AND o.source_generation=p.storage_generation AND o.refs_sha256 IS NOT NULL \
           AND o.journal_sequence IS NOT NULL AND NOT r.draining AND NOT r.read_only_degraded \
           AND candidate.status='healthy' AND candidate.role='replica' \
           AND candidate.lease_expires_unix>$2 \
         ORDER BY r.repository_id,o.updated_at DESC LIMIT 16",
        &[&node_id, &models::unix_now()],
    ).await?;
    Ok(rows.into_iter().map(|r| Candidate { repo_id: r.get(0), old_node: r.get(1),
        route_epoch: r.get(2), operation_id: r.get(3), refs_sha256: r.get(4), journal_sequence: r.get(5) }).collect())
}

async fn verify_target(state: &AppState, candidate: &Candidate, lease: &Lease) -> Result<()> {
    lease.ensure_active().map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let repo = state.storage.verify_path(candidate.repo_id)?;
    migration::git_output_lease(state, &["--git-dir", repo.to_str().context("non-UTF8 repository path")?,
        "fsck", "--full", "--strict"], state.config.git_timeout, lease).await.map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let digest = migration::refs_digest_lease(state, &repo, lease).await.map_err(|e| anyhow::anyhow!("{e:?}"))?;
    ensure!(digest == candidate.refs_sha256, "replica refs changed since verified transfer");
    ensure!(journal::sequence(&state.storage.root, candidate.repo_id)? >= candidate.journal_sequence,
        "replica journal is behind measured transfer");
    let client = state.pool.get().await?;
    let row = client.query_one(
        "SELECT COALESCE(MAX(sequence),0),COUNT(*) FILTER (WHERE outcome='unknown') \
         FROM git_operations WHERE repository_id=$1", &[&candidate.repo_id],
    ).await?;
    let required: i64 = row.get(0);
    let unknown: i64 = row.get(1);
    ensure!(unknown == 0 && candidate.journal_sequence >= required,
        "replica lacks an acknowledged or unresolved source operation");
    lease.ensure_active().map_err(|e| anyhow::anyhow!("{e:?}"))?;
    Ok(())
}

async fn promote(state: &AppState, node_id: &str, candidate: &Candidate,
    proof: &local_fence::ProcessIdentity, lease: &Lease) -> Result<bool> {
    lease.ensure_active().map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let mut client = state.pool.get().await?;
    let tx = client.transaction().await?;
    let elected: bool = tx.query_one(
        "SELECT pg_try_advisory_xact_lock(7348291,hashtext($1))", &[&candidate.repo_id.to_string()],
    ).await?.get(0);
    if !elected { return Ok(false); }
    // Match events::publish lock order: repository -> route -> admission.
    let locked_generation: i64 = tx.query_one(
        "SELECT storage_generation FROM repositories WHERE id=$1 FOR UPDATE",
        &[&candidate.repo_id]).await?.get(0);
    let query = format!("SELECT {REPO_ROUTE_FIELDS} FROM repository_shard_routes WHERE repository_id=$1 FOR UPDATE");
    let route = RepoShardRoute::row(&tx.query_one(&query, &[&candidate.repo_id]).await?);
    if route.primary_node_id != candidate.old_node || route.route_epoch != candidate.route_epoch
        || route.draining || route.read_only_degraded { return Ok(false); }
    // Fence the old epoch before inspecting ADMITTED writers. The route row is
    // already locked, so no settlement can acquire a fresh share lock; any
    // settlement that began earlier either commits before us or is fenced.
    tx.execute(
        "UPDATE repository_shard_routes SET draining=true, fenced_epoch=GREATEST(fenced_epoch,$2), \
         version=version+1, updated_at=clock_timestamp() WHERE repository_id=$1 AND route_epoch=$2",
        &[&candidate.repo_id, &route.route_epoch]).await?;
    crate::storage::ref_admission::fence_epoch(
        &tx, candidate.repo_id, route.route_epoch, crate::storage::ref_admission::DRAIN_WINDOW,
    ).await.map_err(|error| anyhow::anyhow!(error.1))?;
    let row = tx.query_one(
        "SELECT p.storage_generation,p.owner_id,p.state,old.lease_expires_unix, \
                o.state,o.source_generation,o.source_route_epoch,o.refs_sha256,o.journal_sequence \
         FROM repositories p JOIN shard_nodes old ON old.node_id=$2 \
         JOIN shard_replication_operations o ON o.id=$3 AND o.repository_id=p.id \
         WHERE p.id=$1 FOR UPDATE OF p,o", &[&candidate.repo_id,&candidate.old_node,&candidate.operation_id],
    ).await?;
    let generation: i64 = row.get(0);
    let owner_id: Uuid = row.get(1);
    let repo_state: String = row.get(2);
    let lease_expiry: i64 = row.get(3);
    let op_state: String = row.get(4);
    let source_generation: i64 = row.get(5);
    let source_epoch: i64 = row.get(6);
    let digest: String = row.get(7);
    let sequence: i64 = row.get(8);
    ensure!(repo_state == "ready" && lease_expiry > 0 && lease_expiry < models::unix_now()
        && op_state == "verified" && source_generation == generation && source_epoch == route.route_epoch
        && digest == candidate.refs_sha256 && sequence == candidate.journal_sequence
        && generation == locked_generation,
        "takeover evidence or expired lease changed");
    let operation_status = tx.query_one(
        "SELECT COALESCE(MAX(sequence),0), COUNT(*) FILTER (WHERE outcome='unknown') FROM git_operations WHERE repository_id=$1",
        &[&candidate.repo_id],
    ).await?;
    let max: i64 = operation_status.get(0);
    let unknown: i64 = operation_status.get(1);
    ensure!(unknown == 0 && sequence >= max, "acknowledged or unresolved write is newer than verified replica");
    let target = tx.query_one("SELECT status,role,lease_expires_unix FROM shard_nodes WHERE node_id=$1 FOR UPDATE", &[&node_id]).await?;
    let status: String = target.get(0);
    let role: String = target.get(1);
    let target_lease: i64 = target.get(2);
    ensure!(status == "healthy" && role == "replica" && target_lease > models::unix_now(),
        "target node lost its healthy lease");
    let new_epoch = route.route_epoch + 1;
    let new_token = route.fencing_token.max(new_epoch) + 1;
    let new_generation = generation + 1;
    tx.execute("UPDATE shard_nodes SET role='fenced',status='fenced',fenced_epoch=GREATEST(fenced_epoch,$2),version=version+1 WHERE node_id=$1",
        &[&candidate.old_node,&new_epoch]).await?;
    tx.execute("UPDATE shard_nodes SET role='primary',lease_epoch=GREATEST(lease_epoch,$2),version=version+1 WHERE node_id=$1",
        &[&node_id,&new_epoch]).await?;
    tx.execute("UPDATE repositories SET storage_generation=$2 WHERE id=$1 AND storage_generation=$3",
        &[&candidate.repo_id,&new_generation,&generation]).await?;
    let moved = RepoShardRoute::row(&tx.query_one(&format!(
        "UPDATE repository_shard_routes SET primary_node_id=$2,route_epoch=$3,fencing_token=$4, \
            fenced_epoch=$5,required_generation=$6,required_op_sequence=GREATEST(required_op_sequence,$7), \
            explicit_override=true,read_replica_nodes='[]'::jsonb,replica_watermarks='{{}}'::jsonb, \
            version=version+1,updated_at=clock_timestamp() WHERE repository_id=$1 RETURNING {REPO_ROUTE_FIELDS}"),
        &[&candidate.repo_id,&node_id,&new_epoch,&new_token,&route.route_epoch,&new_generation,&sequence],
    ).await?);
    tx.execute("UPDATE shard_replication_operations SET state='completed',updated_at=clock_timestamp() WHERE id=$1 AND state='verified'",
        &[&candidate.operation_id]).await?;
    tx.execute(
        "INSERT INTO shard_failover_operations(id,tenant_id,repository_id,old_primary_node_id,new_primary_node_id, \
            old_route_epoch,new_route_epoch,fencing_token,storage_generation,state,reason,snapshot) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'promoted','local process fence and measured replica',$10)",
        &[&Uuid::new_v4(),&owner_id,&candidate.repo_id,&candidate.old_node,&node_id,&route.route_epoch,
          &new_epoch,&new_token,&new_generation,&serde_json::json!({"driver":"local_process_group_v1",
          "process":proof,"replication_operation_id":candidate.operation_id,
          "refs_sha256":candidate.refs_sha256,"journal_sequence":sequence})],
    ).await?;
    let marker = VolumeFenceMarker::from_route(&moved, new_generation,
        Some(candidate.old_node.clone()), models::unix_now());
    transitions::stage(&tx, state, &marker).await.map_err(|e| anyhow::anyhow!("{e:?}"))?;
    lease.ensure_active().map_err(|e| anyhow::anyhow!("{e:?}"))?;
    tx.commit().await?;
    Ok(true)
}

/// Each node heartbeats and scans for expired primaries. PostgreSQL transaction
/// locks elect one promoter; physical fencing and measured data remain mandatory.
pub async fn run(state: Arc<AppState>) {
    let Ok(Some(node_id)) = super::transport::node_id() else { return; };
    if std::env::var_os("ROOTYARD_LOCAL_FENCE_DIR").is_none() { return; }
    loop {
        if let Err(error) = heartbeat(&state, &node_id).await { eprintln!("rootyard: cluster heartbeat failed: {error:#}"); }
        match candidates(&state, &node_id).await {
            Ok(items) => for candidate in items {
                let attempt: anyhow::Result<bool> = async {
                    let mutation = locks::exclusive(&state, candidate.repo_id).await
                        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
                    verify_target(&state, &candidate, &mutation.lease).await?;
                    let proof = local_fence::fence_local_process(&candidate.old_node).await?;
                    mutation.ensure_active().map_err(|e| anyhow::anyhow!("{e:?}"))?;
                    let promoted = promote(&state, &node_id, &candidate, &proof, &mutation.lease).await?;
                    if promoted && let Err(error) = crate::storage::ref_admission::cleanup_fenced(
                        &state, candidate.repo_id).await {
                        eprintln!("rootyard: fenced writer cleanup for {} deferred: {error:#}", candidate.repo_id);
                    }
                    Ok(promoted)
                }.await;
                match attempt {
                    Ok(true) => if let Err(error) = transitions::reconcile_pending(&state).await {
                        eprintln!("rootyard: takeover of {} awaits marker reconciliation: {error:?}", candidate.repo_id);
                    },
                    Ok(false) => {},
                    Err(error) => eprintln!("rootyard: takeover of {} remains blocked: {error:#}", candidate.repo_id),
                }
            },
            Err(error) => eprintln!("rootyard: cluster controller scan failed: {error:#}"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}
