//! Positive durable terminal-abort proof and strict pre-replay / replay zero-write gates (#183).
//!
//! Proves two surgical merge gates on real PostgreSQL 17 + `LoopbackS3` + stock Git:
//! 1. a missing or still-`pending` `ref_store_operations` row NEVER qualifies as deletable, while a
//!    durable `cancelled`/`rejected` terminal (or a durable `ref_store_cancellations` tombstone) with
//!    zero live references does;
//! 2. an HTTP `Claim::Replay` performs zero reclaim-ledger writes, zero PostgreSQL writes and zero S3
//!    mutations even while remote S3 reclaim is ARMED and a cancelled recoverable canary is staged.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, ensure};
use axum::http::StatusCode;
use deadpool_postgres::Pool;
use rootyard::blob_store::BlobLocator;
use rootyard::namespace_service::push_causal_stream::*;
use rootyard::ref_store::{IssuerLane, OperationIdentity, PgRefStore, RequestDigest};
use sha2::{Digest, Sha256};
use tokio::time::Instant as TokioInstant;
use uuid::Uuid;

use super::pg_http_gateway::git_http;
use super::pg_restart_and_reclaim::post_receive;
use super::support::{LoopbackS3, mk_commit};

/// Live PG17 + `LoopbackS3` + armed-reclaim gateway context shared by both acceptance helpers.
pub struct ReclaimGateCtx<'a> {
    pub pool: &'a Pool,
    pub s3: &'a LoopbackS3,
    pub backend_hex: &'a str,
    pub scratch_root: &'a Path,
    pub work: &'a Path,
    pub url: &'a str,
    pub auth_hdr: &'a str,
    pub repo_id: Uuid,
    pub actor_id: Uuid,
}

/// Exact row counts of the six PostgreSQL ledgers the zero-write replay contract covers.
#[derive(Debug, Eq, PartialEq)]
struct GatewayRowCounts {
    operations: i64,
    cancellations: i64,
    decisions: i64,
    events: i64,
    holds: i64,
    memberships: i64,
}

fn pg_deadline() -> TokioInstant {
    TokioInstant::now() + Duration::from_secs(30)
}

fn dbg_err<E: std::fmt::Debug>(error: E) -> anyhow::Error {
    anyhow!("{error:?}")
}

fn ledger_file_names(dir: &Path) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        names.push(entry?.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    Ok(names)
}

async fn gateway_row_counts(pool: &Pool, repository_id: Uuid) -> Result<GatewayRowCounts> {
    let client = pool.get().await?;
    let sql = "SELECT (SELECT COUNT(*) FROM ref_store_operations WHERE repository_id = $1), (SELECT COUNT(*) FROM ref_store_cancellations WHERE repository_id = $1), (SELECT COUNT(*) FROM ref_store_publication_decisions WHERE repository_id = $1), (SELECT COUNT(*) FROM ref_store_core_events WHERE repository_id = $1), (SELECT COUNT(*) FROM artifact_holds WHERE repository_id = $1), (SELECT COUNT(*) FROM ref_store_core_pack_memberships WHERE repository_id = $1)";
    let row = client.query_one(sql, &[&repository_id]).await?;
    Ok(GatewayRowCounts {
        operations: row.get(0),
        cancellations: row.get(1),
        decisions: row.get(2),
        events: row.get(3),
        holds: row.get(4),
        memberships: row.get(5),
    })
}

/// Stage one real object into the loopback S3 map and return `(path, sha256, length, key)`.
fn stage_object(ctx: &ReclaimGateCtx<'_>, payload: &[u8]) -> Result<(String, String, u64, String)> {
    let sha256 = hex::encode(Sha256::digest(payload));
    let length = payload.len() as u64;
    let locator = BlobLocator::new(ctx.repo_id, ctx.repo_id, 1, Uuid::new_v4(), "git-pack", &sha256, length)?;
    let key = LoopbackS3::key(&locator);
    ctx.s3.objects.lock().unwrap().insert(key.clone(), payload.to_vec());
    Ok((locator.path(), sha256, length, key))
}

async fn begin_pending_operation(
    ctx: &ReclaimGateCtx<'_>,
    operation_id: Uuid,
    lane_name: &str,
) -> Result<OperationIdentity> {
    let dl = pg_deadline();
    let lane = IssuerLane::new(lane_name)?;
    let digest = RequestDigest::of(lane_name, &[operation_id.as_bytes()]);
    let mut client = ctx.pool.get().await?;
    let tx = client.transaction().await?;
    let reserved = PgRefStore.reserve_sequence(&tx, ctx.repo_id, ctx.actor_id, operation_id, &lane, dl);
    let sequence = reserved.await?.sequence();
    let identity = OperationIdentity::new(ctx.repo_id, ctx.actor_id, lane, sequence, operation_id, digest)?;
    PgRefStore.begin(&tx, &identity, dl).await?;
    tx.commit().await?;
    Ok(identity)
}

async fn cancel_pending_operation(ctx: &ReclaimGateCtx<'_>, identity: &OperationIdentity) -> Result<()> {
    let dl = pg_deadline();
    let mut client = ctx.pool.get().await?;
    let tx = client.transaction().await?;
    PgRefStore.cancel(&tx, identity, dl).await?;
    tx.commit().await?;
    Ok(())
}

async fn cancel_canary_operation(ctx: &ReclaimGateCtx<'_>, operation_id: Uuid, lane_name: &str) -> Result<()> {
    let identity = begin_pending_operation(ctx, operation_id, lane_name).await?;
    cancel_pending_operation(ctx, &identity).await
}

/// A cancelled recoverable canary with staged S3 blobs must survive a byte-identical HTTP
/// `Claim::Replay` (zero ledger / SQL / S3 writes) and be swept only by the next `Claim::Fresh`.
pub async fn verify_http_replay_strict_zero_write(
    ctx: &ReclaimGateCtx<'_>,
    op2: Uuid,
    wire2: &[u8],
    expected_body: &[u8],
    rec2_before: &CausalPushProofReceipt,
) -> Result<()> {
    let (repo_id, backend) = (ctx.repo_id, ctx.backend_hex);
    let op_canary = Uuid::new_v4();
    cancel_canary_operation(ctx, op_canary, "gateway-replay-canary").await?;
    let (pack_path, pack_sha256, pack_bytes, pack_key) = stage_object(ctx, b"canary-pack-bytes\n")?;
    let (idx_path, idx_sha256, idx_bytes, idx_key) = stage_object(ctx, b"canary-idx-bytes\n")?;
    let ledger = open_gateway_reclaim_ledger(ctx.scratch_root).map_err(dbg_err)?;
    let pair = StagedPairDigest { pack_sha256, pack_bytes, idx_sha256, idx_bytes };
    ledger.record_inflight_multi(op_canary, repo_id, repo_id, 1, backend, &[pair]).map_err(dbg_err)?;
    let paths = vec![pack_path, idx_path];
    let state = UploadReclaimState::PartialFailed;
    let detail = "cancelled recoverable canary for the replay zero-write gate";
    ledger.transition(op_canary, state, paths, 0, detail).map_err(dbg_err)?;

    let ledger_dir = gateway_reclaim_ledger_dir_for_scratch(ctx.scratch_root);
    let canary_file = ledger_dir.join(format!("reclaim-{op_canary}.json"));
    let bytes_before = std::fs::read(&canary_file).context("canary reclaim record is missing")?;
    let mtime_before = std::fs::metadata(&canary_file)?.modified()?;
    let listing_before = ledger_file_names(&ledger_dir)?;
    let rows_before = gateway_row_counts(ctx.pool, repo_id).await?;
    let objects_before = ctx.s3.objects.lock().unwrap().clone();

    let (status, body) = post_receive(ctx.url, ctx.auth_hdr, op2, wire2.to_vec()).await?;
    ensure!(status == StatusCode::OK && body == expected_body, "HTTP Claim::Replay wire mismatch");
    let replayed = recent_gateway_push_receipt(op2);
    ensure!(replayed.as_ref() == Some(rec2_before), "HTTP Claim::Replay receipt mismatch");

    ensure!(ctx.s3.objects.lock().unwrap().contains_key(&pack_key), "Claim::Replay deleted the canary pack");
    ensure!(ctx.s3.objects.lock().unwrap().contains_key(&idx_key), "Claim::Replay deleted the canary idx");
    ensure!(std::fs::read(&canary_file)? == bytes_before, "Claim::Replay mutated the reclaim record bytes");
    ensure!(std::fs::metadata(&canary_file)?.modified()? == mtime_before, "replay mutated the record mtime");
    ensure!(ledger_file_names(&ledger_dir)? == listing_before, "Claim::Replay created a reclaim ledger file");
    let op2_file = ledger_dir.join(format!("reclaim-{op2}.json"));
    ensure!(!op2_file.exists(), "Claim::Replay must not create a reclaim record for its own operation");
    ensure!(gateway_row_counts(ctx.pool, repo_id).await? == rows_before, "Claim::Replay performed a SQL write");
    let objects_after = ctx.s3.objects.lock().unwrap().clone();
    ensure!(objects_after == objects_before, "Claim::Replay performed an S3 PUT or DELETE");

    mk_commit(ctx.work, "reclaim-canary-sweep.txt", "reclaim-canary-sweep\n", "canary-sweep")?;
    git_http(ctx.work, &["push", "origin", "HEAD:refs/heads/canary-sweep"]).await?;
    ensure!(!ctx.s3.objects.lock().unwrap().contains_key(&pack_key), "fresh push must sweep the canary pack");
    ensure!(!ctx.s3.objects.lock().unwrap().contains_key(&idx_key), "fresh push must sweep the canary idx");
    let record = ledger.load(op_canary).map_err(dbg_err)?;
    let state = record.map(|r| r.state);
    ensure!(state == Some(UploadReclaimState::ReclaimedAfterAbort), "swept canary must be reclaimed");
    Ok(())
}

/// A missing operation row, then a `pending` one, must never delete staged objects even with zero
/// references; only a durable `cancelled` terminal releases the full `6/6` remote sweep.
pub async fn verify_missing_and_pending_op_rows_never_sweep_until_durably_aborted(
    ctx: &ReclaimGateCtx<'_>,
) -> Result<()> {
    let dl = pg_deadline();
    let (repo_id, backend) = (ctx.repo_id, ctx.backend_hex);
    let op_missing = Uuid::new_v4();
    let mut paths = Vec::new();
    let mut keys = Vec::new();
    let mut pairs = Vec::new();
    for slot in 0..3 {
        let pack_payload = format!("missing-row-pack-{slot}\n");
        let idx_payload = format!("missing-row-idx-{slot}\n");
        let (pack_path, pack_sha256, pack_bytes, pack_key) = stage_object(ctx, pack_payload.as_bytes())?;
        let (idx_path, idx_sha256, idx_bytes, idx_key) = stage_object(ctx, idx_payload.as_bytes())?;
        paths.push(pack_path);
        paths.push(idx_path);
        keys.push(pack_key);
        keys.push(idx_key);
        pairs.push(StagedPairDigest { pack_sha256, pack_bytes, idx_sha256, idx_bytes });
    }
    let ledger = open_gateway_reclaim_ledger(ctx.scratch_root).map_err(dbg_err)?;
    ledger.record_inflight_multi(op_missing, repo_id, repo_id, 1, backend, &pairs).map_err(dbg_err)?;
    let state = UploadReclaimState::PartialFailed;
    ledger.transition(op_missing, state, paths, 0, "missing/pending rows retain staging").map_err(dbg_err)?;

    let missing = is_operation_proven_aborted_and_unreferenced(ctx.pool, repo_id, op_missing, dl);
    ensure!(!missing.await.map_err(dbg_err)?, "a missing operation row must never be deletable");
    mk_commit(ctx.work, "missing-row-guard.txt", "missing-row-guard\n", "missing-row-guard")?;
    git_http(ctx.work, &["push", "origin", "HEAD:refs/heads/missing-row-guard"]).await?;
    let swept = sweep_gateway_reclaim_ledger(ctx.pool, ctx.scratch_root, backend, dl);
    ensure!(swept.await.map_err(dbg_err)? == 0, "a missing operation row must sweep 0 records");
    assert_staged_objects_present(ctx, &keys, "missing operation row")?;

    let identity = begin_pending_operation(ctx, op_missing, "missing-row-guard-lane").await?;
    let pending = is_operation_proven_aborted_and_unreferenced(ctx.pool, repo_id, op_missing, dl);
    ensure!(!pending.await.map_err(dbg_err)?, "a pending operation row must never be deletable");
    mk_commit(ctx.work, "pending-row-guard.txt", "pending-row-guard\n", "pending-row-guard")?;
    git_http(ctx.work, &["push", "origin", "HEAD:refs/heads/pending-row-guard"]).await?;
    assert_staged_objects_present(ctx, &keys, "pending operation row")?;

    cancel_pending_operation(ctx, &identity).await?;
    let aborted = is_operation_proven_aborted_and_unreferenced(ctx.pool, repo_id, op_missing, dl);
    let aborted = aborted.await.map_err(dbg_err)?;
    ensure!(aborted, "a durably cancelled row with 0 references must be deletable");
    mk_commit(ctx.work, "cancelled-row-sweep.txt", "cancelled-row-sweep\n", "cancelled-row-sweep")?;
    git_http(ctx.work, &["push", "origin", "HEAD:refs/heads/cancelled-row-sweep"]).await?;
    for key in &keys {
        ensure!(!ctx.s3.objects.lock().unwrap().contains_key(key), "cancelled row must sweep {key}");
    }
    let record = ledger.load(op_missing).map_err(dbg_err)?;
    let state = record.map(|r| r.state);
    ensure!(state == Some(UploadReclaimState::ReclaimedAfterAbort), "cancelled row must be reclaimed");
    Ok(())
}

fn assert_staged_objects_present(ctx: &ReclaimGateCtx<'_>, keys: &[String], stage: &str) -> Result<()> {
    for key in keys {
        ensure!(ctx.s3.objects.lock().unwrap().contains_key(key), "{stage} must retain {key}");
    }
    Ok(())
}
