//! Direct-store late commits after lease expiry/reconciler revocation and HTTP late completion.

use std::time::Duration;

use anyhow::{Context, Result, ensure};
use deadpool_postgres::Pool;
use reqwest::StatusCode;
use rootyard::lfs::blob_proof_publication::{LfsBlobRuntimeGate, LfsRepoRealm, PgLfsBlobStore};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::super::{RunningProdLfsServer, TestActor};
use super::harness::{
    AttemptRowSpec, StreamSpec, assert_no_object_rows, attempt_state, expect_equivocation, finish_stream,
    insert_attempt, op_state, open_upload_stream, upload_hold_candidate, wait_pending_attempt,
};

pub(super) async fn scenario_late_commit(
    pg: &PgLfsBlobStore,
    pool: &Pool,
    gate: &LfsBlobRuntimeGate,
    realm: &LfsRepoRealm,
    alice: &TestActor,
) -> Result<()> {
    let payload: Vec<u8> = (0..16_384u32).map(|i| ((i.wrapping_mul(7) ^ 0x3f) & 0xff) as u8).collect();
    let oid = hex::encode(Sha256::digest(&payload));
    let size = payload.len() as i64;
    let candidate = upload_hold_candidate(pg, gate, realm, alice.user_id, &oid, &payload).await?;
    let op_id = Uuid::new_v4();
    let attempt_id = Uuid::new_v4();
    pg.begin_or_load_upload_operation(realm.repository_id, op_id, realm.owner_tenant_id, alice.user_id, &oid, size)
        .await?;
    insert_attempt(
        pg,
        realm,
        alice.user_id,
        &oid,
        size,
        AttemptRowSpec { attempt_id, op_id: Some(op_id), live: false },
    )
    .await?;

    // Case 1A: the lease is already expired while both rows still read `pending`.
    expect_equivocation(pg.record_committed_blob_with_auth(attempt_id, Some(op_id), &candidate, None, None).await)?;
    ensure!(attempt_state(pool, attempt_id).await? != "committed");
    ensure!(op_state(pool, realm.repository_id, op_id).await? != "committed");
    assert_no_object_rows(pool, realm, &oid).await?;

    // Case 1B: the reconciler reclaims both rows, and a late commit can never resurrect them.
    pg.reconcile_stale_pending_uploads(realm.repository_id, Duration::from_secs(20)).await?;
    ensure!(attempt_state(pool, attempt_id).await? == "aborted_failed");
    ensure!(op_state(pool, realm.repository_id, op_id).await? == "aborted_failed");
    expect_equivocation(pg.record_committed_blob_with_auth(attempt_id, Some(op_id), &candidate, None, None).await)?;
    ensure!(attempt_state(pool, attempt_id).await? == "aborted_failed");
    ensure!(op_state(pool, realm.repository_id, op_id).await? == "aborted_failed");
    let attempt_live = Uuid::new_v4();
    insert_attempt(
        pg,
        realm,
        alice.user_id,
        &oid,
        size,
        AttemptRowSpec { attempt_id: attempt_live, op_id: None, live: true },
    )
    .await?;
    expect_equivocation(pg.record_committed_blob_with_auth(attempt_live, Some(op_id), &candidate, None, None).await)?;
    ensure!(op_state(pool, realm.repository_id, op_id).await? == "aborted_failed");
    assert_no_object_rows(pool, realm, &oid).await
}

pub(super) async fn scenario_http_late_completion(
    srv: &RunningProdLfsServer,
    pg: &PgLfsBlobStore,
    pool: &Pool,
    realm: &LfsRepoRealm,
    alice: &TestActor,
) -> Result<()> {
    let payload: Vec<u8> = (0..24_576u32).map(|i| ((i.wrapping_mul(11) ^ 0x55) & 0xff) as u8).collect();
    let oid = hex::encode(Sha256::digest(&payload));
    let spec = StreamSpec { op_tok: Some("op-late-http-lease-01"), oid: &oid, first: &payload, sized: true };
    let stream = open_upload_stream(&srv.base_url, realm, alice, spec).await?;
    let (attempt, op) = wait_pending_attempt(pool, realm.repository_id, &oid).await?;
    let op = op.context("late HTTP attempt must bind its operation")?;
    pg.pool()
        .get()
        .await?
        .execute(
            "UPDATE lfs_blob_upload_attempts
             SET lease_until = clock_timestamp() - make_interval(secs => 10)
             WHERE attempt_id = $1",
            &[&attempt],
        )
        .await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let expired: bool = pg
        .pool()
        .get()
        .await?
        .query_one(
            "SELECT lease_until <= clock_timestamp() FROM lfs_blob_upload_attempts WHERE attempt_id = $1",
            &[&attempt],
        )
        .await?
        .get(0);
    ensure!(expired, "heartbeat must never resurrect an expired upload lease");
    pg.reconcile_stale_pending_uploads(realm.repository_id, Duration::from_secs(20)).await?;
    ensure!(attempt_state(pool, attempt).await? == "aborted_failed");
    ensure!(op_state(pool, realm.repository_id, op).await? == "aborted_failed");
    let status = finish_stream(stream, true, &payload).await?;
    ensure!(status == StatusCode::CONFLICT, "late HTTP completion expected 409, got {status}");
    ensure!(attempt_state(pool, attempt).await? == "aborted_failed");
    ensure!(op_state(pool, realm.repository_id, op).await? == "aborted_failed");
    assert_no_object_rows(pool, realm, &oid).await
}
