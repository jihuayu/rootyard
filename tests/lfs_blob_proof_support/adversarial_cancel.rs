//! Production mid-stream TCP cancellation + automatic stale-`pending` reconciler E2E (`Refs #145`).

use std::time::Duration;

use anyhow::{Context, Result, ensure};
use base64::Engine as _;
use reqwest::StatusCode;
use rootyard::lfs::blob_proof_publication::{LfsRepoRealm, PgLfsBlobStore, operation_token_to_uuid};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use super::{RunningProdLfsServer, TestActor};

pub struct UploadCancelReconcileInput<'a> {
    pub srv: &'a RunningProdLfsServer,
    pub pool: &'a deadpool_postgres::Pool,
    pub pg: &'a PgLfsBlobStore,
    pub realm: &'a LfsRepoRealm,
    pub alice: &'a TestActor,
}

pub async fn exercise_production_upload_cancellation_and_stale_reconciler(
    inp: UploadCancelReconcileInput<'_>,
) -> Result<()> {
    let UploadCancelReconcileInput { srv, pool, pg, realm, alice } = inp;
    mid_stream_tcp_cancel(srv, pg, realm, alice).await?;
    stale_pending_auto_sweep(srv, pool, pg, realm, alice).await
}

async fn mid_stream_tcp_cancel(
    srv: &RunningProdLfsServer,
    pg: &PgLfsBlobStore,
    realm: &LfsRepoRealm,
    alice: &TestActor,
) -> Result<()> {
    let payload: Vec<u8> = (0..131_072u32).map(|i| ((i.wrapping_mul(37) ^ 0x9d) & 0xff) as u8).collect();
    let oid = hex::encode(Sha256::digest(&payload));
    let sz = payload.len() as i64;
    let op_tok = "op-midstream-tcp-cancel-01";
    let op_uuid = operation_token_to_uuid(op_tok)?;
    let batch = upload_batch(srv, realm, alice, op_tok, &oid, sz).await?;
    ensure!(batch["objects"][0]["actions"]["upload"].is_object(), "batch upload action: {batch}");
    ensure!(pg.load_upload_operation(realm.repository_id, op_uuid).await?.context("pending op")?.state == "pending");

    let host_port = srv.base_url.strip_prefix("http://").context("http base url")?;
    let mut stream = tokio::net::TcpStream::connect(host_port).await?;
    let auth = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", alice.username, alice.token));
    let head = format!(
        "PUT /{}/{}/info/lfs/objects/{oid}/{sz} HTTP/1.1\r\nHost: {host_port}\r\nAuthorization: Basic {auth}\r\nX-Rootyard-Operation-Id: {op_tok}\r\nContent-Type: application/octet-stream\r\nContent-Length: {sz}\r\nConnection: close\r\n\r\n",
        realm.owner_username, realm.repo_name
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&payload[..8_192]).await?;
    stream.flush().await?;
    tokio::time::sleep(Duration::from_millis(120)).await;
    drop(stream);

    let mut cancelled = false;
    for _ in 0..60 {
        let row = pg.load_upload_operation(realm.repository_id, op_uuid).await?;
        if row.is_some_and(|r| r.state == "aborted_cancelled") {
            cancelled = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    ensure!(cancelled, "InFlightUploadGuard must transition pending -> aborted_cancelled on abrupt TCP drop");
    ensure!(verify_request(srv, realm, alice, op_tok, &oid, sz).await? == StatusCode::CONFLICT);
    let retried = reqwest::Client::new()
        .put(format!("{}/{}/{}/info/lfs/objects/{oid}/{sz}", srv.base_url, realm.owner_username, realm.repo_name))
        .basic_auth(&alice.username, Some(&alice.token))
        .header("X-Rootyard-Operation-Id", op_tok)
        .body(payload)
        .send()
        .await?;
    ensure!(retried.status() == StatusCode::OK, "retried PUT failed: {}", retried.status());
    let row = pg.load_upload_operation(realm.repository_id, op_uuid).await?.context("retried op")?;
    ensure!(row.state == "committed" && row.locator.is_some(), "retried op not committed: {row:?}");
    ensure!(verify_request(srv, realm, alice, op_tok, &oid, sz).await? == StatusCode::OK);
    Ok(())
}

async fn stale_pending_auto_sweep(
    srv: &RunningProdLfsServer,
    pool: &deadpool_postgres::Pool,
    pg: &PgLfsBlobStore,
    realm: &LfsRepoRealm,
    alice: &TestActor,
) -> Result<()> {
    let payload: Vec<u8> = (0..32_768u32).map(|i| ((i.wrapping_mul(19) ^ 0x21) & 0xff) as u8).collect();
    let oid = hex::encode(Sha256::digest(&payload));
    let sz = payload.len() as i64;
    let stale_tok = "op-stale-pending-auto-sweep-01";
    let stale_uuid = operation_token_to_uuid(stale_tok)?;
    pg.begin_or_load_upload_operation(realm.repository_id, stale_uuid, realm.owner_tenant_id, alice.user_id, &oid, sz)
        .await?;
    let attempt_id = Uuid::new_v4();
    pg.record_upload_attempt_start(attempt_id, realm.owner_tenant_id, realm.repository_id, alice.user_id, &oid, sz)
        .await?;
    let client = pool.get().await?;
    client
        .execute(
            "UPDATE lfs_blob_upload_operations SET updated_at = clock_timestamp() - make_interval(mins => 10)
             WHERE repository_id = $1 AND operation_id = $2",
            &[&realm.repository_id, &stale_uuid],
        )
        .await?;
    client
        .execute(
            "UPDATE lfs_blob_upload_attempts SET updated_at = clock_timestamp() - make_interval(mins => 10)
             WHERE repository_id = $1 AND state = 'pending'",
            &[&realm.repository_id],
        )
        .await?;
    drop(client);

    let unrelated_oid = "7f".repeat(32);
    let batch = upload_batch(srv, realm, alice, "op-unrelated-prod-batch-01", &unrelated_oid, 64).await?;
    ensure!(batch["objects"][0].get("actions").is_some(), "unrelated batch: {batch}");
    let swept = pg.load_upload_operation(realm.repository_id, stale_uuid).await?.context("swept op")?;
    ensure!(swept.state == "aborted_failed", "production write path must sweep stale pending: {swept:?}");
    let retried = reqwest::Client::new()
        .put(format!("{}/{}/{}/info/lfs/objects/{oid}/{sz}", srv.base_url, realm.owner_username, realm.repo_name))
        .basic_auth(&alice.username, Some(&alice.token))
        .header("X-Rootyard-Operation-Id", stale_tok)
        .body(payload)
        .send()
        .await?;
    ensure!(retried.status() == StatusCode::OK, "stale retried PUT failed: {}", retried.status());
    let row = pg.load_upload_operation(realm.repository_id, stale_uuid).await?.context("stale retried op")?;
    ensure!(row.state == "committed", "stale retried op not committed: {row:?}");
    Ok(())
}

async fn upload_batch(
    srv: &RunningProdLfsServer,
    realm: &LfsRepoRealm,
    alice: &TestActor,
    op_tok: &str,
    oid: &str,
    size: i64,
) -> Result<Value> {
    let res = reqwest::Client::new()
        .post(format!("{}/{}/{}.git/info/lfs/objects/batch", srv.base_url, realm.owner_username, realm.repo_name))
        .basic_auth(&alice.username, Some(&alice.token))
        .header("Accept", "application/vnd.git-lfs+json")
        .header("Content-Type", "application/vnd.git-lfs+json")
        .header("X-Rootyard-Operation-Id", op_tok)
        .json(&json!({ "operation": "upload", "objects": [{ "oid": oid, "size": size }] }))
        .send()
        .await?;
    ensure!(res.status().is_success(), "batch failed: {}", res.status());
    Ok(res.json().await?)
}

async fn verify_request(
    srv: &RunningProdLfsServer,
    realm: &LfsRepoRealm,
    alice: &TestActor,
    op_tok: &str,
    oid: &str,
    size: i64,
) -> Result<StatusCode> {
    Ok(reqwest::Client::new()
        .post(format!("{}/{}/{}/info/lfs/verify", srv.base_url, realm.owner_username, realm.repo_name))
        .basic_auth(&alice.username, Some(&alice.token))
        .header("Accept", "application/vnd.git-lfs+json")
        .header("Content-Type", "application/vnd.git-lfs+json")
        .header("X-Rootyard-Operation-Id", op_tok)
        .json(&json!({ "oid": oid, "size": size }))
        .send()
        .await?
        .status())
}
