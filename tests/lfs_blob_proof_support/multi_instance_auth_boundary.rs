//! Post-auth `pending` isolation, multi-instance active lease, and atomic commit-auth E2E (`Refs #145`).

use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use base64::Engine as _;
use deadpool_postgres::Pool;
use reqwest::StatusCode;
use rootyard::{
    db,
    lfs::blob_proof_publication::{
        LfsBlobRuntimeGate, LfsRepoRealm, PgLfsBlobStore, operation_token_to_uuid, upload_attempt_advisory_keys,
    },
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

use super::{LoopbackS3, RunningProdLfsServer, TestActor, issue_actor};

pub struct MultiInstanceAuthInput<'a> {
    pub s3: &'a LoopbackS3,
    pub root_prefix: &'a str,
    pub pool: &'a Pool,
    pub db_url: &'a str,
    pub realm: &'a LfsRepoRealm,
    pub alice: &'a TestActor,
}

pub async fn exercise_post_auth_pending_multi_instance_active_lease_and_atomic_commit_auth(
    inp: MultiInstanceAuthInput<'_>,
) -> Result<()> {
    let MultiInstanceAuthInput { s3, root_prefix, pool, db_url, realm, alice } = inp;
    let gate = LfsBlobRuntimeGate::configured(s3.open_store(root_prefix)?);
    let pool_1 = db::pool(db_url)?;
    let srv1 = RunningProdLfsServer::start(gate.clone(), pool_1.clone(), db_url).await?;
    let pool_2 = db::pool(db_url)?;
    let srv2 = RunningProdLfsServer::start(gate.clone(), pool_2, db_url).await?;

    scenario_unauthorized_pending_isolation(&srv1, pool, realm, alice).await?;
    let lease = ActiveLeaseScenario { srv1, pool_1, srv2: &srv2, gate: &gate, db_url, realm, alice };
    scenario_multi_instance_active_lease(lease).await?;
    for token_revocation in [false, true] {
        let scn = RevocationScenario { srv: &srv2, pool, realm, alice, token_revocation };
        scenario_mid_upload_revocation(scn).await?;
    }
    Ok(())
}

async fn scenario_unauthorized_pending_isolation(
    srv: &RunningProdLfsServer,
    pool: &Pool,
    realm: &LfsRepoRealm,
    alice: &TestActor,
) -> Result<()> {
    let mallory = issue_actor(pool, &format!("mallory-{}", alice.username)).await?;
    let viewer = issue_actor(pool, &format!("viewer-{}", alice.username)).await?;
    srv.put_collaborator(alice, &realm.owner_username, &realm.repo_name, &viewer.username, "read").await?;

    let op_unauth = Uuid::new_v4();
    let attempt_unauth = Uuid::new_v4();
    let oid = "5a".repeat(32);
    let c = pool.get().await?;
    c.execute(
        "INSERT INTO lfs_blob_upload_operations(
            repository_id, operation_id, tenant_id, actor_id, oid_sha256, size_bytes, state, updated_at
         ) VALUES($1,$2,$3,$4,$5,$6,'pending', clock_timestamp() - make_interval(mins => 10))",
        &[&realm.repository_id, &op_unauth, &realm.owner_tenant_id, &alice.user_id, &oid, &64i64],
    )
    .await?;
    c.execute(
        "INSERT INTO lfs_blob_upload_attempts(
            attempt_id, tenant_id, repository_id, actor_id, oid_sha256, size_bytes, operation_id, state, updated_at, lease_until
         ) VALUES($1,$2,$3,$4,$5,$6,$7,'pending', clock_timestamp() - make_interval(mins => 10),
                   clock_timestamp() - make_interval(mins => 10))",
        &[&attempt_unauth, &realm.owner_tenant_id, &realm.repository_id, &alice.user_id, &oid, &64i64, &op_unauth],
    )
    .await?;

    let (fresh_repo_id, _) = srv.create_repo(alice, None, "unauth-no-realm", "sha1").await?;
    for actor in [&mallory, &viewer] {
        for (owner, repo) in
            [(realm.owner_username.as_str(), realm.repo_name.as_str()), (alice.username.as_str(), "unauth-no-realm")]
        {
            let st = attempt_batch_status(&srv.base_url, owner, repo, actor, "op-unauth-batch-01", &oid, 64).await?;
            ensure!(st == StatusCode::FORBIDDEN || st == StatusCode::NOT_FOUND, "batch status {st}");
            let st = attempt_put_status(&srv.base_url, owner, repo, actor, "op-unauth-put-01", &oid, 64).await?;
            ensure!(st == StatusCode::FORBIDDEN || st == StatusCode::NOT_FOUND, "put status {st}");
        }
    }
    ensure!(op_state(pool, realm.repository_id, op_unauth).await? == "pending");
    ensure!(attempt_state(pool, attempt_unauth).await? == "pending");
    let realm_count: i64 = pool
        .get()
        .await?
        .query_one("SELECT COUNT(*) FROM lfs_blob_repo_realms WHERE repository_id = $1", &[&fresh_repo_id])
        .await?
        .get(0);
    ensure!(realm_count == 0, "unauthorized requests must not create lfs_blob_repo_realms rows");

    upload_batch(&srv.base_url, realm, alice, "op-authorized-sweep-01", &"5b".repeat(32), 32).await?;
    ensure!(op_state(pool, realm.repository_id, op_unauth).await? == "aborted_failed");
    ensure!(attempt_state(pool, attempt_unauth).await? == "aborted_failed");
    Ok(())
}

struct ActiveLeaseScenario<'a> {
    srv1: RunningProdLfsServer,
    pool_1: Pool,
    srv2: &'a RunningProdLfsServer,
    gate: &'a LfsBlobRuntimeGate,
    db_url: &'a str,
    realm: &'a LfsRepoRealm,
    alice: &'a TestActor,
}

async fn scenario_multi_instance_active_lease(inp: ActiveLeaseScenario<'_>) -> Result<()> {
    let ActiveLeaseScenario { srv1, pool_1, srv2, gate, db_url, realm, alice } = inp;
    let crashed_conn = pool_1.get().await?;
    let op_inst1 = operation_token_to_uuid("op-inst1-crash-01")?;
    let attempt_inst1 = Uuid::new_v4();
    let payload1 = b"instance-one-crash-retry-payload-v1".to_vec();
    let payload1_len = payload1.len() as i64;
    let oid1 = hex::encode(Sha256::digest(&payload1));
    let (k1, k2) = upload_attempt_advisory_keys(attempt_inst1);
    let locked: bool = crashed_conn.query_one("SELECT pg_try_advisory_lock($1, $2)", &[&k1, &k2]).await?.get(0);
    ensure!(locked, "crashed instance must hold its attempt advisory lock");
    crashed_conn
        .execute(
            "INSERT INTO lfs_blob_upload_operations(
                repository_id, operation_id, tenant_id, actor_id, oid_sha256, size_bytes, state
             ) VALUES($1,$2,$3,$4,$5,$6,'pending')",
            &[&realm.repository_id, &op_inst1, &realm.owner_tenant_id, &alice.user_id, &oid1, &payload1_len],
        )
        .await?;
    crashed_conn
        .execute(
            "INSERT INTO lfs_blob_upload_attempts(
                attempt_id, tenant_id, repository_id, actor_id, oid_sha256, size_bytes, operation_id, state
             ) VALUES($1,$2,$3,$4,$5,$6,$7,'pending')",
            &[
                &attempt_inst1,
                &realm.owner_tenant_id,
                &realm.repository_id,
                &alice.user_id,
                &oid1,
                &payload1_len,
                &op_inst1,
            ],
        )
        .await?;

    let live_op_tok = "op-inst2-live-01";
    let op_inst2 = operation_token_to_uuid(live_op_tok)?;
    let payload2: Vec<u8> = (0..65_536u32).map(|i| ((i.wrapping_mul(41) ^ 0x3c) & 0xff) as u8).collect();
    let oid2 = hex::encode(Sha256::digest(&payload2));
    let live_stream = start_streaming_upload(&srv2.base_url, realm, alice, live_op_tok, &oid2, &payload2).await?;
    let (attempt_inst2, live_op) = wait_pending_attempt(&pool_1, realm.repository_id, &oid2).await?;
    ensure!(live_op == Some(op_inst2), "live instance #2 operation_id mismatch");
    {
        let mut check = pool_1.get().await?;
        let tx = check.transaction().await?;
        let (ak1, ak2) = upload_attempt_advisory_keys(attempt_inst2);
        let free: bool = tx.query_one("SELECT pg_try_advisory_xact_lock($1, $2)", &[&ak1, &ak2]).await?.get(0);
        tx.rollback().await?;
        ensure!(!free, "live instance #2 upload must hold its session advisory lock");
    }

    drop(crashed_conn);
    pool_1.close();
    drop(pool_1);
    drop(srv1);
    let pool_1b = db::pool(db_url)?;
    let mut reclaimed = false;
    for _ in 0..50 {
        let mut probe = pool_1b.get().await?;
        let tx = probe.transaction().await?;
        let free: bool = tx.query_one("SELECT pg_try_advisory_xact_lock($1, $2)", &[&k1, &k2]).await?.get(0);
        tx.rollback().await?;
        if free {
            reclaimed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    ensure!(reclaimed, "crashed instance session advisory lock was never released");
    let srv1_restarted = RunningProdLfsServer::start(gate.clone(), pool_1b.clone(), db_url).await?;
    let pg_1b = PgLfsBlobStore::new(pool_1b.clone());
    let rep = pg_1b.reconcile_in_flight_uploads(realm.repository_id).await?;
    let sweep_oid = "6c".repeat(32);
    upload_batch(&srv1_restarted.base_url, realm, alice, "op-post-restart-sweep-01", &sweep_oid, 32).await?;
    ensure!(
        rep.aborted_orphaned_attempts >= 1 && rep.aborted_orphaned_operations >= 1,
        "restart reconciler must reclaim the crashed instance rows: {rep:?}"
    );
    ensure!(attempt_state(&pool_1b, attempt_inst1).await? == "aborted_failed");
    ensure!(op_state(&pool_1b, realm.repository_id, op_inst1).await? == "aborted_failed");
    ensure!(attempt_state(&pool_1b, attempt_inst2).await? == "pending");
    ensure!(op_state(&pool_1b, realm.repository_id, op_inst2).await? == "pending");

    let live_status = finish_streaming_upload(live_stream, &payload2).await?;
    ensure!(live_status == StatusCode::OK, "live instance #2 PUT failed: {live_status}");
    ensure!(attempt_state(&pool_1b, attempt_inst2).await? == "committed");
    ensure!(op_state(&pool_1b, realm.repository_id, op_inst2).await? == "committed");
    let committed_blobs = count_rows(
        &pool_1b,
        "SELECT COUNT(*) FROM lfs_blob_objects WHERE repository_id=$1 AND oid_sha256=$2",
        realm.repository_id,
        &oid2,
    )
    .await?;
    ensure!(committed_blobs == 1);
    let committed_objects = count_rows(
        &pool_1b,
        "SELECT COUNT(*) FROM lfs_objects WHERE repository_id=$1 AND oid=$2 AND state='ready'",
        realm.repository_id,
        &oid2,
    )
    .await?;
    ensure!(committed_objects == 1);

    let got = reqwest::Client::new()
        .get(format!(
            "{}/{}/{}/info/lfs/objects/{oid2}/{}",
            srv1_restarted.base_url,
            realm.owner_username,
            realm.repo_name,
            payload2.len()
        ))
        .basic_auth(&alice.username, Some(&alice.token))
        .send()
        .await?;
    ensure!(got.status() == StatusCode::OK, "download after restart failed: {}", got.status());
    ensure!(got.bytes().await?.as_ref() == payload2.as_slice());

    let retried = reqwest::Client::new()
        .put(format!(
            "{}/{}/{}/info/lfs/objects/{oid1}/{}",
            srv1_restarted.base_url,
            realm.owner_username,
            realm.repo_name,
            payload1.len()
        ))
        .basic_auth(&alice.username, Some(&alice.token))
        .header("X-Rootyard-Operation-Id", "op-inst1-crash-01")
        .body(payload1)
        .send()
        .await?;
    ensure!(retried.status() == StatusCode::OK, "crashed operation retry failed: {}", retried.status());
    ensure!(op_state(&pool_1b, realm.repository_id, op_inst1).await? == "committed");
    Ok(())
}

struct RevocationScenario<'a> {
    srv: &'a RunningProdLfsServer,
    pool: &'a Pool,
    realm: &'a LfsRepoRealm,
    alice: &'a TestActor,
    token_revocation: bool,
}

async fn scenario_mid_upload_revocation(inp: RevocationScenario<'_>) -> Result<()> {
    let RevocationScenario { srv, pool, realm, alice, token_revocation } = inp;
    let (collab, expected) = if token_revocation {
        (issue_actor(pool, &format!("tok-rev-{}", realm.owner_username)).await?, StatusCode::UNAUTHORIZED)
    } else {
        (issue_actor(pool, &format!("collab-rev-{}", realm.owner_username)).await?, StatusCode::FORBIDDEN)
    };
    srv.put_collaborator(alice, &realm.owner_username, &realm.repo_name, &collab.username, "write").await?;
    let seed = if token_revocation { 29 } else { 23 };
    let payload: Vec<u8> = (0..32_768u32).map(|i| ((i.wrapping_mul(seed) ^ 0x71) & 0xff) as u8).collect();
    let oid = hex::encode(Sha256::digest(&payload));
    let op_tok = if token_revocation { "op-token-revoked-mid" } else { "op-collab-revoked-mid" };
    let live_stream = start_streaming_upload(&srv.base_url, realm, &collab, op_tok, &oid, &payload).await?;
    wait_pending_attempt(pool, realm.repository_id, &oid).await?;
    if token_revocation {
        pool.get().await?.execute("UPDATE tokens SET revoked = TRUE WHERE id = $1", &[&collab.token_id]).await?;
    } else {
        pool.get()
            .await?
            .execute(
                "DELETE FROM repository_collaborators WHERE repository_id = $1 AND user_id = $2",
                &[&realm.repository_id, &collab.user_id],
            )
            .await?;
    }
    let status = finish_streaming_upload(live_stream, &payload).await?;
    ensure!(status == expected, "expected {expected}, got {status}");
    let blobs = count_rows(
        pool,
        "SELECT COUNT(*) FROM lfs_blob_objects WHERE repository_id=$1 AND oid_sha256=$2",
        realm.repository_id,
        &oid,
    )
    .await?;
    ensure!(blobs == 0, "single commit boundary must not publish lfs_blob_objects");
    let objects = count_rows(
        pool,
        "SELECT COUNT(*) FROM lfs_objects WHERE repository_id=$1 AND oid=$2",
        realm.repository_id,
        &oid,
    )
    .await?;
    ensure!(objects == 0, "single commit boundary must not publish lfs_objects");
    let pending_attempts = count_rows(
        pool,
        "SELECT COUNT(*) FROM lfs_blob_upload_attempts WHERE repository_id=$1 AND oid_sha256=$2 AND state='pending'",
        realm.repository_id,
        &oid,
    )
    .await?;
    ensure!(pending_attempts == 0);
    let pending_ops = count_rows(
        pool,
        "SELECT COUNT(*) FROM lfs_blob_upload_operations WHERE repository_id=$1 AND oid_sha256=$2 AND state='pending'",
        realm.repository_id,
        &oid,
    )
    .await?;
    ensure!(pending_ops == 0);
    Ok(())
}

async fn start_streaming_upload(
    base_url: &str,
    realm: &LfsRepoRealm,
    actor: &TestActor,
    op_tok: &str,
    oid: &str,
    payload: &[u8],
) -> Result<tokio::net::TcpStream> {
    let host_port = base_url.strip_prefix("http://").context("http base url")?;
    let mut stream = tokio::net::TcpStream::connect(host_port).await?;
    let auth = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", actor.username, actor.token));
    let len = payload.len();
    let head = format!(
        "PUT /{}/{}/info/lfs/objects/{oid}/{len} HTTP/1.1\r\nHost: {host_port}\r\nAuthorization: Basic {auth}\r\nX-Rootyard-Operation-Id: {op_tok}\r\nContent-Type: application/octet-stream\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n",
        realm.owner_username, realm.repo_name
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&payload[..payload.len().min(8_192)]).await?;
    stream.flush().await?;
    Ok(stream)
}

async fn finish_streaming_upload(mut stream: tokio::net::TcpStream, payload: &[u8]) -> Result<StatusCode> {
    if payload.len() > 8_192 {
        stream.write_all(&payload[8_192..]).await?;
    }
    stream.flush().await?;
    stream.shutdown().await?;
    let mut head = Vec::new();
    let mut buf = [0u8; 4096];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        head.extend_from_slice(&buf[..n]);
    }
    let text = String::from_utf8_lossy(&head);
    let code = text.split_whitespace().nth(1).context("HTTP status line")?.parse::<u16>()?;
    Ok(StatusCode::from_u16(code)?)
}

async fn attempt_batch_status(
    base_url: &str,
    owner: &str,
    repo: &str,
    actor: &TestActor,
    op_tok: &str,
    oid: &str,
    size: i64,
) -> Result<StatusCode> {
    Ok(reqwest::Client::new()
        .post(format!("{base_url}/{owner}/{repo}/info/lfs/objects/batch"))
        .basic_auth(&actor.username, Some(&actor.token))
        .header("Accept", "application/vnd.git-lfs+json")
        .header("Content-Type", "application/vnd.git-lfs+json")
        .header("X-Rootyard-Operation-Id", op_tok)
        .json(&json!({ "operation": "upload", "objects": [{ "oid": oid, "size": size }] }))
        .send()
        .await?
        .status())
}

async fn attempt_put_status(
    base_url: &str,
    owner: &str,
    repo: &str,
    actor: &TestActor,
    op_tok: &str,
    oid: &str,
    size: i64,
) -> Result<StatusCode> {
    Ok(reqwest::Client::new()
        .put(format!("{base_url}/{owner}/{repo}/info/lfs/objects/{oid}/{size}"))
        .basic_auth(&actor.username, Some(&actor.token))
        .header("X-Rootyard-Operation-Id", op_tok)
        .body(vec![0u8; size as usize])
        .send()
        .await?
        .status())
}

async fn upload_batch(
    base_url: &str,
    realm: &LfsRepoRealm,
    actor: &TestActor,
    op_tok: &str,
    oid: &str,
    size: i64,
) -> Result<Value> {
    let res = reqwest::Client::new()
        .post(format!("{}/{}/{}/info/lfs/objects/batch", base_url, realm.owner_username, realm.repo_name))
        .basic_auth(&actor.username, Some(&actor.token))
        .header("Accept", "application/vnd.git-lfs+json")
        .header("Content-Type", "application/vnd.git-lfs+json")
        .header("X-Rootyard-Operation-Id", op_tok)
        .json(&json!({ "operation": "upload", "objects": [{ "oid": oid, "size": size }] }))
        .send()
        .await?;
    ensure!(res.status().is_success(), "batch failed: {}", res.status());
    Ok(res.json().await?)
}

async fn wait_pending_attempt(pool: &Pool, repository_id: Uuid, oid: &str) -> Result<(Uuid, Option<Uuid>)> {
    for _ in 0..50 {
        let row = pool
            .get()
            .await?
            .query_opt(
                "SELECT attempt_id, operation_id FROM lfs_blob_upload_attempts
                 WHERE repository_id=$1 AND oid_sha256=$2 AND state='pending'
                 ORDER BY created_at DESC LIMIT 1",
                &[&repository_id, &oid],
            )
            .await?;
        if let Some(r) = row {
            return Ok((r.get(0), r.get(1)));
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    bail!("no pending upload attempt appeared for oid {oid}")
}

async fn attempt_state(pool: &Pool, attempt_id: Uuid) -> Result<String> {
    Ok(pool
        .get()
        .await?
        .query_one("SELECT state FROM lfs_blob_upload_attempts WHERE attempt_id=$1", &[&attempt_id])
        .await?
        .get(0))
}

async fn op_state(pool: &Pool, repository_id: Uuid, operation_id: Uuid) -> Result<String> {
    Ok(pool
        .get()
        .await?
        .query_one(
            "SELECT state FROM lfs_blob_upload_operations WHERE repository_id=$1 AND operation_id=$2",
            &[&repository_id, &operation_id],
        )
        .await?
        .get(0))
}

async fn count_rows(pool: &Pool, sql: &str, repository_id: Uuid, oid: &str) -> Result<i64> {
    Ok(pool.get().await?.query_one(sql, &[&repository_id, &oid]).await?.get(0))
}
