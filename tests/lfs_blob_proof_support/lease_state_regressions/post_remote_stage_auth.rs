//! Post-remote-staging final commit-boundary authorization revocation E2E (`Refs #145`).

use std::time::Duration;

use anyhow::{Result, ensure};
use deadpool_postgres::Pool;
use reqwest::StatusCode;
use rootyard::lfs::blob_proof_publication::{
    LfsRepoRealm, derive_default_upload_operation_id, operation_token_to_uuid,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::super::{LoopbackS3, RunningProdLfsServer, TestActor, issue_actor};
use super::harness::{assert_no_object_rows, attempt_state, count_rows, op_state, wait_pending_attempt};

#[derive(Clone, Copy)]
enum PostStageRevoke {
    DemoteToRead,
    RemoveCollaborator,
    RevokeToken,
}

impl PostStageRevoke {
    const fn tag(self) -> &'static str {
        match self {
            Self::DemoteToRead => "demote-read",
            Self::RemoveCollaborator => "remove-collab",
            Self::RevokeToken => "revoke-token",
        }
    }

    const fn seed(self) -> u32 {
        match self {
            Self::DemoteToRead => 53,
            Self::RemoveCollaborator => 59,
            Self::RevokeToken => 61,
        }
    }

    const fn precreated(self) -> bool {
        !matches!(self, Self::RevokeToken)
    }

    const fn expected(self) -> (StatusCode, &'static str) {
        if self.precreated() {
            (StatusCode::FORBIDDEN, "unauthorized_collaborator")
        } else {
            (StatusCode::UNAUTHORIZED, "unauthenticated")
        }
    }
}

pub(super) async fn scenario_post_remote_stage_final_auth_revocation(
    s3: &LoopbackS3,
    srv: &RunningProdLfsServer,
    pool: &Pool,
    realm: &LfsRepoRealm,
    alice: &TestActor,
) -> Result<()> {
    for revoke in [PostStageRevoke::DemoteToRead, PostStageRevoke::RemoveCollaborator, PostStageRevoke::RevokeToken] {
        run_case(s3, srv, pool, realm, alice, revoke).await?;
    }
    Ok(())
}

async fn run_case(
    s3: &LoopbackS3,
    srv: &RunningProdLfsServer,
    pool: &Pool,
    realm: &LfsRepoRealm,
    alice: &TestActor,
    revoke: PostStageRevoke,
) -> Result<()> {
    let tag = revoke.tag();
    let actor = issue_actor(pool, &format!("post-stage-{tag}-{}", realm.owner_username)).await?;
    srv.put_collaborator(alice, &realm.owner_username, &realm.repo_name, &actor.username, "write").await?;
    let payload: Vec<u8> = (0..32_768u32).map(|i| ((i.wrapping_mul(revoke.seed()) ^ 0x5d) & 0xff) as u8).collect();
    let oid = hex::encode(Sha256::digest(&payload));
    let size = payload.len() as i64;
    let op_tok = format!("op-post-stage-{tag}-01");
    let op_id = if revoke.precreated() {
        let id = operation_token_to_uuid(&op_tok)?;
        precreate_batch(srv, realm, &actor, &op_tok, &oid, size).await?;
        id
    } else {
        derive_default_upload_operation_id(realm.repository_id, realm.owner_tenant_id, actor.user_id, &oid, size, 0)
    };
    let (staged_rx, resume_tx) = s3.arm_post_put_pause(&oid);
    let mut req = reqwest::Client::new()
        .put(format!("{}/{}/{}/info/lfs/objects/{oid}/{size}", srv.base_url, realm.owner_username, realm.repo_name))
        .basic_auth(&actor.username, Some(&actor.token))
        .header("Content-Type", "application/octet-stream")
        .body(payload.clone());
    if revoke.precreated() {
        req = req.header("X-Rootyard-Operation-Id", &op_tok);
    }
    let task = tokio::spawn(async move { req.send().await });
    let staged_key = tokio::time::timeout(Duration::from_secs(15), staged_rx).await??;
    ensure!(
        s3.raw_object_len(&staged_key) == Some(payload.len()),
        "{tag}: remote object must be staged before auth revocation"
    );
    let (attempt_id, _) = wait_pending_attempt(pool, realm.repository_id, &oid).await?;
    ensure!(attempt_state(pool, attempt_id).await? == "pending", "{tag}: attempt must be pending while staged");
    ensure!(
        op_state(pool, realm.repository_id, op_id).await? == "pending",
        "{tag}: operation must be pending while staged"
    );
    apply_revocation(pool, realm.repository_id, &actor, revoke).await?;
    let _ = resume_tx.send(());
    let resp = tokio::time::timeout(Duration::from_secs(30), task).await???;
    let (expected_status, expected_code) = revoke.expected();
    ensure!(resp.status() == expected_status, "{tag}: expected {expected_status}, got {}", resp.status());
    let body: Value = resp.json().await?;
    ensure!(body["code"] == expected_code, "{tag}: expected {expected_code}, got {body}");
    ensure!(s3.raw_object_len(&staged_key) == Some(payload.len()), "{tag}: staged bytes must stay uncommitted");
    assert_no_object_rows(pool, realm, &oid).await?;
    ensure!(attempt_state(pool, attempt_id).await? == "aborted_failed", "{tag}: attempt must end aborted_failed");
    ensure!(failure_reason_present(pool, attempt_id).await?, "{tag}: failure_reason must be recorded");
    let live_attempts = "SELECT COUNT(*) FROM lfs_blob_upload_attempts WHERE repository_id=$1 AND oid_sha256=$2 AND state IN ('pending','committed')";
    ensure!(count_rows(pool, live_attempts, realm.repository_id, &oid).await? == 0, "{tag}: live attempt left");
    ensure!(
        op_state(pool, realm.repository_id, op_id).await? == "aborted_failed",
        "{tag}: operation must end aborted_failed"
    );
    let live_ops = "SELECT COUNT(*) FROM lfs_blob_upload_operations WHERE repository_id=$1 AND oid_sha256=$2 AND state IN ('pending','committed')";
    ensure!(count_rows(pool, live_ops, realm.repository_id, &oid).await? == 0, "{tag}: live operation left");
    Ok(())
}

async fn apply_revocation(pool: &Pool, repo_id: Uuid, actor: &TestActor, revoke: PostStageRevoke) -> Result<()> {
    if matches!(revoke, PostStageRevoke::RevokeToken) {
        pool.get().await?.execute("UPDATE tokens SET revoked = TRUE WHERE id = $1", &[&actor.token_id]).await?;
        return Ok(());
    }
    let sql = if matches!(revoke, PostStageRevoke::DemoteToRead) {
        "UPDATE repository_collaborators SET role = 'read' WHERE repository_id = $1 AND user_id = $2"
    } else {
        "DELETE FROM repository_collaborators WHERE repository_id = $1 AND user_id = $2"
    };
    pool.get().await?.execute(sql, &[&repo_id, &actor.user_id]).await?;
    Ok(())
}

async fn precreate_batch(
    srv: &RunningProdLfsServer,
    realm: &LfsRepoRealm,
    actor: &TestActor,
    op_tok: &str,
    oid: &str,
    size: i64,
) -> Result<()> {
    let res = reqwest::Client::new()
        .post(format!("{}/{}/{}/info/lfs/objects/batch", srv.base_url, realm.owner_username, realm.repo_name))
        .basic_auth(&actor.username, Some(&actor.token))
        .header("Accept", "application/vnd.git-lfs+json")
        .header("Content-Type", "application/vnd.git-lfs+json")
        .header("X-Rootyard-Operation-Id", op_tok)
        .json(&json!({ "operation": "upload", "objects": [{ "oid": oid, "size": size }] }))
        .send()
        .await?;
    ensure!(res.status().is_success(), "post-stage batch pre-create failed: {}", res.status());
    Ok(())
}

async fn failure_reason_present(pool: &Pool, attempt_id: Uuid) -> Result<bool> {
    Ok(pool
        .get()
        .await?
        .query_one(
            "SELECT failure_reason IS NOT NULL FROM lfs_blob_upload_attempts WHERE attempt_id = $1",
            &[&attempt_id],
        )
        .await?
        .get(0))
}
