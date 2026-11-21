//! Mid-upload collaborator/token revocation with unprecreated operations and chunked reopen guards.

use anyhow::{Result, ensure};
use deadpool_postgres::Pool;
use reqwest::StatusCode;
use rootyard::lfs::blob_proof_publication::{LfsRepoRealm, operation_token_to_uuid};
use sha2::{Digest, Sha256};

use super::super::{RunningProdLfsServer, TestActor, issue_actor};
use super::harness::{
    StreamSpec, assert_no_object_rows, count_rows, finish_stream, op_state, open_upload_stream, wait_null_op_attempt,
    wait_pending_attempt,
};

pub(super) async fn scenario_unprecreated_revocation(
    srv: &RunningProdLfsServer,
    pool: &Pool,
    realm: &LfsRepoRealm,
    alice: &TestActor,
    token_revocation: bool,
) -> Result<()> {
    let collab = issue_actor(pool, &format!("lease-collab-{token_revocation}-{}", realm.owner_username)).await?;
    srv.put_collaborator(alice, &realm.owner_username, &realm.repo_name, &collab.username, "write").await?;
    let seed = if token_revocation { 37 } else { 41 };
    let payload: Vec<u8> = (0..24_576u32).map(|i| ((i.wrapping_mul(seed) ^ 0x2d) & 0xff) as u8).collect();
    let oid = hex::encode(Sha256::digest(&payload));
    let spec = StreamSpec { op_tok: None, oid: &oid, first: &payload, sized: true };
    let stream = open_upload_stream(&srv.base_url, realm, &collab, spec).await?;
    wait_null_op_attempt(pool, realm.repository_id, &oid).await?;
    ensure!(
        count_rows(
            pool,
            "SELECT COUNT(*) FROM lfs_blob_upload_operations WHERE repository_id=$1 AND oid_sha256=$2",
            realm.repository_id,
            &oid,
        )
        .await?
            == 0,
        "unprecreated streaming upload must not create an operation mid-stream"
    );
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
    let status = finish_stream(stream, true, &payload).await?;
    let expected = if token_revocation { StatusCode::UNAUTHORIZED } else { StatusCode::FORBIDDEN };
    ensure!(status == expected, "expected {expected}, got {status}");
    ensure!(
        count_rows(
            pool,
            "SELECT COUNT(*) FROM lfs_blob_upload_operations WHERE repository_id=$1 AND oid_sha256=$2",
            realm.repository_id,
            &oid,
        )
        .await?
            == 0,
        "mid-upload revocation must never create an operation row"
    );
    assert_no_object_rows(pool, realm, &oid).await?;
    ensure!(
        count_rows(
            pool,
            "SELECT COUNT(*) FROM lfs_blob_upload_attempts WHERE repository_id=$1 AND oid_sha256=$2 AND state='pending'",
            realm.repository_id,
            &oid,
        )
        .await?
            == 0
    );
    Ok(())
}

pub(super) async fn scenario_chunked_reopen(
    srv: &RunningProdLfsServer,
    pool: &Pool,
    realm: &LfsRepoRealm,
    alice: &TestActor,
) -> Result<()> {
    let collab = issue_actor(pool, &format!("chunk-collab-{}", realm.owner_username)).await?;
    srv.put_collaborator(alice, &realm.owner_username, &realm.repo_name, &collab.username, "write").await?;
    let payload: Vec<u8> = (0..20_480u32).map(|i| ((i.wrapping_mul(19) ^ 0x6b) & 0xff) as u8).collect();
    let oid = hex::encode(Sha256::digest(&payload));
    let op_tok = "op-chunked-reopen-mid-revoke-01";
    let op_id = operation_token_to_uuid(op_tok)?;
    pool.get()
        .await?
        .execute(
            "INSERT INTO lfs_blob_upload_operations(
            repository_id, operation_id, tenant_id, actor_id, oid_sha256, size_bytes, state
         ) VALUES($1,$2,$3,$4,$5,$6,'aborted_cancelled')",
            &[&realm.repository_id, &op_id, &realm.owner_tenant_id, &collab.user_id, &oid, &(payload.len() as i64)],
        )
        .await?;
    let first = &payload[..8_192];
    let spec = StreamSpec { op_tok: Some(op_tok), oid: &oid, first, sized: false };
    let stream = open_upload_stream(&srv.base_url, realm, &collab, spec).await?;
    wait_pending_attempt(pool, realm.repository_id, &oid).await?;
    ensure!(op_state(pool, realm.repository_id, op_id).await? == "aborted_cancelled");
    pool.get()
        .await?
        .execute(
            "DELETE FROM repository_collaborators WHERE repository_id = $1 AND user_id = $2",
            &[&realm.repository_id, &collab.user_id],
        )
        .await?;
    let status = finish_stream(stream, false, &payload[8_192..]).await?;
    ensure!(status == StatusCode::FORBIDDEN, "chunked reopen after revocation expected 403, got {status}");
    ensure!(op_state(pool, realm.repository_id, op_id).await? == "aborted_cancelled");
    assert_no_object_rows(pool, realm, &oid).await?;

    let ok_payload: Vec<u8> = (0..24_576u32).map(|i| ((i.wrapping_mul(23) ^ 0x17) & 0xff) as u8).collect();
    let ok_oid = hex::encode(Sha256::digest(&ok_payload));
    let first = &ok_payload[..8_192];
    let spec = StreamSpec { op_tok: None, oid: &ok_oid, first, sized: false };
    let stream = open_upload_stream(&srv.base_url, realm, alice, spec).await?;
    let status = finish_stream(stream, false, &ok_payload[8_192..]).await?;
    ensure!(status == StatusCode::OK, "authorized chunked PUT expected 200, got {status}");
    ensure!(
        count_rows(
            pool,
            "SELECT COUNT(*) FROM lfs_blob_objects WHERE repository_id=$1 AND oid_sha256=$2",
            realm.repository_id,
            &ok_oid,
        )
        .await?
            == 1
    );
    ensure!(
        count_rows(
            pool,
            "SELECT COUNT(*) FROM lfs_objects WHERE repository_id=$1 AND oid=$2",
            realm.repository_id,
            &ok_oid,
        )
        .await?
            == 1
    );
    Ok(())
}
