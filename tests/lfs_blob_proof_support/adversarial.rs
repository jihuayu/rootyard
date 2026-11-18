//! Adversarial same-`operation_id` retries, locator repair/corruption verification,
//! and named pointer rejection E2E checks (`Refs #145`).

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use reqwest::StatusCode;
use rootyard::{
    journal::RefChange,
    lfs::blob_proof_publication::{
        LfsBlobRuntimeGate, LfsProofRejectCode, LfsRepoRealm, LfsTransferContext, PgLfsBlobStore,
        PushAttestationSession, delete_or_retire_lfs_object, operation_token_to_uuid, upload_lfs_object_to_remote,
        with_push_attestation_session,
    },
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use uuid::Uuid;

pub use super::adversarial_org_restart::{
    OrgRestartSharedHoldInput, exercise_org_authority_restart_recovery_hydration_and_shared_holds,
};
use super::{LoopbackS3, RunningProdLfsServer, TestActor, run_git_ok, run_git_raw};

pub struct UploadRetryRepairInput<'a> {
    pub srv: &'a RunningProdLfsServer,
    pub s3: &'a LoopbackS3,
    pub root_prefix: &'a str,
    pub gate: &'a LfsBlobRuntimeGate,
    pub pg: &'a PgLfsBlobStore,
    pub realm: &'a LfsRepoRealm,
    pub alice: &'a TestActor,
}

pub async fn exercise_same_operation_upload_retries_locator_repair_and_corruption_guard(
    inp: UploadRetryRepairInput<'_>,
) -> Result<String> {
    let UploadRetryRepairInput { srv, s3, root_prefix, gate, pg, realm, alice } = inp;
    let cli = reqwest::Client::new();
    let payload: Vec<u8> = (0..98_304u32).map(|i| ((i.wrapping_mul(31) ^ 0x5a) & 0xff) as u8).collect();
    let oid = hex::encode(Sha256::digest(&payload));
    let sz = payload.len() as i64;
    let put_url = format!("{}/{}/{}/info/lfs/objects/{oid}/{sz}", srv.base_url, realm.owner_username, realm.repo_name);

    let op_tok = "op-upload-stable-retry-01";
    let op_uuid = operation_token_to_uuid(op_tok)?;
    let r1: Value = cli
        .put(&put_url)
        .basic_auth(&alice.username, Some(&alice.token))
        .header("X-Rootyard-Operation-Id", op_tok)
        .body(payload.clone())
        .send()
        .await?
        .json()
        .await?;
    ensure!(r1["state"] == "ready", "initial PUT failed: {r1}");
    let saved_op = pg.load_upload_operation(realm.repository_id, op_uuid).await?.context("saved upload op")?;
    ensure!(saved_op.state == "committed" && saved_op.locator.is_some());

    let r2: Value = cli
        .put(&put_url)
        .basic_auth(&alice.username, Some(&alice.token))
        .header("X-Rootyard-Operation-Id", op_tok)
        .header("Idempotency-Key", op_tok)
        .body(payload.clone())
        .send()
        .await?
        .json()
        .await?;
    ensure!(r1["hold_id"] == r2["hold_id"] && r1["locator_attempt_id"] == r2["locator_attempt_id"]);

    let equiv_res = cli
        .put(format!(
            "{}/{}/{}/info/lfs/objects/{}/{sz}",
            srv.base_url,
            realm.owner_username,
            realm.repo_name,
            "e4".repeat(32)
        ))
        .basic_auth(&alice.username, Some(&alice.token))
        .header("X-Rootyard-Operation-Id", op_tok)
        .body(payload.clone())
        .send()
        .await?;
    ensure!(equiv_res.status() == StatusCode::CONFLICT);
    let equiv_body: Value = equiv_res.json().await?;
    ensure!(equiv_body["code"] == "attestation_equivocation", "got {equiv_body}");

    let access = pg.resolve_authoritative_repo_access(realm, alice.user_id, &alice.username, true, true).await?;
    let scratch = TempDir::new()?;
    let ctx = LfsTransferContext {
        gate,
        pg,
        realm,
        access: &access,
        scratch_dir: scratch.path(),
        timeout: Duration::from_secs(20),
    };
    let payload2: Vec<u8> = (0..49_152u32).map(|i| ((i * 13 + 7) & 0xff) as u8).collect();
    let oid2 = hex::encode(Sha256::digest(&payload2));
    let sz2 = payload2.len() as i64;
    let mut bad_bytes = payload2.clone();
    bad_bytes[0] ^= 0xff;
    let (c1, c2, c3, bad_digest, bad_len) = tokio::join!(
        upload_lfs_object_to_remote(&ctx, None, &oid2, sz2, &payload2),
        upload_lfs_object_to_remote(&ctx, None, &oid2, sz2, &payload2),
        upload_lfs_object_to_remote(&ctx, None, &oid2, sz2, &payload2),
        upload_lfs_object_to_remote(&ctx, None, &oid2, sz2, &bad_bytes),
        upload_lfs_object_to_remote(&ctx, None, &oid2, sz2 + 9, &payload2),
    );
    let (w1, w2, w3) = (c1?, c2?, c3?);
    ensure!(
        w1.hold_id == w2.hold_id && w2.hold_id == w3.hold_id && w1.locator == w2.locator && w2.locator == w3.locator
    );
    ensure!(bad_digest.unwrap_err().code == LfsProofRejectCode::SizeOrDigestMismatch);
    ensure!(bad_len.unwrap_err().code == LfsProofRejectCode::SizeOrDigestMismatch);

    let orig_loc = w1.locator.to_locator()?;
    let _ = s3.take_raw(root_prefix, &orig_loc).context("remove orig_loc from LoopbackS3")?;
    let repair_put: Value = cli
        .put(format!("{}/{}/{}/info/lfs/objects/{oid2}/{sz2}", srv.base_url, realm.owner_username, realm.repo_name))
        .basic_auth(&alice.username, Some(&alice.token))
        .header("X-Rootyard-Operation-Id", "op-locator-repair-01")
        .body(payload2.clone())
        .send()
        .await?
        .json()
        .await?;
    ensure!(repair_put["state"] == "ready" && repair_put["locator_attempt_id"] != orig_loc.attempt_id().to_string());
    let repaired_rec =
        pg.load_committed_blob(realm.owner_tenant_id, realm.repository_id, &oid2).await?.context("repaired")?;
    let repaired_loc = repaired_rec.locator.to_locator()?;
    ensure!(repaired_loc != orig_loc);

    let clean_raw = s3.take_raw(root_prefix, &repaired_loc).context("repaired s3 bytes")?;
    let mut corrupted_raw = clean_raw.clone();
    corrupted_raw[0] ^= 0xaa;
    s3.restore_raw(root_prefix, &repaired_loc, corrupted_raw);

    let retry_corrupt = cli
        .put(format!("{}/{}/{}/info/lfs/objects/{oid2}/{sz2}", srv.base_url, realm.owner_username, realm.repo_name))
        .basic_auth(&alice.username, Some(&alice.token))
        .header("X-Rootyard-Operation-Id", "op-locator-repair-01")
        .body(payload2)
        .send()
        .await?;
    ensure!(retry_corrupt.status() == StatusCode::UNPROCESSABLE_ENTITY);
    let verify_corrupt = cli
        .post(format!("{}/{}/{}/info/lfs/verify", srv.base_url, realm.owner_username, realm.repo_name))
        .basic_auth(&alice.username, Some(&alice.token))
        .header("Accept", "application/vnd.git-lfs+json")
        .header("Content-Type", "application/vnd.git-lfs+json")
        .json(&json!({ "oid": oid2, "size": sz2 }))
        .send()
        .await?;
    ensure!(verify_corrupt.status() == StatusCode::UNPROCESSABLE_ENTITY);
    s3.restore_raw(root_prefix, &repaired_loc, clean_raw);

    let del_http = cli
        .delete(format!("{}/{}/{}/info/lfs/objects/{oid}", srv.base_url, realm.owner_username, realm.repo_name))
        .basic_auth(&alice.username, Some(&alice.token))
        .send()
        .await?;
    ensure!(del_http.status() == StatusCode::METHOD_NOT_ALLOWED);
    let del_body: Value = del_http.json().await?;
    ensure!(del_body["code"] == "delete_disabled_by_policy", "got {del_body}");
    let del_err = delete_or_retire_lfs_object(&ctx, &oid, false).await.expect_err("physical delete must fail");
    ensure!(del_err.code == LfsProofRejectCode::DeleteDisabledByPolicy);
    Ok(oid)
}

pub struct PointerRejectionInput<'a> {
    pub srv: &'a RunningProdLfsServer,
    pub pg: &'a PgLfsBlobStore,
    pub realm: &'a LfsRepoRealm,
    pub alice: &'a TestActor,
    pub home: &'a Path,
    pub committed_oid: &'a str,
    pub committed_size: i64,
}

pub async fn exercise_named_pointer_rejections_and_prod_attestation_replay(
    inp: PointerRejectionInput<'_>,
) -> Result<()> {
    let PointerRejectionInput { srv, pg, realm, alice, home, committed_oid, committed_size } = inp;
    let url = srv.git_url_for(alice, &realm.owner_username, &realm.repo_name);

    let missing_wt = TempDir::new()?;
    run_git_ok(missing_wt.path(), home, &["clone", &url, "."])?;
    let ghost_ptr = format!("version https://git-lfs.github.com/spec/v1\noid sha256:{}\nsize 777\n", "9e".repeat(32));
    std::fs::write(missing_wt.path().join("ghost.txt"), ghost_ptr)?;
    run_git_ok(missing_wt.path(), home, &["add", "ghost.txt"])?;
    run_git_ok(missing_wt.path(), home, &["commit", "-m", "ghost pointer"])?;
    let out_missing = run_git_raw(missing_wt.path(), home, &["push", "--no-verify", "origin", "main"])?;
    ensure!(
        !out_missing.status.success() && String::from_utf8_lossy(&out_missing.stderr).contains("missing_remote_blob")
    );

    let bad_sz_wt = TempDir::new()?;
    run_git_ok(bad_sz_wt.path(), home, &["clone", &url, "."])?;
    std::fs::write(
        bad_sz_wt.path().join("ok_ref.ptr"),
        format!("version https://git-lfs.github.com/spec/v1\noid sha256:{committed_oid}\nsize {committed_size}\n"),
    )?;
    std::fs::write(
        bad_sz_wt.path().join("wrong_ref.ptr"),
        format!(
            "version https://git-lfs.github.com/spec/v1\noid sha256:{committed_oid}\nsize {}\n",
            committed_size + 55
        ),
    )?;
    run_git_ok(bad_sz_wt.path(), home, &["add", "ok_ref.ptr", "wrong_ref.ptr"])?;
    run_git_ok(bad_sz_wt.path(), home, &["commit", "-m", "dual valid + wrong-size pointer"])?;
    let out_sz = run_git_raw(bad_sz_wt.path(), home, &["push", "--no-verify", "origin", "main"])?;
    ensure!(!out_sz.status.success() && String::from_utf8_lossy(&out_sz.stderr).contains("size_or_digest_mismatch"));

    let mal_wt = TempDir::new()?;
    run_git_ok(mal_wt.path(), home, &["clone", &url, "."])?;
    std::fs::write(
        mal_wt.path().join("corrupt.ptr"),
        "version https://git-lfs.github.com/spec/v1\noid sha256:not-a-valid-hex\nsize 10\n",
    )?;
    run_git_ok(mal_wt.path(), home, &["add", "corrupt.ptr"])?;
    run_git_ok(mal_wt.path(), home, &["commit", "-m", "malformed pointer"])?;
    let out_mal = run_git_raw(mal_wt.path(), home, &["push", "--no-verify", "origin", "main"])?;
    ensure!(!out_mal.status.success() && String::from_utf8_lossy(&out_mal.stderr).contains("malformed_lfs_pointer"));

    let bare_dir = srv.state.storage.repo_path(realm.repository_id);
    let head_oid = run_git_ok(&bare_dir, home, &["rev-parse", "refs/heads/main"])?;
    let zero_oid = "0".repeat(head_oid.len());
    let op_id = Uuid::new_v4();
    let changes = vec![RefChange {
        ref_name: "refs/heads/replay-check".into(),
        old_oid: zero_oid.clone(),
        new_oid: head_oid.clone(),
    }];
    let sess = PushAttestationSession {
        pool: srv.state.pool.clone(),
        actor_id: alice.user_id,
        actor_username: alice.username.clone(),
        operation_id: op_id,
        git_object_dir: None,
        git_alternate_object_dirs: None,
    };
    let client = srv.state.pool.get().await?;
    with_push_attestation_session(sess.clone(), async {
        rootyard::lfs::publication::validate_new_refs_with_client(
            &**client,
            &bare_dir,
            &srv.state.storage.root,
            &srv.state.config.git,
            srv.state.config.git_timeout,
            realm.repository_id,
            realm.owner_tenant_id,
            &changes,
        )
        .await
    })
    .await?;
    let att1 = pg.load_attestation(realm.repository_id, op_id).await?.context("att1")?;

    with_push_attestation_session(sess.clone(), async {
        rootyard::lfs::publication::validate_new_refs_with_client(
            &**client,
            &bare_dir,
            &srv.state.storage.root,
            &srv.state.config.git,
            srv.state.config.git_timeout,
            realm.repository_id,
            realm.owner_tenant_id,
            &changes,
        )
        .await
    })
    .await?;
    let att2 = pg.load_attestation(realm.repository_id, op_id).await?.context("att2")?;
    ensure!(att1.attestation_id == att2.attestation_id && att1.proof_digest == att2.proof_digest);

    let tampered =
        vec![RefChange { ref_name: "refs/heads/tampered-target".into(), old_oid: zero_oid, new_oid: head_oid }];
    let equiv_err = with_push_attestation_session(sess, async {
        rootyard::lfs::publication::validate_new_refs_with_client(
            &**client,
            &bare_dir,
            &srv.state.storage.root,
            &srv.state.config.git,
            srv.state.config.git_timeout,
            realm.repository_id,
            realm.owner_tenant_id,
            &tampered,
        )
        .await
    })
    .await
    .expect_err("equivocated replay must fail closed");
    ensure!(equiv_err.to_string().contains("attestation_equivocation"), "got {equiv_err}");
    Ok(())
}
