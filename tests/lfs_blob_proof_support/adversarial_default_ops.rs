//! Unmodified official `git-lfs` + `git push` (zero custom headers) default-`operation_id`
//! stability and canonical missing-locator repair + attestation refresh E2E checks (`Refs #145`).

use std::path::Path;

use anyhow::{Context, Result, ensure};
use rootyard::lfs::blob_proof_publication::{
    LfsRefUpdateSpec, LfsRepoRealm, PgLfsBlobStore, derive_default_push_operation_id,
    derive_default_upload_operation_id,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use super::{LoopbackS3, RunningProdLfsServer, TestActor, run_git_ok};

pub struct DefaultOpClientInput<'a> {
    pub srv: &'a RunningProdLfsServer,
    pub s3: &'a LoopbackS3,
    pub root_prefix: &'a str,
    pub pg: &'a PgLfsBlobStore,
    pub realm: &'a LfsRepoRealm,
    pub alice: &'a TestActor,
    pub home: &'a Path,
}

pub async fn exercise_unmodified_client_default_operation_replay_and_canonical_repair(
    inp: DefaultOpClientInput<'_>,
) -> Result<()> {
    let DefaultOpClientInput { srv, s3, root_prefix, pg, realm, alice, home } = inp;
    let alice_url = srv.git_url_for(alice, &realm.owner_username, &realm.repo_name);
    let cli = reqwest::Client::new();

    let wt = TempDir::new()?;
    run_git_ok(wt.path(), home, &["clone", &alice_url, "."])?;
    run_git_ok(wt.path(), home, &["lfs", "install", "--local"])?;
    let prev_head = run_git_ok(wt.path(), home, &["rev-parse", "HEAD"])?;

    let payload: Vec<u8> = (0..73_728u32).map(|i| ((i.wrapping_mul(43) ^ 0x3c) & 0xff) as u8).collect();
    let oid = hex::encode(Sha256::digest(&payload));
    let sz = payload.len() as i64;
    std::fs::write(wt.path().join("stock_default_op.bin"), &payload)?;
    run_git_ok(wt.path(), home, &["add", "stock_default_op.bin"])?;
    run_git_ok(wt.path(), home, &["commit", "-m", "unmodified stock git-lfs default op"])?;
    let new_head = run_git_ok(wt.path(), home, &["rev-parse", "HEAD"])?;

    // 1. Headerless Batch `upload` deterministically mints & reuses `default_upload_operation_id(..., epoch=0)`
    //    and injects `X-Rootyard-Operation-Id` into BOTH `actions.upload.header` and `actions.verify.header`.
    let expected_uop0 =
        derive_default_upload_operation_id(realm.repository_id, realm.owner_tenant_id, alice.user_id, &oid, sz, 0);
    let batch_url = format!("{}/{}/{}.git/info/lfs/objects/batch", srv.base_url, realm.owner_username, realm.repo_name);
    let b1: Value = cli
        .post(&batch_url)
        .basic_auth(&alice.username, Some(&alice.token))
        .header("Accept", "application/vnd.git-lfs+json")
        .header("Content-Type", "application/vnd.git-lfs+json")
        .json(&json!({ "operation": "upload", "objects": [{ "oid": oid, "size": sz }] }))
        .send()
        .await?
        .json()
        .await?;
    let b2: Value = cli
        .post(&batch_url)
        .basic_auth(&alice.username, Some(&alice.token))
        .header("Accept", "application/vnd.git-lfs+json")
        .header("Content-Type", "application/vnd.git-lfs+json")
        .json(&json!({ "operation": "upload", "objects": [{ "oid": oid, "size": sz }] }))
        .send()
        .await?
        .json()
        .await?;
    let hdr_u1 = b1["objects"][0]["actions"]["upload"]["header"]["X-Rootyard-Operation-Id"]
        .as_str()
        .context("upload header op_id")?;
    let hdr_v1 = b1["objects"][0]["actions"]["verify"]["header"]["X-Rootyard-Operation-Id"]
        .as_str()
        .context("verify header op_id")?;
    let hdr_u2 = b2["objects"][0]["actions"]["upload"]["header"]["X-Rootyard-Operation-Id"]
        .as_str()
        .context("upload header op_id retry")?;
    ensure!(hdr_u1 == expected_uop0.to_string() && hdr_v1 == hdr_u1 && hdr_u2 == hdr_u1);

    // 2. Unmodified official `git push origin main` (ZERO `http.extraHeader`!) echoes `expected_uop0`
    //    across upload + verify AND attests refs via real `browse::policy::validate_hook`.
    run_git_ok(wt.path(), home, &["push", "origin", "main"])?;
    let uop0_row =
        pg.load_upload_operation(realm.repository_id, expected_uop0).await?.context("default upload op committed")?;
    ensure!(uop0_row.state == "committed" && uop0_row.locator.is_some());

    let expected_pop = derive_default_push_operation_id(
        realm.repository_id,
        realm.owner_tenant_id,
        alice.user_id,
        &[LfsRefUpdateSpec {
            ref_name: "refs/heads/main".into(),
            old_oid: prev_head.clone(),
            new_oid: new_head.clone(),
        }],
    );
    let att_first =
        pg.load_attestation(realm.repository_id, expected_pop).await?.context("default push attestation")?;
    ensure!(att_first.pointers.iter().any(|p| p.oid_sha256 == oid));

    // Simulate interrupted push retry (reset bare `refs/heads/main` back to `prev_head` and re-run
    // unmodified `git push origin main` with ZERO custom headers) -> deterministically replays `att_first`!
    let bare_dir = srv.state.storage.repo_path(realm.repository_id);
    run_git_ok(&bare_dir, home, &["update-ref", "refs/heads/main", &prev_head])?;
    run_git_ok(wt.path(), home, &["push", "origin", "main"])?;
    let att_replayed =
        pg.load_attestation(realm.repository_id, expected_pop).await?.context("replayed default push attestation")?;
    ensure!(
        att_replayed.attestation_id == att_first.attestation_id && att_replayed.proof_digest == att_first.proof_digest,
        "unmodified git push retry must replay identical attestation"
    );

    // 3. Canonical remote object missing -> unmodified official `git lfs push --all origin` (ZERO headers)
    //    repairs `lfs_blob_objects` (`orig_loc` -> `repaired_loc`), commits `epoch=1`, AND re-running
    //    unmodified `git push origin main` refreshes `lfs_pointer_attestations` to `repaired_rec.locator`!
    let orig_rec = pg
        .load_committed_blob(realm.owner_tenant_id, realm.repository_id, &oid)
        .await?
        .context("orig committed rec")?;
    let orig_loc = orig_rec.locator.to_locator()?;
    let _ = s3.take_raw(root_prefix, &orig_loc).context("delete canonical object from LoopbackS3")?;

    run_git_ok(wt.path(), home, &["lfs", "push", "--all", "origin"])?;

    let repaired_rec = pg
        .load_committed_blob(realm.owner_tenant_id, realm.repository_id, &oid)
        .await?
        .context("repaired committed rec")?;
    let repaired_loc = repaired_rec.locator.to_locator()?;
    ensure!(repaired_loc != orig_loc, "official git-lfs push repair must replace missing canonical BlobLocator");
    let expected_uop1 =
        derive_default_upload_operation_id(realm.repository_id, realm.owner_tenant_id, alice.user_id, &oid, sz, 1);
    let uop1_row =
        pg.load_upload_operation(realm.repository_id, expected_uop1).await?.context("repair epoch=1 upload op")?;
    ensure!(uop1_row.state == "committed" && uop1_row.locator == Some(repaired_rec.locator));

    run_git_ok(&bare_dir, home, &["update-ref", "refs/heads/main", &prev_head])?;
    run_git_ok(wt.path(), home, &["push", "origin", "main"])?;
    let att_after_repair = pg
        .load_attestation(realm.repository_id, expected_pop)
        .await?
        .context("refreshed push attestation after canonical repair")?;
    ensure!(
        att_after_repair.pointers.iter().any(|p| p.oid_sha256 == oid && p.locator == repaired_rec.locator),
        "re-push after canonical missing-locator repair must refresh lfs_pointer_attestations locator"
    );

    let verify_clone = TempDir::new()?;
    run_git_ok(verify_clone.path(), home, &["clone", &alice_url, "."])?;
    ensure!(std::fs::read(verify_clone.path().join("stock_default_op.bin"))? == payload);
    Ok(())
}
