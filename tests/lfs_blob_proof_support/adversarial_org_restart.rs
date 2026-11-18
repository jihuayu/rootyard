//! Organization RBAC, ownership-transfer tenant re-validation, crash/restart recovery,
//! clean hydration, and cross-owner shared-holds (`Refs #145`).

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use deadpool_postgres::Pool;
use reqwest::StatusCode;
use rootyard::{
    journal::{self, IdempotencyIntent, RefChange},
    lfs::blob_proof_publication::{
        LfsAccessMode, LfsBlobRuntimeGate, LfsProofRejectCode, LfsRepoRealm, LfsTransferContext, PgLfsBlobStore,
        PointerResolutionSource, SharedLfsHoldGrant, hydrate_clean_compute_view, operation_token_to_uuid,
    },
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use uuid::Uuid;

use super::{
    LoopbackS3, RealHookInput, RunningProdLfsServer, TestActor, copy_dir_recursive, issue_actor, run_git_ok,
    run_git_raw, run_real_validate_hook,
};

pub struct OrgRestartSharedHoldInput<'a> {
    pub s3: &'a LoopbackS3,
    pub root_prefix: &'a str,
    pub pool: &'a Pool,
    pub db_url: &'a str,
    pub pg: &'a PgLfsBlobStore,
    pub realm: &'a LfsRepoRealm,
    pub alice: &'a TestActor,
    pub bob: &'a TestActor,
    pub prev_repos_dir: &'a Path,
    pub home: &'a Path,
    pub historical_commit: &'a str,
    pub shared_oid: &'a str,
    pub shared_bytes: &'a [u8],
}

pub async fn exercise_org_authority_restart_recovery_hydration_and_shared_holds(
    inp: OrgRestartSharedHoldInput<'_>,
) -> Result<()> {
    let OrgRestartSharedHoldInput {
        s3,
        root_prefix,
        pool,
        db_url,
        pg,
        realm,
        alice,
        bob,
        prev_repos_dir,
        home,
        historical_commit,
        shared_oid,
        shared_bytes,
    } = inp;

    let crash_payload = b"crash-recovery-same-operation-payload-v1".to_vec();
    let crash_oid = hex::encode(Sha256::digest(&crash_payload));
    let crash_op_tok = "op-crash-restart-retry-01";
    let crash_op_id = operation_token_to_uuid(crash_op_tok)?;
    pg.begin_or_load_upload_operation(
        realm.repository_id,
        crash_op_id,
        realm.owner_tenant_id,
        alice.user_id,
        &crash_oid,
        crash_payload.len() as i64,
    )
    .await?;
    pg.record_upload_attempt_start(
        Uuid::new_v4(),
        realm.owner_tenant_id,
        realm.repository_id,
        alice.user_id,
        &crash_oid,
        crash_payload.len() as i64,
    )
    .await?;

    let restart_dir = TempDir::new()?;
    copy_dir_recursive(prev_repos_dir, &restart_dir.path().join("data").join("repos"))?;
    ensure!(!restart_dir.path().join("data").join("lfs").exists());
    let fresh_gate = LfsBlobRuntimeGate::configured(s3.open_store(root_prefix)?);
    let restarted = RunningProdLfsServer::start_in_dir(fresh_gate.clone(), pool.clone(), db_url, restart_dir).await?;
    let cli = reqwest::Client::new();

    let rec_report = pg.reconcile_in_flight_uploads(realm.repository_id).await?;
    ensure!(rec_report.aborted_orphaned_attempts >= 1 && rec_report.committed_objects_preserved >= 2);

    let retry_res = cli
        .put(format!(
            "{}/{}/{}/info/lfs/objects/{crash_oid}/{}",
            restarted.base_url,
            realm.owner_username,
            realm.repo_name,
            crash_payload.len()
        ))
        .basic_auth(&alice.username, Some(&alice.token))
        .header("X-Rootyard-Operation-Id", crash_op_tok)
        .body(crash_payload)
        .send()
        .await?;
    ensure!(retry_res.status() == StatusCode::OK);

    let bob_access = pg.resolve_authoritative_repo_access(realm, bob.user_id, &bob.username, false, false).await?;
    let compute_dir = TempDir::new()?;
    let scratch = TempDir::new()?;
    let ctx = LfsTransferContext {
        gate: &fresh_gate,
        pg,
        realm,
        access: &bob_access,
        scratch_dir: scratch.path(),
        timeout: Duration::from_secs(20),
    };
    let hydration = hydrate_clean_compute_view(&ctx, historical_commit, compute_dir.path()).await?;
    ensure!(hydration.hydrated_files >= 1);
    ensure!(std::fs::read(compute_dir.path().join("weights.bin"))? == shared_bytes);

    let org_id = restarted.create_org(alice, "acme").await?;
    ensure!(org_id != alice.user_id && org_id != bob.user_id);
    restarted.put_org_member(alice, "acme", &bob.username, "maintain").await?;
    let (org_repo_id, org_owner_id) = restarted.create_repo(alice, Some("acme"), "org-engine", "sha1").await?;
    ensure!(org_owner_id == org_id);
    let org_wt = TempDir::new()?;
    run_git_ok(org_wt.path(), home, &["init", "--initial-branch=main"])?;
    run_git_ok(org_wt.path(), home, &["lfs", "install", "--local"])?;
    run_git_ok(org_wt.path(), home, &["remote", "add", "origin", &restarted.git_url_for(bob, "acme", "org-engine")])?;
    run_git_ok(org_wt.path(), home, &["lfs", "track", "*.bin"])?;
    let org_bytes = b"organization-member-remote-lfs-blob-payload".to_vec();
    std::fs::write(org_wt.path().join("org_asset.bin"), &org_bytes)?;
    run_git_ok(org_wt.path(), home, &["add", ".gitattributes", "org_asset.bin"])?;
    run_git_ok(org_wt.path(), home, &["commit", "-m", "org member LFS push"])?;
    let org_op_tok = "op-org-push-01";
    run_git_ok(
        org_wt.path(),
        home,
        &["-c", &format!("http.extraHeader=X-Rootyard-Operation-Id: {org_op_tok}"), "push", "-u", "origin", "main"],
    )?;
    let org_att = pg
        .load_attestation(org_repo_id, operation_token_to_uuid(org_op_tok)?)
        .await?
        .context("org push attestation")?;
    ensure!(
        matches!(org_att.access_mode, LfsAccessMode::OrganizationMember { organization_id, .. } if organization_id == org_id)
    );

    let org_clone = TempDir::new()?;
    run_git_ok(org_clone.path(), home, &["clone", &restarted.git_url_for(alice, "acme", "org-engine"), "."])?;
    ensure!(std::fs::read(org_clone.path().join("org_asset.bin"))? == org_bytes);

    // Ownership transfer (`alice/xfer-repo` -> `acme/xfer-repo`): `ensure_realm_for_repository`,
    // upload operations, push attestations, and clean hydration must re-validate live `owner_id`
    // and reject stale pre-transfer tenant records (`409 attestation_equivocation` / `missing_remote_blob`).
    let (xfer_repo_id, pre_owner_id) = restarted.create_repo(alice, None, "xfer-repo", "sha1").await?;
    ensure!(pre_owner_id != org_id);
    let xfer_wt = TempDir::new()?;
    run_git_ok(xfer_wt.path(), home, &["init", "--initial-branch=main"])?;
    run_git_ok(xfer_wt.path(), home, &["lfs", "install", "--local"])?;
    run_git_ok(
        xfer_wt.path(),
        home,
        &["remote", "add", "origin", &restarted.git_url_for(alice, &alice.username, "xfer-repo")],
    )?;
    run_git_ok(xfer_wt.path(), home, &["lfs", "track", "*.bin"])?;
    let pre_bytes = b"pre-ownership-transfer-lfs-payload-v1".to_vec();
    let pre_oid = hex::encode(Sha256::digest(&pre_bytes));
    let pre_sz = pre_bytes.len() as i64;
    std::fs::write(xfer_wt.path().join("pre_xfer.bin"), &pre_bytes)?;
    run_git_ok(xfer_wt.path(), home, &["add", ".gitattributes", "pre_xfer.bin"])?;
    run_git_ok(xfer_wt.path(), home, &["commit", "-m", "pre-transfer LFS commit"])?;
    let pre_commit_oid = run_git_ok(xfer_wt.path(), home, &["rev-parse", "HEAD"])?;
    let pre_push_tok = "op-pre-xfer-push-01";
    run_git_ok(
        xfer_wt.path(),
        home,
        &["-c", &format!("http.extraHeader=X-Rootyard-Operation-Id: {pre_push_tok}"), "push", "-u", "origin", "main"],
    )?;
    let pre_up_tok = "op-pre-xfer-upload-01";
    let pre_put = cli
        .put(format!("{}/{}/xfer-repo/info/lfs/objects/{pre_oid}/{pre_sz}", restarted.base_url, alice.username))
        .basic_auth(&alice.username, Some(&alice.token))
        .header("X-Rootyard-Operation-Id", pre_up_tok)
        .body(pre_bytes.clone())
        .send()
        .await?;
    ensure!(pre_put.status() == StatusCode::OK);

    let new_gen: i64 = pool
        .get()
        .await?
        .query_one(
            "UPDATE repositories
             SET owner_id = $2, storage_generation = storage_generation + 1
             WHERE id = $1
             RETURNING storage_generation",
            &[&xfer_repo_id, &org_id],
        )
        .await?
        .get(0);
    let post_realm = pg.ensure_realm_for_repository(xfer_repo_id, &restarted.state.storage.root).await?;
    ensure!(post_realm.owner_tenant_id == org_id && post_realm.owner_username == "acme");

    let stale_put = cli
        .put(format!("{}/acme/xfer-repo/info/lfs/objects/{pre_oid}/{pre_sz}", restarted.base_url))
        .basic_auth(&alice.username, Some(&alice.token))
        .header("X-Rootyard-Operation-Id", pre_up_tok)
        .body(pre_bytes)
        .send()
        .await?;
    ensure!(stale_put.status() == StatusCode::CONFLICT);
    let stale_put_json: Value = stale_put.json().await?;
    ensure!(stale_put_json["code"] == "attestation_equivocation", "got {stale_put_json}");

    let stale_verify = cli
        .post(format!("{}/acme/xfer-repo/info/lfs/verify", restarted.base_url))
        .basic_auth(&alice.username, Some(&alice.token))
        .header("Accept", "application/vnd.git-lfs+json")
        .header("Content-Type", "application/vnd.git-lfs+json")
        .header("X-Rootyard-Operation-Id", pre_up_tok)
        .json(&json!({ "oid": pre_oid, "size": pre_sz }))
        .send()
        .await?;
    ensure!(stale_verify.status() == StatusCode::CONFLICT);

    let pre_push_uuid = operation_token_to_uuid(pre_push_tok)?;
    let xfer_bare = restarted.state.storage.repo_path(xfer_repo_id);
    let stale_op = journal::begin_ref_transaction(
        &restarted.state.storage.root,
        xfer_repo_id,
        alice.user_id,
        alice.username.clone(),
        alice.token_id,
        new_gen,
        Some(IdempotencyIntent { key_sha256: pre_push_uuid.to_string(), request_sha256: "0".repeat(64) }),
    )?;
    let stale_hook_err = tokio::task::block_in_place(|| {
        run_real_validate_hook(RealHookInput {
            db_url: &restarted.state.config.database_url,
            git_bin: &restarted.state.config.git,
            git_dir: &xfer_bare,
            data_root: &restarted.state.storage.root,
            git_obj_dir: None,
            git_alt_dirs: None,
            op: &stale_op,
            changes: &[RefChange {
                ref_name: "refs/heads/main".into(),
                old_oid: "0".repeat(40),
                new_oid: pre_commit_oid.clone(),
            }],
        })
    })
    .expect_err("stale pre-transfer push attestation replay must fail closed");
    let _ = journal::finish(&stale_op);
    ensure!(stale_hook_err.to_string().contains("attestation_equivocation"), "got {stale_hook_err}");

    let post_access =
        pg.resolve_authoritative_repo_access(&post_realm, bob.user_id, &bob.username, true, false).await?;
    let stale_hyd_dir = TempDir::new()?;
    let post_ctx = LfsTransferContext {
        gate: &fresh_gate,
        pg,
        realm: &post_realm,
        access: &post_access,
        scratch_dir: scratch.path(),
        timeout: Duration::from_secs(20),
    };
    let stale_hyd_err = hydrate_clean_compute_view(&post_ctx, &pre_commit_oid, stale_hyd_dir.path())
        .await
        .expect_err("pre-transfer tenant blob without shared-hold must not hydrate under new owner");
    ensure!(stale_hyd_err.code == LfsProofRejectCode::MissingRemoteBlob);

    let post_wt = TempDir::new()?;
    run_git_ok(post_wt.path(), home, &["init", "--initial-branch=post-xfer"])?;
    run_git_ok(post_wt.path(), home, &["lfs", "install", "--local"])?;
    run_git_ok(post_wt.path(), home, &["remote", "add", "origin", &restarted.git_url_for(bob, "acme", "xfer-repo")])?;
    run_git_ok(post_wt.path(), home, &["lfs", "track", "*.bin"])?;
    let post_bytes = b"post-ownership-transfer-acme-lfs-payload-v2".to_vec();
    std::fs::write(post_wt.path().join("post_xfer.bin"), &post_bytes)?;
    run_git_ok(post_wt.path(), home, &["add", ".gitattributes", "post_xfer.bin"])?;
    run_git_ok(post_wt.path(), home, &["commit", "-m", "post-transfer org push"])?;
    run_git_ok(post_wt.path(), home, &["push", "-u", "origin", "post-xfer"])?;

    let post_clone = TempDir::new()?;
    run_git_ok(
        post_clone.path(),
        home,
        &["clone", "--branch", "post-xfer", &restarted.git_url_for(alice, "acme", "xfer-repo"), "."],
    )?;
    ensure!(std::fs::read(post_clone.path().join("post_xfer.bin"))? == post_bytes);

    let dave = issue_actor(pool, "dave").await?;
    let (fork_repo_id, fork_owner_id) = restarted.create_repo(&dave, None, "fork-engine", "sha1").await?;
    restarted.put_collaborator(&dave, &dave.username, "fork-engine", &bob.username, "write").await?;
    let src_blob =
        pg.load_committed_blob(realm.owner_tenant_id, realm.repository_id, shared_oid).await?.context("src")?;
    let grant_id = Uuid::new_v4();
    pg.grant_shared_hold(&SharedLfsHoldGrant {
        grant_id,
        source_tenant_id: realm.owner_tenant_id,
        source_repository_id: realm.repository_id,
        target_tenant_id: fork_owner_id,
        target_repository_id: fork_repo_id,
        grantee_actor_id: Some(bob.user_id),
        oid_sha256: shared_oid.to_owned(),
        size_bytes: shared_bytes.len() as i64,
        source_hold_id: src_blob.hold_id,
        active: false,
    })
    .await?;

    let fork_url = restarted.git_url_for(bob, &dave.username, "fork-engine");
    let fork_wt = TempDir::new()?;
    run_git_ok(fork_wt.path(), home, &["init", "--initial-branch=main"])?;
    run_git_ok(fork_wt.path(), home, &["remote", "add", "origin", &fork_url])?;
    std::fs::write(
        fork_wt.path().join("shared_weights.bin"),
        format!("version https://git-lfs.github.com/spec/v1\noid sha256:{shared_oid}\nsize {}\n", shared_bytes.len()),
    )?;
    std::fs::write(fork_wt.path().join(".gitattributes"), "*.bin filter=lfs diff=lfs merge=lfs -text\n")?;
    run_git_ok(fork_wt.path(), home, &["add", ".gitattributes", "shared_weights.bin"])?;
    run_git_ok(fork_wt.path(), home, &["commit", "-m", "cross-owner shared pointer"])?;

    let denied = run_git_raw(fork_wt.path(), home, &["push", "--no-verify", "origin", "main"])?;
    ensure!(!denied.status.success() && String::from_utf8_lossy(&denied.stderr).contains("unauthorized_shared_hold"));

    pg.set_shared_hold_active(grant_id, true).await?;
    let fork_op_tok = "op-shared-hold-push-01";
    run_git_ok(
        fork_wt.path(),
        home,
        &[
            "-c",
            &format!("http.extraHeader=X-Rootyard-Operation-Id: {fork_op_tok}"),
            "push",
            "--no-verify",
            "origin",
            "main",
        ],
    )?;
    let fork_att =
        pg.load_attestation(fork_repo_id, operation_token_to_uuid(fork_op_tok)?).await?.context("fork attestation")?;
    ensure!(matches!(fork_att.pointers[0].resolution, PointerResolutionSource::SharedHold { .. }));

    let fork_clone = TempDir::new()?;
    run_git_ok(fork_clone.path(), home, &["clone", &fork_url, "."])?;
    run_git_ok(fork_clone.path(), home, &["lfs", "install", "--local"])?;
    run_git_ok(fork_clone.path(), home, &["lfs", "pull"])?;
    ensure!(std::fs::read(fork_clone.path().join("shared_weights.bin"))? == shared_bytes);

    pg.set_shared_hold_active(grant_id, false).await?;
    let after_revoke = run_git_raw(fork_wt.path(), home, &["lfs", "fetch", "--all"])?;
    ensure!(!after_revoke.status.success());
    ensure!(!restarted.state.storage.root.join("lfs").exists());
    Ok(())
}
