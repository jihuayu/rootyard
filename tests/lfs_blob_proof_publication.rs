//! Integration & official `git-lfs` E2E tests over production `rootyard::lfs::routes()` (`Refs #145`).

#[path = "lfs_blob_proof_support/mod.rs"]
mod support;

use anyhow::{Context, Result, ensure};
use deadpool_postgres::{Manager, Pool};
use reqwest::StatusCode;
use rootyard::{
    lfs::blob_proof_publication::{LfsBlobRuntimeGate, LfsProofRejectCode, PgLfsBlobStore, operation_token_to_uuid},
    ref_store::GitObjectFormat,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use support::adversarial::{
    OrgRestartSharedHoldInput, PointerRejectionInput, UploadRetryRepairInput,
    exercise_named_pointer_rejections_and_prod_attestation_replay,
    exercise_org_authority_restart_recovery_hydration_and_shared_holds,
    exercise_same_operation_upload_retries_locator_repair_and_corruption_guard,
};
use support::adversarial_cancel::{
    UploadCancelReconcileInput, exercise_production_upload_cancellation_and_stale_reconciler,
};
use support::adversarial_default_ops::{
    DefaultOpClientInput, exercise_unmodified_client_default_operation_replay_and_canonical_repair,
};
use support::multi_instance_auth_boundary::{
    MultiInstanceAuthInput, exercise_post_auth_pending_multi_instance_active_lease_and_atomic_commit_auth,
};
use support::{
    LoopbackS3, RunningProdLfsServer, copy_dir_recursive, init_git_lfs_home, issue_actor, run_git_ok, run_git_raw,
    run_with_migrated_pg_schema,
};
use tempfile::TempDir;
use uuid::Uuid;

fn dummy_lazy_pool() -> Result<Pool> {
    let cfg: tokio_postgres::Config = "postgres://postgres@127.0.0.1:9/unreached".parse()?;
    Ok(Pool::builder(Manager::new(cfg, tokio_postgres::NoTls))
        .runtime(deadpool_postgres::Runtime::Tokio1)
        .max_size(2)
        .build()?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unconfigured_blob_gate_fails_closed_on_startup_and_every_lfs_or_git_endpoint() -> Result<()> {
    let gate = LfsBlobRuntimeGate::unconfigured("ROOTYARD_BLOB_ENDPOINT absent");
    let Err(gate_err) = gate.require_store() else {
        anyhow::bail!("unconfigured gate must fail closed");
    };
    assert_eq!(gate_err.code, LfsProofRejectCode::RemoteBlobUnconfigured);

    let srv =
        RunningProdLfsServer::start(gate, dummy_lazy_pool()?, "postgres://postgres@127.0.0.1:9/unreached").await?;
    let cli = reqwest::Client::new();

    let batch_res = cli
        .post(format!("{}/alice/engine.git/info/lfs/objects/batch", srv.base_url))
        .header("Accept", "application/vnd.git-lfs+json")
        .header("Content-Type", "application/vnd.git-lfs+json")
        .json(&json!({ "operation": "upload", "objects": [{ "oid": "a".repeat(64), "size": 12 }] }))
        .send()
        .await?;
    ensure!(batch_res.status() == StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = batch_res.json().await?;
    ensure!(body["code"] == "remote_blob_unconfigured");

    let put_res = cli
        .put(format!("{}/alice/engine.git/info/lfs/objects/{}/12", srv.base_url, "a".repeat(64)))
        .body("0123456789ab")
        .send()
        .await?;
    ensure!(put_res.status() == StatusCode::SERVICE_UNAVAILABLE);

    let locks_res = cli.get(format!("{}/alice/engine.git/info/lfs/locks", srv.base_url)).send().await?;
    ensure!(locks_res.status() == StatusCode::SERVICE_UNAVAILABLE);

    let del_res =
        cli.delete(format!("{}/alice/engine.git/info/lfs/objects/{}", srv.base_url, "a".repeat(64))).send().await?;
    ensure!(del_res.status() == StatusCode::SERVICE_UNAVAILABLE);

    let refs_res =
        cli.get(format!("{}/alice/engine.git/info/refs?service=git-receive-pack", srv.base_url)).send().await?;
    ensure!(refs_res.status() == StatusCode::SERVICE_UNAVAILABLE);
    Ok(())
}

#[test]
#[ignore = "requires PostgreSQL 17 (ROOTYARD_TEST_DATABASE_URL) and official git-lfs client"]
fn pg17_loopback_s3_official_git_lfs_batch_locks_delete_recovery_and_shared_holds() -> Result<()> {
    std::thread::Builder::new()
        .name("s4-lfs-e2e-main".into())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| -> Result<()> {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .thread_stack_size(16 * 1024 * 1024)
                .enable_all()
                .build()?;
            rt.block_on(Box::pin(run_pg17_loopback_s3_e2e()))
        })?
        .join()
        .map_err(|_| anyhow::anyhow!("s4-lfs-e2e-main thread panicked"))?
}

async fn run_pg17_loopback_s3_e2e() -> Result<()> {
    run_with_migrated_pg_schema(|pool, schema_url| async move {
        let home_dir = TempDir::new()?;
        init_git_lfs_home(home_dir.path())?;
        let s3 = LoopbackS3::shared();

        for (idx, fmt) in [(1usize, GitObjectFormat::Sha1), (2usize, GitObjectFormat::Sha256)] {
            s3.set_fail_503(false);
            let root_prefix = format!("lfs145-fmt{idx}-{}", &Uuid::new_v4().simple().to_string()[..8]);
            let store = s3.open_store(&root_prefix)?;
            let pg = PgLfsBlobStore::new(pool.clone());

            let alice = issue_actor(&pool, if idx == 1 { "alice" } else { "alice256" }).await?;
            let bob = issue_actor(&pool, if idx == 1 { "bob" } else { "bob256" }).await?;
            let carol = issue_actor(&pool, if idx == 1 { "carol" } else { "carol256" }).await?;
            let mallory = issue_actor(&pool, if idx == 1 { "mallory" } else { "mallory256" }).await?;

            let fmt_str = match fmt {
                GitObjectFormat::Sha1 => "sha1",
                GitObjectFormat::Sha256 => "sha256",
            };
            let gate = LfsBlobRuntimeGate::configured(store.clone());
            let srv = RunningProdLfsServer::start(gate.clone(), pool.clone(), &schema_url).await?;
            let (repo_id, _owner_id) = srv.create_repo(&alice, None, "engine", fmt_str).await?;
            srv.put_collaborator(&alice, &alice.username, "engine", &bob.username, "write").await?;
            srv.put_collaborator(&alice, &alice.username, "engine", &carol.username, "read").await?;
            let realm = pg.ensure_realm_for_repository(repo_id, &srv.state.storage.root).await?;

            let alice_url = srv.git_url_for(&alice, &alice.username, "engine");
            let bob_url = srv.git_url_for(&bob, &alice.username, "engine");
            let carol_url = srv.git_url_for(&carol, &alice.username, "engine");
            let cli = reqwest::Client::new();

            // Unrelated `mallory` and read-only `carol` (on upload) receive `403 unauthorized_collaborator`!
            for denied_actor in [&mallory, &carol] {
                let denied_res = cli
                    .post(format!("{}/{}/engine.git/info/lfs/objects/batch", srv.base_url, alice.username))
                    .basic_auth(&denied_actor.username, Some(&denied_actor.token))
                    .header("Accept", "application/vnd.git-lfs+json")
                    .header("Content-Type", "application/vnd.git-lfs+json")
                    .json(&json!({ "operation": "upload", "objects": [{ "oid": "b".repeat(64), "size": 16 }] }))
                    .send()
                    .await?;
                ensure!(denied_res.status() == StatusCode::FORBIDDEN);
                let denied_json: Value = denied_res.json().await?;
                ensure!(denied_json["code"] == "unauthorized_collaborator", "got {denied_json}");
            }

            // 1. Official `git-lfs` track + push by owner `alice` with explicit `X-Rootyard-Operation-Id`.
            let alice_wt = TempDir::new()?;
            run_git_ok(
                alice_wt.path(),
                home_dir.path(),
                &["init", "--initial-branch=main", &format!("--object-format={fmt_str}")],
            )?;
            run_git_ok(alice_wt.path(), home_dir.path(), &["lfs", "install", "--local"])?;
            run_git_ok(alice_wt.path(), home_dir.path(), &["remote", "add", "origin", &alice_url])?;
            run_git_ok(alice_wt.path(), home_dir.path(), &["config", "lfs.locksverify", "true"])?;
            run_git_ok(alice_wt.path(), home_dir.path(), &["lfs", "track", "*.bin"])?;
            let weights_v1: Vec<u8> = (0..131_072u32).map(|n| ((n * 17 + 3) & 0xff) as u8).collect();
            let weights_v1_oid = hex::encode(Sha256::digest(&weights_v1));
            std::fs::write(alice_wt.path().join("weights.bin"), &weights_v1)?;
            std::fs::write(alice_wt.path().join("README.md"), "LFS Blob S4 acceptance\n")?;
            run_git_ok(alice_wt.path(), home_dir.path(), &["add", ".gitattributes", "weights.bin", "README.md"])?;
            run_git_ok(alice_wt.path(), home_dir.path(), &["commit", "-m", "initial LFS weights"])?;
            let first_commit = run_git_ok(alice_wt.path(), home_dir.path(), &["rev-parse", "HEAD"])?;
            let push_op_tok = format!("op-initial-push-{idx}");
            run_git_ok(
                alice_wt.path(),
                home_dir.path(),
                &[
                    "-c",
                    &format!("http.extraHeader=X-Rootyard-Operation-Id: {push_op_tok}"),
                    "push",
                    "-u",
                    "origin",
                    "main",
                ],
            )?;

            // Local `data_dir/lfs` must NEVER be created; durable `LfsPointerAttestation` must exist!
            ensure!(!srv.state.storage.root.join("lfs").exists(), "production S4 mode must write zero local LFS files");
            let initial_att = pg
                .load_attestation(realm.repository_id, operation_token_to_uuid(&push_op_tok)?)
                .await?
                .context("initial push attestation")?;
            ensure!(initial_att.pointers.len() == 1 && initial_att.pointers[0].oid_sha256 == weights_v1_oid);
            let committed_v1 = pg
                .load_committed_blob(realm.owner_tenant_id, realm.repository_id, &weights_v1_oid)
                .await?
                .context("v1 committed in PG")?;

            // Remote byte presence (verified via `verify_committed_locator_bytes`) drives Batch `upload` ACK (`actions: None`).
            let ack_res: Value = cli
                .post(format!("{}/{}/engine.git/info/lfs/objects/batch", srv.base_url, alice.username))
                .basic_auth(&alice.username, Some(&alice.token))
                .header("Accept", "application/vnd.git-lfs+json")
                .header("Content-Type", "application/vnd.git-lfs+json")
                .json(&json!({
                    "operation": "upload",
                    "objects": [{ "oid": weights_v1_oid, "size": weights_v1.len() }]
                }))
                .send()
                .await?
                .json()
                .await?;
            ensure!(ack_res["objects"][0].get("actions").is_none(), "expected remote-verified idempotent ACK");

            // Removing bytes from LoopbackS3 forces Batch `upload` to re-request upload (never ACKs from metadata alone).
            let loc_v1 = committed_v1.locator.to_locator()?;
            let raw_saved = s3.take_raw(&root_prefix, &loc_v1).context("s3 object")?;
            let reupload_res: Value = cli
                .post(format!("{}/{}/engine.git/info/lfs/objects/batch", srv.base_url, alice.username))
                .basic_auth(&alice.username, Some(&alice.token))
                .header("Accept", "application/vnd.git-lfs+json")
                .header("Content-Type", "application/vnd.git-lfs+json")
                .json(&json!({
                    "operation": "upload",
                    "objects": [{ "oid": weights_v1_oid, "size": weights_v1.len() }]
                }))
                .send()
                .await?
                .json()
                .await?;
            ensure!(reupload_res["objects"][0]["actions"]["upload"].is_object(), "missing remote bytes must not ACK");
            s3.restore_raw(&root_prefix, &loc_v1, raw_saved);

            // Unreachable S3 (`503`) fails closed with HTTP `503` `remote_blob_unreachable`.
            s3.set_fail_503(true);
            let fail_s3 = cli
                .post(format!("{}/{}/engine.git/info/lfs/objects/batch", srv.base_url, alice.username))
                .basic_auth(&alice.username, Some(&alice.token))
                .header("Accept", "application/vnd.git-lfs+json")
                .header("Content-Type", "application/vnd.git-lfs+json")
                .json(&json!({
                    "operation": "download",
                    "objects": [{ "oid": weights_v1_oid, "size": weights_v1.len() }]
                }))
                .send()
                .await?;
            ensure!(fail_s3.status() == StatusCode::SERVICE_UNAVAILABLE);
            s3.set_fail_503(false);

            // 2. Cross-owner `bob != tenant` clone, `git lfs fetch/pull`, `lock`/`locks`/`locks --verify`/`unlock`, and locked-path enforcement.
            let bob_wt = TempDir::new()?;
            run_git_ok(bob_wt.path(), home_dir.path(), &["clone", &bob_url, "."])?;
            run_git_ok(bob_wt.path(), home_dir.path(), &["lfs", "install", "--local"])?;
            ensure!(std::fs::read(bob_wt.path().join("weights.bin"))? == weights_v1, "bob clone LFS smudge mismatch");
            run_git_ok(bob_wt.path(), home_dir.path(), &["lfs", "fetch", "--all"])?;
            run_git_ok(bob_wt.path(), home_dir.path(), &["lfs", "lock", "weights.bin"])?;
            let locks_list = run_git_ok(bob_wt.path(), home_dir.path(), &["lfs", "locks"])?;
            ensure!(locks_list.contains("weights.bin") && locks_list.contains(&bob.username));
            let locks_verify = run_git_ok(bob_wt.path(), home_dir.path(), &["lfs", "locks", "--verify"])?;
            ensure!(locks_verify.contains('O') && locks_verify.contains("weights.bin"));

            // Read-only `carol` can clone/list locks, but cannot lock or push.
            let carol_wt = TempDir::new()?;
            run_git_ok(carol_wt.path(), home_dir.path(), &["clone", &carol_url, "."])?;
            ensure!(!run_git_raw(carol_wt.path(), home_dir.path(), &["lfs", "lock", "README.md"])?.status.success());
            std::fs::write(carol_wt.path().join("README.md"), "unauthorized edit\n")?;
            run_git_ok(carol_wt.path(), home_dir.path(), &["add", "README.md"])?;
            run_git_ok(carol_wt.path(), home_dir.path(), &["commit", "-m", "carol write attempt"])?;
            ensure!(!run_git_raw(carol_wt.path(), home_dir.path(), &["push", "origin", "main"])?.status.success());

            // Owner `alice` attempting `git rm weights.bin` while `bob` holds lock fails closed on both client & server!
            run_git_ok(alice_wt.path(), home_dir.path(), &["rm", "weights.bin"])?;
            run_git_ok(alice_wt.path(), home_dir.path(), &["commit", "-m", "delete while locked"])?;
            ensure!(!run_git_raw(alice_wt.path(), home_dir.path(), &["push", "origin", "main"])?.status.success());
            let server_locked_rm =
                run_git_raw(alice_wt.path(), home_dir.path(), &["push", "--no-verify", "origin", "main"])?;
            ensure!(!server_locked_rm.status.success());
            ensure!(String::from_utf8_lossy(&server_locked_rm.stderr).contains("locked_path_conflict"));
            run_git_ok(alice_wt.path(), home_dir.path(), &["reset", "--hard", "HEAD~1"])?;

            // `bob` unlocks `weights.bin`, pushes updated LFS v2 on a branch, then deletes `weights.bin` on `main` & deletes branch!
            run_git_ok(bob_wt.path(), home_dir.path(), &["lfs", "unlock", "weights.bin"])?;
            run_git_ok(bob_wt.path(), home_dir.path(), &["checkout", "-b", "temp-lfs-branch"])?;
            let weights_v2: Vec<u8> = (0..65_536u32).map(|n| ((n * 29 + 11) & 0xff) as u8).collect();
            std::fs::write(bob_wt.path().join("weights.bin"), &weights_v2)?;
            run_git_ok(bob_wt.path(), home_dir.path(), &["add", "weights.bin"])?;
            run_git_ok(bob_wt.path(), home_dir.path(), &["commit", "-m", "bob v2 LFS push"])?;
            run_git_ok(bob_wt.path(), home_dir.path(), &["push", "-u", "origin", "temp-lfs-branch"])?;
            run_git_ok(bob_wt.path(), home_dir.path(), &["checkout", "main"])?;
            run_git_ok(bob_wt.path(), home_dir.path(), &["rm", "weights.bin"])?;
            run_git_ok(bob_wt.path(), home_dir.path(), &["commit", "-m", "delete weights.bin after unlock"])?;
            run_git_ok(bob_wt.path(), home_dir.path(), &["push", "origin", "main"])?;
            run_git_ok(bob_wt.path(), home_dir.path(), &["push", "origin", "--delete", "temp-lfs-branch"])?;

            Box::pin(exercise_unmodified_client_default_operation_replay_and_canonical_repair(DefaultOpClientInput {
                srv: &srv,
                s3,
                root_prefix: &root_prefix,
                pg: &pg,
                realm: &realm,
                alice: &alice,
                home: home_dir.path(),
            }))
            .await?;

            if idx == 1 {
                let _ = Box::pin(exercise_same_operation_upload_retries_locator_repair_and_corruption_guard(
                    UploadRetryRepairInput {
                        srv: &srv,
                        s3,
                        root_prefix: &root_prefix,
                        gate: &gate,
                        pg: &pg,
                        realm: &realm,
                        alice: &alice,
                    },
                ))
                .await?;
                Box::pin(exercise_named_pointer_rejections_and_prod_attestation_replay(PointerRejectionInput {
                    srv: &srv,
                    pg: &pg,
                    realm: &realm,
                    alice: &alice,
                    home: home_dir.path(),
                    committed_oid: &weights_v1_oid,
                    committed_size: weights_v1.len() as i64,
                }))
                .await?;

                let cancel_inp =
                    UploadCancelReconcileInput { srv: &srv, pool: &pool, pg: &pg, realm: &realm, alice: &alice };
                Box::pin(exercise_production_upload_cancellation_and_stale_reconciler(cancel_inp)).await?;
                Box::pin(exercise_post_auth_pending_multi_instance_active_lease_and_atomic_commit_auth(
                    MultiInstanceAuthInput {
                        s3,
                        root_prefix: &root_prefix,
                        pool: &pool,
                        db_url: &schema_url,
                        realm: &realm,
                        alice: &alice,
                    },
                ))
                .await?;

                let saved_repos = TempDir::new()?;
                copy_dir_recursive(&srv.state.storage.root.join("repos"), saved_repos.path())?;
                drop(srv);
                Box::pin(exercise_org_authority_restart_recovery_hydration_and_shared_holds(
                    OrgRestartSharedHoldInput {
                        s3,
                        root_prefix: &root_prefix,
                        pool: &pool,
                        db_url: &schema_url,
                        pg: &pg,
                        realm: &realm,
                        alice: &alice,
                        bob: &bob,
                        prev_repos_dir: saved_repos.path(),
                        home: home_dir.path(),
                        historical_commit: &first_commit,
                        shared_oid: &weights_v1_oid,
                        shared_bytes: &weights_v1,
                    },
                ))
                .await?;
            }
        }
        Ok(())
    })
    .await
}
