//! Integration & official `git-lfs` E2E tests for Issue #145 (`Refs #145`).

#[path = "lfs_blob_proof_support/mod.rs"]
mod support;

use anyhow::{Context, Result, ensure};
use deadpool_postgres::{Manager, Pool};
use reqwest::StatusCode;
use rootyard::lfs::blob_proof_publication::{
    LfsBlobRuntimeGate, LfsCollaboratorRole, LfsProofRejectCode, PgLfsBlobStore,
};
use rootyard::ref_store::GitObjectFormat;
use serde_json::json;
use sha2::{Digest, Sha256};
use support::adversarial::{
    PointerRejectionInput, RestartSharedHoldInput, exercise_concurrent_uploads_and_corrupt_retries,
    exercise_named_pointer_rejections_and_attestation_replay, exercise_restart_recovery_hydration_and_shared_holds,
};
use support::{
    LoopbackS3, RunningLfsServer, init_bare_git_repo, init_git_lfs_home, run_git_ok, run_git_raw,
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

#[tokio::test]
async fn unconfigured_blob_gate_fails_closed_on_startup_and_every_lfs_or_git_endpoint() -> Result<()> {
    let gate = LfsBlobRuntimeGate::unconfigured("ROOTYARD_BLOB_ENDPOINT absent");
    let Err(gate_err) = gate.require_store() else {
        anyhow::bail!("unconfigured gate must fail closed");
    };
    assert_eq!(gate_err.code, LfsProofRejectCode::RemoteBlobUnconfigured);

    let pg = PgLfsBlobStore::new(dummy_lazy_pool()?);
    let srv = RunningLfsServer::start(gate, pg).await?;
    assert_eq!(srv.svc.base_url(), srv.base_url);
    let cli = reqwest::Client::new();

    let batch_res = cli
        .post(format!("{}/alice/engine.git/info/lfs/objects/batch", srv.base_url))
        .basic_auth("alice", Some("tok"))
        .json(&json!({ "operation": "upload", "objects": [{ "oid": "a".repeat(64), "size": 12 }] }))
        .send()
        .await?;
    ensure!(batch_res.status() == StatusCode::SERVICE_UNAVAILABLE);
    let body: serde_json::Value = batch_res.json().await?;
    ensure!(body["code"] == "remote_blob_unconfigured");

    let locks_res = cli
        .get(format!("{}/alice/engine.git/info/lfs/locks", srv.base_url))
        .basic_auth("alice", Some("tok"))
        .send()
        .await?;
    ensure!(locks_res.status() == StatusCode::SERVICE_UNAVAILABLE);

    let refs_res = cli
        .get(format!("{}/alice/engine.git/info/refs?service=git-receive-pack", srv.base_url))
        .basic_auth("alice", Some("tok"))
        .send()
        .await?;
    ensure!(refs_res.status() == StatusCode::SERVICE_UNAVAILABLE);
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL 17 (ROOTYARD_TEST_DATABASE_URL) and official git-lfs client"]
async fn pg17_loopback_s3_official_git_lfs_batch_locks_delete_recovery_and_shared_holds() -> Result<()> {
    run_with_migrated_pg_schema(|pool| async move {
        let home_dir = TempDir::new()?;
        init_git_lfs_home(home_dir.path())?;
        let s3 = LoopbackS3::shared();

        for (idx, fmt) in [(1usize, GitObjectFormat::Sha1), (2usize, GitObjectFormat::Sha256)] {
            s3.set_fail_503(false);
            let root_prefix = format!("lfs145-fmt{idx}-{}", &Uuid::new_v4().simple().to_string()[..8]);
            let store = s3.open_store(&root_prefix)?;
            let pg = PgLfsBlobStore::new(pool.clone());

            let alice_name = if idx == 1 { "alice" } else { "alice256" };
            let bob_name = if idx == 1 { "bob" } else { "bob256" };
            let carol_name = if idx == 1 { "carol" } else { "carol256" };
            let alice_sec = if idx == 1 { "alice-tok" } else { "alice256-tok" };
            let bob_sec = if idx == 1 { "bob-tok" } else { "bob256-tok" };
            let carol_sec = if idx == 1 { "carol-tok" } else { "carol256-tok" };

            let alice = pg.register_principal(Uuid::new_v4(), alice_name, alice_sec).await?;
            let bob = pg.register_principal(Uuid::new_v4(), bob_name, bob_sec).await?;
            let carol = pg.register_principal(Uuid::new_v4(), carol_name, carol_sec).await?;

            let bare_dir = TempDir::new()?;
            let fmt_str = match fmt {
                GitObjectFormat::Sha1 => "sha1",
                GitObjectFormat::Sha256 => "sha256",
            };
            init_bare_git_repo(bare_dir.path(), fmt_str)?;
            let realm = pg
                .provision_repository(
                    Uuid::new_v4(),
                    alice.actor_id,
                    &alice.username,
                    "engine",
                    fmt,
                    bare_dir.path().to_str().context("utf8 path")?,
                )
                .await?;
            pg.grant_collaborator(realm.repository_id, bob.actor_id, LfsCollaboratorRole::Write).await?;
            pg.grant_collaborator(realm.repository_id, carol.actor_id, LfsCollaboratorRole::Read).await?;

            let gate = LfsBlobRuntimeGate::configured(store.clone());
            let srv = RunningLfsServer::start(gate.clone(), pg.clone()).await?;
            let alice_url = format!("{}/{}/engine.git", srv.base_url, alice.username)
                .replacen("http://", &format!("http://{}:{alice_sec}@", alice.username));
            let bob_url = format!("{}/{}/engine.git", srv.base_url, alice.username)
                .replacen("http://", &format!("http://{}:{bob_sec}@", bob.username));
            let carol_url = format!("{}/{}/engine.git", srv.base_url, alice.username)
                .replacen("http://", &format!("http://{}:{carol_sec}@", carol.username));

            // 1. Official `git-lfs` track + push by owner `alice`.
            let alice_wt = TempDir::new()?;
            run_git_ok(
                alice_wt.path(),
                home_dir.path(),
                &["init", "--initial-branch=main", &format!("--object-format={fmt_str}")],
            )?;
            run_git_ok(alice_wt.path(), home_dir.path(), &["lfs", "install", "--local"])?;
            run_git_ok(alice_wt.path(), home_dir.path(), &["remote", "add", "origin", &alice_url])?;
            run_git_ok(alice_wt.path(), home_dir.path(), &["lfs", "track", "*.bin"])?;
            let weights_v1: Vec<u8> = (0..131_072u32).map(|n| ((n * 17 + 3) & 0xff) as u8).collect();
            let weights_v1_oid = hex::encode(Sha256::digest(&weights_v1));
            std::fs::write(alice_wt.path().join("weights.bin"), &weights_v1)?;
            std::fs::write(alice_wt.path().join("README.md"), "LFS Blob S4 acceptance\n")?;
            run_git_ok(alice_wt.path(), home_dir.path(), &["add", ".gitattributes", "weights.bin", "README.md"])?;
            run_git_ok(alice_wt.path(), home_dir.path(), &["commit", "-m", "initial LFS weights"])?;
            let first_commit = run_git_ok(alice_wt.path(), home_dir.path(), &["rev-parse", "HEAD"])?;
            run_git_ok(alice_wt.path(), home_dir.path(), &["push", "-u", "origin", "main"])?;

            // Scratch dir must retain ZERO durable files: all bytes live solely in remote OpenDAL S3!
            ensure!(std::fs::read_dir(srv.scratch_dir.path())?.count() == 0, "scratch_dir leaked local files");
            let committed_v1 = pg
                .load_committed_blob(realm.owner_tenant_id, realm.repository_id, &weights_v1_oid)
                .await?
                .context("v1 committed in PG")?;

            // Remote byte presence (never local disk) drives Batch `upload` idempotent ACK (`actions: None`).
            let cli = reqwest::Client::new();
            let ack_res: serde_json::Value = cli
                .post(format!("{}/{}/engine.git/info/lfs/objects/batch", srv.base_url, alice.username))
                .basic_auth(&alice.username, Some(alice_sec))
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
            let reupload_res: serde_json::Value = cli
                .post(format!("{}/{}/engine.git/info/lfs/objects/batch", srv.base_url, alice.username))
                .basic_auth(&alice.username, Some(alice_sec))
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
                .basic_auth(&alice.username, Some(alice_sec))
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
            ensure!(locks_verify.contains("O") && locks_verify.contains("weights.bin"));

            // Read-only `carol` can clone/list locks, but cannot lock or push (`403 unauthorized_collaborator`).
            let carol_wt = TempDir::new()?;
            run_git_ok(carol_wt.path(), home_dir.path(), &["clone", &carol_url, "."])?;
            ensure!(!run_git_raw(carol_wt.path(), home_dir.path(), &["lfs", "lock", "README.md"])?.status.success());
            std::fs::write(carol_wt.path().join("README.md"), "unauthorized edit\n")?;
            run_git_ok(carol_wt.path(), home_dir.path(), &["add", "README.md"])?;
            run_git_ok(carol_wt.path(), home_dir.path(), &["commit", "-m", "carol write attempt"])?;
            ensure!(!run_git_raw(carol_wt.path(), home_dir.path(), &["push", "origin", "main"])?.status.success());

            // Owner `alice` attempting `git rm weights.bin` while `bob` holds lock fails closed with `locked_path_conflict`!
            run_git_ok(alice_wt.path(), home_dir.path(), &["rm", "weights.bin"])?;
            run_git_ok(alice_wt.path(), home_dir.path(), &["commit", "-m", "delete while locked"])?;
            let locked_rm = run_git_raw(alice_wt.path(), home_dir.path(), &["push", "origin", "main"])?;
            ensure!(!locked_rm.status.success(), "deleting locked path must be rejected");
            ensure!(String::from_utf8_lossy(&locked_rm.stderr).contains("locked_path_conflict"));
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

            if idx == 1 {
                let _ = exercise_concurrent_uploads_and_corrupt_retries(
                    &gate,
                    &pg,
                    &realm,
                    alice.actor_id,
                    srv.scratch_dir.path(),
                )
                .await?;
                exercise_named_pointer_rejections_and_attestation_replay(PointerRejectionInput {
                    srv: &srv,
                    gate: &gate,
                    pg: &pg,
                    realm: &realm,
                    home: home_dir.path(),
                    committed_oid: &weights_v1_oid,
                    committed_size: weights_v1.len() as i64,
                })
                .await?;
                drop(srv);
                exercise_restart_recovery_hydration_and_shared_holds(RestartSharedHoldInput {
                    s3,
                    root_prefix: &root_prefix,
                    pg: &pg,
                    realm: &realm,
                    fmt,
                    home: home_dir.path(),
                    historical_commit: &first_commit,
                    shared_oid: &weights_v1_oid,
                    shared_bytes: &weights_v1,
                })
                .await?;
            }
        }
        Ok(())
    })
    .await
}
