//! End-to-end PostgreSQL 17 + `LoopbackS3` + `blob_git_gateway::router` acceptance for:
//! 1. Authoritative PG `sequence` binding + durable `CausalPushProofReceipt` replay across process restart
//! 2. Production HTTP `receive-pack` object-level causal closure refusal before CAS
//! 3. All `0..=8` `.pack`/`.idx` pair recording + production remote partial/rejected pack sweep (#183).

use std::path::Path;
use std::time::Duration;

use anyhow::{Result, anyhow, ensure};
use axum::http::{StatusCode, header};
use deadpool_postgres::Pool;
use rootyard::blob_store::opendal::BlobStore;
use rootyard::namespace_service::push_causal_stream::*;
use rootyard::ref_store::core::artifact_hold::{
    AcquireArtifactHoldsRequest, AcquireOutcome, ArtifactHoldPurpose, ArtifactSpec, HoldScope, PgArtifactHoldStore,
    ProtectedUploader, UploadSource,
};
use rootyard::ref_store::serving::lookup;
use rootyard::ref_store::{IssuerLane, OperationIdentity, PgRefStore, RequestDigest};
use tempfile::TempDir;
use tokio::time::Instant as TokioInstant;
use uuid::Uuid;

use super::pg_http_gateway::{LiveGateway, PgActor, base64_basic, create_and_provision_repo, git_http};
use super::support::{LoopbackS3, build_receive_wire, mk_commit, run_git};

pub struct RestartReclaimSuiteEnv<'a> {
    pub pool: &'a Pool,
    pub store: &'a BlobStore,
    pub s3: &'a LoopbackS3,
    pub actor: &'a PgActor,
    pub git_binary: &'a Path,
    pub backend_hex: &'a str,
}

pub async fn exercise_restart_replay_causal_negatives_and_multipack_sweep(
    env: RestartReclaimSuiteEnv<'_>,
) -> Result<()> {
    configure_gateway_remote_reclaim_s3(
        env.backend_hex,
        RemoteS3ReclaimConfig {
            endpoint: env.s3.endpoint.clone(),
            bucket: "push-causal-bucket".into(),
            region: "us-east-1".into(),
            root: "push-causal-it".into(),
            access_key_id: "test-ak".into(),
            secret_access_key: "test-sk".into(),
        },
    )?;
    let res = run_suite_inner(&env).await;
    clear_gateway_remote_reclaim_s3(env.backend_hex);
    res
}

async fn run_suite_inner(env: &RestartReclaimSuiteEnv<'_>) -> Result<()> {
    let gw1 = LiveGateway::start(env.pool.clone(), env.store.clone(), Duration::from_secs(60)).await?;
    let repo_name = format!("restart-{}", &Uuid::new_v4().simple().to_string()[..8]);
    let repo_id = create_and_provision_repo(gw1.addr, env.pool, env.store, env.actor, &repo_name, "sha1").await?;
    let remote1 = format!(
        "http://{}:{}@{}/git/{}/{repo_name}.git",
        env.actor.username, env.actor.token, gw1.addr, env.actor.username
    );

    let tmp = TempDir::new()?;
    let work = tmp.path().join("work");
    git_http(tmp.path(), &["clone", "--no-hardlinks", &remote1, work.to_str().unwrap()]).await?;
    let base_body = "causal-restart-shared-delta-line-\n".repeat(120);
    let c1 = mk_commit(&work, "f.txt", &base_body, "c1")?;
    let op1 = Uuid::new_v4();
    git_http(
        &work,
        &["-c", &format!("http.extraHeader=X-Rootyard-Operation: {op1}"), "push", "origin", "HEAD:refs/heads/main"],
    )
    .await?;
    let rec1 = recent_gateway_push_receipt(op1).ok_or_else(|| anyhow!("missing op1 receipt"))?;
    ensure!(rec1.sequence == 1 && rec1.object_count >= 3 && rec1.pack_pairs.len() == 1);

    // Build raw receive-pack wire for push #2 (`c1 -> c2`, PG sequence == 2!) so we can replay the exact bytes after restart.
    let c2 = mk_commit(&work, "f.txt", &format!("{base_body}v2-thin-delta\n"), "c2")?;
    let thin_pack2 = run_git(
        &work,
        &["--no-pager", "pack-objects", "--revs", "--thin", "--stdout"],
        Some(format!("{c2}\n^{c1}\n").as_bytes()),
    )?;
    let wire2 = build_receive_wire(&[(c1.as_str(), c2.as_str(), "refs/heads/main")], "report-status", &thin_pack2);
    let op2 = Uuid::new_v4();
    let auth_hdr = format!("Basic {}", base64_basic(&env.actor.username, &env.actor.token));
    let url1 = format!("http://{}/git/{}/{repo_name}.git/git-receive-pack", gw1.addr, env.actor.username);

    let (st2, body2) = post_receive(&url1, &auth_hdr, op2, wire2.clone()).await?;
    ensure!(st2 == StatusCode::OK && String::from_utf8_lossy(&body2).contains("ok refs/heads/main\n"));
    let rec2_before = recent_gateway_push_receipt(op2).ok_or_else(|| anyhow!("missing op2 receipt before restart"))?;
    rec2_before.verify_digest()?;
    ensure!(rec2_before.sequence == 2, "expected PG sequence 2 on second push, got {}", rec2_before.sequence);
    ensure!(rec2_before.lane == "blob-git-receive", "expected PG lane blob-git-receive, got {}", rec2_before.lane);
    ensure!(rec2_before.base_snapshot_seq == 2 && rec2_before.committed_gate_revision == Some(3));
    ensure!(rec2_before.object_count >= 3 && rec2_before.pack_pairs.len() == 1);
    ensure!(
        rec2_before.required_ancestor_oids == vec![c1.clone()],
        "ancestors={:?}",
        rec2_before.required_ancestor_oids
    );

    // Advance live repository further (`c2 -> c3`, sequence == 3, gate revision -> 4) BEFORE restarting!
    git_http(&work, &["fetch", "origin"]).await?;
    let c3 = mk_commit(&work, "f.txt", &format!("{base_body}v2-thin-delta\nv3\n"), "c3")?;
    let op3 = Uuid::new_v4();
    git_http(
        &work,
        &["-c", &format!("http.extraHeader=X-Rootyard-Operation: {op3}"), "push", "origin", "HEAD:refs/heads/main"],
    )
    .await?;
    let rec3 = recent_gateway_push_receipt(op3).ok_or_else(|| anyhow!("missing op3 receipt"))?;
    ensure!(rec3.sequence == 3 && rec3.committed_gate_revision == Some(4));

    // 1. FULL SERVER RESTART: stop gw1, wipe scratch + reclaim dir + in-memory receipt ring, boot fresh gw2.
    let gw1_reclaim = gateway_reclaim_ledger_dir_for_scratch(gw1.scratch.path());
    let _ = gw1.stop.send(());
    drop(gw1);
    let _ = std::fs::remove_dir_all(&gw1_reclaim);
    clear_observed_gateway_receipts();
    ensure!(recent_gateway_push_receipt(op2).is_none(), "in-memory receipt ring must be empty after restart");

    let gw2 = LiveGateway::start(env.pool.clone(), env.store.clone(), Duration::from_secs(60)).await?;
    let url2 = format!("http://{}/git/{}/{repo_name}.git/git-receive-pack", gw2.addr, env.actor.username);

    // Replay `op2` over HTTP against fresh `gw2` (`Claim::Replay`): must rebuild byte-identical `CausalPushProofReceipt`!
    let (st2_rep, body2_rep) = post_receive(&url2, &auth_hdr, op2, wire2).await?;
    ensure!(st2_rep == StatusCode::OK && body2_rep == body2, "HTTP replay wire mismatch across restart");
    let rec2_after =
        recent_gateway_push_receipt(op2).ok_or_else(|| anyhow!("missing op2 receipt after HTTP replay"))?;
    rec2_after.verify_digest()?;
    ensure!(rec2_after == rec2_before, "replayed CausalPushProofReceipt differed after server restart");

    clear_observed_gateway_receipts();
    let dl = TokioInstant::now() + Duration::from_secs(30);
    let direct_loaded = load_durable_gateway_push_receipt(&DurableGatewayReceiptArgs {
        pool: env.pool,
        store: env.store,
        git_binary: env.git_binary,
        scratch_root: None,
        repository_id: repo_id,
        operation_id: op2,
        deadline: dl,
    })
    .await?
    .ok_or_else(|| anyhow!("load_durable_gateway_push_receipt returned None"))?;
    ensure!(direct_loaded == rec2_before && direct_loaded.sequence == 2);

    // 2. HTTP NEGATIVE TEST: unresolved causal parent / thin-pack base outside verified snapshot closure fails closed BEFORE CAS.
    let rogue = tmp.path().join("rogue");
    run_git(tmp.path(), &["init", "-b", "main", rogue.to_str().unwrap()], None)?;
    let unpushed_parent = mk_commit(&rogue, "secret.txt", &"unpushed-base-payload-\n".repeat(80), "unpushed")?;
    let orphan_tip =
        mk_commit(&rogue, "secret.txt", &format!("{}child-delta\n", "unpushed-base-payload-\n".repeat(80)), "child")?;
    let bad_thin_pack = run_git(
        &rogue,
        &["--no-pager", "pack-objects", "--revs", "--thin", "--stdout"],
        Some(format!("{orphan_tip}\n^{unpushed_parent}\n").as_bytes()),
    )?;
    let bad_wire =
        build_receive_wire(&[(c3.as_str(), orphan_tip.as_str(), "refs/heads/main")], "report-status", &bad_thin_pack);
    let op_bad = Uuid::new_v4();
    let (st_bad, _) = post_receive(&url2, &auth_hdr, op_bad, bad_wire).await?;
    ensure!(st_bad == StatusCode::BAD_REQUEST, "expected 400 Bad Request on unresolved base dependency, got {st_bad}");
    ensure!(
        recent_gateway_causal_rejection(op_bad).is_some(),
        "expected causal prover rejection diagnostic for {op_bad}"
    );
    let db_c = env.pool.get().await?;
    let bad_ops: i64 = db_c
        .query_one(
            "SELECT COUNT(*) FROM ref_store_operations WHERE repository_id=$1 AND operation_id=$2",
            &[&repo_id, &op_bad],
        )
        .await?
        .get(0);
    let bad_holds: i64 = db_c
        .query_one(
            "SELECT COUNT(*) FROM artifact_holds WHERE repository_id=$1 AND operation_id=$2",
            &[&repo_id, &op_bad],
        )
        .await?
        .get(0);
    ensure!(bad_ops == 0 && bad_holds == 0, "causal prover refusal must fail before CAS and hold admission");

    // 3A. REJECTED HTTP PUSH REMOTE SWEEP: stale-CAS push built on `c1` passes causal closure, uploads `.pack`+`.idx` to S3, gets rejected (`200 OK` `ng`), and sweeps 100% of remote staging blobs.
    let stale_work = tmp.path().join("stale-work");
    let remote2 = format!(
        "http://{}:{}@{}/git/{}/{repo_name}.git",
        env.actor.username, env.actor.token, gw2.addr, env.actor.username
    );
    git_http(tmp.path(), &["clone", "--no-hardlinks", &remote2, stale_work.to_str().unwrap()]).await?;
    run_git(&stale_work, &["reset", "--hard", &c1], None)?;
    let c_stale = mk_commit(&stale_work, "stale.txt", "stale-branch-content\n", "stale")?;
    let stale_pack = run_git(
        &stale_work,
        &["--no-pager", "pack-objects", "--revs", "--stdout"],
        Some(format!("{c_stale}\n^{c1}\n").as_bytes()),
    )?;
    let stale_wire =
        build_receive_wire(&[(c1.as_str(), c_stale.as_str(), "refs/heads/main")], "report-status", &stale_pack);
    let op_stale = Uuid::new_v4();
    let (st_stale, body_stale) = post_receive(&url2, &auth_hdr, op_stale, stale_wire).await?;
    ensure!(
        st_stale == StatusCode::OK && String::from_utf8_lossy(&body_stale).contains("ng refs/heads/main stale info\n")
    );
    let (stale_paths, _) = query_operation_hold_blob_paths(env.pool, repo_id, op_stale, dl).await?;
    ensure!(stale_paths.len() == 2, "expected 2 uploaded hold paths for rejected push, got {}", stale_paths.len());
    assert_s3_paths_swept(env.s3, &stale_paths)?;
    let gw2_ledger = open_gateway_reclaim_ledger(gw2.scratch.path()).map_err(|e| anyhow!("{e:?}"))?;
    ensure!(gw2_ledger.load(op_stale)?.unwrap().state == UploadReclaimState::ReclaimedAfterAbort);

    // 3B. MULTI-PAIR (`3` pairs = `6` S3 objects!) PARTIAL/ABORTED UPLOAD RECOVERY SWEEP ON NEXT GATEWAY REQUEST:
    let op_multi = stage_three_aborted_pairs_in_s3_and_ledger(env, gw2.scratch.path(), repo_id, &repo_name).await?;
    let (multi_paths, _) = query_operation_hold_blob_paths(env.pool, repo_id, op_multi, dl).await?;
    ensure!(multi_paths.len() == 6, "expected 6 S3 objects across 3 pack/idx pairs, got {}", multi_paths.len());
    for p in &multi_paths {
        let key = format!("push-causal-bucket/push-causal-it/{p}");
        ensure!(env.s3.objects.lock().unwrap().contains_key(&key), "expected staged S3 key before sweep: {key}");
    }

    // First verify default-off (`BlobDeletePolicy::Disabled`) performs ZERO provider deletes while preserving ledger!
    clear_gateway_remote_reclaim_s3(env.backend_hex);
    let replay_wire =
        build_receive_wire(&[(c1.as_str(), c2.as_str(), "refs/heads/main")], "report-status", &thin_pack2);
    let (st_off, _) = post_receive(&url2, &auth_hdr, op2, replay_wire.clone()).await?;
    ensure!(st_off == StatusCode::OK);
    for p in &multi_paths {
        let key = format!("push-causal-bucket/push-causal-it/{p}");
        ensure!(env.s3.objects.lock().unwrap().contains_key(&key), "default-off must NOT delete S3 key: {key}");
    }
    ensure!(gw2_ledger.load(op_multi)?.unwrap().needs_recovery(), "default-off must retain recoverable ledger record");

    // Re-arm explicit S3 reclaim operator and verify next receive-pack sweeps all 6/6 S3 objects!
    configure_gateway_remote_reclaim_s3(
        env.backend_hex,
        RemoteS3ReclaimConfig {
            endpoint: env.s3.endpoint.clone(),
            bucket: "push-causal-bucket".into(),
            region: "us-east-1".into(),
            root: "push-causal-it".into(),
            access_key_id: "test-ak".into(),
            secret_access_key: "test-sk".into(),
        },
    )?;
    let (st_trig, _) = post_receive(&url2, &auth_hdr, op2, replay_wire).await?;
    ensure!(st_trig == StatusCode::OK);
    assert_s3_paths_swept(env.s3, &multi_paths)?;
    let multi_rec = gw2_ledger.load(op_multi)?.ok_or_else(|| anyhow!("missing multi-pair reclaim record"))?;
    ensure!(multi_rec.staged_pairs.len() == 3 && multi_rec.recorded_blob_paths.len() == 6);
    ensure!(multi_rec.state == UploadReclaimState::ReclaimedAfterAbort);

    // Verify committed repository packs are 100% intact via fresh clone + `git fsck --full --strict`.
    let verify_clone = tmp.path().join("verify-clone");
    git_http(tmp.path(), &["clone", "--no-hardlinks", &remote2, verify_clone.to_str().unwrap()]).await?;
    let head_oid = String::from_utf8(run_git(&verify_clone, &["rev-parse", "HEAD"], None)?)?.trim().to_owned();
    ensure!(head_oid == c3, "expected HEAD == {c3} after sweeps, got {head_oid}");
    run_git(&verify_clone, &["fsck", "--full", "--strict"], None)?;

    let _ = gw2.stop.send(());
    Ok(())
}

async fn stage_three_aborted_pairs_in_s3_and_ledger(
    env: &RestartReclaimSuiteEnv<'_>,
    scratch_root: &Path,
    repo_id: Uuid,
    repo_name: &str,
) -> Result<Uuid> {
    let dl = TokioInstant::now() + Duration::from_secs(30);
    let serving =
        lookup(env.pool, &env.actor.identity, &env.actor.username, repo_name, true, env.store.backend_identity(), dl)
            .await?;
    let gate = serving.gate;
    let closure = verify_gateway_authority_closure(&gate, &env.actor.identity, None, &[], env.backend_hex)
        .map_err(|e| anyhow!("{e:?}"))?;

    let op_id = Uuid::new_v4();
    let lane = IssuerLane::new("reclaim-multi-test")?;
    let req_dig = RequestDigest::of("reclaim-multi", &[op_id.as_bytes()]);
    let mut client = env.pool.get().await?;
    let tx = client.transaction().await?;
    let seq = PgRefStore.reserve_sequence(&tx, repo_id, env.actor.identity.id, op_id, &lane, dl).await?;
    let identity = OperationIdentity::new(repo_id, env.actor.identity.id, lane, seq.sequence(), op_id, req_dig)?;
    PgRefStore.begin(&tx, &identity, dl).await?;
    tx.commit().await?;

    let tmp = TempDir::new()?;
    let (work, bare) = (tmp.path().join("w"), tmp.path().join("b"));
    run_git(tmp.path(), &["init", "-b", "main", work.to_str().unwrap()], None)?;
    run_git(tmp.path(), &["init", "--bare", bare.to_str().unwrap()], None)?;

    let mut summaries = Vec::new();
    let scope = HoldScope::new(
        repo_id,
        gate.tenant_id(),
        gate.tenant_id(),
        ArtifactHoldPurpose::RefPublication,
        gate.object_format(),
        gate.history_incarnation(),
        gate.authority_epoch(),
        gate.group_epoch(),
    )?;
    for idx in 0..3 {
        let c = mk_commit(&work, &format!("m{idx}.txt"), &format!("multi-pair-{idx}\n"), &format!("m{idx}"))?;
        let raw = run_git(&work, &["pack-objects", "--revs", "--stdout"], Some(format!("{c}\n").as_bytes()))?;
        let p_path = bare.join(format!("objects/pack/m{idx}.pack"));
        let i_path = bare.join(format!("objects/pack/m{idx}.idx"));
        run_git(&bare, &["index-pack", "--stdin", "--strict", p_path.to_str().unwrap()], Some(&raw))?;
        let (p_sha, p_len) = sha256_file(&p_path)?;
        let (i_sha, i_len) = sha256_file(&i_path)?;
        summaries.push(GatewayPairSummary {
            pack_sha256: p_sha.clone(),
            pack_len: p_len,
            idx_sha256: i_sha.clone(),
            idx_len: i_len,
        });

        let req = AcquireArtifactHoldsRequest::new(
            scope.clone(),
            identity.clone(),
            Uuid::new_v4(),
            env.store.backend_identity().clone(),
            repo_id,
            1,
            *gate.digest(),
            vec![ArtifactSpec::new("git-pack", p_sha, p_len)?, ArtifactSpec::new("git-pack", i_sha, i_len)?],
        )?;
        let AcquireOutcome::Granted { grant, .. } =
            PgArtifactHoldStore.acquire(&mut client, env.store, &req, dl).await?
        else {
            return Err(anyhow!("unexpected hold replay"));
        };
        let uploader = ProtectedUploader::new(env.store.clone());
        uploader
            .consume_and_upload(
                env.pool,
                grant,
                &[UploadSource::new(p_path), UploadSource::new(i_path)],
                std::time::Instant::now() + Duration::from_secs(20),
            )
            .await?;
    }
    record_gateway_staging_inflight(scratch_root, op_id, &closure.snapshot, env.backend_hex, &summaries)
        .map_err(|e| anyhow!("{e:?}"))?;

    // Cancel the aborted operation in PG so its terminal state is `'cancelled'` (`0` memberships!).
    let tx_cancel = client.transaction().await?;
    PgRefStore.cancel(&tx_cancel, &identity, dl).await?;
    tx_cancel.commit().await?;
    Ok(op_id)
}

fn assert_s3_paths_swept(s3: &LoopbackS3, paths: &[String]) -> Result<()> {
    let guard = s3.objects.lock().unwrap();
    for p in paths {
        let key = format!("push-causal-bucket/push-causal-it/{p}");
        ensure!(!guard.contains_key(&key), "orphaned partial/rejected pack was NOT swept from S3: {key}");
    }
    Ok(())
}

async fn post_receive(url: &str, auth_hdr: &str, op_id: Uuid, body: Vec<u8>) -> Result<(StatusCode, Vec<u8>)> {
    let resp = reqwest::Client::new()
        .post(url)
        .header(header::AUTHORIZATION, auth_hdr)
        .header(header::CONTENT_TYPE, "application/x-git-receive-pack-request")
        .header("X-Rootyard-Operation", op_id.to_string())
        .body(body)
        .send()
        .await?;
    Ok((resp.status(), resp.bytes().await?.to_vec()))
}

fn sha256_file(path: &Path) -> Result<(String, u64)> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path)?;
    Ok((hex::encode(Sha256::digest(&bytes)), bytes.len() as u64))
}
