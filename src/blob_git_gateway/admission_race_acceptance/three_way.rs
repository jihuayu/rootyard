//! Deterministic first-attempt acceptance for three independent stock Git clients.

use super::{
    AdmissionPause, BlobGitConfig, BlobGitState, Captures, Db, Git, INDEPENDENT_A, INDEPENDENT_B, SEED_CONTENT,
    SEED_FILE, SEED_REF, WitnessResources, actor, capture_receive_responses, clone_one, clone_url, create_repository,
    deadline, durable_ref, gate_revision, git, open_store, prepare, provision_decision_realm, report_status,
    require_owned_disposable_blob_fixture, require_per_run_blob_prefix, router, spawn_push_ref,
};
use anyhow::{Context, Result, anyhow, ensure};
use futures_util::FutureExt;
use serde_json::{Value, json};
use std::{panic::AssertUnwindSafe, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle, time::timeout_at};
use uuid::Uuid;

const INDEPENDENT_C: &str = "refs/heads/indep-c";

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL 17, Garage and stock Git"]
async fn three_independent_pushes_succeed_on_their_first_request() -> Result<()> {
    require_owned_disposable_blob_fixture()?;
    let _serial = crate::blob_git_gateway::NATIVE_ACCEPTANCE_SERIAL.lock().await;
    prepare()?;
    require_per_run_blob_prefix()?;
    let db = Db::setup_public_owned().await?;
    let mut resources = WitnessResources::default();
    let outcome = AssertUnwindSafe(qualify(&db, &mut resources)).catch_unwind().await;
    let mut fence = Vec::new();
    let cleanup = resources.teardown(&db, &mut fence).await;
    if cleanup.is_err() {
        resources.seal_failed_cleanup(&db).await;
    }
    drop(fence);
    match outcome {
        Ok(result) => result.and(cleanup),
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

async fn qualify(db: &Db, resources: &mut WitnessResources) -> Result<()> {
    let store = open_store()?;
    let git: &'static Git = Box::leak(Box::new(Git::new()?));
    let [first, second, third] = [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];
    let second_zero = Arc::new(AdmissionPause::new_after_admission(second));
    let third_zero = Arc::new(AdmissionPause::new_after_admission(third));
    let second_one = Arc::new(AdmissionPause::new_after_slot_one(second));
    let third_one = Arc::new(AdmissionPause::new_after_slot_one(third));
    resources.extra_pauses = vec![second_zero.clone(), third_zero.clone(), second_one.clone(), third_one.clone()];
    let captures = Captures::default();
    let scratch = resources.scratch.insert(tempfile::tempdir()?);
    let mut state = BlobGitState::new(BlobGitConfig {
        pool: db.pool.clone(),
        store: store.clone(),
        git_binary: git.binary().to_path_buf(),
        scratch_root: scratch.path().to_path_buf(),
        max_concurrent_requests: 4,
        max_request_bytes: 16 * 1024 * 1024,
        max_response_bytes: 64 * 1024 * 1024,
        max_inflight_bytes: 64 * 1024 * 1024,
        operation_deadline: Duration::from_secs(120),
        native_limits: Default::default(),
    })
    .map_err(|error| anyhow!("gateway configuration refused: {error}"))?;
    for pause in &resources.extra_pauses {
        state = state.with_admission_pause(pause.clone());
    }
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let app = capture_receive_responses(router(Arc::new(state)), captures.clone());
    let (shutdown, signal) = oneshot::channel();
    resources.shutdown = Some(shutdown);
    resources.server = Some(tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = signal.await;
            })
            .await
    }));

    let owner = actor::owner(&db.pool).await?;
    let name = format!("race-three-way-{}", &Uuid::new_v4().simple().to_string()[..12]);
    let created = create_repository(addr, &owner, &name).await?;
    let repo = Uuid::parse_str(created["id"].as_str().context("create response has no repo id")?)?;
    provision_decision_realm(db, &owner, &name, &store).await?;
    let root = resources.work.insert(tempfile::tempdir()?);
    let url = clone_url(addr, &owner, &name);
    ensure!(git.clone(root.path(), &url, "seed").await?.success, "empty clone failed");
    let seed_dir = root.path().join("seed");
    let seed = git.commit(&seed_dir, SEED_FILE, SEED_CONTENT, "three-way seed").await?;
    let seed_ref = format!("HEAD:{SEED_REF}");
    ensure!(git.run(&seed_dir, &["push", "origin", &seed_ref]).await?.success, "seed push failed");

    let mut dirs = Vec::new();
    let mut oids = Vec::new();
    for label in ["three-a", "three-b", "three-c"] {
        let dir = clone_one(git, root.path(), &url, label).await?;
        ensure!(git.text(&dir, &["rev-parse", "refs/remotes/origin/main"]).await? == seed);
        oids.push(git.commit(&dir, label, label, label).await?);
        dirs.push(dir);
    }
    let base = gate_revision(db, repo).await?;

    resources.second_push = Some(spawn_push_ref(git, dirs[1].clone(), url.clone(), second, INDEPENDENT_B));
    resources.third_push = Some(spawn_push_ref(git, dirs[2].clone(), url.clone(), third, INDEPENDENT_C));
    wait_pause(&second_zero, &mut resources.second_push).await?;
    wait_pause(&third_zero, &mut resources.third_push).await?;
    pending_at(db, repo, second, 0, base).await?;
    pending_at(db, repo, third, 0, base).await?;
    ensure!(gate_revision(db, repo).await? == base, "gate advanced before either loser was frozen");

    resources.first_push = Some(spawn_push_ref(git, dirs[0].clone(), url.clone(), first, INDEPENDENT_A));
    ensure!(join_push(&mut resources.first_push).await?.success, "first stock push failed");
    ensure!(gate_revision(db, repo).await? == base + 1);

    second_zero.release();
    third_zero.release();
    wait_pause(&second_one, &mut resources.second_push).await?;
    wait_pause(&third_one, &mut resources.third_push).await?;
    pending_at(db, repo, second, 1, base + 1).await?;
    pending_at(db, repo, third, 1, base + 1).await?;
    ensure!(gate_revision(db, repo).await? == base + 1, "gate advanced before both rotations were frozen");

    second_one.release();
    ensure!(join_push(&mut resources.second_push).await?.success, "second stock push failed");
    ensure!(gate_revision(db, repo).await? == base + 2);
    third_one.release();
    let third_output = join_push(&mut resources.third_push).await?;

    for (public, name) in [(first, INDEPENDENT_A), (second, INDEPENDENT_B)] {
        let capture = captures.take(public).context("winning request has no capture")?;
        ensure!(capture.status == 200 && !capture.truncated);
        ensure!(report_status(&capture.body)? == ("ok".to_owned(), vec![(name.to_owned(), None)]));
    }
    let capture = captures.take(third).context("third request has no capture")?;
    ensure!(capture.status == 200 && !capture.truncated, "third HTTP status {}", capture.status);
    let third_verdict = report_status(&capture.body)?;
    ensure!(
        third_output.success && third_verdict == ("ok".to_owned(), vec![(INDEPENDENT_C.to_owned(), None)]),
        "third independent ref did not ACK on its first request: {third_verdict:?}"
    );
    ensure!(captures.is_empty(), "unexpected extra receive-pack request");
    ensure!(durable_ref(db, repo, INDEPENDENT_A).await?.as_deref() == Some(oids[0].as_str()));
    ensure!(durable_ref(db, repo, INDEPENDENT_B).await?.as_deref() == Some(oids[1].as_str()));
    ensure!(durable_ref(db, repo, INDEPENDENT_C).await?.as_deref() == Some(oids[2].as_str()));
    ensure!(gate_revision(db, repo).await? == base + 3);

    let a = attempts(db, repo, first).await?;
    let b = attempts(db, repo, second).await?;
    let c = attempts(db, repo, third).await?;
    let retired = json!([0, base, "rejected", "rejected", base + 1, "revision_mismatch", true, false]);
    ensure!(a == json!(["committed", 0, [[0, base, "committed", "committed", base + 1, null, false, true]]]));
    ensure!(
        b == json!(["committed", 1, [retired, [1, base + 1, "committed", "committed", base + 2, null, false, true]]])
    );
    ensure!(
        c == json!([
            "committed",
            2,
            [
                retired,
                [1, base + 1, "rejected", "rejected", base + 2, "revision_mismatch", true, false],
                [2, base + 2, "committed", "committed", base + 3, null, false, true]
            ]
        ])
    );

    let clone = clone_one(git, root.path(), &url, "three-readback").await?;
    ensure!(git.run(&clone, &["fsck", "--full", "--strict"]).await?.success, "reclone strict fsck failed");
    for (branch, oid) in ["indep-a", "indep-b", "indep-c"].into_iter().zip(&oids) {
        let target = format!("refs/remotes/origin/{branch}");
        ensure!(git.text(&clone, &["rev-parse", &target]).await? == *oid);
    }
    println!("three-way first ref verdicts: [ok, ok, ok], gate movement: +3, all refs match after strict fsck");
    println!("attempt evidence (wrapper state, current slot, attempts): A={a} B={b} C={c}");
    Ok(())
}

async fn wait_pause(pause: &AdmissionPause, push: &mut Option<JoinHandle<Result<git::Output>>>) -> Result<()> {
    let completion = tokio::select! {
        result = timeout_at(deadline(), pause.wait_reached()) => {
            result.context("timed out waiting for the expected admission rendezvous")?;
            None
        }
        result = push.as_mut().context("missing stock push task")? => Some(result),
    };
    if let Some(completion) = completion {
        push.take();
        let _ = completion.context("stock push task failed")??;
        return Err(anyhow!("stock push exited before its admission rendezvous"));
    }
    Ok(())
}

async fn join_push(push: &mut Option<JoinHandle<Result<git::Output>>>) -> Result<git::Output> {
    let result = timeout_at(deadline(), push.as_mut().context("missing stock push task")?).await?;
    push.take();
    result?
}

async fn pending_at(db: &Db, repo: Uuid, public_id: Uuid, slot: i16, base: i64) -> Result<()> {
    let row = db
        .pool
        .get()
        .await?
        .query_one(
            "SELECT a.slot, a.base_revision, w.state, o.state
         FROM ref_store_public_operations w
         JOIN ref_store_private_attempts a USING (repository_id, public_id)
         JOIN ref_store_operations o ON o.repository_id=a.repository_id AND o.operation_id=a.private_id
         WHERE w.repository_id=$1 AND w.public_id=$2 AND a.slot=w.current_slot",
            &[&repo, &public_id],
        )
        .await?;
    ensure!(row.get::<_, i16>(0) == slot && row.get::<_, i64>(1) == base);
    ensure!(row.get::<_, String>(2) == "pending" && row.get::<_, String>(3) == "pending");
    Ok(())
}

async fn attempts(db: &Db, repo: Uuid, public_id: Uuid) -> Result<Value> {
    let row = db
        .pool
        .get()
        .await?
        .query_one(
            "SELECT jsonb_build_array(w.state, w.current_slot, jsonb_agg(jsonb_build_array(
             a.slot, a.base_revision, o.state, e.outcome, e.revision, o.terminal_result#>>'{rejection,code}',
             COALESCE(e.event_id=r.event_id,false), COALESCE(e.event_id=w.event_id,false)) ORDER BY a.slot))
         FROM ref_store_public_operations w
         JOIN ref_store_private_attempts a USING (repository_id, public_id)
         JOIN ref_store_operations o ON o.repository_id=a.repository_id AND o.operation_id=a.private_id
         LEFT JOIN ref_store_core_events e ON e.repository_id=a.repository_id AND e.operation_id=a.private_id
         LEFT JOIN ref_store_attempt_retirements r ON r.repository_id=a.repository_id
           AND r.public_id=a.public_id AND r.slot=a.slot
         WHERE w.repository_id=$1 AND w.public_id=$2 GROUP BY w.repository_id,w.public_id",
            &[&repo, &public_id],
        )
        .await?;
    Ok(row.get(0))
}
