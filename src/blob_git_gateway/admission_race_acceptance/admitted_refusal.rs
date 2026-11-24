//! Same-ref post-admission refusal using the exact public and private ledger.
use std::net::SocketAddr;

use super::*;

const PUSH_BOUND: Duration = Duration::from_secs(180);
const STOP_BOUND: Duration = Duration::from_secs(30);
const OPERATION_VIEW_BOUND: Duration = Duration::from_secs(10);
const MAX_OPERATION_VIEW_BYTES: usize = 64 * 1024;
type Push = JoinHandle<Result<git::Output>>;

pub(super) async fn run() -> Result<()> {
    let mut phase = "fixture_setup";
    let result = run_owned(&mut phase).await;
    if result.is_err()
        && let Some(path) = std::env::var_os(FAILURE_PHASE_MARKER)
    {
        let _ = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .and_then(|mut file| file.write_all(phase.as_bytes()));
    }
    result.map_err(|_| anyhow!("admitted refusal fixture failed during fixed phase {phase}"))
}

async fn run_owned(phase: &mut &'static str) -> Result<()> {
    require_owned_disposable_blob_fixture()?;
    let _serial = super::super::NATIVE_ACCEPTANCE_SERIAL.lock().await;
    prepare()?;
    require_per_run_blob_prefix()?;
    let db = Db::setup().await?;
    let mut resources = WitnessResources::default();
    let mut unproven = false;
    let outcome =
        AssertUnwindSafe(admitted_refusal_case(&db, &mut resources, &mut unproven, phase)).catch_unwind().await;
    let outcome = match outcome {
        Ok(result) => result,
        Err(_) => {
            *phase = "panic_assertion";
            Err(anyhow!("admitted refusal assertion panicked"))
        }
    };
    if let Some(pause) = &resources.pause {
        pause.abandon();
    }
    let mut fence = Vec::new();
    let cleanup = AssertUnwindSafe(async {
        let loser_clean = confirm_or_stop(&mut resources.second_push, unproven).await;
        let winner_clean = confirm_or_stop(&mut resources.first_push, unproven).await;
        ensure!(!unproven && loser_clean && winner_clean, "stock Git reap was not proved");
        resources.teardown(&db, &mut fence).await
    })
    .catch_unwind()
    .await;
    drop(fence);
    if !matches!(cleanup, Ok(Ok(()))) {
        db.pool.close();
        if let Some(server) = resources.server.take() {
            server.abort();
        }
        // Keep fixture-owned directories and the schema for unproved cleanup.
        std::mem::forget(resources.work.take());
        std::mem::forget(resources.scratch.take());
        *phase = "cleanup_drain";
        return Err(anyhow!("fixture retained after unresolved cleanup"));
    }
    outcome
}

fn consume(
    slot: &mut Option<Push>,
    outcome: Result<Result<git::Output>, tokio::task::JoinError>,
    unproven: &mut bool,
) -> Result<git::Output> {
    drop(slot.take());
    match outcome {
        Ok(Ok(output)) => Ok(output),
        _ => {
            *unproven = true;
            Err(anyhow!("stock Git finished without a reaped output"))
        }
    }
}

async fn take_output(slot: &mut Option<Push>, unproven: &mut bool) -> Result<git::Output> {
    let push = slot.as_mut().ok_or_else(|| anyhow!("missing stock Git task"))?;
    match tokio::time::timeout(PUSH_BOUND, push).await {
        Ok(ready) => consume(slot, ready, unproven),
        Err(_) => {
            *unproven = true;
            Err(anyhow!("stock Git did not join within its bound"))
        }
    }
}

async fn confirm_or_stop(slot: &mut Option<Push>, unproven: bool) -> bool {
    let Some(task) = slot.as_mut() else {
        return true;
    };
    if !unproven && let Ok(ready) = tokio::time::timeout(PUSH_BOUND, &mut *task).await {
        return consume(slot, ready, &mut false).is_ok();
    }
    task.abort();
    if tokio::time::timeout(STOP_BOUND, &mut *task).await.is_ok() {
        drop(slot.take());
    }
    false
}

#[tokio::test]
async fn push_join_results_are_consumed_once_before_cleanup() {
    let (release, wait) = oneshot::channel::<()>();
    let mut task = tokio::spawn(async move {
        let _ = wait.await;
        Ok::<_, anyhow::Error>(git::Output { success: false, stdout: Vec::new(), stderr: Vec::new() })
    });
    assert!(tokio::time::timeout(Duration::from_millis(1), &mut task).await.is_err());
    let _ = release.send(());
    assert!(matches!(tokio::time::timeout(Duration::from_secs(1), &mut task).await, Ok(Ok(Ok(_)))));
    let mut slot = Some(tokio::spawn(async { Err(anyhow!("synthetic Git runner error")) }));
    let ready = slot.as_mut().expect("test push task").await;
    let mut unproven = false;
    assert!(consume(&mut slot, ready, &mut unproven).is_err());
    assert!(unproven && slot.is_none());
    assert!(confirm_or_stop(&mut slot, unproven).await);
}

/// One real seed push and two real clones from that tip. Both clones advertise
/// the same old OID and each makes a distinct commit, which is the shared
/// starting point of both deterministic races.
struct SameTipRace {
    direct_url: String,
    seed: String,
    first_dir: PathBuf,
    second_dir: PathBuf,
    first_new: String,
    revision_before: i64,
}

async fn seed_same_tip_race(
    db: &Db,
    work: &Path,
    git: &Git,
    address: SocketAddr,
    owner: &Actor,
    name: &str,
    repository_id: Uuid,
) -> Result<SameTipRace> {
    let direct_url = clone_url(address, owner, name);
    let seeded = git.clone(work, &direct_url, "seed").await?;
    ensure!(seeded.success, "real Smart HTTP clone of the empty repository failed");
    let seed_dir = work.join("seed");
    let seed = git.commit(&seed_dir, SEED_FILE, SEED_CONTENT, "seed commit").await?;
    let seed_target = format!("HEAD:{SEED_REF}");
    let pushed = git.run(&seed_dir, &["push", "origin", seed_target.as_str()]).await?;
    ensure!(pushed.success, "seed push was refused");

    let first_dir = clone_one(git, work, &direct_url, "race-a").await?;
    let second_dir = clone_one(git, work, &direct_url, "race-b").await?;
    let first_old = git.text(&first_dir, &["rev-parse", "refs/remotes/origin/main"]).await?;
    let second_old = git.text(&second_dir, &["rev-parse", "refs/remotes/origin/main"]).await?;
    ensure!(first_old == seed && second_old == seed, "the two clones did not share the seed tip");
    let first_new = git.commit(&first_dir, "a.txt", "from a\n", "commit from a").await?;
    let second_new = git.commit(&second_dir, "b.txt", "from b\n", "commit from b").await?;
    ensure!(first_new != second_new, "the two racers made the same commit");
    let revision_before = gate_revision(db, repository_id).await?;
    Ok(SameTipRace { direct_url, seed, first_dir, second_dir, first_new, revision_before })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MembershipStats {
    total: i64,
    at_revision: i64,
    above_revision: i64,
}

async fn membership_stats(db: &Db, repository_id: Uuid, revision: i64) -> Result<MembershipStats> {
    let row = db
        .pool
        .get()
        .await?
        .query_one(
            "SELECT count(*),
                    count(*) FILTER (WHERE joined_revision=$2),
                    count(*) FILTER (WHERE joined_revision>$2)
               FROM ref_store_core_pack_memberships WHERE repository_id=$1",
            &[&repository_id, &revision],
        )
        .await?;
    Ok(MembershipStats { total: row.get(0), at_revision: row.get(1), above_revision: row.get(2) })
}

async fn ref_count(db: &Db, repository_id: Uuid) -> Result<i64> {
    Ok(db
        .pool
        .get()
        .await?
        .query_one("SELECT count(*) FROM ref_store_core_refs WHERE repository_id=$1", &[&repository_id])
        .await?
        .get(0))
}

/// Authenticated historical operation read via the existing production route.
/// The caller compares the returned terminal with the scoped durable row.
async fn operation_view(address: SocketAddr, owner: &Actor, name: &str, operation: Uuid) -> Result<Value> {
    let result = tokio::time::timeout(OPERATION_VIEW_BOUND, async {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| anyhow!("operation view client unavailable"))?;
        let mut response = client
            .get(format!("http://{address}/api/repos/{}/{name}/operations/{operation}", owner.username))
            .bearer_auth(&owner.token)
            .send()
            .await
            .map_err(|_| anyhow!("operation view transport failed"))?;
        if !response.status().is_success() {
            return Err(anyhow!("operation view returned a non-success status"));
        }
        if matches!(response.content_length(), Some(length) if length > MAX_OPERATION_VIEW_BYTES as u64) {
            return Err(anyhow!("operation view body exceeded its fixed cap"));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| anyhow!("operation view body read failed"))? {
            let next =
                body.len().checked_add(chunk.len()).ok_or_else(|| anyhow!("operation view body length overflow"))?;
            if next > MAX_OPERATION_VIEW_BYTES {
                return Err(anyhow!("operation view body exceeded its fixed cap"));
            }
            body.extend_from_slice(&chunk);
        }
        let body: Value =
            serde_json::from_slice(&body).map_err(|_| anyhow!("operation view body was not valid JSON"))?;
        let expected = operation.to_string();
        ensure!(body["operation_id"].as_str() == Some(expected.as_str()), "operation view identity mismatch");
        Ok(body)
    })
    .await;
    match result {
        Ok(value) => value,
        Err(_) => Err(anyhow!("operation view exceeded its fixed deadline")),
    }
}

async fn admitted_refusal_case(
    db: &Db,
    resources: &mut WitnessResources,
    unproven: &mut bool,
    phase: &mut &'static str,
) -> Result<()> {
    let store = open_store()?;
    let git: &'static Git = Box::leak(Box::new(Git::new()?));
    let owner = actor::owner(&db.pool).await?;
    let name = format!("race-admitted-{}", &Uuid::new_v4().simple().to_string()[..12]);
    let winner_operation = Uuid::new_v4();
    let loser_operation = Uuid::new_v4();
    let pause = resources.pause.insert(Arc::new(AdmissionPause::new_after_admission(loser_operation))).clone();
    let captures = Captures::default();
    let scratch = resources.scratch.insert(tempfile::tempdir().context("temporary gateway scratch root")?);
    let state = Arc::new(
        BlobGitState::new(BlobGitConfig {
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
        .map_err(|error| anyhow!("gateway configuration refused: {error}"))?
        .with_admission_pause(pause.clone()),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let app = capture_receive_responses(router(state), captures.clone());
    let (shutdown, signal) = oneshot::channel();
    resources.shutdown = Some(shutdown);
    resources.server = Some(tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = signal.await;
            })
            .await
    }));

    *phase = "repository_seed";
    let created = create_repository(address, &owner, &name).await?;
    let repository_id = Uuid::parse_str(created["id"].as_str().ok_or_else(|| anyhow!("no repository id"))?)?;
    provision_decision_realm(db, &owner, &name, &store).await?;
    let work = resources.work.insert(tempfile::tempdir().context("temporary Git work root")?);
    let SameTipRace { direct_url, seed, first_dir, second_dir, first_new, revision_before } =
        seed_same_tip_race(db, work.path(), git, address, &owner, &name, repository_id).await?;

    *phase = "post_admission_barrier";
    let task = resources.second_push.insert(spawn_push(git, second_dir, direct_url.clone(), loser_operation));
    let early = tokio::select! {
        reached = tokio::time::timeout(PUSH_BOUND, pause.wait_reached()) => {
            reached.map_err(|_| anyhow!("losing stock push did not reach the admission pause"))?;
            None
        }
        exited = task => Some(exited),
    };
    if let Some(ready) = early {
        let output = consume(&mut resources.second_push, ready, unproven)?;
        return Err(anyhow!("losing stock Git exited before its rendezvous: {}", redacted(&output)));
    }
    *phase = "pre_release_assertions";
    let admitted = attempt_history(db, repository_id, loser_operation).await?;
    let [slot_zero] = admitted.as_slice() else {
        return Err(anyhow!("expected one pending attempt"));
    };
    ensure!(
        slot_zero.slot == 0
            && slot_zero.current_slot == 0
            && slot_zero.base == revision_before
            && slot_zero.wrapper_state == "pending"
            && slot_zero.state == "pending"
            && slot_zero.terminal.is_none()
            && slot_zero.event.is_none()
            && slot_zero.retired_event.is_none()
            && slot_zero.wrapper_event.is_none(),
        "the paused attempt is not exactly pending at its original base"
    );
    ensure!(
        durable_main(db, repository_id).await? == seed
            && gate_revision(db, repository_id).await? == revision_before
            && ref_count(db, repository_id).await? == 1,
        "ref or gate moved before winner"
    );
    let before = membership_stats(db, repository_id, revision_before).await?;
    ensure!(before.above_revision == 0, "membership above the initial gate");

    *phase = "winner_publish";
    resources.first_push = Some(spawn_push(git, first_dir, direct_url, winner_operation));
    let winner_output = take_output(&mut resources.first_push, unproven).await?;
    ensure!(winner_output.success, "the winner failed: {}", redacted(&winner_output));

    *phase = "post_winner_assertions";
    let revision_after = gate_revision(db, repository_id).await?;
    ensure!(
        revision_after == revision_before + 1 && durable_main(db, repository_id).await? == first_new,
        "the winner did not advance the gate and main exactly once"
    );
    ensure!(attempt_history(db, repository_id, loser_operation).await? == admitted, "the paused admission changed");
    let memberships = membership_stats(db, repository_id, revision_after).await?;
    ensure!(
        memberships.total == before.total + 1 && memberships.at_revision == 1 && memberships.above_revision == 0,
        "the winner failed to add exactly one pack membership"
    );

    *phase = "superseded_refusal_await";
    pause.release();
    let loser_output = take_output(&mut resources.second_push, unproven).await?;
    ensure!(!loser_output.success, "the losing push succeeded");
    let text = output_text(&loser_output);
    for forbidden in ["409", "503", "non-fast-forward", "fetch first", "unexpected disconnect", "remote end hung up"] {
        let found = match forbidden {
            "409" | "503" => has_stock_http_error(&text, forbidden),
            _ => text.contains(forbidden),
        };
        ensure!(!found, "a transport or local refusal replaced report-status");
    }
    ensure!(text.contains("[rejected]") && text.contains("stale info"), "stock Git did not report stale info");

    *phase = "report_assertions";
    let winner_capture = captures.take(winner_operation).ok_or_else(|| anyhow!("the winner has no raw reply"))?;
    let loser_capture = captures.take(loser_operation).ok_or_else(|| anyhow!("the loser has no raw reply"))?;
    ensure!(captures.is_empty(), "the service answered unexpected extra receive-pack operations");
    ensure!(winner_capture.status == 200, "the service answered the winner with {}", winner_capture.status);
    ensure!(loser_capture.status == 200, "the service answered the loser with {}", loser_capture.status);
    ensure!(!winner_capture.truncated, "the winner's raw service reply is truncated");
    ensure!(!loser_capture.truncated, "the loser's raw service reply is truncated");
    let (winner_unpack, winner_verdicts) = report_status(&winner_capture.body)?;
    ensure!(winner_unpack == "ok", "the winner's report-status did not unpack: {winner_unpack}");
    ensure!(
        winner_verdicts == vec![(SEED_REF.to_owned(), None)],
        "the winner's report-status is not exactly one ok on main: {winner_verdicts:?}"
    );
    let (loser_unpack, loser_verdicts) = report_status(&loser_capture.body)?;
    ensure!(loser_unpack == "ok", "the loser's report-status did not unpack: {loser_unpack}");
    ensure!(
        loser_verdicts == vec![(SEED_REF.to_owned(), Some("stale info".to_owned()))],
        "the loser's report-status is not exactly one ng stale info on main: {loser_verdicts:?}"
    );

    *phase = "durable_refusal_assertions";
    let after = attempt_history(db, repository_id, loser_operation).await?;
    let [retired, current] = after.as_slice() else {
        return Err(anyhow!("expected exactly two attempts"));
    };
    ensure!(
        retired.slot == 0
            && retired.base == revision_before
            && retired.identity == slot_zero.identity
            && retired.event.is_some()
            && retired.event == retired.retired_event,
        "the admitted attempt or retirement changed"
    );
    ensure!(
        current.slot == 1
            && current.current_slot == 1
            && current.base == revision_after
            && current.wrapper_state == "rejected"
            && current.event.is_some()
            && current.event == current.wrapper_event
            && current.retired_event.is_none()
            && current.identity.private_id != slot_zero.identity.private_id
            && current.identity.issuer == slot_zero.identity.issuer
            && current.identity.lane == slot_zero.identity.lane
            && current.identity.wire == slot_zero.identity.wire
            && current.identity.sequence > slot_zero.identity.sequence,
        "the successor did not preserve the public identity and advance the lane"
    );
    assert_refusal(
        retired,
        repository_id,
        revision_after,
        PackCommitRejectCode::RevisionMismatch,
        "admitted base was superseded",
    )?;
    assert_refusal(
        current,
        repository_id,
        revision_after,
        PackCommitRejectCode::NoRefApplied,
        DenialCode::AllRejected.as_str(),
    )?;
    let terminal = current.terminal.as_ref().ok_or_else(|| anyhow!("current terminal missing"))?;
    ensure!(
        operation_row(db, repository_id, loser_operation).await?
            == Some(("rejected".to_owned(), Some(terminal.clone()))),
        "the verified public row does not project the successor terminal"
    );

    *phase = "authenticated_operation_read";
    let view = operation_view(address, &owner, &name, loser_operation).await?;
    ensure!(
        view["state"] == "rejected" && &view["terminal"] == terminal,
        "the public read delivered a different terminal"
    );
    ensure!(attempt_history(db, repository_id, loser_operation).await? == after, "public read changed the evidence");
    ensure!(
        gate_revision(db, repository_id).await? == revision_after
            && durable_main(db, repository_id).await? == first_new
            && ref_count(db, repository_id).await? == 1
            && membership_stats(db, repository_id, revision_after).await? == memberships,
        "the losing request published refs or memberships"
    );

    let winner = attempt_history(db, repository_id, winner_operation).await?;
    let [winner_after] = winner.as_slice() else {
        return Err(anyhow!("expected exactly one winner attempt"));
    };
    ensure!(
        winner_after.slot == 0
            && winner_after.current_slot == 0
            && winner_after.base == revision_before
            && winner_after.wrapper_state == "committed"
            && winner_after.state == "committed"
            && winner_after.outcome.as_deref() == Some("committed")
            && winner_after.event.is_some()
            && winner_after.event == winner_after.wrapper_event
            && winner_after.retired_event.is_none(),
        "the winner does not have one matching event"
    );
    let winner_terminal: PackCommitTerminal = serde_json::from_value(
        winner_after.terminal.clone().ok_or_else(|| anyhow!("the committed operation has no terminal"))?,
    )
    .map_err(|_| anyhow!("the committed terminal does not match the pack terminal schema"))?;
    ensure!(winner_terminal.kind == TerminalKind::Committed, "the winning terminal is not committed");
    ensure!(winner_terminal.repository_id == repository_id, "the winning terminal names another repository");
    ensure!(winner_terminal.revision == revision_after, "the winning terminal recorded another revision");
    ensure!(winner_terminal.refs.len() == 1, "the winning terminal does not cover exactly one ref");
    match &winner_terminal.refs[0] {
        RefCommitResult::Applied { name, old_oid, new_oid } => {
            ensure!(name.as_str() == SEED_REF, "the winning terminal names another ref");
            ensure!(old_oid.as_deref() == Some(seed.as_str()), "the winning terminal did not use the shared old OID");
            ensure!(new_oid.as_deref() == Some(first_new.as_str()), "the winning terminal did not apply the winner");
        }
        RefCommitResult::NotApplied { .. } => {
            return Err(anyhow!("the winning terminal contains a refused ref"));
        }
    }

    *phase = "fixture_cleanup";
    Ok(())
}

fn assert_refusal(
    row: &Attempt,
    repository_id: Uuid,
    revision: i64,
    code: PackCommitRejectCode,
    detail: &str,
) -> Result<()> {
    ensure!(row.state == "rejected" && row.outcome.as_deref() == Some("rejected"), "one rejected event required");
    let body = row.terminal.as_ref().ok_or_else(|| anyhow!("private terminal missing"))?;
    let terminal: PackCommitTerminal = serde_json::from_value(body.clone())?;
    ensure!(
        terminal.kind == TerminalKind::Rejected
            && terminal.repository_id == repository_id
            && terminal.revision == revision
            && terminal.head_ref.as_deref() == Some(SEED_REF)
            && terminal.registrations.is_empty()
            && matches!(terminal.refs.as_slice(),
            [RefCommitResult::NotApplied { name, reason }] if name == SEED_REF && *reason == CommitRejectCode::OldOidMismatch),
        "private terminal did not refuse the exact old OID without publication"
    );
    ensure!(
        terminal.rejection.as_ref().is_some_and(|value| value.code == code.as_str() && value.detail == detail),
        "private terminal has a different rejection code or detail"
    );
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct AttemptIdentity {
    private_id: Uuid,
    issuer: Uuid,
    lane: String,
    sequence: i64,
    plan: String,
    wire: String,
}

#[derive(Debug, PartialEq, Eq)]
struct Attempt {
    identity: AttemptIdentity,
    slot: i16,
    current_slot: i16,
    base: i64,
    state: String,
    wrapper_state: String,
    terminal: Option<Value>,
    event: Option<Uuid>,
    outcome: Option<String>,
    wrapper_event: Option<Uuid>,
    retired_event: Option<Uuid>,
}

async fn attempt_history(db: &Db, repository_id: Uuid, public_id: Uuid) -> Result<Vec<Attempt>> {
    let rows = db.pool.get().await?.query(
        "SELECT a.private_id,o.issuer_id,o.lane,o.sequence,a.plan_digest,w.wire_digest,
                a.slot,w.current_slot,a.base_revision,o.state,w.state,o.terminal_result,
                e.event_id,e.outcome,w.event_id,r.event_id,e.payload IS NOT DISTINCT FROM o.terminal_result
           FROM ref_store_public_operations w
           JOIN ref_store_private_attempts a USING (repository_id,public_id)
           JOIN ref_store_operations o ON (o.repository_id,o.operation_id)=(a.repository_id,a.private_id)
           JOIN ref_store_serving_operations s ON (s.repository_id,s.operation_id)=(a.repository_id,a.private_id)
           LEFT JOIN ref_store_core_events e ON (e.repository_id,e.operation_id)=(a.repository_id,a.private_id)
           LEFT JOIN ref_store_attempt_retirements r ON (r.repository_id,r.public_id,r.slot)=(a.repository_id,a.public_id,a.slot)
          WHERE (w.repository_id,w.public_id)=($1,$2)
            AND w.issuer_id=o.issuer_id AND s.issuer_id=o.issuer_id
            AND a.plan_digest=o.request_digest AND s.plan_parent_digest=o.request_digest
            AND s.producer_request_digest=w.wire_digest AND a.private_id<>w.public_id
          ORDER BY a.slot,e.event_id LIMIT 8",
        &[&repository_id, &public_id],
    ).await?;
    rows.into_iter()
        .map(|row| {
            ensure!(row.get::<_, bool>(16), "private event differs from terminal");
            Ok(Attempt {
                identity: AttemptIdentity {
                    private_id: row.get(0),
                    issuer: row.get(1),
                    lane: row.get(2),
                    sequence: row.get(3),
                    plan: row.get(4),
                    wire: row.get(5),
                },
                slot: row.get(6),
                current_slot: row.get(7),
                base: row.get(8),
                state: row.get(9),
                wrapper_state: row.get(10),
                terminal: row.get(11),
                event: row.get(12),
                outcome: row.get(13),
                wrapper_event: row.get(14),
                retired_event: row.get(15),
            })
        })
        .collect()
}
