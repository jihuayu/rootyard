use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::oneshot;

#[derive(Default)]
struct RecordingDriver {
    events: Mutex<Vec<String>>,
    capture_error: Option<String>,
    git_ok: bool,
    process_failed: bool,
}

impl RecordingDriver {
    fn clean() -> Self {
        Self { git_ok: true, ..Self::default() }
    }

    fn record(&self, event: &str) {
        self.events.lock().unwrap().push(event.to_owned());
    }
}

impl CleanupDriver for RecordingDriver {
    fn stop_capture_and_mounts<'a>(
        &'a self,
        capture: Option<JoinHandle<()>>,
        _stop: CancellationToken,
        _capture_grace: Duration,
        _deadline: Instant,
    ) -> BoxFuture<'a, (Result<(), String>, Option<LegacyShutdownEvidence>)> {
        self.record(if capture.is_some() { "capture:present" } else { "capture:absent" });
        let result = match &self.capture_error {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        };
        Box::pin(async move {
            if let Some(task) = capture {
                task.abort();
                let _ = task.await;
            }
            (result, None)
        })
    }

    fn drain_git<'a>(&'a self, _deadline: Instant) -> BoxFuture<'a, bool> {
        self.record("git");
        let ok = self.git_ok;
        Box::pin(async move { ok })
    }

    fn process_cleanup_failed(&self) -> bool {
        self.record("process");
        self.process_failed
    }
}

struct DropFlag(Arc<AtomicBool>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

#[tokio::test]
async fn early_serve_error_is_primary_and_enters_the_same_cleanup() {
    let mut owner = ServiceOwner::arm(Duration::from_secs(2));
    owner.attach_server(tokio::spawn(async { Err::<(), io::Error>(io::Error::other("injected early serve failure")) }));
    let primary = owner
        .wait_for_stop_or_serve(std::future::pending::<anyhow::Result<()>>())
        .await
        .expect("an early serve completion must become the primary error");
    assert!(primary.to_string().contains("injected early serve failure"));

    let driver = RecordingDriver::clean();
    let completion = owner.cleanup(Some(primary), &driver).await;
    assert!(!completion.is_clean(), "a primary error can never be clean");
    assert!(!completion.pending_runtime(), "cleanup itself was complete");
    let events = driver.events.lock().unwrap().clone();
    assert_eq!(events, vec!["capture:absent".to_owned(), "git".to_owned(), "git".to_owned(), "process".to_owned()]);
    let error = completion.into_result().expect_err("primary error must survive cleanup");
    assert!(error.to_string().contains("injected early serve failure"));
}

#[tokio::test]
async fn early_serve_ok_before_signal_is_still_a_primary_error() {
    let mut owner = ServiceOwner::arm(Duration::from_secs(2));
    owner.attach_server(tokio::spawn(async { Ok::<(), io::Error>(()) }));
    let primary = owner
        .wait_for_stop_or_serve(std::future::pending::<anyhow::Result<()>>())
        .await
        .expect("an early clean serve return is not a normal signal");
    assert!(primary.to_string().contains("before the normal shutdown signal"));

    let driver = RecordingDriver::clean();
    let completion = owner.cleanup(Some(primary), &driver).await;
    assert!(!completion.is_clean());
    assert!(!completion.pending_runtime());
    assert!(owner.server.is_none(), "the completed serve JoinHandle must not be polled twice");
}

#[tokio::test]
async fn cleanup_failure_stays_separate_and_requests_bounded_runtime_termination() {
    let mut owner = ServiceOwner::arm(Duration::from_secs(2));
    let driver = RecordingDriver {
        capture_error: Some("fixture capture failure".to_owned()),
        git_ok: false,
        process_failed: true,
        ..RecordingDriver::default()
    };
    let completion = owner.cleanup(None, &driver).await;
    assert!(!completion.is_clean());
    assert!(completion.pending_runtime(), "incomplete cleanup must use the bounded runtime path");
    assert_eq!(completion.cleanup_failures.len(), 4);
    let error = completion.into_result().expect_err("incomplete cleanup is not exit zero");
    let text = error.to_string();
    assert!(text.contains("normal shutdown incomplete"), "{text}");
    assert!(text.contains("fixture capture failure"), "{text}");
    assert!(text.contains("Git jobs/process cleanup"), "{text}");
    assert!(text.contains("process cleanup did not prove quiescence"), "{text}");
}

#[tokio::test]
async fn primary_and_cleanup_failures_are_preserved_separately() {
    let mut owner = ServiceOwner::arm(Duration::from_secs(2));
    let driver = RecordingDriver { git_ok: false, ..RecordingDriver::default() };
    let primary = anyhow::anyhow!("injected startup failure");
    let completion = owner.cleanup(Some(primary), &driver).await;
    let error = completion.into_result().expect_err("the primary failure must be returned");
    let chain = format!("{error:#}");
    assert!(chain.contains("service cleanup incomplete"));
    assert!(chain.contains("Git jobs/process cleanup"));
    assert!(chain.contains("injected startup failure"));
}

#[tokio::test]
async fn tracked_tasks_are_joined_or_aborted_before_cleanup_returns() {
    let mut owner = ServiceOwner::arm(Duration::from_secs(2));
    let dispatch = owner.dispatch_stop().clone();
    let maintenance = owner.maintenance_stop().clone();
    let session_gc = owner.session_gc_stop().clone();
    let capture = owner.capture_stop().clone();
    let http = owner.http_stop().clone();
    let ready = Arc::new(tokio::sync::Barrier::new(11));

    let controller_dropped = Arc::new(AtomicBool::new(false));
    let metrics_dropped = Arc::new(AtomicBool::new(false));
    let worker_dropped = Arc::new(AtomicBool::new(false));
    let publish_done = Arc::new(AtomicBool::new(false));
    let delivery_done = Arc::new(AtomicBool::new(false));
    let webhook_done = Arc::new(AtomicBool::new(false));
    let maintenance_done = Arc::new(AtomicBool::new(false));
    let session_done = Arc::new(AtomicBool::new(false));
    let capture_dropped = Arc::new(AtomicBool::new(false));
    let server_done = Arc::new(AtomicBool::new(false));

    let flag = controller_dropped.clone();
    let gate = ready.clone();
    owner.attach_controller(tokio::spawn(async move {
        gate.wait().await;
        let _drop = DropFlag(flag);
        std::future::pending::<()>().await;
    }));
    let flag = metrics_dropped.clone();
    let gate = ready.clone();
    owner.attach_metrics(tokio::spawn(async move {
        gate.wait().await;
        let _drop = DropFlag(flag);
        std::future::pending::<()>().await;
    }));
    let flag = worker_dropped.clone();
    let gate = ready.clone();
    owner.attach_worker(tokio::spawn(async move {
        gate.wait().await;
        let _drop = DropFlag(flag);
        std::future::pending::<()>().await;
    }));
    let flag = publish_done.clone();
    let gate = ready.clone();
    owner.attach_publish(tokio::spawn(async move {
        gate.wait().await;
        dispatch.cancelled().await;
        flag.store(true, Ordering::Release);
    }));
    let flag = delivery_done.clone();
    let dispatch_delivery = owner.dispatch_stop().clone();
    let gate = ready.clone();
    owner.attach_delivery(tokio::spawn(async move {
        gate.wait().await;
        dispatch_delivery.cancelled().await;
        flag.store(true, Ordering::Release);
    }));
    let flag = webhook_done.clone();
    let dispatch_webhook = owner.dispatch_stop().clone();
    let gate = ready.clone();
    owner.attach_webhook(tokio::spawn(async move {
        gate.wait().await;
        dispatch_webhook.cancelled().await;
        flag.store(true, Ordering::Release);
    }));
    let flag = maintenance_done.clone();
    let gate = ready.clone();
    owner.attach_maintenance(tokio::spawn(async move {
        gate.wait().await;
        maintenance.cancelled().await;
        flag.store(true, Ordering::Release);
        Ok(())
    }));
    let flag = session_done.clone();
    let gate = ready.clone();
    owner.attach_session_gc(tokio::spawn(async move {
        gate.wait().await;
        session_gc.cancelled().await;
        flag.store(true, Ordering::Release);
    }));
    let flag = capture_dropped.clone();
    let gate = ready.clone();
    owner.attach_capture(tokio::spawn(async move {
        gate.wait().await;
        let _drop = DropFlag(flag);
        capture.cancelled().await;
    }));
    let flag = server_done.clone();
    let gate = ready.clone();
    owner.attach_server(tokio::spawn(async move {
        gate.wait().await;
        http.cancelled().await;
        flag.store(true, Ordering::Release);
        Ok(())
    }));

    // Every task has reached its owned wait before cleanup takes ownership.
    ready.wait().await;

    let driver = RecordingDriver::clean();
    let completion = owner.cleanup(None, &driver).await;
    assert!(completion.is_clean(), "{:?}", completion.cleanup_failures);
    assert!(controller_dropped.load(Ordering::Acquire));
    assert!(metrics_dropped.load(Ordering::Acquire));
    assert!(worker_dropped.load(Ordering::Acquire));
    assert!(publish_done.load(Ordering::Acquire));
    assert!(delivery_done.load(Ordering::Acquire));
    assert!(webhook_done.load(Ordering::Acquire));
    assert!(maintenance_done.load(Ordering::Acquire));
    assert!(session_done.load(Ordering::Acquire));
    assert!(capture_dropped.load(Ordering::Acquire));
    assert!(server_done.load(Ordering::Acquire));
}

#[tokio::test]
async fn deadline_is_published_once_and_not_extended() {
    let mut owner = ServiceOwner::arm(Duration::from_millis(50));
    let first = owner.absolute_deadline();
    tokio::time::sleep(Duration::from_millis(5)).await;
    let second = owner.absolute_deadline();
    assert_eq!(first, second);
}

#[test]
fn empty_join_evidence_is_not_emitted_and_nonempty_evidence_is_bounded() {
    let mut owner = ServiceOwner::arm(Duration::from_secs(1));
    let empty = LegacyShutdownEvidence { mount_namespace: 7, joined_mounts: 0, workspaces: Vec::new() };
    owner.emit_legacy_evidence(&empty);
    assert!(!owner.evidence_emitted, "an empty ticket is never one mount of proof");

    let joined = LegacyShutdownEvidence { mount_namespace: 7, joined_mounts: 1, workspaces: vec![uuid::Uuid::nil()] };
    owner.emit_legacy_evidence(&joined);
    assert!(owner.evidence_emitted);
    owner.emit_legacy_evidence(&joined);
    assert!(owner.evidence_emitted, "one cleanup emits one bounded line");
}

#[tokio::test]
async fn stop_is_polled_before_setup_and_setup_is_not_started() {
    let setup_started = Arc::new(AtomicBool::new(false));
    let flag = setup_started.clone();
    let result = select_startup(async { Ok(()) }, async move {
        flag.store(true, Ordering::SeqCst);
        Ok(())
    })
    .await;
    assert!(matches!(result, StartupTrigger::Stop(Ok(()))));
    assert!(!setup_started.load(Ordering::SeqCst), "a ready stop must not start setup");
}

#[tokio::test]
async fn signal_stream_error_is_a_finite_primary_trigger() {
    let result =
        select_startup(async { Err(anyhow::anyhow!("injected signal stream closed")) }, std::future::pending()).await;
    match result {
        StartupTrigger::Stop(Err(error)) => {
            assert!(error.to_string().contains("injected signal stream closed"));
        }
        _ => panic!("expected a finite stop error"),
    }
}

#[tokio::test]
async fn stop_first_no_setup_sets_one_deadline_and_keeps_server() {
    let mut owner = ServiceOwner::arm(Duration::from_secs(1));
    owner.attach_server(tokio::spawn(async {
        std::future::pending::<()>().await;
        Ok::<(), io::Error>(())
    }));
    let primary = owner.wait_for_stop_or_serve(async { Ok::<(), anyhow::Error>(()) }).await;
    assert!(primary.is_none());
    assert!(owner.server.is_some(), "a signal stop must retain the server handle for cleanup");
    let first = owner.deadline.expect("stop must fix D");
    let second = owner.begin_stop();
    assert_eq!(first, second, "begin_stop must never reset the deadline");
}

#[tokio::test]
async fn setup_failure_before_any_startup_still_uses_the_cleanup_funnel() {
    let mut owner = ServiceOwner::arm(Duration::from_secs(1));
    let driver = RecordingDriver::clean();
    let completion = owner.cleanup(Some(anyhow::anyhow!("injected setup failure")), &driver).await;
    assert!(!completion.is_clean());
    assert!(!completion.pending_runtime());
    let error = completion.into_result().expect_err("a setup failure must stay nonzero");
    assert!(error.to_string().contains("injected setup failure"));
}

#[tokio::test]
async fn pending_startup_completion_is_incomplete_and_retains_owner_marker() {
    let deadline = Instant::now() + Duration::from_secs(1);
    let completion = ServiceCompletion::new(None, Vec::new(), deadline, Some(PendingStartup::Test));
    assert!(completion.pending_runtime(), "pending startup must request bounded runtime termination");
    assert!(!completion.is_clean(), "pending startup can never be exit zero");
    let error = completion.into_result().expect_err("pending startup is incomplete");
    let text = format!("{error:#}");
    assert!(text.contains("startup reconcile owner remained pending"), "{text}");
}

#[tokio::test]
async fn teardown_is_polled_before_the_startup_join_and_releases_it() {
    let (release_tx, release_rx) = oneshot::channel();
    let teardown_polled = Arc::new(AtomicBool::new(false));
    let teardown_seen = teardown_polled.clone();
    let teardown = async move {
        teardown_seen.store(true, Ordering::SeqCst);
        release_tx.send(()).expect("startup release receiver");
        "teardown"
    };
    let startup_seen = teardown_polled.clone();
    let startup = async move {
        assert!(startup_seen.load(Ordering::SeqCst), "startup join was polled before mount teardown");
        let _ = release_rx.await;
        StartupJoinResult::Clean
    };
    let (teardown_result, startup_result) = join_teardown_and_startup(teardown, startup).await;
    assert_eq!(teardown_result, "teardown");
    assert!(matches!(startup_result, StartupJoinResult::Clean));
}
