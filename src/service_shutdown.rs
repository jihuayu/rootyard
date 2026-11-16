//! One owned service cleanup funnel for SIGTERM, returned startup errors and an
//! early Axum serve completion.
//!
//! The owner is armed before workspace reconcile. Every fallible step after
//! that point runs inside one result-producing scope, so a reconcile failure
//! that already mounted an earlier row reaches this same cleanup instead of
//! returning through `?`. The caller's observation wait is bounded by one
//! absolute deadline computed at the first stop/error. Native work is not
//! cancelled or dropped at that deadline; a timeout leaves it owned and makes
//! the service exit unsuccessful.
//!
//! A private injected-future seam lets source tests exercise this production
//! funnel (primary-error preservation, tracked task join/abort, early serve
//! Ok/Err) without a public fault endpoint or environment backdoor.
use anyhow::{anyhow, bail};
use rootyard::workspaces::mounts::{LegacyShutdownEvidence, shutdown_helper_until_with_evidence};
use sha2::{Digest, Sha256};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    task::{JoinError, JoinHandle},
    time::Instant,
};
use tokio_util::sync::CancellationToken;

/// Fixed, bounded evidence line emitted only after the retained legacy ticket
/// has actually joined its exact owned mounts.
const LEGACY_EVIDENCE_PREFIX: &str = "rootyard: legacy-shutdown-evidence ";
const LEGACY_EVIDENCE_SCHEMA: &str = "rootyard/issues91-95/legacy-shutdown-evidence/v1";
const LEGACY_EVIDENCE_MAX_WORKSPACES: usize = 64;

/// Result of one service run. The primary error and cleanup failures stay
/// separate: cleanup can never overwrite or relabel the original failure.
pub(crate) struct ServiceCompletion {
    primary: Option<anyhow::Error>,
    cleanup_failures: Vec<String>,
    deadline: std::time::Instant,
}

impl ServiceCompletion {
    fn new(primary: Option<anyhow::Error>, cleanup_failures: Vec<String>, deadline: Instant) -> Self {
        Self { primary, cleanup_failures, deadline: deadline.into_std() }
    }

    /// Only an unsuccessful/pending cleanup may consume the remaining product
    /// deadline through `Runtime::shutdown_timeout`. A clean terminal outcome
    /// keeps the ordinary runtime drop and makes no native-cleanup claim from
    /// process death.
    pub(crate) fn pending_runtime(&self) -> bool {
        !self.cleanup_failures.is_empty()
    }

    pub(crate) fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(std::time::Instant::now())
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn is_clean(&self) -> bool {
        self.primary.is_none() && self.cleanup_failures.is_empty()
    }

    /// Preserve the original failure as the error and append cleanup failures
    /// as a separate, explicit incomplete classification.
    pub(crate) fn into_result(self) -> anyhow::Result<()> {
        match (self.primary, self.cleanup_failures.is_empty()) {
            (Some(primary), true) => Err(primary),
            (Some(primary), false) => {
                let cleanup = format!("service cleanup incomplete: {}", self.cleanup_failures.join("; "));
                Err(primary.context(cleanup))
            }
            (None, true) => Ok(()),
            (None, false) => bail!("normal shutdown incomplete: {}", self.cleanup_failures.join("; ")),
        }
    }
}

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// The blocking/native side of cleanup. Production uses [`NativeCleanupDriver`];
/// source tests inject a recording driver so they exercise the same ordering,
/// deadline, primary-error and task-ownership code without pretending to be a
/// native mount.
pub(crate) trait CleanupDriver {
    fn stop_capture_and_mounts<'a>(
        &'a self,
        capture: Option<JoinHandle<()>>,
        stop: CancellationToken,
        capture_grace: Duration,
        deadline: Instant,
    ) -> BoxFuture<'a, (Result<(), String>, Option<LegacyShutdownEvidence>)>;

    fn drain_git<'a>(&'a self, deadline: Instant) -> BoxFuture<'a, bool>;

    fn process_cleanup_failed(&self) -> bool;
}

pub(crate) struct NativeCleanupDriver;

impl CleanupDriver for NativeCleanupDriver {
    fn stop_capture_and_mounts<'a>(
        &'a self,
        capture: Option<JoinHandle<()>>,
        stop: CancellationToken,
        capture_grace: Duration,
        deadline: Instant,
    ) -> BoxFuture<'a, (Result<(), String>, Option<LegacyShutdownEvidence>)> {
        Box::pin(async move {
            match capture {
                Some(task) => {
                    let evidence = Arc::new(Mutex::new(None));
                    let slot = evidence.clone();
                    let result =
                        rootyard::workspaces::stop_capture_before_helper(stop, task, capture_grace, async move {
                            let (helper_result, evidence) = shutdown_helper_until_with_evidence(deadline).await;
                            *slot.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = evidence;
                            helper_result.map_err(|error| format!("{error}"))
                        })
                        .await
                        .map_err(|error| format!("{error:#}"));
                    let evidence = evidence.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
                    (result, evidence)
                }
                None => {
                    // No capture producer was created (for example an early
                    // reconcile failure). Mount teardown is still mandatory.
                    let (result, evidence) = shutdown_helper_until_with_evidence(deadline).await;
                    (result.map_err(|error| format!("{error}")), evidence)
                }
            }
        })
    }

    fn drain_git<'a>(&'a self, deadline: Instant) -> BoxFuture<'a, bool> {
        Box::pin(async move { rootyard::workspaces::drain_git_jobs_until(deadline).await })
    }

    fn process_cleanup_failed(&self) -> bool {
        rootyard::workspaces::process_cleanup_failed()
    }
}

/// Owns every task and cancellation token created by one serving lifecycle.
/// All partial creations are `Option`s so a later fallible startup step can run
/// the same cleanup without an early function-level return.
pub(crate) struct ServiceOwner {
    git_grace: Duration,
    deadline: Option<Instant>,
    cleanup_started: bool,
    evidence_emitted: bool,
    http_stop: CancellationToken,
    dispatch_stop: CancellationToken,
    capture_stop: CancellationToken,
    maintenance_stop: CancellationToken,
    session_gc_stop: CancellationToken,
    server: Option<JoinHandle<io::Result<()>>>,
    controller_task: Option<JoinHandle<()>>,
    metrics_worker: Option<JoinHandle<()>>,
    publish_task: Option<JoinHandle<()>>,
    delivery_task: Option<JoinHandle<()>>,
    webhook_task: Option<JoinHandle<()>>,
    capture_task: Option<JoinHandle<()>>,
    worker: Option<JoinHandle<()>>,
    maintenance_task: Option<JoinHandle<anyhow::Result<()>>>,
    session_gc_task: Option<JoinHandle<()>>,
}

impl ServiceOwner {
    pub(crate) fn arm(git_grace: Duration) -> Self {
        Self {
            git_grace,
            deadline: None,
            cleanup_started: false,
            evidence_emitted: false,
            http_stop: CancellationToken::new(),
            dispatch_stop: CancellationToken::new(),
            capture_stop: CancellationToken::new(),
            maintenance_stop: CancellationToken::new(),
            session_gc_stop: CancellationToken::new(),
            server: None,
            controller_task: None,
            metrics_worker: None,
            publish_task: None,
            delivery_task: None,
            webhook_task: None,
            capture_task: None,
            worker: None,
            maintenance_task: None,
            session_gc_task: None,
        }
    }

    pub(crate) fn http_stop(&self) -> &CancellationToken {
        &self.http_stop
    }

    pub(crate) fn dispatch_stop(&self) -> &CancellationToken {
        &self.dispatch_stop
    }

    pub(crate) fn capture_stop(&self) -> &CancellationToken {
        &self.capture_stop
    }

    pub(crate) fn maintenance_stop(&self) -> &CancellationToken {
        &self.maintenance_stop
    }

    pub(crate) fn session_gc_stop(&self) -> &CancellationToken {
        &self.session_gc_stop
    }

    pub(crate) fn attach_server(&mut self, task: JoinHandle<io::Result<()>>) {
        self.server = Some(task);
    }

    pub(crate) fn attach_controller(&mut self, task: JoinHandle<()>) {
        self.controller_task = Some(task);
    }

    pub(crate) fn attach_metrics(&mut self, task: JoinHandle<()>) {
        self.metrics_worker = Some(task);
    }

    pub(crate) fn attach_publish(&mut self, task: JoinHandle<()>) {
        self.publish_task = Some(task);
    }

    pub(crate) fn attach_delivery(&mut self, task: JoinHandle<()>) {
        self.delivery_task = Some(task);
    }

    pub(crate) fn attach_webhook(&mut self, task: JoinHandle<()>) {
        self.webhook_task = Some(task);
    }

    pub(crate) fn attach_capture(&mut self, task: JoinHandle<()>) {
        self.capture_task = Some(task);
    }

    pub(crate) fn attach_worker(&mut self, task: JoinHandle<()>) {
        self.worker = Some(task);
    }

    pub(crate) fn attach_maintenance(&mut self, task: JoinHandle<anyhow::Result<()>>) {
        self.maintenance_task = Some(task);
    }

    pub(crate) fn attach_session_gc(&mut self, task: JoinHandle<()>) {
        self.session_gc_task = Some(task);
    }

    /// Wait for the normal signal or for the serving future to complete on its
    /// own. On an early completion the `JoinHandle` is consumed exactly once
    /// and converted to the primary error; it is never polled again by cleanup.
    pub(crate) async fn wait_for_stop_or_serve<F>(&mut self, stop: F) -> Option<anyhow::Error>
    where
        F: Future<Output = ()>,
    {
        let Some(server) = self.server.as_mut() else {
            return Some(anyhow!("HTTP server task was not armed before the service wait"));
        };
        let early = tokio::select! {
            _ = stop => None,
            joined = server => Some(serve_primary(joined)),
        };
        if early.is_some() {
            // The handle completed exactly once. Drop the consumed handle; a
            // later cleanup must not poll it again.
            self.server = None;
        }
        early
    }

    /// Run the single cleanup funnel. Ordering is the existing product order:
    /// close admission and stop capture, then exact mount teardown, then
    /// request/Git/background joins, then the final plumbing drain.
    pub(crate) async fn cleanup(
        &mut self,
        primary: Option<anyhow::Error>,
        driver: &dyn CleanupDriver,
    ) -> ServiceCompletion {
        let deadline = self.absolute_deadline();
        if self.cleanup_started {
            return ServiceCompletion::new(primary, vec!["service cleanup was invoked twice".to_owned()], deadline);
        }
        self.cleanup_started = true;

        self.http_stop.cancel();
        // Already accepted Git jobs keep their permits and JoinSet ownership;
        // only new acquisition is refused from here on.
        rootyard::workspaces::close_git_admission();

        let mut failures = Vec::new();
        let capture_grace = rootyard::workspaces::capture_shutdown_grace().min(remaining_until(deadline));
        let (capture_result, evidence) = driver
            .stop_capture_and_mounts(self.capture_task.take(), self.capture_stop.clone(), capture_grace, deadline)
            .await;
        if let Err(error) = capture_result {
            failures.push(format!("workspace capture/helper shutdown did not complete cleanly: {error}"));
        }
        if let Some(evidence) = evidence {
            self.emit_legacy_evidence(&evidence);
        }

        // The helper has fenced and unmounted before this join. The retained
        // Git set consumes only the remaining shared deadline.
        if !driver.drain_git(deadline).await {
            failures.push("owned workspace Git jobs/process cleanup did not complete cleanly".to_owned());
        }

        if let Some(mut server) = self.server.take() {
            match tokio::time::timeout_at(deadline, &mut server).await {
                Ok(Ok(Ok(()))) => {}
                Ok(Ok(Err(_))) | Ok(Err(_)) => failures.push("HTTP server did not stop cleanly".to_owned()),
                Err(_) => {
                    server.abort();
                    failures.push("HTTP server did not join within the shutdown deadline".to_owned());
                }
            }
        }

        if let Some(worker) = self.worker.take() {
            worker.abort();
            if join_aborted_until(deadline, worker).await.is_err() {
                failures.push("background worker did not stop cleanly".to_owned());
            }
        }

        self.maintenance_stop.cancel();
        self.session_gc_stop.cancel();
        if let Some(task) = self.session_gc_task.take()
            && join_task_until(deadline, task).await.is_err()
        {
            failures.push("session GC task did not join cleanly".to_owned());
        }
        if let Some(task) = self.controller_task.take() {
            task.abort();
            if join_aborted_until(deadline, task).await.is_err() {
                failures.push("sharding controller did not stop cleanly".to_owned());
            }
        }
        if let Some(task) = self.maintenance_task.take() {
            match join_task_until(deadline, task).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) | Err(_) => failures.push("workspace maintenance task did not stop cleanly".to_owned()),
            }
        }

        self.dispatch_stop.cancel();
        if let Some(task) = self.publish_task.take()
            && join_task_until(deadline, task).await.is_err()
        {
            failures.push("dispatch publisher did not stop cleanly".to_owned());
        }
        if let Some(task) = self.delivery_task.take()
            && join_task_until(deadline, task).await.is_err()
        {
            failures.push("dispatch delivery worker did not stop cleanly".to_owned());
        }
        if let Some(task) = self.webhook_task.take()
            && join_task_until(deadline, task).await.is_err()
        {
            failures.push("webhook worker did not stop cleanly".to_owned());
        }
        if let Some(task) = self.metrics_worker.take() {
            task.abort();
            if join_aborted_until(deadline, task).await.is_err() {
                failures.push("metrics worker did not stop cleanly".to_owned());
            }
        }

        // The serving future and producers are joined now. A request admitted
        // immediately before close can have spawned its owned job after the
        // first snapshot; this second same-deadline drain catches that late
        // ownership without resetting the budget.
        if !driver.drain_git(deadline).await {
            failures.push("late owned workspace Git jobs/process cleanup did not complete cleanly".to_owned());
        }
        if driver.process_cleanup_failed() {
            failures.push("native Git process cleanup did not prove quiescence".to_owned());
        }

        ServiceCompletion::new(primary, failures, deadline)
    }

    /// One absolute deadline, computed at the first stop/error and reused for
    /// every later phase. It never starts a fresh phase grace and only tightens
    /// the product's existing Git allowance via the shared publication API.
    fn absolute_deadline(&mut self) -> Instant {
        if let Some(deadline) = self.deadline {
            return deadline;
        }
        let deadline = Instant::now() + self.git_grace;
        self.deadline = Some(deadline);
        rootyard::workspaces::set_process_cleanup_deadline(deadline);
        deadline
    }

    fn emit_legacy_evidence(&mut self, evidence: &LegacyShutdownEvidence) {
        if self.evidence_emitted || evidence.joined_mounts == 0 {
            // An empty/no-work ticket is not one mount of proof.
            return;
        }
        self.evidence_emitted = true;
        let mut workspaces: Vec<String> =
            evidence.workspaces.iter().map(|id| hex::encode(Sha256::digest(id.to_string().as_bytes()))).collect();
        workspaces.sort();
        workspaces.dedup();
        let total = workspaces.len();
        let truncated = total > LEGACY_EVIDENCE_MAX_WORKSPACES;
        workspaces.truncate(LEGACY_EVIDENCE_MAX_WORKSPACES);
        // Fixed schema, counts and bounded hashed identities only. No path,
        // token, request body or SQL text can appear here.
        let payload = serde_json::json!({
            "schema": LEGACY_EVIDENCE_SCHEMA,
            "mount_namespace": evidence.mount_namespace,
            "joined_mounts": evidence.joined_mounts,
            "joined_workspaces": workspaces,
            "joined_workspaces_total": total,
            "joined_workspaces_truncated": truncated,
            "pending_admissions": 0,
            "retained_owners": 0,
            "cleanup_failures": 0,
        });
        eprintln!("{LEGACY_EVIDENCE_PREFIX}{payload}");
    }
}

fn serve_primary(joined: Result<io::Result<()>, JoinError>) -> anyhow::Error {
    match joined {
        Ok(Ok(())) => anyhow!("HTTP server stopped before the normal shutdown signal"),
        Ok(Err(error)) => anyhow::Error::new(error),
        Err(error) => anyhow::Error::new(error),
    }
}

fn remaining_until(deadline: Instant) -> Duration {
    let now = Instant::now();
    if deadline <= now { Duration::ZERO } else { deadline - now }
}

async fn join_task_until<T>(deadline: Instant, mut task: JoinHandle<T>) -> Result<T, &'static str> {
    match tokio::time::timeout_at(deadline, &mut task).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(_)) => Err("shutdown task ended abnormally"),
        Err(_) => {
            task.abort();
            Err("shutdown task did not join within the deadline")
        }
    }
}

async fn join_aborted_until<T>(deadline: Instant, mut task: JoinHandle<T>) -> Result<(), &'static str> {
    match tokio::time::timeout_at(deadline, &mut task).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) if error.is_cancelled() => Ok(()),
        Ok(Err(_)) => Err("aborted shutdown task failed"),
        Err(_) => {
            task.abort();
            Err("aborted shutdown task did not join within the deadline")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

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
        owner.attach_server(tokio::spawn(async { Err(io::Error::other("injected early serve failure")) }));
        let primary = owner
            .wait_for_stop_or_serve(std::future::pending())
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
        owner.attach_server(tokio::spawn(async { Ok(()) }));
        let primary = owner
            .wait_for_stop_or_serve(std::future::pending())
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
        let primary = anyhow!("injected startup failure");
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

        let joined =
            LegacyShutdownEvidence { mount_namespace: 7, joined_mounts: 1, workspaces: vec![uuid::Uuid::nil()] };
        owner.emit_legacy_evidence(&joined);
        assert!(owner.evidence_emitted);
        owner.emit_legacy_evidence(&joined);
        assert!(owner.evidence_emitted, "one cleanup emits one bounded line");
    }
}
