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
use anyhow::anyhow;
use rootyard::workspaces::mounts::{
    LegacyShutdownEvidence, StartupJoinError, StartupOutcome, StartupReconcile, shutdown_helper_until_with_evidence,
};
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

#[path = "service_shutdown/completion.rs"]
mod completion;
#[path = "service_shutdown/signals.rs"]
mod signals;

pub(crate) use self::completion::{PendingStartup, startup_join_error_text};
pub(crate) use self::completion::{ServiceCompletion, is_startup_stopped, startup_join_failure, startup_stopped};
pub(crate) use self::signals::StopSignals;

/// Biased startup wait used by the service. A ready stop signal is always
/// polled before the setup future is first polled, including when both become
/// ready together.
pub(crate) enum StartupTrigger {
    Stop(anyhow::Result<()>),
    Setup(anyhow::Result<()>),
}

pub(crate) async fn select_startup<S, F>(stop: S, setup: F) -> StartupTrigger
where
    S: Future<Output = anyhow::Result<()>>,
    F: Future<Output = anyhow::Result<()>>,
{
    tokio::select! {
        biased;
        result = stop => StartupTrigger::Stop(result),
        result = setup => StartupTrigger::Setup(result),
    }
}

enum StartupJoinResult {
    None,
    Clean,
    Stopped,
    Failed(anyhow::Error),
    JoinFailed(StartupJoinError),
    Pending,
}

/// Fixed, bounded evidence line emitted only after the retained legacy ticket
/// has actually joined its exact owned mounts.
const LEGACY_EVIDENCE_PREFIX: &str = "rootyard: legacy-shutdown-evidence ";
const LEGACY_EVIDENCE_SCHEMA: &str = "rootyard/issues91-95/legacy-shutdown-evidence/v1";
const LEGACY_EVIDENCE_MAX_WORKSPACES: usize = 64;

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
                            helper_result.map_err(|error| anyhow!("{error}"))
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
    startup: Option<StartupReconcile>,
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
            startup: None,
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

    pub(crate) fn attach_startup(&mut self, startup: StartupReconcile) {
        self.startup = Some(startup);
    }

    /// Await the owned startup producer while leaving its handle here if this
    /// future is dropped by the outer startup select. Service startup calls
    /// this before any listener bind or later task attachment.
    pub(crate) async fn wait_startup(&mut self) -> Result<StartupOutcome, StartupJoinError> {
        let result = {
            let Some(startup) = self.startup.as_mut() else {
                return Err(StartupJoinError::AlreadyJoined);
            };
            startup.wait().await
        };
        self.startup = None;
        result
    }

    /// Fix and publish the one deadline, stop new startup row admission, close
    /// Git admission and stop HTTP acceptance. Idempotent: a later cleanup call
    /// reuses the same D and cannot extend it.
    pub(crate) fn begin_stop(&mut self) -> Instant {
        let deadline = self.absolute_deadline();
        if let Some(startup) = self.startup.as_ref() {
            startup.stop();
        }
        rootyard::workspaces::close_git_admission();
        self.http_stop.cancel();
        deadline
    }

    /// Wait for the normal signal or for the serving future to complete on its
    /// own. On an early completion the `JoinHandle` is consumed exactly once
    /// and converted to the primary error; it is never polled again by cleanup.
    /// A signal/stream error is a finite primary error. Both branches call
    /// `begin_stop` before returning.
    pub(crate) async fn wait_for_stop_or_serve<F>(&mut self, stop: F) -> Option<anyhow::Error>
    where
        F: Future<Output = anyhow::Result<()>>,
    {
        enum StopOrServe {
            Stop(anyhow::Result<()>),
            Serve(Result<io::Result<()>, JoinError>),
        }
        let event = {
            let Some(server) = self.server.as_mut() else {
                self.begin_stop();
                return Some(anyhow!("HTTP server task was not armed before the service wait"));
            };
            tokio::select! {
                biased;
                result = stop => StopOrServe::Stop(result),
                joined = server => StopOrServe::Serve(joined),
            }
        };
        self.begin_stop();
        match event {
            StopOrServe::Stop(Ok(())) => None,
            StopOrServe::Stop(Err(error)) => Some(error),
            StopOrServe::Serve(joined) => {
                // The handle completed exactly once. Drop the consumed handle;
                // a later cleanup must not poll it again.
                self.server = None;
                Some(serve_primary(joined))
            }
        }
    }

    /// Run the single cleanup funnel. Ordering is the existing product order:
    /// close admission and stop capture, then exact mount teardown, then
    /// request/Git/background joins, then the final plumbing drain.
    pub(crate) async fn cleanup(
        &mut self,
        mut primary: Option<anyhow::Error>,
        driver: &dyn CleanupDriver,
    ) -> ServiceCompletion {
        let deadline = self.begin_stop();
        if self.cleanup_started {
            return ServiceCompletion::new(
                primary,
                vec!["service cleanup was invoked twice".to_owned()],
                deadline,
                self.startup.take().map(|owner| PendingStartup::Owned { _owner: owner }),
            );
        }
        self.cleanup_started = true;

        let mut failures = Vec::new();
        let capture_grace = rootyard::workspaces::capture_shutdown_grace().min(remaining_until(deadline));
        let capture_task = self.capture_task.take();
        let capture_stop = self.capture_stop.clone();
        let teardown = driver.stop_capture_and_mounts(capture_task, capture_stop, capture_grace, deadline);
        // Start mount closing/teardown and the retained startup producer join
        // under the same D. The biased `join!` polls the driver future first,
        // so a blocked startup ensure is never awaited before teardown can
        // release the mount it is holding.
        let startup_join = self.join_startup_until(deadline);
        let (teardown_result, startup_result) = join_teardown_and_startup(teardown, startup_join).await;
        let (capture_result, evidence) = teardown_result;
        if let Err(error) = capture_result {
            failures.push(format!("workspace capture/helper shutdown did not complete cleanly: {error}"));
        }
        if let Some(evidence) = evidence {
            self.emit_legacy_evidence(&evidence);
        }
        match startup_result {
            StartupJoinResult::None | StartupJoinResult::Clean | StartupJoinResult::Stopped => {}
            StartupJoinResult::Failed(error) => {
                if primary.is_none() {
                    primary = Some(error);
                } else {
                    failures.push(format!("startup reconcile failed after another primary error: {error:#}"));
                }
            }
            StartupJoinResult::JoinFailed(error) => {
                failures.push(format!("startup reconcile join failed: {}", startup_join_error_text(error)));
            }
            StartupJoinResult::Pending => {
                // `ServiceCompletion` retains the owner and its `into_result`
                // adds the incomplete classification after bounded runtime
                // termination.
            }
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

        let pending_startup = self.startup.take().map(|owner| PendingStartup::Owned { _owner: owner });
        ServiceCompletion::new(primary, failures, deadline, pending_startup)
    }

    async fn join_startup_until(&mut self, deadline: Instant) -> StartupJoinResult {
        let result = {
            let Some(startup) = self.startup.as_mut() else {
                return StartupJoinResult::None;
            };
            startup.join_until(deadline).await
        };
        match result {
            Ok(StartupOutcome::Completed(Ok(()))) => {
                self.startup = None;
                StartupJoinResult::Clean
            }
            Ok(StartupOutcome::Stopped) => {
                self.startup = None;
                StartupJoinResult::Stopped
            }
            Ok(StartupOutcome::Completed(Err(error))) => {
                self.startup = None;
                StartupJoinResult::Failed(anyhow::Error::new(error))
            }
            Err(StartupJoinError::Deadline) => StartupJoinResult::Pending,
            Err(error) => {
                self.startup = None;
                StartupJoinResult::JoinFailed(error)
            }
        }
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

async fn join_teardown_and_startup<T, F, S>(teardown: F, startup: S) -> (T, StartupJoinResult)
where
    F: Future<Output = T>,
    S: Future<Output = StartupJoinResult>,
{
    // Biased join: the mount-closing future is polled first. Both futures stay
    // concurrent under the same D, so teardown can release a blocked startup
    // ensure and startup is never awaited serially before teardown.
    tokio::join!(biased; teardown, startup)
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
#[path = "service_shutdown/tests.rs"]
mod tests;
