//! Test-only gateway rendezvous for exact acceptance operations.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::time::Instant;
use uuid::Uuid;

use super::{BlobGitState, GatewayError};

impl BlobGitState {
    /// Acceptance-only: attach a private rendezvous to this gateway instance.
    /// The production constructor has no parameter, environment variable or
    /// route that can reach this field.
    pub(crate) fn with_admission_pause(mut self, pause: Arc<AdmissionPause>) -> Self {
        self.admission_pause = Some(pause);
        self
    }

    /// Acceptance-only: attach a private rendezvous that fires after the
    /// admission transaction committed and before the first protected upload.
    /// It is a distinct hook from the pre-admission pause so one fixture can
    /// hold either side of the immutable `COMMIT` without changing production
    /// behavior.
    pub(crate) fn with_publication_pause(mut self, pause: Arc<AdmissionPause>) -> Self {
        self.publication_pause = Some(pause);
        self
    }

    /// Called after the publish baseline was captured and before the admission
    /// transaction starts. In production this method does not exist.
    pub(crate) async fn pause_before_admission(&self, operation_id: Uuid) {
        if let Some(pause) = &self.admission_pause {
            let _ = pause.pause(operation_id).await;
        }
    }

    /// Called after the caller-owned admission transaction returned a definite
    /// `COMMIT` and before any A3 hold/upload. The pause therefore never holds a
    /// PostgreSQL transaction open. In production this method does not exist.
    ///
    /// An armed test-side release guard can abandon the rendezvous on an early
    /// failure or panic. The selected operation then returns this fixed refusal
    /// before the first protected upload instead of continuing into a write.
    pub(crate) async fn pause_after_admission(&self, operation_id: Uuid) -> Result<(), GatewayError> {
        if let Some(pause) = &self.publication_pause
            && pause.pause(operation_id).await
            && pause.was_abandoned()
        {
            return Err(GatewayError::Conflict("acceptance publication was abandoned before upload"));
        }
        Ok(())
    }

    /// Acceptance-only: attach a private read rendezvous to this gateway.
    pub(crate) fn with_read_pause(mut self, pause: Arc<ReadPause>) -> Self {
        self.read_pause = Some(pause);
        self
    }

    /// Acceptance-only: pause one exact commit-preview request after its
    /// advisory payload lookup and before response encoding/final fences.
    pub(crate) async fn pause_before_commit_finalize(&self, oid: &str) {
        if let Some(pause) = &self.read_pause {
            pause.pause(oid).await;
        }
    }
}

/// Acceptance-only rendezvous used by the deterministic stale-baseline cases.
/// The pause is keyed by operation UUID and can fire at most once.
pub(crate) struct AdmissionPause {
    operation: Uuid,
    paused: AtomicBool,
    abandoned: AtomicBool,
    reached: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

impl AdmissionPause {
    pub(crate) fn new(operation: Uuid) -> Self {
        Self {
            operation,
            paused: AtomicBool::new(false),
            abandoned: AtomicBool::new(false),
            reached: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        }
    }

    async fn pause(&self, operation: Uuid) -> bool {
        if operation != self.operation || self.paused.swap(true, Ordering::AcqRel) {
            return false;
        }
        // `notify_one` stores a permit, so a test that starts waiting after the
        // request arrived still observes the rendezvous.
        self.reached.notify_one();
        self.release.notified().await;
        true
    }

    /// Wait until the selected operation reached the post-capture pause.
    pub(crate) async fn wait_reached(&self) {
        self.reached.notified().await;
    }

    /// Let the paused operation continue into admission.
    pub(crate) fn release(&self) {
        self.release.notify_one();
    }

    /// Mark the rendezvous abandoned and let the paused operation return. The
    /// release permit is stored even if the request has not reached the pause
    /// yet, so an early failure cannot leave a server-side handler waiting.
    pub(crate) fn abandon(&self) {
        self.abandoned.store(true, Ordering::Release);
        self.release.notify_one();
    }

    fn was_abandoned(&self) -> bool {
        self.abandoned.load(Ordering::Acquire)
    }
}

/// Acceptance-only rendezvous reached after an exact commit-preview payload
/// lookup and before the final encoded-response authorization fence. It is
/// keyed by the exact OID admitted by the route and fires at most once; the
/// wait has a fixed bounded timeout so a missing release fails the test rather
/// than hanging the process.
pub(crate) struct ReadPause {
    target: std::sync::Mutex<Option<String>>,
    paused: AtomicBool,
    reached: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

impl ReadPause {
    pub(crate) fn new() -> Self {
        Self {
            target: std::sync::Mutex::new(None),
            paused: AtomicBool::new(false),
            reached: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        }
    }

    /// Select the one exact OID whose next commit-preview request pauses.
    pub(crate) fn target(&self, oid: impl Into<String>) {
        *self.target.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(oid.into());
    }

    async fn pause(&self, oid: &str) {
        let matches = self
            .target
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_deref()
            .is_some_and(|target| target == oid);
        if !matches || self.paused.swap(true, Ordering::AcqRel) {
            return;
        }
        // `notify_one` stores a permit, so a test that starts waiting after the
        // request arrived still observes the rendezvous.
        self.reached.notify_one();
        let _ = tokio::time::timeout(Duration::from_secs(30), self.release.notified()).await;
    }

    /// Wait until the selected exact-OID request reached the pre-finalize pause.
    /// The caller's one deadline bounds the wait; expiration is a normal error so
    /// the fixture can still release, reap and finish the database.
    pub(crate) async fn wait_reached(&self, deadline: Instant) -> anyhow::Result<()> {
        tokio::time::timeout_at(deadline, self.reached.notified())
            .await
            .map(|_| ())
            .map_err(|_| anyhow::anyhow!("deterministic commit-finalize pause was not reached"))
    }

    /// Let the paused request continue into response encoding and final fences.
    pub(crate) fn release(&self) {
        self.release.notify_one();
    }
}

#[tokio::test]
async fn acceptance_pause_waits_once_for_only_its_operation() {
    let target = Uuid::new_v4();
    let pause = Arc::new(AdmissionPause::new(target));
    let waiting = {
        let pause = pause.clone();
        tokio::spawn(async move { pause.pause(target).await })
    };
    pause.wait_reached().await;
    assert!(!waiting.is_finished(), "the selected operation must remain paused until release");
    pause.release();
    waiting.await.expect("pause task");
    // The rendezvous is one-shot and keyed by operation: a rebase retry or
    // any other operation passes without blocking.
    pause.pause(target).await;
    pause.pause(Uuid::new_v4()).await;
}
