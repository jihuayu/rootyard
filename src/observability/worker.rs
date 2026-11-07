//! Bounded background-operation correlation for long-lived workers.
//!
//! A worker round owns one server-generated operation UUID. Only fixed worker
//! and phase labels plus, when a persisted attempt/generation already exists,
//! their numeric values are emitted. Actor, repository, token, job and remote
//! object identifiers are deliberately absent.
use std::future::Future;

use tokio::task_local;
use uuid::Uuid;

/// Every background loop that has a real operation scope in this change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WorkerKind {
    WebhooksBackground,
    StorageLifecycle,
    WorkspaceCapture,
    WorkspaceRemoteGc,
    DurableDispatch,
}

impl WorkerKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::WebhooksBackground => "webhooks_background",
            Self::StorageLifecycle => "storage_lifecycle",
            Self::WorkspaceCapture => "workspace_capture",
            Self::WorkspaceRemoteGc => "workspace_remote_gc",
            Self::DurableDispatch => "durable_dispatch",
        }
    }

    #[cfg(test)]
    pub(crate) const ALL: [Self; 5] = [
        Self::WebhooksBackground,
        Self::StorageLifecycle,
        Self::WorkspaceCapture,
        Self::WorkspaceRemoteGc,
        Self::DurableDispatch,
    ];
}

/// Bounded stage labels. They never carry a raw repository, actor or endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    Round,
    Scan,
    Reconcile,
    Deliver,
    Claim,
    Execute,
    Collect,
    Dispatch,
    Subscribe,
}

impl Phase {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Round => "round",
            Self::Scan => "scan",
            Self::Reconcile => "reconcile",
            Self::Deliver => "deliver",
            Self::Claim => "claim",
            Self::Execute => "execute",
            Self::Collect => "collect",
            Self::Dispatch => "dispatch",
            Self::Subscribe => "subscribe",
        }
    }

    #[cfg(test)]
    pub(crate) const ALL: [Self; 9] = [
        Self::Round,
        Self::Scan,
        Self::Reconcile,
        Self::Deliver,
        Self::Claim,
        Self::Execute,
        Self::Collect,
        Self::Dispatch,
        Self::Subscribe,
    ];
}

/// The selected context for one worker round. `new` always samples a fresh
/// server-generated UUID; callers can only add non-negative numeric values that
/// were already persisted for the claimed job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OperationContext {
    worker: WorkerKind,
    operation_id: Uuid,
    attempt: Option<i64>,
    generation: Option<i64>,
}

impl OperationContext {
    pub(crate) fn new(worker: WorkerKind) -> Self {
        Self { worker, operation_id: Uuid::new_v4(), attempt: None, generation: None }
    }

    pub(crate) fn with_attempt(mut self, attempt: Option<i64>) -> Self {
        self.attempt = attempt.filter(|value| *value >= 0);
        self
    }

    pub(crate) fn with_generation(mut self, generation: Option<i64>) -> Self {
        self.generation = generation.filter(|value| *value >= 0);
        self
    }
}

/// Materialised task-local value. HTTP request scope is a separate task local
/// and is never consulted while an operation scope is installed.
#[derive(Clone, Debug)]
pub(crate) struct OperationScope {
    pub(crate) worker: WorkerKind,
    pub(crate) operation_id: Uuid,
    pub(crate) phase: Phase,
    pub(crate) attempt: Option<i64>,
    pub(crate) generation: Option<i64>,
}

task_local! {
    static OPERATION_SCOPE: OperationScope;
}

fn scope_for(context: &OperationContext, phase: Phase) -> OperationScope {
    OperationScope {
        worker: context.worker,
        operation_id: context.operation_id,
        phase,
        attempt: context.attempt,
        generation: context.generation,
    }
}

/// Read the active operation, if any. Used only to build a fixed-key event.
pub(crate) fn current() -> Option<OperationScope> {
    OPERATION_SCOPE.try_with(Clone::clone).ok()
}

/// Run one phase of a round inside the selected operation context. Nested
/// phases keep the round UUID while changing only the fixed phase label.
pub(crate) async fn run<F: Future>(context: &OperationContext, phase: Phase, future: F) -> F::Output {
    OPERATION_SCOPE.scope(scope_for(context, phase), future).await
}

/// Spawn a child with an explicitly selected operation context. A plain
/// `tokio::spawn` does not inherit task locals, and this helper deliberately
/// installs only the operation scope so request context can never leak in.
pub(crate) fn spawn<F>(context: &OperationContext, phase: Phase, future: F) -> tokio::task::JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    tokio::spawn(OPERATION_SCOPE.scope(scope_for(context, phase), future))
}

#[cfg(test)]
mod tests {
    use super::{
        super::{REQUEST_SCOPE, RequestScope, event_json},
        *,
    };
    use serde_json::Value;

    fn io_error() -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::Other, "SECRET-worker-display-never-formatted")
    }

    fn parse(text: &str) -> Value {
        let value: Value = serde_json::from_str(text).expect("event is valid JSON");
        assert!(!text.contains("SECRET"), "event formatted content");
        value
    }

    #[test]
    fn fixed_worker_and_phase_labels_are_bounded_ascii() {
        for worker in WorkerKind::ALL {
            assert!(worker.as_str().bytes().all(|byte| byte.is_ascii_lowercase() || byte == b'_'));
        }
        for phase in Phase::ALL {
            assert!(phase.as_str().bytes().all(|byte| byte.is_ascii_lowercase() || byte == b'_'));
        }
        let workers = WorkerKind::ALL.map(WorkerKind::as_str);
        let phases = Phase::ALL.map(Phase::as_str);
        for index in 0..workers.len() {
            assert!(!workers[..index].contains(&workers[index]), "duplicate worker label");
        }
        for index in 0..phases.len() {
            assert!(!phases[..index].contains(&phases[index]), "duplicate phase label");
        }
    }

    #[test]
    fn each_round_samples_a_distinct_server_generated_uuid() {
        let first = OperationContext::new(WorkerKind::StorageLifecycle);
        let second = OperationContext::new(WorkerKind::StorageLifecycle);
        assert_ne!(first.operation_id, second.operation_id);
        assert!(Uuid::parse_str(&first.operation_id.to_string()).is_ok());
    }

    #[tokio::test]
    async fn http_request_scope_is_never_attributed_to_worker() {
        let request_id = Uuid::new_v4();
        let request = RequestScope { request_id, route: Some("/api/repos".to_owned()) };
        let (inline, spawned) = REQUEST_SCOPE
            .scope(request, async {
                let context = OperationContext::new(WorkerKind::WebhooksBackground);
                let inline = run(&context, Phase::Scan, async { event_json(&io_error()) }).await;
                let child_context = context.clone();
                let spawned = spawn(&child_context, Phase::Deliver, async { event_json(&io_error()) })
                    .await
                    .expect("child joined");
                (inline, spawned)
            })
            .await;
        for (text, phase) in [(inline, "scan"), (spawned, "deliver")] {
            let value = parse(&text);
            assert_eq!(value["scope"].as_str(), Some("worker"));
            assert_eq!(value["worker"].as_str(), Some("webhooks_background"));
            assert_eq!(value["phase"].as_str(), Some(phase));
            assert!(Uuid::parse_str(value["operation_id"].as_str().unwrap()).is_ok());
            assert!(value.get("request_id").is_none(), "request id leaked into worker event");
            assert!(value.get("route").is_none(), "HTTP route leaked into worker event");
            assert_ne!(value["operation_id"].as_str(), Some(request_id.to_string().as_str()));
        }
    }

    #[tokio::test]
    async fn spawn_without_an_explicit_context_is_detached() {
        let text = tokio::spawn(async { event_json(&io_error()) }).await.expect("joined");
        let value = parse(&text);
        assert_eq!(value["scope"].as_str(), Some("detached"));
        assert!(value.get("worker").is_none());
        assert!(value.get("operation_id").is_none());
        assert!(value.get("phase").is_none());
    }

    #[tokio::test]
    async fn nested_phase_keeps_the_round_operation_id() {
        let context = OperationContext::new(WorkerKind::StorageLifecycle);
        let (outer, inner) = run(&context, Phase::Round, async {
            let outer = current().expect("outer operation scope");
            let inner = run(&context, Phase::Scan, async { current().expect("inner operation scope") }).await;
            (outer, inner)
        })
        .await;
        assert_eq!(outer.worker, WorkerKind::StorageLifecycle);
        assert_eq!(outer.phase, Phase::Round);
        assert_eq!(inner.phase, Phase::Scan);
        assert_eq!(outer.operation_id, inner.operation_id);
    }

    #[tokio::test]
    async fn persisted_numeric_attempt_and_generation_are_the_only_job_fields() {
        let context =
            OperationContext::new(WorkerKind::StorageLifecycle).with_attempt(Some(3)).with_generation(Some(42));
        let text = run(&context, Phase::Execute, async { event_json(&io_error()) }).await;
        let value = parse(&text);
        assert_eq!(value["scope"].as_str(), Some("worker"));
        assert_eq!(value["worker"].as_str(), Some("storage_lifecycle"));
        assert_eq!(value["phase"].as_str(), Some("execute"));
        assert_eq!(value["attempt"].as_i64(), Some(3));
        assert_eq!(value["generation"].as_i64(), Some(42));
        for forbidden in ["actor", "actor_id", "repository_id", "job_id", "token", "url", "endpoint", "contents"] {
            assert!(value.get(forbidden).is_none(), "raw field {forbidden} was emitted");
        }

        let negative =
            OperationContext::new(WorkerKind::StorageLifecycle).with_attempt(Some(-1)).with_generation(Some(-2));
        let value = REQUEST_SCOPE
            .scope(RequestScope { request_id: Uuid::new_v4(), route: Some("/api/private".to_owned()) }, async {
                parse(&run(&negative, Phase::Claim, async { event_json(&io_error()) }).await)
            })
            .await;
        assert!(value.get("attempt").is_none(), "negative attempt was emitted");
        assert!(value.get("generation").is_none(), "negative generation was emitted");
        assert_eq!(value["scope"].as_str(), Some("worker"));
        assert!(value.get("route").is_none(), "request route overrode worker scope");
    }
}
