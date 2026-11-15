//! Bubblewrap process isolation for Agent and CI jobs.
#[path = "sandbox/cgroup.rs"]
mod cgroup;
#[path = "sandbox/ci.rs"]
pub mod ci;
#[path = "sandbox/export.rs"]
mod export;
#[path = "sandbox/handlers.rs"]
mod handlers;
#[path = "sandbox/runner.rs"]
mod runner;
#[path = "sandbox/terminal.rs"]
mod terminal;

use crate::AppState;
use axum::{
    Router,
    routing::{get, post},
};
use std::sync::Arc;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/repos/{owner}/{name}/integrations/{hook_id}/runs/{run_id}/sandbox-jobs", post(ci::start))
        .route(
            "/api/repos/{owner}/{name}/integrations/{hook_id}/runs/{run_id}/sandbox-jobs/{job_id}",
            get(ci::status).delete(ci::cancel),
        )
        .route(
            "/api/repos/{owner}/{name}/integrations/{hook_id}/runs/{run_id}/sandbox-jobs/{job_id}/logs",
            get(ci::logs),
        )
        .route(
            "/api/repos/{owner}/{name}/integrations/{hook_id}/runs/{run_id}/sandbox-jobs/{job_id}/artifacts",
            get(ci::artifact),
        )
        .route(
            "/api/repos/{owner}/{name}/integrations/{hook_id}/runs/{run_id}/sandbox-jobs/{job_id}/cleanup",
            post(ci::cleanup),
        )
        .route(
            "/api/repos/{owner}/{name}/integrations/{hook_id}/runs/{run_id}/sandbox-jobs/{job_id}/terminal/input",
            post(ci::terminal_input),
        )
        .route(
            "/api/repos/{owner}/{name}/integrations/{hook_id}/runs/{run_id}/sandbox-jobs/{job_id}/terminal/output",
            get(ci::terminal_output),
        )
        .route(
            "/api/repos/{owner}/{name}/integrations/{hook_id}/runs/{run_id}/sandbox-jobs/{job_id}/terminal/resize",
            post(ci::terminal_resize),
        )
        .route("/api/workspaces/{id}/sandbox-jobs", post(handlers::start))
        .route("/api/sandbox-jobs/{id}", get(handlers::status))
        .route("/api/sandbox-jobs/{id}/stop", post(handlers::stop))
        .route("/api/sandbox-jobs/{id}/cleanup", post(handlers::cleanup))
        .route("/api/sandbox-jobs/{id}/logs", get(handlers::logs))
        .route("/api/sandbox-jobs/{id}/artifacts", get(handlers::artifact))
        .route("/api/sandbox-jobs/{id}/terminal/input", post(handlers::terminal_input))
        .route("/api/sandbox-jobs/{id}/terminal/output", get(handlers::terminal_output))
        .route("/api/sandbox-jobs/{id}/terminal/resize", post(handlers::terminal_resize))
}
pub use runner::reconcile_startup;

/// Test-only stage observation for the PostgreSQL start-gate regression.
///
/// The probe lives in the task-local scope of one spawned gate future. It is
/// not installed by production code and cannot leak into another test task.
/// It records only fixed stage names, a validated five-character SQLSTATE and
/// the two bounded test facts requested by the regression.
#[cfg(test)]
pub(crate) mod gate_probe {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, AtomicU16, AtomicU64, Ordering},
    };

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum GateStage {
        StateGuard,
        IdentityGuard,
        PoolTxPolicy,
        JobSelect,
        AuthoritySelect,
        Marker,
        Commit,
    }

    impl GateStage {
        const fn index(self) -> usize {
            match self {
                Self::StateGuard => 0,
                Self::IdentityGuard => 1,
                Self::PoolTxPolicy => 2,
                Self::JobSelect => 3,
                Self::AuthoritySelect => 4,
                Self::Marker => 5,
                Self::Commit => 6,
            }
        }

        pub(crate) const fn label(self) -> &'static str {
            match self {
                Self::StateGuard => "state_guard",
                Self::IdentityGuard => "identity_guard",
                Self::PoolTxPolicy => "pool_tx_policy",
                Self::JobSelect => "job_select",
                Self::AuthoritySelect => "authority_select",
                Self::Marker => "marker",
                Self::Commit => "commit",
            }
        }
    }

    const STAGES: [GateStage; 7] = [
        GateStage::StateGuard,
        GateStage::IdentityGuard,
        GateStage::PoolTxPolicy,
        GateStage::JobSelect,
        GateStage::AuthoritySelect,
        GateStage::Marker,
        GateStage::Commit,
    ];

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum StageOutcome {
        Ok,
        Refused,
        Failed,
    }

    /// Typed read-only view of one recorded stage. Regression assertions use
    /// this instead of parsing the human-readable diagnostics snapshot.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum StageRecord {
        NotReached,
        Ok,
        Refused,
        Failed,
        SqlState([u8; 5]),
    }

    impl StageRecord {
        pub(crate) fn is_failed(self) -> bool {
            matches!(self, Self::Failed | Self::SqlState(_))
        }
    }

    #[derive(Default)]
    pub(crate) struct GateProbe {
        stages: [AtomicU8; 7],
        sqlstates: [AtomicU64; 7],
        shared_policy_advisory_wait_observed: AtomicBool,
        revoke_final_http_status: AtomicU16,
    }

    impl GateProbe {
        pub(crate) fn current() -> Option<Arc<Self>> {
            GATE_PROBE.try_with(Arc::clone).ok()
        }

        pub(crate) fn record(&self, stage: GateStage, outcome: StageOutcome) {
            let index = stage.index();
            // A PostgreSQL SQLSTATE is more specific than a later generic
            // failure mark from the same stage.
            if self.stages[index].load(Ordering::SeqCst) == 4 {
                return;
            }
            let outcome = match outcome {
                StageOutcome::Ok => 1,
                StageOutcome::Refused => 2,
                StageOutcome::Failed => 3,
            };
            self.stages[index].store(outcome, Ordering::SeqCst);
        }

        pub(crate) fn record_pg_error(&self, stage: GateStage, error: &tokio_postgres::Error) {
            if let Some(code) = safe_pg_sqlstate(error) {
                self.record_sqlstate(stage, code);
            } else {
                self.stages[stage.index()].store(3, Ordering::SeqCst);
            }
        }

        pub(crate) fn record_pool_error(&self, stage: GateStage, error: &deadpool_postgres::PoolError) {
            if let Some(code) = safe_pool_sqlstate(error) {
                self.record_sqlstate(stage, code);
            } else {
                self.stages[stage.index()].store(3, Ordering::SeqCst);
            }
        }

        fn record_sqlstate(&self, stage: GateStage, code: &str) {
            let index = stage.index();
            self.sqlstates[index].store(pack_sqlstate(code), Ordering::SeqCst);
            self.stages[index].store(4, Ordering::SeqCst);
        }

        pub(crate) fn stage_record(&self, stage: GateStage) -> StageRecord {
            match self.stages[stage.index()].load(Ordering::SeqCst) {
                1 => StageRecord::Ok,
                2 => StageRecord::Refused,
                3 => StageRecord::Failed,
                4 => match self.sqlstate_bytes(stage.index()) {
                    Some(code) => StageRecord::SqlState(code),
                    None => StageRecord::Failed,
                },
                _ => StageRecord::NotReached,
            }
        }

        pub(crate) fn shared_policy_advisory_wait_observed(&self) -> bool {
            self.shared_policy_advisory_wait_observed.load(Ordering::SeqCst)
        }

        pub(crate) fn revoke_final_http_status(&self) -> Option<axum::http::StatusCode> {
            let status = self.revoke_final_http_status.load(Ordering::SeqCst);
            if status == 0 { None } else { axum::http::StatusCode::from_u16(status).ok() }
        }

        pub(crate) fn note_shared_policy_advisory_wait(&self, observed: bool) {
            self.shared_policy_advisory_wait_observed.store(observed, Ordering::SeqCst);
        }

        pub(crate) fn note_revoke_final_http_status(&self, status: u16) {
            self.revoke_final_http_status.store(status, Ordering::SeqCst);
        }

        pub(crate) fn snapshot(&self) -> String {
            let mut stages = Vec::with_capacity(STAGES.len());
            for stage in STAGES {
                let index = stage.index();
                let outcome = match self.stages[index].load(Ordering::SeqCst) {
                    1 => "ok",
                    2 => "refused",
                    3 => "failed",
                    4 => "failed_sqlstate",
                    _ => "not_reached",
                };
                match self.sqlstate(index) {
                    Some(code) => stages.push(format!("{}={outcome}[{code}]", stage.label())),
                    None => stages.push(format!("{}={outcome}", stage.label())),
                }
            }
            let revoke_status = self.revoke_final_http_status.load(Ordering::SeqCst);
            let revoke_status = if revoke_status == 0 { "not_recorded".to_owned() } else { revoke_status.to_string() };
            format!(
                "stages={{{}}} shared_policy_advisory_wait_observed={} revoke_final_http_status={revoke_status}",
                stages.join(","),
                self.shared_policy_advisory_wait_observed.load(Ordering::SeqCst),
            )
        }

        fn sqlstate(&self, index: usize) -> Option<String> {
            self.sqlstate_bytes(index).map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        }

        fn sqlstate_bytes(&self, index: usize) -> Option<[u8; 5]> {
            let packed = self.sqlstates[index].load(Ordering::SeqCst);
            if packed == 0 {
                return None;
            }
            let mut bytes = [0; 5];
            bytes.copy_from_slice(&packed.to_be_bytes()[3..]);
            Some(bytes)
        }
    }

    pub(crate) fn safe_pg_sqlstate(error: &tokio_postgres::Error) -> Option<&str> {
        error.code().map(|code| code.code()).filter(|code| valid_sqlstate(code))
    }

    pub(crate) fn safe_pool_sqlstate(error: &deadpool_postgres::PoolError) -> Option<&str> {
        match error {
            deadpool_postgres::PoolError::Backend(error) => safe_pg_sqlstate(error),
            _ => None,
        }
    }

    pub(crate) fn observe_pg_error(stage: GateStage, error: &tokio_postgres::Error) {
        if let Some(probe) = GateProbe::current() {
            probe.record_pg_error(stage, error);
        }
    }

    fn valid_sqlstate(code: &str) -> bool {
        code.len() == 5 && code.bytes().all(|byte| byte.is_ascii_alphanumeric())
    }

    fn pack_sqlstate(code: &str) -> u64 {
        code.bytes().fold(0u64, |packed, byte| (packed << 8) | u64::from(byte))
    }

    tokio::task_local! {
        pub(crate) static GATE_PROBE: Arc<GateProbe>;
    }
}
