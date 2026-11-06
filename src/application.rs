//! Shared application state, bounded error responses and readiness checks.
use crate::{config, dispatch, metrics, reliability, storage};
use axum::{
    Json,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use deadpool_postgres::Pool;
use std::sync::Arc;
use tokio::sync::Semaphore;

pub struct AppState {
    pub mirror_primary: Option<String>,
    pub dispatch: dispatch::Signals,
    pub config: config::Config,
    pub pool: Pool,
    pub storage: storage::Storage,
    pub hooks: Option<reliability::HookInstallation>,
    pub transfer_metrics: Arc<metrics::TransferCounters>,
    pub git_slots: Arc<Semaphore>,
}

#[derive(Debug)]
pub struct Error(pub StatusCode, pub &'static str);
impl Error {
    pub fn internal(_error: impl std::fmt::Display) -> Self {
        // Do not print DB URLs, tokens, raw headers, Git stderr or client content.
        eprintln!("rootyard: internal operation failed");
        Self(StatusCode::SERVICE_UNAVAILABLE, "service temporarily unavailable")
    }
    pub fn unauthorized() -> Self {
        Self(StatusCode::UNAUTHORIZED, "valid credentials required")
    }
    pub fn not_found() -> Self {
        Self(StatusCode::NOT_FOUND, "not found")
    }
    pub fn bad_request() -> Self {
        Self(StatusCode::BAD_REQUEST, "invalid request")
    }
    pub fn timeout() -> Self {
        Self(StatusCode::GATEWAY_TIMEOUT, "Git request timed out")
    }
}
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let mut response = (self.0, Json(serde_json::json!({"error":self.1}))).into_response();
        response.headers_mut().insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
        if self.0 == StatusCode::UNAUTHORIZED {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, "Basic realm=\"Rootyard\", charset=\"UTF-8\"".parse().unwrap());
        }
        response
    }
}

pub(crate) async fn ready(State(state): State<Arc<AppState>>) -> Result<&'static str, Error> {
    state.pool.get().await.map_err(Error::internal)?.simple_query("SELECT 1").await.map_err(Error::internal)?;
    if !state.storage.root.join("repos").is_dir() {
        return Err(Error(StatusCode::SERVICE_UNAVAILABLE, "storage unavailable"));
    }
    reliability::verify_hooks(&state).map_err(Error::internal)?;
    Ok("ready")
}
