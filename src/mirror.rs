//! Explicit, full-snapshot read mirrors with bounded concurrency, observability,
//! and safe LRU/watermark eviction preserving active CI pins and checkout leases.
pub mod eviction;
pub mod limiter;
pub mod observability;
pub mod sync;
pub mod views;

pub(crate) use sync::{ci_route, mirror_git, repository};
pub(crate) use views::{job_path, pinned_path};

use crate::{AppState, Error, config::Config, git_http, storage::Storage};
use anyhow::{Context, Result, bail};
use axum::{
    Router,
    extract::{DefaultBodyLimit, State},
    routing::{get, post},
};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Snapshot {
    pub repository_id: Uuid,
    pub storage_generation: i64,
    pub snapshot: Uuid,
}

pub async fn open(config: Config, pool: Pool) -> Result<Arc<AppState>> {
    let primary = sync::primary_origin(
        &std::env::var("ROOTYARD_PRIMARY_URL")
            .context("ROOTYARD_PRIMARY_URL is required for a read mirror")?,
    )?;
    let storage = Storage::open_mirror(&config)?;
    // Read replicas never migrate, repair, provision, reconcile, or run workers.
    pool.get()
        .await?
        .simple_query("SELECT id, storage_generation FROM repositories LIMIT 0")
        .await?;
    let state = Arc::new(AppState {
        git_slots: Arc::new(tokio::sync::Semaphore::new(config.max_concurrent_git)),
        mirror_primary: Some(primary),
        config,
        pool,
        storage,
        hooks: None,
        transfer_metrics: Arc::new(crate::metrics::TransferCounters::default()),
        dispatch: crate::dispatch::Signals::default(),
    });
    limiter::init_for_state(&state)?;
    observability::init_for_state(&state);
    let mut command = mirror_git(&state);
    command.arg("--version");
    let version = git_http::collect_git_output(command, 256, state.config.git_timeout).await?;
    let text = String::from_utf8(version)?;
    let version: Vec<_> = text
        .split_whitespace()
        .nth(2)
        .unwrap_or("")
        .split('.')
        .take(2)
        .map(|n| n.parse::<u32>().unwrap_or(0))
        .collect();
    if version.len() != 2 || (version[0], version[1]) < (2, 43) {
        bail!("Git 2.43 or newer is required");
    }
    Ok(state)
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/repos/{owner}/{name}/mirror-sync", post(sync::sync))
        .route("/api/repos/{owner}/{name}/mirror-prepare", post(sync::prepare))
        .route("/api/repos/{owner}/{name}/mirror-evict", post(eviction::evict))
        .route("/api/repos/{owner}/{name}/mirror-prune", post(eviction::prune))
        .route("/api/repos/{owner}/{name}/mirror-status", get(observability::status))
        .route("/metrics", get(observability::metrics))
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health/live", get(|| async { "ok" }))
        .route("/health/ready", get(ready))
        .merge(routes())
        .fallback(|State(state): State<Arc<AppState>>, request| async move {
            git_http::handle(state, request).await
        })
        .layer(DefaultBodyLimit::max(16 * 1024))
        .with_state(state)
}

async fn ready(State(state): State<Arc<AppState>>) -> Result<&'static str, Error> {
    state
        .pool
        .get()
        .await
        .map_err(Error::internal)?
        .simple_query("SELECT id, storage_generation FROM repositories LIMIT 0")
        .await
        .map_err(Error::internal)?;
    if !state.storage.root.join("repos").is_dir() {
        return Err(Error::internal("mirror volume unavailable"));
    }
    Ok("ready")
}
