//! Primary-issued, one-shot delivery of bounded mirror-only checkout credentials.
//! SQL authorizes access; only durable native pins establish source retention.
use crate::{AppState, Error, auth, ci_pins, db};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[path = "ci_checkouts/dependencies.rs"]
pub mod dependencies;
#[path = "ci_checkouts/mirror_prepare.rs"]
pub mod mirror_prepare;
#[path = "ci_checkouts/mirror_lfs.rs"]
pub mod mirror_lfs;
#[path = "ci_checkouts/authority.rs"]
pub mod authority;
#[path = "ci_checkouts/integration.rs"]
pub mod integration;
pub(crate) use authority::{authenticate,still_authorized};

pub fn mirror_routes() -> Router<Arc<AppState>> {
    Router::new().route("/api/repos/{owner}/{name}/ci-checkouts/{job}/prepare-dependencies",
        post(mirror_prepare::prepare))
        .route("/ci/{target}/git/{owner}/{name}/info/lfs/objects/batch", post(mirror_lfs::batch))
        .route("/ci/{target}/git/{owner}/{name}/info/lfs/objects/{oid}", axum::routing::get(mirror_lfs::download))
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/repos/{owner}/{name}/ci-checkouts", post(issue))
        .route(
            "/api/repos/{owner}/{name}/ci-checkouts/{job}/cancel",
            post(cancel),
        )
        .route(
            "/api/repos/{owner}/{name}/ci-checkouts/{job}/revoke",
            post(revoke),
        )
}

#[path = "ci_checkouts/models.rs"]
mod models;
#[path = "ci_checkouts/handlers.rs"]
mod handlers;
#[path = "ci_checkouts/leases.rs"]
mod leases;
pub use models::Plan;
pub(crate) use models::audience;
pub use handlers::{issue,cancel,revoke};
pub use leases::*;
