//! Controller-owned, exact-target GitFS retention. Local intent and pinned receipt
//! are part of the paired offline volume backup, not a second authority for refs.
use crate::{AppState, Error, auth, db, git_http, journal, reliability, storage};
use anyhow::{Context, Result, ensure};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::{Path as FsPath, PathBuf},
    sync::Arc,
};
use uuid::Uuid;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/api/repos/{owner}/{name}/ci-pins",
            post(pin).get(list_pins),
        )
        .route(
            "/api/repos/{owner}/{name}/ci-pins/{job}",
            axum::routing::get(get_pin)
                .delete(release_pin)
                .post(release_pin),
        )
        .route(
            "/api/repos/{owner}/{name}/ci-pins/{job}/release",
            post(release_pin),
        )
        .route(
            "/ci/{target}/git/{owner}/{name}/info/refs",
            axum::routing::get(s4_transport::info_refs),
        )
        .route(
            "/ci/{target}/git/{owner}/{name}/git-upload-pack",
            post(s4_transport::upload_pack)
                .layer(axum::extract::DefaultBodyLimit::max(16 * 1024 * 1024)),
        )
        .route(
            "/ci/{target}/git/{owner}/{name}/git-receive-pack",
            post(s4_transport::receive_pack),
        )
}

#[path = "ci_pins/s4_models.rs"]
pub(crate) mod s4_models;
#[path = "ci_pins/s4_schema.rs"]
pub(crate) mod s4_schema;
#[path = "ci_pins/s4_pin.rs"]
pub(crate) mod s4_pin;
#[path = "ci_pins/s4_release.rs"]
pub(crate) mod s4_release;
#[path = "ci_pins/s4_authority.rs"]
pub(crate) mod s4_authority;
#[path = "ci_pins/s4_checkout.rs"]
pub(crate) mod s4_checkout;
#[path = "ci_pins/s4_transport.rs"]
pub(crate) mod s4_transport;
#[path = "ci_pins/s4_tests.rs"]
#[cfg(test)]
mod s4_tests;

#[path = "ci_pins/models.rs"]
mod models;
#[path = "ci_pins/store.rs"]
mod store;
#[path = "ci_pins/native.rs"]
mod native;
#[path = "ci_pins/issue.rs"]
mod issue;
#[path = "ci_pins/lifecycle.rs"]
mod lifecycle;
#[path = "ci_pins/roots.rs"]
mod roots;
#[path = "ci_pins/tests.rs"]
#[cfg(test)]
mod tests;
pub use models::Intent;
pub(crate) use models::{MAX_PINS,reserved,valid_format,valid_oid,valid_oid_for_format};
use models::*;
use store::*;
use native::*;
pub(crate) use store::load_intent;
pub(crate) use issue::verify_receipt;
pub(crate) use native::observed_operation;
pub use issue::pin;
pub use lifecycle::{list_pins,get_pin,release_pin};
pub use roots::{git_dir_pinned_roots,active_pinned_oids};
