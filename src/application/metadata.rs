//! Metadata-only subset of the shared application state.
//!
//! Token and session management needs exactly one durable dependency: the
//! PostgreSQL pool. It never reads storage, hooks, transfer metrics, Git slots,
//! mirror configuration or dispatch signals, and it never creates a legacy
//! `Storage`/`AppState` authority. This type is the extractor state for those
//! handlers, so the same routes can be mounted by the legacy application router
//! (`Arc<AppState>`) and by the Blob-only gateway (`Arc<BlobGitState>`) without
//! either profile learning about the other's state type.
//!
//! The pool handle is a clone of an existing pool: no connection, credential or
//! native process authority is opened here.

use axum::extract::FromRef;
use deadpool_postgres::Pool;
use std::sync::Arc;

use crate::AppState;

/// The only state a token/session handler may observe.
#[derive(Clone)]
pub struct MetadataState {
    pub pool: Pool,
}

impl FromRef<Arc<AppState>> for MetadataState {
    fn from_ref(state: &Arc<AppState>) -> Self {
        Self { pool: state.pool.clone() }
    }
}
