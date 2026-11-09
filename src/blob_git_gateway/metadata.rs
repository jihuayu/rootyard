//! Metadata extractor bridge for the Blob-only gateway.
//!
//! Token and session routes are mounted on the gateway router, whose state is
//! `Arc<BlobGitState>`. Those handlers must never reach the Blob store, the
//! trusted Git binary, the scratch root or the native process/byte budgets, so
//! this bridge derives only the already-open PostgreSQL pool from the gateway
//! state's public accessor. It opens no connection, no storage authority and no
//! native process, and it does not copy any request-scoped deadline.

use std::sync::Arc;

use axum::extract::FromRef;

use crate::application::MetadataState;

use super::state::BlobGitState;

impl FromRef<Arc<BlobGitState>> for MetadataState {
    fn from_ref(state: &Arc<BlobGitState>) -> Self {
        Self { pool: state.pool().clone() }
    }
}
