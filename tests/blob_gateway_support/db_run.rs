//! Integration-only extensions of the run-owned PostgreSQL fixture.
//!
//! `session_http_acceptance` includes only [`super::db`], so the helpers the
//! out-of-process service/proxy fixtures need live here and are included only
//! by `tests/blob_gateway_support/mod.rs`. Keeping them in a sibling module is
//! what lets the narrow library harness stay warning-free without any
//! `dead_code` allowance.
use std::sync::OnceLock;

use anyhow::{Result, anyhow};

use super::db::{Db, prepare};

/// The run-owned remote object prefix, or the reason it cannot be used.
///
/// The prefix is pinned into `ROOTYARD_BLOB_ROOT` by [`prepare`]; reading it
/// back here keeps it out of the narrow session fixture's state.
pub fn owned_root() -> Result<&'static str> {
    prepare()?;
    static ROOT: OnceLock<String> = OnceLock::new();
    let root = ROOT.get_or_init(|| {
        std::env::var("ROOTYARD_BLOB_ROOT")
            .map_err(|_| anyhow!("the run environment did not pin ROOTYARD_BLOB_ROOT"))
            .unwrap_or_else(|error| panic!("blob_git_gateway fixture environment is incomplete: {error}"))
    });
    Ok(root.as_str())
}

impl Db {
    /// The run database URL, already selecting [`Db::schema`]; this is what the
    /// launched service receives as `DATABASE_URL`.
    pub fn database_url(&self) -> String {
        std::env::var("ROOTYARD_TEST_DATABASE_URL")
            .expect("a live Db fixture always has the pinned run URL in its environment")
    }

    /// The run-owned schema installed by `db::migrate`.
    pub fn schema(&self) -> &str {
        &self.schema
    }
}
