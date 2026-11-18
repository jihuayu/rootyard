//! Owned-fixture attestation and PostgreSQL 17 requirement.

use super::{OWNED_BLOB_OPT_IN, db};
use anyhow::{Context, Result, ensure};

pub(super) fn require_owned_disposable_blob_fixture() -> Result<()> {
    ensure!(
        matches!(std::env::var(OWNED_BLOB_OPT_IN).as_deref(), Ok("1")),
        "this real fixture requires {OWNED_BLOB_OPT_IN}=1: the caller must own the whole configured Blob bucket/namespace and dispose of the complete fixture after the run"
    );
    Ok(())
}

pub(super) async fn require_postgres_17(db: &db::Db) -> Result<()> {
    let version: String =
        db.pool.get().await?.query_one("SELECT current_setting('server_version_num')", &[]).await?.get(0);
    let number: u32 = version.parse().with_context(|| format!("server_version_num is not numeric: {version}"))?;
    ensure!(
        (17_0000..18_0000).contains(&number),
        "this fixture requires PostgreSQL 17, got server_version_num={version}"
    );
    Ok(())
}
