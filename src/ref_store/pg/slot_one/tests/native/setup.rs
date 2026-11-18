//! Owned-fixture attestation and PostgreSQL 17 requirement.
//!
//! `Db::setup` creates and seeds `public.cluster_authority` outside its random
//! schema and only drops that random schema. The PostgreSQL marker therefore
//! attests one dedicated database that is disposed whole, never a shared schema,
//! even when the configured URL is valid. No connection string is printed here.
//! Call the guard before `Db::setup` or any other database connection.

use super::db;
use anyhow::{Context, Result, ensure};

const OWNED_POSTGRES_OPT_IN: &str = "ROOTYARD_TEST_OWNED_DISPOSABLE_POSTGRES";
const OWNED_BLOB_OPT_IN: &str = "ROOTYARD_TEST_OWNED_DISPOSABLE_BLOB";

pub(super) fn require_owned_disposable_fixture() -> Result<()> {
    let postgres = matches!(std::env::var(OWNED_POSTGRES_OPT_IN).as_deref(), Ok("1"));
    let blob = matches!(std::env::var(OWNED_BLOB_OPT_IN).as_deref(), Ok("1"));
    ensure!(
        postgres && blob,
        "this real fixture requires {OWNED_POSTGRES_OPT_IN}=1 and {OWNED_BLOB_OPT_IN}=1: the PostgreSQL target must be one dedicated database disposed whole (never a shared schema, even if the URL is valid), and the Blob bucket/namespace must be wholly owned and disposed after the run"
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
