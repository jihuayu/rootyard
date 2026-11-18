//! Idempotent DDL for the isolated `s4_ci_retention` coordination schema.
//!
//! S4 deliberately owns no `public` table: the migration-151 backup catalog
//! verifies the exact `public` table set, so every coordination row lives in its
//! own schema and only *references* the authoritative `public`
//! `ref_store_core_root_heads`, `ci_checkout_jobs` and `ci_checkout_delegations`.
//!
//! `ensure_s4_schema` is called at the start of every S4 producer/consumer
//! path. `CREATE ... IF NOT EXISTS` is idempotent, so a fresh database and a
//! long-lived one converge on the same shape without a migration.
use crate::Error;
use deadpool_postgres::Pool;

const CI_PINS: &str = "CREATE TABLE IF NOT EXISTS s4_ci_retention.ci_pins (
    repository_id UUID NOT NULL,
    job_id UUID NOT NULL,
    owner_tenant_id UUID NOT NULL,
    issuer_actor_id UUID NOT NULL,
    issuer_token_id UUID NOT NULL,
    storage_generation BIGINT NOT NULL,
    authority_epoch BIGINT NOT NULL,
    object_format TEXT NOT NULL,
    target_oid TEXT NOT NULL,
    retention_root_id UUID NOT NULL,
    register_digest_hex TEXT NOT NULL,
    pack_set_digest_hex TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pinned', 'released')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    released_at TIMESTAMPTZ,
    PRIMARY KEY (repository_id, job_id)
)";

const CLOSURE_GRANTS: &str = "CREATE TABLE IF NOT EXISTS s4_ci_retention.closure_grants (
    repository_id UUID NOT NULL,
    job_id UUID NOT NULL,
    owner_tenant_id UUID NOT NULL,
    storage_generation BIGINT NOT NULL,
    authority_epoch BIGINT NOT NULL,
    object_format TEXT NOT NULL,
    target_oid TEXT NOT NULL,
    retention_root_id UUID NOT NULL,
    pack_set_digest_hex TEXT NOT NULL,
    mirror_audience UUID NOT NULL,
    expires_unix BIGINT NOT NULL,
    credential_digest BYTEA NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    cancelled BOOLEAN NOT NULL DEFAULT FALSE,
    grant_json JSONB NOT NULL,
    PRIMARY KEY (repository_id, job_id)
)";

const GIT_VIEW_BINDINGS: &str = "CREATE TABLE IF NOT EXISTS s4_ci_retention.git_view_bindings (
    view_id UUID PRIMARY KEY,
    namespace_id UUID NOT NULL,
    repository_id UUID NOT NULL,
    owner_tenant_id UUID NOT NULL,
    mount_path TEXT NOT NULL,
    subdir TEXT NOT NULL,
    source_oid TEXT NOT NULL,
    projected_oid TEXT NOT NULL,
    retention_root_id UUID NOT NULL,
    register_digest_hex TEXT NOT NULL,
    authority_epoch BIGINT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('active', 'released')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
)";

const INDEXES: [&str; 2] = [
    "CREATE INDEX IF NOT EXISTS s4_ci_pins_state ON s4_ci_retention.ci_pins (repository_id, state)",
    "CREATE INDEX IF NOT EXISTS s4_ci_grants_audience \
     ON s4_ci_retention.closure_grants (repository_id, mirror_audience)",
];

/// Create the coordination schema and its three tables when absent.
pub(crate) async fn ensure_s4_schema(pool: &Pool) -> Result<(), Error> {
    let client = pool.get().await.map_err(Error::internal)?;
    client
        .batch_execute("CREATE SCHEMA IF NOT EXISTS s4_ci_retention")
        .await
        .map_err(Error::internal)?;
    for statement in [CI_PINS, CLOSURE_GRANTS, GIT_VIEW_BINDINGS] {
        client.batch_execute(statement).await.map_err(Error::internal)?;
    }
    for statement in INDEXES {
        client.batch_execute(statement).await.map_err(Error::internal)?;
    }
    Ok(())
}
