//! Typed authority for an in-process CI runner bound to a signed integration claim.
use crate::{
    AppState, Error,
    ci_checkouts::{self, Plan},
    ci_pins,
};
use axum::http::{HeaderMap, StatusCode};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub(crate) struct ClaimedRun {
    pub run_id: Uuid,
    pub hook_id: Uuid,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub head_oid: String,
    pub storage_generation: i64,
    pub attempt: i64,
    pub lease_generation: i64,
    pub runner_id: String,
    pub source: String,
    pub job_id: Uuid,
    pub plan: Plan,
}

/// Recheck the same active candidate, trusted binding, attempt and checkout
/// identity used by the external claim/report adapter. No human Identity is
/// synthesized for an integration runner.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn authorize_claimed_run(
    state: &AppState,
    owner: &str,
    name: &str,
    hook_id: Uuid,
    run_id: Uuid,
    runner_id: &str,
    attempt: i64,
    lease_generation: i64,
    head_oid: &str,
    storage_generation: i64,
    headers: &HeaderMap,
) -> Result<ClaimedRun, Error> {
    if attempt <= 0
        || lease_generation <= 0
        || storage_generation <= 0
        || runner_id.is_empty()
        || runner_id.len() > 64
        || !runner_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        || !ci_pins::valid_oid(head_oid)
    {
        return Err(Error::bad_request());
    }
    let (repository_id, tenant_id) =
        super::runs::integration(state, owner, name, hook_id, headers).await?;
    let client = state.pool.get().await.map_err(Error::internal)?;
    let row = client
        .query_opt(
            "SELECT c.job_id,c.source_url,i.plan,i.expires_unix \
         FROM ci_runs c \
         JOIN forge_trusted_check_contexts b ON b.repository_id=c.repository_id \
           AND b.context=c.context AND b.webhook_id=$3 AND b.active=true \
         JOIN forge_pulls p ON p.repository_id=c.repository_id \
           AND p.number=c.pull_number AND p.state='open' \
           AND p.version=c.pull_version AND p.head_oid=c.head_oid AND p.base_oid=c.base_oid \
         JOIN ci_integration_checkout_jobs i ON i.run_id=c.id \
           AND i.repository_id=c.repository_id AND i.job_id=c.job_id \
           AND i.attempt=c.attempt AND i.lease_generation=c.lease_generation \
           AND i.issuer_webhook_id=$3 AND i.owner_id=c.tenant_id \
         JOIN repositories r ON r.id=c.repository_id AND r.owner_id=c.tenant_id \
           AND r.state='ready' AND r.storage_backend='gitfs' \
           AND r.storage_generation=c.storage_generation \
         WHERE c.id=$1 AND c.repository_id=$2 AND c.tenant_id=$4 \
           AND c.state='leased' AND c.attempt=$5 AND c.lease_generation=$6 \
           AND c.runner_id=$7 AND c.head_oid=$8 AND c.storage_generation=$9 \
           AND c.source_url IS NOT NULL \
           AND c.lease_expires_unix>extract(epoch FROM clock_timestamp()) \
           AND i.expires_unix>extract(epoch FROM clock_timestamp())",
            &[
                &run_id,
                &repository_id,
                &hook_id,
                &tenant_id,
                &attempt,
                &lease_generation,
                &runner_id,
                &head_oid,
                &storage_generation,
            ],
        )
        .await
        .map_err(Error::internal)?
        .ok_or(Error(StatusCode::CONFLICT, "CI run claim or checkout changed"))?;
    let job_id: Uuid = row.get("job_id");
    let expires_unix: i64 = row.get("expires_unix");
    let plan: Plan = serde_json::from_value(row.get("plan")).map_err(Error::internal)?;
    if plan.version != 1
        || plan.job_id != job_id
        || plan.owner_id != tenant_id
        || plan.repository_id != repository_id
        || plan.target_oid != head_oid
        || plan.storage_generation != storage_generation
        || plan.expires_unix != expires_unix
        || plan.object_format
            != if head_oid.len() == 40 {
                "sha1"
            } else {
                "sha256"
            }
        || plan.mirror_audience != ci_checkouts::audience()?
        || plan.dependencies.version != 1
    {
        return Err(Error(
            StatusCode::CONFLICT,
            "CI checkout plan differs from active claim",
        ));
    }
    Ok(ClaimedRun {
        run_id,
        hook_id,
        repository_id,
        tenant_id,
        head_oid: head_oid.into(),
        storage_generation,
        attempt,
        lease_generation,
        runner_id: runner_id.into(),
        source: row.get("source_url"),
        job_id,
        plan,
    })
}
