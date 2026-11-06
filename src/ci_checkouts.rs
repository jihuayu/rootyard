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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub version: u32,
    pub job_id: Uuid,
    pub owner_id: Uuid,
    pub repository_id: Uuid,
    pub storage_generation: i64,
    pub object_format: String,
    pub target_oid: String,
    pub source_receipt_sha256: String,
    pub mirror_audience: Uuid,
    pub expires_unix: i64,
    #[serde(default)]
    pub dependencies: dependencies::Manifest,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Issue {
    job_id: Uuid,
    target_oid: String,
    storage_generation: i64,
    mirror_audience: Uuid,
    expires_unix: i64,
    #[serde(default)]
    history: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
}
fn audience() -> Result<Uuid, Error> {
    std::env::var("ROOTYARD_CI_MIRROR_AUDIENCE")
        .ok()
        .and_then(|v| v.parse().ok())
        .ok_or(Error(
            StatusCode::SERVICE_UNAVAILABLE,
            "CI mirror audience is not configured",
        ))
}
async fn repository(
    state: &AppState,
    actor: &db::Identity,
    owner: &str,
    name: &str,
) -> Result<db::Repository, Error> {
    auth::writable(actor)?;
    if owner != actor.username || !db::valid_name(owner) || !db::valid_name(name) {
        return Err(Error::not_found());
    }
    let row = state
        .pool
        .get()
        .await
        .map_err(Error::internal)?
        .query_opt(
            &format!("{} WHERE r.owner_id=$1 AND r.name=$2", db::REPO_SELECT),
            &[&actor.id, &name],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    Ok(db::Repository::from_row(&row))
}
/// Lock authority, then use a fresh statement/clock after any lock wait. Token
/// revocation and repository fencing cannot commit through these SHARE locks.
async fn lock_authority(
    tx: &tokio_postgres::Transaction<'_>,
    actor: &db::Identity,
    repo: &db::Repository,
) -> Result<(), Error> {
    tx.batch_execute("SET LOCAL lock_timeout='5s'; SET LOCAL statement_timeout='10s'")
        .await
        .map_err(Error::internal)?;
    tx.query_opt("SELECT t.id FROM tokens t JOIN users u ON u.id=t.user_id WHERE t.id=$1 AND t.user_id=$2 AND u.username=$3 FOR SHARE OF t,u", &[&actor.token_id,&actor.id,&actor.username]).await.map_err(Error::internal)?.ok_or_else(Error::unauthorized)?;
    tx.query_opt(
        "SELECT id FROM repositories WHERE id=$1 AND owner_id=$2 AND name=$3 FOR SHARE",
        &[&repo.id, &actor.id, &repo.name],
    )
    .await
    .map_err(Error::internal)?
    .ok_or_else(Error::not_found)?;
    tx.query_opt("SELECT t.id FROM tokens t JOIN repositories r ON r.owner_id=t.user_id WHERE t.id=$1 AND t.digest=$2 AND NOT t.revoked AND NOT t.read_only AND (t.expires_at IS NULL OR t.expires_at>clock_timestamp()) AND r.id=$3 AND r.state='ready' AND r.storage_generation=$4", &[&actor.token_id,&actor.token_digest,&repo.id,&repo.storage_generation]).await.map_err(Error::internal)?.ok_or_else(Error::unauthorized)?;
    Ok(())
}
pub async fn issue(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<Issue>,
) -> Result<Response, Error> {
    tokio::spawn(async move { issue_inner(state, owner, name, headers, input).await })
        .await
        .map_err(Error::internal)?
}
async fn issue_inner(
    state: Arc<AppState>,
    owner: String,
    name: String,
    headers: HeaderMap,
    input: Issue,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let repo = repository(&state, &actor, &owner, &name).await?;
    if !ci_pins::valid_oid(&input.target_oid)
        || input.target_oid.bytes().all(|b|b==b'0')
        || input.storage_generation <= 0
    {
        return Err(Error::bad_request());
    }
    if input.mirror_audience != audience()? {
        return Err(Error(StatusCode::CONFLICT, "mirror audience differs"));
    }
    if repo.storage_generation != input.storage_generation || repo.state != "ready" {
        return Err(Error(StatusCode::CONFLICT, "repository authority changed"));
    }
    let _slot = state.git_slots.clone().try_acquire_owned().map_err(|_| {
        Error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Git capacity exhausted; retry later",
        )
    })?;
    let _lock = tokio::time::timeout(state.config.git_timeout, state.storage.write_lock(repo.id))
        .await
        .map_err(|_| Error::timeout())?;
    let intent = ci_pins::Intent {
        version: 1,
        job_id: input.job_id,
        owner_id: actor.id,
        repository_id: repo.id,
        storage_generation: input.storage_generation,
        object_format: if input.target_oid.len()==40 {"sha1"} else {"sha256"}.into(),
        target_oid: input.target_oid,
        retention_ref: format!("refs/rootyard-ci/jobs/{}", input.job_id),
    };
    let receipt = ci_pins::verify_receipt(&state, &intent)
        .await
        .map_err(|_| Error(StatusCode::CONFLICT, "verified durable source pin required"))?;
    drop(_lock);
    drop(_slot);
    let deps = dependencies::scan(&state,dependencies::Principal::User(&actor),repo.clone(),input.job_id,&intent.target_oid,
        input.history.as_deref().unwrap_or("full"),
        input.tags.as_deref().unwrap_or(&[])).await?;
    let plan = Plan {
        version: 1,
        job_id: intent.job_id,
        owner_id: actor.id,
        repository_id: repo.id,
        storage_generation: intent.storage_generation,
        object_format: intent.object_format.clone(),
        target_oid: intent.target_oid,
        source_receipt_sha256: receipt,
        mirror_audience: input.mirror_audience,
        expires_unix: input.expires_unix,
        dependencies: deps,
    };
    let mut delegated = Vec::new();
    for sub in &plan.dependencies.submodules {
        let client=state.pool.get().await.map_err(Error::internal)?;
        let owner_id:Uuid=client.query_one("SELECT owner_id FROM repositories WHERE id=$1",&[&sub.repository_id])
            .await.map_err(Error::internal)?.get(0);
        drop(client);
        let sub_intent=ci_pins::Intent{version:1,job_id:sub.job_id,owner_id,
            repository_id:sub.repository_id,storage_generation:sub.storage_generation,
            object_format:if sub.target_oid.len()==40 {"sha1"} else {"sha256"}.into(),target_oid:sub.target_oid.clone(),
            retention_ref:format!("refs/rootyard-ci/jobs/{}",sub.job_id)};
        let sub_receipt=ci_pins::verify_receipt(&state,&sub_intent).await
            .map_err(|_|Error(StatusCode::CONFLICT,"verified submodule pin required"))?;
        let sub_plan=Plan{version:1,job_id:sub.job_id,owner_id,repository_id:sub.repository_id,
            storage_generation:sub.storage_generation,object_format:sub_intent.object_format.clone(),
            target_oid:sub.target_oid.clone(),source_receipt_sha256:sub_receipt,
            mirror_audience:input.mirror_audience,expires_unix:input.expires_unix,
            dependencies:plan.dependencies.for_submodule(sub)};
        let mut random=[0u8;32];rand::rng().fill_bytes(&mut random);
        delegated.push((sub.clone(),sub_plan,format!("ryj_{}",hex::encode(random))));
    }
    let value = serde_json::to_value(&plan).map_err(Error::internal)?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    lock_authority(&tx, &actor, &repo).await?;
    // Serialize absent-row issue/cancel races without changing repository metadata.
    tx.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
        &[&format!("ci-checkout:{}:{}", repo.id, plan.job_id)],
    )
    .await
    .map_err(Error::internal)?;
    if let Some(row) = tx.query_opt("SELECT plan,cancelled,revoked FROM ci_checkout_jobs WHERE repository_id=$1 AND job_id=$2 FOR UPDATE", &[&repo.id,&plan.job_id]).await.map_err(Error::internal)? {
        if row.get::<_,bool>(1) || row.get::<_,bool>(2) || row.get::<_,Option<serde_json::Value>>(0).as_ref() != Some(&value) { return Err(Error(StatusCode::CONFLICT,"job is terminal or has a different immutable plan")); }
        // No plaintext is persisted: retries cannot recover a lost bearer.
        tx.commit().await.map_err(Error::internal)?;
        return Ok(([(header::CACHE_CONTROL,"no-store")],Json(serde_json::json!({"plan":plan,"credential_issued":true}))).into_response());
    }
    // Recheck clocks after pin verification and cancellation/authority lock waits.
    let valid: bool = tx.query_one("SELECT $1::bigint > extract(epoch FROM clock_timestamp()) AND $1::bigint <= extract(epoch FROM clock_timestamp()) + 3600 AND EXISTS (SELECT 1 FROM tokens WHERE id=$2 AND NOT revoked AND NOT read_only AND (expires_at IS NULL OR expires_at>clock_timestamp()))", &[&plan.expires_unix,&actor.token_id]).await.map_err(Error::internal)?.get(0);
    if !valid {
        return Err(Error(
            StatusCode::BAD_REQUEST,
            "expiry must be in the next hour and issuer must remain valid",
        ));
    }
    let mut random = [0u8; 32];
    rand::rng().fill_bytes(&mut random);
    let token = format!("ryj_{}", hex::encode(random));
    tx.execute("INSERT INTO ci_checkout_jobs (repository_id,job_id,owner_id,plan,issuer_token_id,credential_digest,expires_unix) VALUES ($1,$2,$3,$4,$5,$6,$7)", &[&repo.id,&plan.job_id,&actor.id,&value,&actor.token_id,&db::digest(&token),&plan.expires_unix]).await.map_err(Error::internal)?;
    let mut submodule_credentials=Vec::new();
    for (sub,sub_plan,secret) in delegated {
        let sub_value=serde_json::to_value(&sub_plan).map_err(Error::internal)?;
        tx.execute("INSERT INTO ci_checkout_delegations(parent_repository_id,parent_job_id,repository_id,job_id,owner_id,plan,issuer_token_id,credential_digest,expires_unix) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            &[&repo.id,&plan.job_id,&sub.repository_id,&sub.job_id,&sub_plan.owner_id,
              &sub_value,&actor.token_id,&db::digest(&secret),&plan.expires_unix])
            .await.map_err(Error::internal)?;
        submodule_credentials.push(serde_json::json!({"path":sub.path,"owner":sub.owner,
            "name":sub.name,"job_id":sub.job_id,"target_oid":sub.target_oid,"token":secret}));
    }
    tx.commit().await.map_err(Error::internal)?;
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({"plan":plan,"token":token,
            "submodule_credentials":submodule_credentials})),
    )
        .into_response())
}
pub async fn cancel(
    State(state): State<Arc<AppState>>,
    Path((owner, name, job)): Path<(String, String, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    terminal(state, owner, name, job, headers, true).await
}
pub async fn revoke(
    State(state): State<Arc<AppState>>,
    Path((owner, name, job)): Path<(String, String, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    terminal(state, owner, name, job, headers, false).await
}
async fn terminal(
    state: Arc<AppState>,
    owner: String,
    name: String,
    job: Uuid,
    headers: HeaderMap,
    cancel: bool,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let repo = repository(&state, &actor, &owner, &name).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    lock_authority(&tx, &actor, &repo).await?;
    tx.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
        &[&format!("ci-checkout:{}:{}", repo.id, job)],
    )
    .await
    .map_err(Error::internal)?;
    if cancel {
        tx.execute("INSERT INTO ci_checkout_jobs(repository_id,job_id,owner_id,cancelled) VALUES($1,$2,$3,true) ON CONFLICT(repository_id,job_id) DO UPDATE SET cancelled=true", &[&repo.id,&job,&actor.id]).await.map_err(Error::internal)?;
    } else if tx.execute("UPDATE ci_checkout_jobs SET revoked=true WHERE repository_id=$1 AND job_id=$2 AND plan IS NOT NULL", &[&repo.id,&job]).await.map_err(Error::internal)? == 0 { return Err(Error::not_found()); }
    tx.commit().await.map_err(Error::internal)?;
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({"job_id":job,"state":if cancel {"cancelled"} else {"revoked"}})),
    )
        .into_response())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActiveLease {
    pub job_id: Uuid,
    pub storage_generation: i64,
    pub target_oid: String,
    pub expires_unix: i64,
}

/// Pure predicate for whether a checkout job row represents an active lease at `now_unix`.
pub fn is_lease_active(
    cancelled: bool,
    revoked: bool,
    expires_unix: Option<i64>,
    now_unix: i64,
) -> bool {
    !cancelled && !revoked && expires_unix.is_some_and(|exp| exp > now_unix)
}

/// Check on an existing SQL client/transaction whether `job_id` has an active checkout lease.
pub async fn has_active_lease_on(
    client: &(impl tokio_postgres::GenericClient + Sync),
    repository_id: Uuid,
    job_id: Uuid,
) -> anyhow::Result<bool> {
    let row = client
        .query_opt(
            "SELECT 1 FROM ci_checkout_jobs \
             WHERE repository_id = $1 AND job_id = $2 \
               AND plan IS NOT NULL \
               AND NOT cancelled AND NOT revoked \
               AND expires_unix > extract(epoch FROM clock_timestamp())",
            &[&repository_id, &job_id],
        )
        .await?;
    Ok(row.is_some())
}

/// Check using the connection pool whether `job_id` has an active checkout lease.
pub async fn has_active_lease(
    pool: &deadpool_postgres::Pool,
    repository_id: Uuid,
    job_id: Uuid,
) -> anyhow::Result<bool> {
    let client = pool.get().await?;
    has_active_lease_on(&**client, repository_id, job_id).await
}

/// List all active (non-cancelled, non-revoked, unexpired) checkout leases for `repository_id`.
pub async fn active_leases_on(
    client: &(impl tokio_postgres::GenericClient + Sync),
    repository_id: Uuid,
) -> anyhow::Result<Vec<ActiveLease>> {
    let rows = client
        .query(
            "SELECT job_id, (plan->>'storage_generation')::bigint, plan->>'target_oid', expires_unix \
             FROM ci_checkout_jobs \
             WHERE repository_id = $1 \
               AND plan IS NOT NULL \
               AND NOT cancelled AND NOT revoked \
               AND expires_unix > extract(epoch FROM clock_timestamp()) \
             ORDER BY job_id",
            &[&repository_id],
        )
        .await?;
    let mut leases = Vec::with_capacity(rows.len());
    for row in rows {
        leases.push(ActiveLease {
            job_id: row.get(0),
            storage_generation: row.get(1),
            target_oid: row.get(2),
            expires_unix: row.get(3),
        });
    }
    Ok(leases)
}

pub async fn active_leases(
    pool: &deadpool_postgres::Pool,
    repository_id: Uuid,
) -> anyhow::Result<Vec<ActiveLease>> {
    let client = pool.get().await?;
    active_leases_on(&**client, repository_id).await
}

/// Return the set of `job_id`s with active checkout leases for `repository_id`.
pub async fn active_job_ids(
    pool: &deadpool_postgres::Pool,
    repository_id: Uuid,
) -> anyhow::Result<std::collections::BTreeSet<Uuid>> {
    Ok(active_leases(pool, repository_id)
        .await?
        .into_iter()
        .map(|lease| lease.job_id)
        .collect())
}

/// Return the set of `target_oid`s protected by active checkout leases for `repository_id`.
pub async fn active_pinned_oids(
    pool: &deadpool_postgres::Pool,
    repository_id: Uuid,
) -> anyhow::Result<std::collections::BTreeSet<String>> {
    Ok(active_leases(pool, repository_id)
        .await?
        .into_iter()
        .map(|lease| lease.target_oid)
        .collect())
}

/// Return the set of `(storage_generation, target_oid)` pairs protected by active checkout leases.
pub async fn active_pinned_targets(
    pool: &deadpool_postgres::Pool,
    repository_id: Uuid,
) -> anyhow::Result<std::collections::BTreeSet<(i64, String)>> {
    Ok(active_leases(pool, repository_id)
        .await?
        .into_iter()
        .map(|lease| (lease.storage_generation, lease.target_oid))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_lease_predicate_enforces_expiry_and_terminal_flags() {
        let now = 1_700_000_000;
        assert!(is_lease_active(false, false, Some(now + 60), now));
        assert!(!is_lease_active(true, false, Some(now + 60), now));
        assert!(!is_lease_active(false, true, Some(now + 60), now));
        assert!(!is_lease_active(false, false, Some(now), now));
        assert!(!is_lease_active(false, false, Some(now - 1), now));
        assert!(!is_lease_active(false, false, None, now));
    }
}

