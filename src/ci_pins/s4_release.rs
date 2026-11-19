//! S4 CI pin read and release paths.
//!
//! Release is the one place where S4 deliberately prefers revocation over
//! waiting: the pin row, every dependent closure grant and the job are all
//! marked terminal *and* the retained root is released in the same transaction.
//! `ci_checkout_delegations` inherits its terminal flags by joining the parent
//! job, so it has no `revoked` column of its own. An in-flight stream therefore
//! observes revocation at its next chunk instead of being allowed to finish from
//! retained bytes.
use super::s4_models::{S4PinView, S4ReleaseBody};
use super::s4_pin::{PIN_COLUMNS, Producer, commit_owned, pin_view, refstore_repository, root_error};
use super::s4_schema::ensure_s4_schema;
use super::*;
use crate::members::models::Role;
use crate::ref_store::{
    contract::RequestDigest,
    core::retention_root::{PgRetentionRoots, ReleaseRootRequest, RootRef, RootsScope},
    serving::lookup,
};
use crate::token_scopes::RepoAction;
use tokio::time::Instant;

/// Exact-vector read for `GET /ci-pins` and `GET /ci-pins/{job}`.
pub(crate) async fn list(
    state: &Arc<AppState>,
    actor: &db::Identity,
    owner: &str,
    name: &str,
    single: Option<Uuid>,
    deadline: Instant,
) -> Result<Response, Error> {
    ensure_s4_schema(&state.pool).await?;
    let producer = Producer::open(state)?;
    let serving = lookup(
        &state.pool,
        actor,
        owner,
        name,
        false,
        producer.store.backend_identity(),
        deadline,
    )
    .await?;
    let rows = state
        .pool
        .get()
        .await
        .map_err(Error::internal)?
        .query(
            &format!(
                "SELECT {PIN_COLUMNS} FROM s4_ci_retention.ci_pins \
                 WHERE repository_id=$1 AND ($2::uuid IS NULL OR job_id=$2) ORDER BY job_id"
            ),
            &[&serving.repository.id, &single],
        )
        .await
        .map_err(Error::internal)?;
    if single.is_some() {
        let row = rows.first().ok_or_else(Error::not_found)?;
        return Ok(([(header::CACHE_CONTROL, "no-store")], Json(pin_view(row))).into_response());
    }
    let items: Vec<S4PinView> = rows.iter().map(pin_view).collect();
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(items)).into_response())
}

/// Release one pin and every grant that depends on it, then release the root.
pub(crate) async fn release(
    state: &Arc<AppState>,
    actor: &db::Identity,
    owner: &str,
    name: &str,
    job: Uuid,
    body: &S4ReleaseBody,
    deadline: Instant,
) -> Result<Response, Error> {
    if body.job_id.is_some_and(|id| id != job) || body.storage_generation.is_some_and(|value| value <= 0) {
        return Err(Error::bad_request());
    }
    ensure_s4_schema(&state.pool).await?;
    let producer = Producer::open(state)?;
    let serving = lookup(
        &state.pool,
        actor,
        owner,
        name,
        true,
        producer.store.backend_identity(),
        deadline,
    )
    .await?;
    let repository_id = serving.repository.id;
    let tenant_id = serving.gate.tenant_id();
    if body.storage_generation.is_some_and(|value| value != serving.repository.storage_generation) {
        return Err(Error(StatusCode::CONFLICT, "repository generation changed"));
    }
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    crate::ref_store::pg::bound(&tx, deadline)
        .await
        .map_err(|_| Error::timeout())?;
    super::s4_schema::lock_job(&tx, repository_id, job).await?;
    let row = tx
        .query_opt(
            &format!(
                "SELECT {PIN_COLUMNS} FROM s4_ci_retention.ci_pins \
                 WHERE repository_id=$1 AND job_id=$2 FOR UPDATE"
            ),
            &[&repository_id, &job],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let root_id: Uuid = row.get(5);
    let register_digest: String = row.get(6);
    let target_oid: String = row.get(3);
    let object_format: String = row.get(2);
    let storage_generation: i64 = row.get(4);
    if row.get::<_, Uuid>(8) != tenant_id {
        return Err(Error::not_found());
    }
    if body.target_oid.as_ref().is_some_and(|value| value != &target_oid) {
        return Err(Error(StatusCode::CONFLICT, "pin target mismatch"));
    }
    if row.get::<_, String>(9) == "pinned" {
        let intent = RequestDigest::of(
            "s4-ci-pin-release-intent",
            &[repository_id.as_bytes(), job.as_bytes(), register_digest.as_bytes()],
        )
        .as_hex();
        // Rebuild the exact scope from the root the producer persisted instead
        // of guessing the creation-time history incarnation or group epoch from
        // the current serving gate.
        let root_ref = RootRef::new(repository_id, root_id, 1).map_err(root_error)?;
        if let Some(record) = PgRetentionRoots::root_record_in_tx(&tx, root_ref).await.map_err(root_error)?
            && record.is_active()
        {
            let scope = RootsScope::new(
                record.repository_id(),
                record.tenant_id(),
                record.owner_id(),
                record.purpose(),
                record.business_intent_digest_hex(),
                record.object_format(),
                record.history_incarnation(),
                record.authority_epoch(),
                record.group_epoch(),
            )
            .map_err(root_error)?;
            let request = ReleaseRootRequest::new(
                scope,
                root_id,
                1,
                Uuid::new_v4(),
                record.register_digest_hex(),
                &intent,
                "ci pin released",
            )
            .map_err(root_error)?;
            let request_digest = request.intent_digest();
            producer.roots.release_in_tx(&tx, &request, request_digest).await.map_err(root_error)?;
        }
        revoke(&tx, repository_id, job).await?;
    } else if body.target_oid.is_some() {
        return Err(Error(StatusCode::CONFLICT, "pin already released"));
    }
    commit_owned(tx, deadline).await?;
    drop(client);
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({
            "job_id": job,
            "repository_id": repository_id,
            "state": "released",
            "released": true,
            "object_format": object_format,
            "target_oid": target_oid,
            "storage_generation": storage_generation,
            "retention_root_id": root_id,
        })),
    )
        .into_response())
}

/// Mark every dependent row terminal in the caller's transaction.
async fn revoke(
    tx: &deadpool_postgres::Transaction<'_>,
    repository_id: Uuid,
    job: Uuid,
) -> Result<(), Error> {
    for statement in [
        "UPDATE s4_ci_retention.ci_pins SET state='released', released_at=clock_timestamp() \
         WHERE repository_id=$1 AND job_id=$2",
        "UPDATE s4_ci_retention.closure_grants SET revoked=true \
         WHERE repository_id=$1 AND job_id=$2",
        "UPDATE ci_checkout_jobs SET revoked=true \
         WHERE repository_id=$1 AND job_id=$2",
    ] {
        tx.execute(statement, &[&repository_id, &job])
            .await
            .map_err(Error::internal)?;
    }
    Ok(())
}

/// Cancel or revoke one pg_refstore checkout job without touching its root.
pub(crate) async fn terminal(
    state: &Arc<AppState>,
    actor: &db::Identity,
    owner: &str,
    name: &str,
    job: Uuid,
    cancel: bool,
    deadline: Instant,
) -> Result<Response, Error> {
    auth::writable(actor)?;
    ensure_s4_schema(&state.pool).await?;
    let repo = refstore_repository(state, owner, name).await?.ok_or_else(Error::not_found)?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    crate::ref_store::pg::bound(&tx, deadline)
        .await
        .map_err(|_| Error::timeout())?;
    let access =
        auth::authorize_repo_with_role(&tx, actor, owner, name, Role::Write, RepoAction::ContentsWrite).await?;
    if access.repo_id != repo.id {
        return Err(Error::not_found());
    }
    super::s4_schema::lock_job(&tx, repo.id, job).await?;
    if cancel {
        tx.execute(
            "INSERT INTO ci_checkout_jobs(repository_id,job_id,owner_id,cancelled) \
             VALUES($1,$2,$3,true) ON CONFLICT(repository_id,job_id) DO UPDATE SET cancelled=true",
            &[&repo.id, &job, &access.owner_id],
        )
        .await
        .map_err(Error::internal)?;
    } else if tx
        .execute(
            "UPDATE ci_checkout_jobs SET revoked=true \
             WHERE repository_id=$1 AND job_id=$2 AND plan IS NOT NULL",
            &[&repo.id, &job],
        )
        .await
        .map_err(Error::internal)?
        == 0
    {
        return Err(Error::not_found());
    }
    let column = if cancel { "cancelled=true" } else { "revoked=true" };
    tx.execute(
        &format!(
            "UPDATE s4_ci_retention.closure_grants SET {column} \
             WHERE repository_id=$1 AND job_id=$2"
        ),
        &[&repo.id, &job],
    )
    .await
    .map_err(Error::internal)?;
    commit_owned(tx, deadline).await?;
    drop(client);
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({
            "job_id": job,
            "state": if cancel { "cancelled" } else { "revoked" },
        })),
    )
        .into_response())
}
