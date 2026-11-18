//! S4 one-shot CI checkout issuance for `pg_refstore` repositories.
//!
//! Issuance is one PostgreSQL transaction that also registers the retained root
//! and the `ci_pins` row when the caller did not pin the job first, so a valid
//! `ryj_` token never exists without its durable root.
use super::s4_models::{MAX_GRANT_TTL, NewGrant, S4ClosureGrant, fixed_oid};
use super::s4_pin::{Producer, commit_owned, root_error};
use super::s4_schema::ensure_s4_schema;
use super::*;
use crate::ci_checkouts::dependencies::Manifest;
use crate::ci_checkouts::{Plan, audience};
use crate::members::models::Role;
use crate::ref_store::{
    RootPurpose,
    contract::RequestDigest,
    core::retention_root::{PgRetentionRoots, RootRef},
    serving::{ServingRepository, lookup},
};
use crate::token_scopes::RepoAction;
use rand::RngCore;
use tokio::time::Instant;

pub(crate) use super::s4_release::terminal;
/// Caller-fixed inputs of one checkout issuance.
pub(crate) struct IssueInput {
    pub job_id: Uuid,
    pub target_oid: String,
    pub storage_generation: i64,
    pub mirror_audience: Uuid,
    pub expires_unix: i64,
}
fn issue_error(message: &'static str) -> Error {
    Error(StatusCode::CONFLICT, message)
}
fn empty_manifest(history: &str) -> Manifest {
    Manifest {
        version: 1,
        history: history.to_owned(),
        tags: Vec::new(),
        lfs: Vec::new(),
        submodules: Vec::new(),
    }
}
fn audience_of(input: &IssueInput) -> Result<Uuid, Error> {
    if input.mirror_audience != audience()? {
        return Err(issue_error("mirror audience differs"));
    }
    Ok(input.mirror_audience)
}
fn expiry(input: &IssueInput, now: i64) -> Result<i64, Error> {
    if input.expires_unix <= now || input.expires_unix > now + MAX_GRANT_TTL {
        return Err(Error(StatusCode::BAD_REQUEST, "expiry must be within the next hour"));
    }
    Ok(input.expires_unix)
}
async fn now_unix(tx: &deadpool_postgres::Transaction<'_>) -> Result<i64, Error> {
    tx.query_one("SELECT extract(epoch FROM clock_timestamp())::bigint", &[])
        .await
        .map_err(Error::internal)
        .map(|row| row.get(0))
}
async fn database_now(pool: &deadpool_postgres::Pool) -> Result<i64, Error> {
    let client = pool.get().await.map_err(Error::internal)?;
    Ok(client
        .query_one("SELECT extract(epoch FROM clock_timestamp())::bigint", &[])
        .await
        .map_err(Error::internal)?
        .get(0))
}
/// Issue one narrow `ryj_` credential and its closure grant.
pub(crate) async fn issue(
    state: &Arc<AppState>,
    actor: &db::Identity,
    owner: &str,
    name: &str,
    input: &IssueInput,
    deadline: Instant,
) -> Result<Response, Error> {
    auth::writable(actor)?;
    if input.storage_generation <= 0 {
        return Err(Error::bad_request());
    }
    let audience = audience_of(input)?;
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
    let format = serving.repository.object_format.clone();
    let target_oid = fixed_oid(&input.target_oid, &format)?;
    if input.storage_generation != serving.repository.storage_generation
        || serving.repository.state != "ready"
    {
        return Err(issue_error("repository authority changed"));
    }
    // A malformed expiry is a request error before any capture or job insert.
    let now = database_now(&state.pool).await?;
    expiry(input, now)?;
    let existing = existing_job(state, serving.repository.id, input.job_id, &format, target_oid).await?;
    if let Some(response) = existing {
        return Ok(response);
    }
    let registration = pin_for_checkout(&producer, &state.pool, &serving, input, target_oid, deadline).await?;
    let source_snapshot = registration.as_ref().map(|prepared| (prepared.snapshot_scope, prepared.snapshot));
    let mut random = [0u8; 32];
    rand::rng().fill_bytes(&mut random);
    let token = format!("{}{}", super::s4_models::JOB_PREFIX, hex::encode(random));
    let digest = db::digest(&token);
    let outcome: Result<Response, Error> = async {
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        crate::ref_store::pg::bound(&tx, deadline)
            .await
            .map_err(|_| Error::timeout())?;
        super::s4_pin::lock_job(&tx, serving.repository.id, input.job_id).await?;
        if let Some(row) = tx
            .query_opt(
                "SELECT plan, cancelled, revoked FROM ci_checkout_jobs \
                 WHERE repository_id=$1 AND job_id=$2 FOR UPDATE",
                &[&serving.repository.id, &input.job_id],
            )
            .await
            .map_err(Error::internal)?
        {
            if row.get::<_, bool>(1) || row.get::<_, bool>(2) {
                return Err(issue_error("job is terminal"));
            }
            let Some(plan) = row.get::<_, Option<serde_json::Value>>(0) else {
                return Err(issue_error("job is terminal"));
            };
            if plan.get("object_format").and_then(serde_json::Value::as_str) != Some(format.as_str())
                || plan.get("target_oid").and_then(serde_json::Value::as_str) != Some(target_oid)
            {
                return Err(issue_error("job has a different immutable plan"));
            }
            commit_owned(tx, deadline).await?;
            drop(client);
            return Ok((
                [(header::CACHE_CONTROL, "no-store")],
                Json(serde_json::json!({"plan": plan, "credential_issued": true})),
            )
                .into_response());
        }
        let access =
            auth::authorize_repo_with_role(&tx, actor, owner, name, Role::Write, RepoAction::ContentsWrite).await?;
        let locked = tx
            .query_opt(
                "SELECT owner_id, state, storage_generation FROM repositories WHERE id=$1 FOR SHARE",
                &[&serving.repository.id],
            )
            .await
            .map_err(Error::internal)?
            .ok_or_else(Error::not_found)?;
        expiry(input, now_unix(&tx).await?)?;
        if access.repo_id != serving.repository.id
            || locked.get::<_, Uuid>(0) != serving.gate.tenant_id()
            || locked.get::<_, String>(1) != "ready"
            || locked.get::<_, i64>(2) != input.storage_generation
        {
            return Err(issue_error("repository authority changed"));
        }
        if !super::s4_schema::gate_live(&tx, &serving).await? {
            return Err(issue_error("repository authority changed"));
        }
        let (root_id, register_digest, pack_set_digest) = if let Some(prepared) = registration {
            match super::s4_pin::existing_pin(&tx, serving.repository.id, input.job_id).await? {
                Some(_) => verify_reused_pin_in_tx(&tx, &serving, input, target_oid).await?,
                None => {
                    producer
                        .roots
                        .register_serving_in_tx(
                            &tx,
                            prepared.request.candidate(),
                            prepared.request.request_id(),
                            prepared.request.digest(),
                            deadline,
                        )
                        .await
                        .map_err(root_error)?;
                    producer
                        .roots
                        .recheck_serving_source_pin_live_in_tx(&tx, &prepared.snapshot, deadline)
                        .await
                        .map_err(root_error)?;
                    tx.execute(
                        "INSERT INTO s4_ci_retention.ci_pins \
                         (repository_id, job_id, owner_tenant_id, issuer_actor_id, issuer_token_id, \
                          storage_generation, authority_epoch, history_incarnation, group_epoch, \
                          object_format, target_oid, retention_root_id, register_digest_hex, \
                          pack_set_digest_hex, state) \
                         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'pinned')",
                        &[
                            &serving.repository.id,
                            &input.job_id,
                            &serving.gate.tenant_id(),
                            &actor.id,
                            &actor.token_id,
                            &input.storage_generation,
                            &serving.gate.authority_epoch(),
                            &serving.gate.history_incarnation(),
                            &serving.gate.group_epoch(),
                            &format,
                            &target_oid,
                            &prepared.request.candidate().root_id(),
                            &prepared.request.candidate().register_digest().as_hex(),
                            &prepared.pack_set_digest,
                        ],
                    )
                    .await
                    .map_err(Error::internal)?;
                    (
                        prepared.request.candidate().root_id(),
                        prepared.request.candidate().register_digest().as_hex(),
                        prepared.pack_set_digest,
                    )
                }
            }
        } else {
            verify_reused_pin_in_tx(&tx, &serving, input, target_oid).await?
        };
        let grant = S4ClosureGrant::new(NewGrant {
            job_id: input.job_id,
            repository_id: serving.repository.id,
            owner_tenant_id: serving.gate.tenant_id(),
            storage_generation: input.storage_generation,
            authority_epoch: serving.gate.authority_epoch(),
            history_incarnation: serving.gate.history_incarnation(),
            group_epoch: serving.gate.group_epoch(),
            object_format: &format,
            target_oid,
            retention_root_id: root_id,
            pack_set_digest: &pack_set_digest,
            mirror_audience: audience,
            expires_unix: input.expires_unix,
        })?;
        let plan = Plan {
            version: 1,
            job_id: input.job_id,
            owner_id: serving.gate.tenant_id(),
            repository_id: serving.repository.id,
            storage_generation: input.storage_generation,
            object_format: format.clone(),
            target_oid: target_oid.to_owned(),
            source_receipt_sha256: register_digest.clone(),
            mirror_audience: audience,
            expires_unix: input.expires_unix,
            dependencies: empty_manifest("full"),
        };
        let plan_json = serde_json::to_value(&plan).map_err(Error::internal)?;
        let grant_json = serde_json::to_value(&grant).map_err(Error::internal)?;
        tx.execute(
            "INSERT INTO ci_checkout_jobs \
             (repository_id,job_id,owner_id,plan,issuer_token_id,credential_digest,expires_unix) \
             VALUES ($1,$2,$3,$4,$5,$6,$7)",
            &[
                &serving.repository.id,
                &input.job_id,
                &serving.gate.tenant_id(),
                &plan_json,
                &actor.token_id,
                &digest,
                &input.expires_unix,
            ],
        )
        .await
        .map_err(Error::internal)?;
        tx.execute(
            "INSERT INTO s4_ci_retention.closure_grants \
             (repository_id,job_id,owner_tenant_id,storage_generation,authority_epoch, \
              history_incarnation,group_epoch,object_format,target_oid,retention_root_id, \
              pack_set_digest_hex,mirror_audience,expires_unix,credential_digest,grant_json) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
            &[
                &serving.repository.id,
                &input.job_id,
                &serving.gate.tenant_id(),
                &input.storage_generation,
                &serving.gate.authority_epoch(),
                &serving.gate.history_incarnation(),
                &serving.gate.group_epoch(),
                &format,
                &target_oid,
                &root_id,
                &pack_set_digest,
                &audience,
                &input.expires_unix,
                &digest,
                &grant_json,
            ],
        )
        .await
        .map_err(Error::internal)?;
        commit_owned(tx, deadline).await?;
        drop(client);
        Ok((
            [(header::CACHE_CONTROL, "no-store")],
            Json(serde_json::json!({
                "plan": plan,
                "token": token,
                "closure_grant": grant,
                "submodule_credentials": [],
            })),
        )
            .into_response())
    }
    .await;
    // Release the transient `MetadataPin` on success and on every refusal.
    if let Some((scope, snapshot)) = source_snapshot {
        producer.release_source_snapshot(&state.pool, scope, &snapshot, deadline).await;
    }
    outcome
}
/// Lock and re-prove one reused pin and its retained root in the issuance tx.
async fn verify_reused_pin_in_tx(
    tx: &deadpool_postgres::Transaction<'_>,
    serving: &ServingRepository,
    input: &IssueInput,
    target_oid: &str,
) -> Result<(Uuid, String, String), Error> {
    let row = super::s4_pin::existing_pin(tx, serving.repository.id, input.job_id)
        .await?
        .ok_or_else(|| issue_error("pin missing or released"))?;
    let gate = &serving.gate;
    let same = row.get::<_, String>(9) == "pinned"
        && row.get::<_, String>(3) == target_oid
        && row.get::<_, i64>(4) == input.storage_generation
        && row.get::<_, Uuid>(8) == gate.tenant_id()
        && row.get::<_, i64>(11) == gate.authority_epoch()
        && row.get::<_, Uuid>(12) == gate.history_incarnation()
        && row.get::<_, i64>(13) == gate.group_epoch();
    if !same {
        return Err(issue_error("pin is released or authority changed"));
    }
    let root_id: Uuid = row.get(5);
    let root_ref = RootRef::new(serving.repository.id, root_id, 1)
        .map_err(|_| issue_error("retained root invalid"))?;
    let live_root = PgRetentionRoots::root_record_in_tx(tx, root_ref)
        .await
        .map_err(root_error)?
        .is_some_and(|record| {
            record.is_active()
                && record.authority_epoch() == gate.authority_epoch()
                && record.history_incarnation() == gate.history_incarnation()
                && record.group_epoch() == gate.group_epoch()
        });
    if !live_root {
        return Err(issue_error("retained root unavailable or released"));
    }
    Ok((root_id, row.get(6), row.get(7)))
}
/// Reuse an already pinned job, or prepare the capture that is registered in
/// the same transaction as the job row.
async fn pin_for_checkout(
    producer: &Producer,
    pool: &deadpool_postgres::Pool,
    serving: &ServingRepository,
    input: &IssueInput,
    target_oid: &str,
    deadline: Instant,
) -> Result<Option<super::s4_pin::Prepared>, Error> {
    let repository_id = serving.repository.id;
    let tenant_id = serving.gate.tenant_id();
    let row = pool
        .get()
        .await
        .map_err(Error::internal)?
        .query_opt(
            "SELECT retention_root_id, register_digest_hex, pack_set_digest_hex, state, target_oid, \
                    storage_generation, owner_tenant_id, authority_epoch, history_incarnation, group_epoch \
             FROM s4_ci_retention.ci_pins WHERE repository_id=$1 AND job_id=$2",
            &[&repository_id, &input.job_id],
        )
        .await
        .map_err(Error::internal)?;
    if let Some(row) = row {
        let valid = row.get::<_, String>(3) == "pinned"
            && row.get::<_, String>(4) == target_oid
            && row.get::<_, i64>(5) == input.storage_generation
            && row.get::<_, Uuid>(6) == tenant_id
            && row.get::<_, i64>(7) == serving.gate.authority_epoch()
            && row.get::<_, Uuid>(8) == serving.gate.history_incarnation()
            && row.get::<_, i64>(9) == serving.gate.group_epoch();
        if !valid {
            return Err(issue_error("pin is released or belongs to a different target or authority"));
        }
        return Ok(None);
    }
    let intent = RequestDigest::of(
        // The exact same domain and field order as the pin producer.
        "s4-ci-pin-intent-v1",
        &[
            repository_id.as_bytes(),
            input.job_id.as_bytes(),
            tenant_id.as_bytes(),
            target_oid.as_bytes(),
            &input.storage_generation.to_be_bytes(),
        ],
    )
    .as_hex();
    let prepared = producer
        .capture(
            pool,
            serving,
            super::s4_pin::CaptureSpec { purpose: RootPurpose::Ci, business_intent: &intent, target_oid },
            deadline,
        )
        .await?;
    Ok(Some(prepared))
}
async fn existing_job(
    state: &AppState,
    repository_id: Uuid,
    job_id: Uuid,
    format: &str,
    target_oid: &str,
) -> Result<Option<Response>, Error> {
    let row = state
        .pool
        .get()
        .await
        .map_err(Error::internal)?
        .query_opt(
            "SELECT plan, cancelled, revoked FROM ci_checkout_jobs \
             WHERE repository_id=$1 AND job_id=$2",
            &[&repository_id, &job_id],
        )
        .await
        .map_err(Error::internal)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let cancelled: bool = row.get(1);
    let revoked: bool = row.get(2);
    if cancelled || revoked {
        return Err(issue_error("job is terminal"));
    }
    let Some(plan) = row.get::<_, Option<serde_json::Value>>(0) else {
        return Err(issue_error("job is terminal"));
    };
    if plan.get("object_format").and_then(serde_json::Value::as_str) != Some(format)
        || plan.get("target_oid").and_then(serde_json::Value::as_str) != Some(target_oid)
    {
        return Err(issue_error("job has a different immutable plan"));
    }
    Ok(Some(
        (
            [(header::CACHE_CONTROL, "no-store")],
            Json(serde_json::json!({"plan": plan, "credential_issued": true})),
        )
            .into_response(),
    ))
}
