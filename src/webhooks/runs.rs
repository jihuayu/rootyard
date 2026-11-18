//! Thin external runner adapter for immutable CI candidates and fenced attempts.
use crate::{
    AppState, Error, ci_checkouts,
    pulls::models::context_valid,
    webhooks::{
        ci_classification::{
            CheckoutStateClass, CheckoutTarget, ClassificationInput, classified_error, classified_response,
            classify_checkout_state, error_with_classification, route_from_snapshot,
        },
        ci_controller,
        signing::{constant_time_eq, sha256_hex},
    },
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use std::{collections::BTreeSet, sync::Arc};
use deadpool_postgres::Transaction;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimInput {
    pub runner_id: String,
    #[serde(default)]
    pub wait_for_ready_ms: Option<u64>,
    #[serde(default)]
    pub prefer_mirror: Option<bool>,
    #[serde(default)]
    pub exclude_sources: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportInput {
    pub attempt: i64,
    pub lease_generation: i64,
    pub conclusion: String,
    pub output: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatInput {
    pub attempt: i64,
    pub lease_generation: i64,
    pub runner_id: String,
}

pub(crate) fn valid_runner_id(v: &str) -> bool {
    !v.is_empty() && v.len() <= 64 && v.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

pub(crate) fn normalize_excluded(raw: Option<Vec<String>>, extra: Option<&str>) -> Result<Vec<String>, Error> {
    let mut set = BTreeSet::new();
    for item in raw.into_iter().flatten() {
        if set.len() >= 32 || item.len() > 512 {
            return Err(Error::bad_request());
        }
        if item.eq_ignore_ascii_case("origin") {
            set.insert("origin".to_owned());
        } else {
            set.insert(ci_controller::validate_mirror_url(&item)?);
        }
    }
    if let Some(s) = extra {
        if s.eq_ignore_ascii_case("origin") {
            set.insert("origin".to_owned());
        } else if let Ok(norm) = ci_controller::validate_mirror_url(s) {
            set.insert(norm);
        } else {
            set.insert(s.to_owned());
        }
    }
    Ok(set.into_iter().collect())
}

/// Lock the exact live repository row before any lease or checkout grant is
/// minted. Soft delete takes the same row exclusively, so a claim either
/// commits its grant first or observes `deleted_at` and returns 404.
async fn lock_claim_repository_tx(
    tx: &Transaction<'_>,
    repo: Uuid,
    owner: &str,
    name: &str,
) -> Result<(), Error> {
    tx.query_opt(
        "SELECT r.id FROM repositories r JOIN namespaces n ON n.id=r.owner_id \
         WHERE r.id=$1 AND n.slug=$2 AND r.name=$3 AND r.state='ready' AND r.deleted_at IS NULL \
         FOR SHARE OF r",
        &[&repo, &owner, &name],
    )
    .await
    .map_err(Error::internal)?
    .ok_or_else(Error::not_found)?;
    Ok(())
}

pub(crate) async fn verify_hook_tx(tx: &Transaction<'_>, hook_id: Uuid, repo: Uuid, headers: &HeaderMap) -> Result<(), Error> {
    let current_hook = tx
        .query_opt(
            "SELECT secret,active FROM forge_webhooks WHERE id=$1 AND repository_id=$2 FOR SHARE",
            &[&hook_id, &repo],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::unauthorized)?;
    let bearer = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(Error::unauthorized)?;
    if !current_hook.get::<_, bool>("active")
        || !constant_time_eq(current_hook.get::<_, String>("secret").as_bytes(), bearer.as_bytes())
    {
        return Err(Error::unauthorized());
    }
    Ok(())
}

pub(crate) async fn choose_checkout_source(
    tx: &Transaction<'_>,
    target: CheckoutTarget<'_>,
    prefer_mirror: bool,
    wait_requested: bool,
) -> Result<Result<String, Response>, Error> {
    let snapshot = ci_controller::select_ready_mirror(
        &**tx,
        target.repo_id,
        target.storage_generation,
        target.audience,
        target.head_oid,
        target.excluded,
    )
    .await?;
    let summary = match route_from_snapshot(snapshot.source, snapshot.availability) {
        Ok(source) => return Ok(Ok(source)),
        Err(availability) => availability,
    };
    let (global, per_repo) = ci_controller::origin_fallback_limits();
    let allow_origin = !prefer_mirror && !target.excluded.iter().any(|s| s == "origin");
    let class = classify_checkout_state(ClassificationInput {
        trusted_bound: true,
        candidate_valid: true,
        ready_available_mirrors: summary.ready_available_mirrors,
        ready_total_mirrors: summary.ready_total_mirrors,
        healthy_unready_mirrors: summary.healthy_unready_mirrors,
        origin_global_active: summary.origin_budget.global_active,
        origin_global_limit: global,
        origin_per_repo_active: summary.origin_budget.per_repo_active,
        origin_per_repo_limit: per_repo,
        allow_origin,
        wait_requested,
    });
    if prefer_mirror || global <= 0 || per_repo <= 0 {
        let (status, msg) = match class {
            CheckoutStateClass::Waiting => (StatusCode::ACCEPTED, "waiting for ready mirror"),
            CheckoutStateClass::Overloaded => (StatusCode::TOO_MANY_REQUESTS, "all ready mirrors at capacity"),
            _ => (StatusCode::TOO_MANY_REQUESTS, "no ready mirror"),
        };
        return Ok(Err(classified_error(
            status,
            msg,
            class,
            json!({ "availability": summary, "retry_after_ms": 250 }),
        )));
    }
    if target.excluded.iter().any(|s| s == "origin")
        || summary.origin_budget.global_active >= global
        || summary.origin_budget.per_repo_active >= per_repo
    {
        return Ok(Err(classified_error(
            StatusCode::TOO_MANY_REQUESTS,
            "origin fallback budget exhausted",
            class,
            json!({ "availability": summary }),
        )));
    }
    Ok(Ok("origin".to_owned()))
}

pub(crate) async fn integration(state: &AppState, owner: &str, name: &str, hook_id: Uuid,
    headers: &HeaderMap) -> Result<(Uuid,Uuid),Error> {
    let bearer = headers.get("authorization").and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer ")).ok_or_else(Error::unauthorized)?;
    let client = state.pool.get().await.map_err(Error::internal)?;
    let row = client.query_opt(
        "SELECT r.id,r.owner_id,w.secret,w.active FROM repositories r \
         JOIN namespaces u ON u.id=r.owner_id JOIN forge_webhooks w ON w.repository_id=r.id \
         WHERE u.slug=$1 AND r.name=$2 AND w.id=$3 AND r.state='ready' AND r.deleted_at IS NULL",
        &[&owner,&name,&hook_id],
    ).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let secret: String = row.get(2);
    if !row.get::<_,bool>(3) || !constant_time_eq(secret.as_bytes(),bearer.as_bytes()) {
        return Err(Error::unauthorized());
    }
    Ok((row.get(0),row.get(1)))
}

pub async fn claim(
    State(state): State<Arc<AppState>>,
    Path((owner,name,hook_id,run_id)): Path<(String,String,Uuid,Uuid)>,
    headers: HeaderMap, Json(input): Json<ClaimInput>,
) -> Result<Response,Error> {
    if !valid_runner_id(&input.runner_id) || input.wait_for_ready_ms.is_some_and(|w| w > 60_000) {
        return Err(Error::bad_request());
    }
    let excluded = normalize_excluded(input.exclude_sources, None)?;
    let prefer_mirror = input.prefer_mirror.unwrap_or(false);
    let wait_ms = input.wait_for_ready_ms.unwrap_or(0);
    let (repo, _) = match integration(&state, &owner, &name, hook_id, &headers).await {
        Ok(ids) => ids,
        Err(err) => return Ok(error_with_classification(err)),
    };
    let snapshot = state.pool.get().await.map_err(Error::internal)?.query_opt(
        "SELECT c.head_oid,c.job_id,c.storage_generation FROM ci_runs c \
         JOIN forge_trusted_check_contexts b ON b.repository_id=c.repository_id \
           AND b.context=c.context AND b.webhook_id=$3 AND b.active=true \
         JOIN forge_webhooks w ON w.id=b.webhook_id AND w.repository_id=c.repository_id \
           AND w.active=true AND w.ci_contexts ? c.context \
         WHERE c.id=$1 AND c.repository_id=$2 AND c.state IN ('queued','leased')",
        &[&run_id, &repo, &hook_id],
    ).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let snap_head: String = snapshot.get("head_oid");
    let snap_gen: i64 = snapshot.get("storage_generation");
    let audience = ci_checkouts::audience()?;
    let mut prewarm_triggered = false;
    {
        let client = state.pool.get().await.map_err(Error::internal)?;
        let summary = ci_controller::probe_availability(&**client, repo, snap_gen, audience, &snap_head, &excluded).await?;
        drop(client);
        if summary.ready_available_mirrors == 0 && summary.healthy_unready_mirrors > 0 {
            let _ = ci_controller::trigger_coalesced_prewarm(
                state.pool.clone(),
                repo,
                audience,
                snap_head.clone(),
                excluded.clone(),
            );
            prewarm_triggered = ci_controller::prewarm_configured();
        }
    }
    let target = CheckoutTarget {
        repo_id: repo,
        storage_generation: snap_gen,
        audience,
        head_oid: &snap_head,
        excluded: &excluded,
    };
    if wait_ms > 0 {
        let ready = ci_controller::wait_for_checkout_slot(&state, target, prefer_mirror, wait_ms).await?;
        if !ready {
            let client = state.pool.get().await.map_err(Error::internal)?;
            let summary = ci_controller::probe_availability(&**client, repo, snap_gen, audience, &snap_head, &excluded).await?;
            let (global, per_repo) = ci_controller::origin_fallback_limits();
            let class = classify_checkout_state(ClassificationInput {
                trusted_bound: true,
                candidate_valid: true,
                ready_available_mirrors: summary.ready_available_mirrors,
                ready_total_mirrors: summary.ready_total_mirrors,
                healthy_unready_mirrors: summary.healthy_unready_mirrors,
                origin_global_active: summary.origin_budget.global_active,
                origin_global_limit: global,
                origin_per_repo_active: summary.origin_budget.per_repo_active,
                origin_per_repo_limit: per_repo,
                allow_origin: !prefer_mirror && !excluded.iter().any(|s| s == "origin"),
                wait_requested: true,
            });
            let (status, msg) = match class {
                CheckoutStateClass::Waiting => (StatusCode::ACCEPTED, "waiting for ready mirror or checkout slot"),
                CheckoutStateClass::Overloaded => (StatusCode::TOO_MANY_REQUESTS, "origin fallback budget exhausted"),
                _ => (StatusCode::TOO_MANY_REQUESTS, "no ready mirror"),
            };
            return Ok(classified_error(
                status,
                msg,
                class,
                json!({ "availability": summary, "prewarm_triggered": prewarm_triggered, "retry_after_ms": 250 }),
            ));
        }
    }
    let prepared = ci_checkouts::integration::prepare(&state, hook_id, repo, snapshot.get("job_id"), &snap_head).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    // Preparation is slow and deliberately lock-free. Re-establish current
    // issuer authority under the same policy fence used by revocation before
    // minting the lease and its checkout capability.
    crate::webhooks::trust::lock_policy_tx(&tx, repo).await?;
    // The early integration lookup is not a fence. Re-lock the exact
    // repository row here, before the run row and before lease/grant mint, so
    // soft delete either wins the row first (this returns 404) or waits until
    // this claim's checkout grant is committed.
    lock_claim_repository_tx(&tx, repo, &owner, &name).await?;
    if let Err(err) = verify_hook_tx(&tx, hook_id, repo, &headers).await {
        return Ok(error_with_classification(err));
    }
    let row = tx.query_opt(
        "SELECT c.context,c.head_oid,c.base_oid,c.job_id,c.storage_generation,c.state,c.attempt,c.lease_generation \
         FROM ci_runs c JOIN forge_trusted_check_contexts b ON b.repository_id=c.repository_id \
          AND b.context=c.context AND b.webhook_id=$3 AND b.active=true \
         JOIN forge_webhooks w ON w.id=b.webhook_id AND w.repository_id=c.repository_id \
          AND w.active=true AND w.ci_contexts ? c.context \
         JOIN forge_pulls p ON p.repository_id=c.repository_id AND p.number=c.pull_number \
         WHERE c.id=$1 AND c.repository_id=$2 AND p.state='open' \
           AND p.version=c.pull_version AND p.head_oid=c.head_oid AND p.base_oid=c.base_oid \
         FOR UPDATE OF c",
        &[&run_id,&repo,&hook_id],
    ).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let state_now: String = row.get("state");
    if state_now != "queued" && state_now != "leased" {
        return Err(Error(StatusCode::CONFLICT,"CI run is terminal"));
    }
    if state_now == "leased" {
        let active: bool = tx.query_one(
            "SELECT lease_expires_unix>extract(epoch FROM clock_timestamp()) FROM ci_runs WHERE id=$1",
            &[&run_id],
        ).await.map_err(Error::internal)?.get(0);
        if active { return Err(Error(StatusCode::CONFLICT,"CI run is leased")); }
    }
    let head: String = row.get("head_oid");
    let base: String = row.get("base_oid");
    let generation: i64 = row.get("storage_generation");
    let job_id: Uuid = row.get("job_id");
    if head != snap_head || job_id != snapshot.get::<_, Uuid>("job_id") || generation != snap_gen {
        return Err(Error(StatusCode::CONFLICT,"CI candidate changed during checkout preparation"));
    }
    tx.execute("SELECT pg_advisory_xact_lock(1062026)", &[]).await.map_err(Error::internal)?;
    let source = match choose_checkout_source(
        &tx,
        CheckoutTarget {
            repo_id: repo,
            storage_generation: generation,
            audience,
            head_oid: &head,
            excluded: &excluded,
        },
        prefer_mirror,
        wait_ms > 0,
    ).await? {
        Ok(src) => src,
        Err(resp) => {
            if !prewarm_triggered {
                let _ = ci_controller::trigger_coalesced_prewarm(
                    state.pool.clone(), repo, audience, head.clone(), excluded.clone(),
                );
            }
            return Ok(resp);
        }
    };
    let updated = tx.query_one(
        "UPDATE ci_runs SET state='leased',attempt=attempt+1,lease_generation=lease_generation+1, \
         lease_expires_unix=extract(epoch FROM clock_timestamp())::bigint+60,runner_id=$2, \
         source_url=$3,updated_at=clock_timestamp() WHERE id=$1 \
         RETURNING attempt,lease_generation,lease_expires_unix",
        &[&run_id,&input.runner_id,&source],
    ).await.map_err(Error::internal)?;
    let attempt:i64=updated.get(0);
    let lease_generation:i64=updated.get(1);
    let expires_unix:i64=updated.get(2);
    let checkout=ci_checkouts::integration::persist(&tx,prepared,hook_id,run_id,
        attempt,lease_generation,expires_unix+3600).await?;
    tx.commit().await.map_err(Error::internal)?;
    Ok(classified_response(
        StatusCode::OK,
        CheckoutStateClass::Ready,
        json!({
            "run_id": run_id, "job_id": job_id, "head_oid": head, "base_oid": base,
            "storage_generation": generation, "source": source,
            "attempt": attempt, "lease_generation": lease_generation,
            "lease_expires_unix": expires_unix, "checkout": checkout,
            "classification": CheckoutStateClass::Ready.as_str(),
            "prewarm_triggered": prewarm_triggered
        }),
    ))
}

pub async fn heartbeat(
    State(state):State<Arc<AppState>>,
    Path((owner,name,hook_id,run_id)):Path<(String,String,Uuid,Uuid)>,
    headers:HeaderMap,Json(input):Json<HeartbeatInput>,
)->Result<Response,Error>{
    if input.attempt<=0 || input.lease_generation<=0 || !valid_runner_id(&input.runner_id) {
        return Err(Error::bad_request());
    }
    let (repo,_)=integration(&state,&owner,&name,hook_id,&headers).await?;
    let mut client=state.pool.get().await.map_err(Error::internal)?;
    let tx=client.transaction().await.map_err(Error::internal)?;
    crate::webhooks::trust::lock_policy_tx(&tx,repo).await?;
    verify_hook_tx(&tx, hook_id, repo, &headers).await?;
    let row=tx.query_opt(
        "UPDATE ci_runs c SET lease_expires_unix=extract(epoch FROM clock_timestamp())::bigint+60, \
         updated_at=clock_timestamp() FROM forge_trusted_check_contexts b, forge_webhooks w, forge_pulls p \
         WHERE c.id=$1 AND c.repository_id=$2 AND b.repository_id=c.repository_id \
           AND b.context=c.context AND b.webhook_id=$3 AND b.active=true \
           AND w.id=b.webhook_id AND w.repository_id=c.repository_id AND w.active=true \
           AND w.ci_contexts ? c.context \
           AND p.repository_id=c.repository_id AND p.number=c.pull_number AND p.state='open' \
           AND p.version=c.pull_version AND p.head_oid=c.head_oid AND p.base_oid=c.base_oid \
           AND c.state='leased' AND c.attempt=$4 AND c.lease_generation=$5 \
           AND c.runner_id=$6 AND c.lease_expires_unix>extract(epoch FROM clock_timestamp()) \
         RETURNING c.lease_expires_unix",
        &[&run_id,&repo,&hook_id,&input.attempt,&input.lease_generation,&input.runner_id],
    ).await.map_err(Error::internal)?.ok_or(Error(StatusCode::CONFLICT,"CI run lease changed"))?;
    tx.commit().await.map_err(Error::internal)?;
    Ok((StatusCode::OK,[(header::CACHE_CONTROL,"no-store")],Json(serde_json::json!({
        "run_id":run_id,"attempt":input.attempt,"lease_generation":input.lease_generation,
        "lease_expires_unix":row.get::<_,i64>(0)}))).into_response())
}

pub async fn report(
    State(state): State<Arc<AppState>>,
    Path((owner,name,hook_id,run_id)): Path<(String,String,Uuid,Uuid)>,
    headers: HeaderMap, Json(input): Json<ReportInput>,
) -> Result<Response,Error> {
    if input.attempt<=0 || input.lease_generation<=0 || input.output.len()>8192 ||
        !matches!(input.conclusion.as_str(),"success"|"failure"|"cancelled"|"timed_out") {
        return Err(Error::bad_request());
    }
    let (repo,tenant) = integration(&state,&owner,&name,hook_id,&headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    crate::webhooks::trust::lock_policy_tx(&tx,repo).await?;
    verify_hook_tx(&tx, hook_id, repo, &headers).await?;
    let row = tx.query_opt(
        "SELECT c.context,c.head_oid,c.base_oid,c.state,c.attempt,c.lease_generation,c.result_sha256, \
          p.head_oid AS live_head,p.base_oid AS live_base,p.version AS live_version, \
          p.state AS live_state,c.pull_version \
         FROM ci_runs c JOIN forge_trusted_check_contexts b ON b.repository_id=c.repository_id \
          AND b.context=c.context AND b.webhook_id=$3 AND b.active=true \
         JOIN forge_webhooks w ON w.id=b.webhook_id AND w.repository_id=c.repository_id \
          AND w.active=true AND w.ci_contexts ? c.context \
         JOIN forge_pulls p ON p.repository_id=c.repository_id AND p.number=c.pull_number \
         WHERE c.id=$1 AND c.repository_id=$2 FOR UPDATE OF c",
        &[&run_id,&repo,&hook_id],
    ).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let digest = sha256_hex(format!("{}\0{}",input.conclusion,input.output).as_bytes());
    // Replays are idempotent only while the exact candidate still owns this
    // run. A revoked context binding removes the row above (404); a changed
    // head/base/version must not return a stale successful result.
    let candidate_current = row.get::<_,String>("head_oid")==row.get::<_,String>("live_head") &&
        row.get::<_,String>("base_oid")==row.get::<_,String>("live_base") &&
        row.get::<_,i64>("pull_version")==row.get::<_,i64>("live_version") &&
        row.get::<_,String>("live_state")=="open";
    if row.get::<_,String>("state")=="completed" &&
        row.get::<_,i64>("attempt")==input.attempt &&
        row.get::<_,i64>("lease_generation")==input.lease_generation &&
        row.get::<_,Option<String>>("result_sha256").as_deref()==Some(&digest) {
        if !candidate_current {
            return Err(Error(StatusCode::CONFLICT,"CI run attempt or candidate changed"));
        }
        tx.commit().await.map_err(Error::internal)?;
        return Ok((StatusCode::OK,[(header::CACHE_CONTROL,"no-store")],Json(serde_json::json!({"run_id":run_id,"replay":true}))).into_response());
    }
    if row.get::<_,String>("state")!="leased" || row.get::<_,i64>("attempt")!=input.attempt ||
        row.get::<_,i64>("lease_generation")!=input.lease_generation || !candidate_current {
        return Err(Error(StatusCode::CONFLICT,"CI run attempt or candidate changed"));
    }
    let lease_valid: bool = tx.query_one(
        "SELECT lease_expires_unix>extract(epoch FROM clock_timestamp()) FROM ci_runs WHERE id=$1",
        &[&run_id],
    ).await.map_err(Error::internal)?.get(0);
    if !lease_valid { return Err(Error(StatusCode::CONFLICT,"CI run lease expired")); }
    let context: String = row.get("context");
    if !context_valid(&context) { return Err(Error::internal("invalid CI context")); }
    let head: String = row.get("head_oid");
    let base: String = row.get("base_oid");
    tx.execute(
        "INSERT INTO forge_check_runs(tenant_id,repository_id,commit_oid,context,attempt,sequence,status,conclusion,output,issuer_webhook_id,ci_run_id,ci_base_oid,ci_lease_generation) \
         VALUES($1,$2,$3,$4,$5,2,'completed',$6,$7,$8,$9,$10,$11) \
         ON CONFLICT(tenant_id,repository_id,commit_oid,context) DO UPDATE \
         SET attempt=excluded.attempt,sequence=excluded.sequence,status=excluded.status, \
         conclusion=excluded.conclusion,output=excluded.output,issuer_webhook_id=excluded.issuer_webhook_id, \
         ci_run_id=excluded.ci_run_id,ci_base_oid=excluded.ci_base_oid, \
         ci_lease_generation=excluded.ci_lease_generation,updated_at=clock_timestamp()",
        &[&tenant,&repo,&head,&context,&input.attempt,&input.conclusion,&input.output,
          &hook_id,&run_id,&base,&input.lease_generation],
    ).await.map_err(Error::internal)?;
    tx.execute(
        "UPDATE ci_runs SET state='completed',conclusion=$2,result_sha256=$3, \
         lease_expires_unix=0,updated_at=clock_timestamp() WHERE id=$1",
        &[&run_id,&input.conclusion,&digest],
    ).await.map_err(Error::internal)?;
    tx.commit().await.map_err(Error::internal)?;
    ci_controller::notify_slot_released(repo);
    Ok((StatusCode::OK,[(header::CACHE_CONTROL,"no-store")],Json(serde_json::json!({"run_id":run_id,"replay":false}))).into_response())
}
