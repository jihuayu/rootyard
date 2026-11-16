//! Multi-mirror checkout inspection, mid-job failover, and pull-sync CI run cleanup.
use crate::{
    AppState, Error, ci_checkouts,
    webhooks::{
        ci_classification::{
            CheckoutStateClass, CheckoutTarget, ClassificationInput, classified_response,
            classify_checkout_state, error_with_classification,
        },
        ci_controller, runs,
    },
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tokio_postgres::GenericClient;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailoverInput {
    pub attempt: i64,
    pub lease_generation: i64,
    pub runner_id: String,
    #[serde(default)]
    pub failed_source: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub requeue_only: Option<bool>,
    #[serde(default)]
    pub prefer_mirror: Option<bool>,
    #[serde(default)]
    pub exclude_sources: Option<Vec<String>>,
}

pub(crate) async fn reconcile_on_pull_sync(
    client: &(impl GenericClient + Sync),
    pool: &deadpool_postgres::Pool,
    repository_id: Uuid,
    head_oid: &str,
) -> Result<(), Error> {
    client
        .execute(
            "UPDATE ci_runs c SET state='cancelled',lease_generation=c.lease_generation+1, \
               lease_expires_unix=0,source_url=NULL,runner_id=NULL,updated_at=clock_timestamp() \
             FROM forge_pulls p WHERE c.repository_id=$1 AND p.repository_id=c.repository_id \
               AND p.number=c.pull_number AND c.state IN ('queued','leased') \
               AND (p.state<>'open' OR p.version<>c.pull_version OR p.head_oid<>c.head_oid OR p.base_oid<>c.base_oid)",
            &[&repository_id],
        )
        .await
        .map_err(Error::internal)?;
    ci_controller::notify_slot_released(repository_id);
    if let Ok(audience) = ci_checkouts::audience() {
        let _ = ci_controller::trigger_coalesced_prewarm(
            pool.clone(),
            repository_id,
            audience,
            head_oid.to_owned(),
            Vec::new(),
        );
    }
    Ok(())
}

pub async fn inspect(
    State(state): State<Arc<AppState>>,
    Path((owner, name, hook_id, run_id)): Path<(String, String, Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let (repo, _) = match runs::integration(&state, &owner, &name, hook_id, &headers).await {
        Ok(ids) => ids,
        Err(err) => return Ok(error_with_classification(err)),
    };
    let client = state.pool.get().await.map_err(Error::internal)?;
    let Some(row) = client
        .query_opt(
            "SELECT c.context,c.head_oid,c.base_oid,c.job_id,c.storage_generation,c.state,c.attempt, \
               c.lease_generation,c.lease_expires_unix,c.runner_id,c.source_url, \
               (b.active IS TRUE AND w.active IS TRUE AND w.ci_contexts ? c.context) AS trusted_bound, \
               (r.state='ready' AND r.storage_generation=c.storage_generation AND p.state='open' \
                 AND p.version=c.pull_version AND p.head_oid=c.head_oid AND p.base_oid=c.base_oid) AS candidate_valid \
             FROM ci_runs c \
             JOIN repositories r ON r.id=c.repository_id \
             JOIN forge_pulls p ON p.repository_id=c.repository_id AND p.number=c.pull_number \
             LEFT JOIN forge_trusted_check_contexts b ON b.repository_id=c.repository_id \
               AND b.context=c.context AND b.webhook_id=$3 \
             LEFT JOIN forge_webhooks w ON w.id=b.webhook_id AND w.repository_id=c.repository_id \
             WHERE c.id=$1 AND c.repository_id=$2",
            &[&run_id, &repo, &hook_id],
        )
        .await
        .map_err(Error::internal)?
    else {
        return Ok(error_with_classification(Error::not_found()));
    };
    let head_oid: String = row.get("head_oid");
    let generation: i64 = row.get("storage_generation");
    let trusted_bound: bool = row.get("trusted_bound");
    let candidate_valid: bool = row.get("candidate_valid");
    let audience = ci_checkouts::audience()?;
    let summary = ci_controller::probe_availability(&**client, repo, generation, audience, &head_oid, &[]).await?;
    let mirrors = super::mirrors::list_repo_mirrors(&**client, repo, Some(audience), Some(&head_oid)).await?;
    let (global, per_repo) = ci_controller::origin_fallback_limits();
    let class = classify_checkout_state(ClassificationInput {
        trusted_bound,
        candidate_valid,
        ready_available_mirrors: summary.ready_available_mirrors,
        ready_total_mirrors: summary.ready_total_mirrors,
        healthy_unready_mirrors: summary.healthy_unready_mirrors,
        origin_global_active: summary.origin_budget.global_active,
        origin_global_limit: global,
        origin_per_repo_active: summary.origin_budget.per_repo_active,
        origin_per_repo_limit: per_repo,
        allow_origin: true,
        wait_requested: false,
    });
    Ok(classified_response(
        StatusCode::OK,
        class,
        json!({
            "run_id": run_id,
            "context": row.get::<_, String>("context"),
            "job_id": row.get::<_, Uuid>("job_id"),
            "head_oid": head_oid,
            "base_oid": row.get::<_, String>("base_oid"),
            "storage_generation": generation,
            "state": row.get::<_, String>("state"),
            "attempt": row.get::<_, i64>("attempt"),
            "lease_generation": row.get::<_, i64>("lease_generation"),
            "lease_expires_unix": row.get::<_, i64>("lease_expires_unix"),
            "runner_id": row.get::<_, Option<String>>("runner_id"),
            "source": row.get::<_, Option<String>>("source_url"),
            "trusted_bound": trusted_bound,
            "candidate_valid": candidate_valid,
            "classification": class.as_str(),
            "availability": summary,
            "mirrors": mirrors,
        }),
    ))
}

pub async fn failover(
    State(state): State<Arc<AppState>>,
    Path((owner, name, hook_id, run_id)): Path<(String, String, Uuid, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<FailoverInput>,
) -> Result<Response, Error> {
    if input.attempt <= 0
        || input.lease_generation <= 0
        || !runs::valid_runner_id(&input.runner_id)
        || input.reason.as_ref().is_some_and(|r| r.len() > 256)
    {
        return Err(Error::bad_request());
    }
    let failed_norm = runs::normalize_excluded(input.failed_source.as_ref().map(|s| vec![s.clone()]), None)?;
    let mut excluded = runs::normalize_excluded(input.exclude_sources, None)?;
    let (repo, _) = match runs::integration(&state, &owner, &name, hook_id, &headers).await {
        Ok(ids) => ids,
        Err(err) => return Ok(error_with_classification(err)),
    };
    let snapshot = state
        .pool
        .get()
        .await
        .map_err(Error::internal)?
        .query_opt(
            "SELECT head_oid,job_id,storage_generation FROM ci_runs WHERE id=$1 AND repository_id=$2",
            &[&run_id, &repo],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let requeue_only = input.requeue_only.unwrap_or(false);
    let snap_head: String = snapshot.get("head_oid");
    let snap_gen: i64 = snapshot.get("storage_generation");
    let prepared = if requeue_only {
        None
    } else {
        Some(ci_checkouts::integration::prepare(&state, hook_id, repo, snapshot.get("job_id"), &snap_head).await?)
    };
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    crate::webhooks::trust::lock_policy_tx(&tx, repo).await?;
    if let Err(err) = runs::verify_hook_tx(&tx, hook_id, repo, &headers).await {
        return Ok(error_with_classification(err));
    }
    let row = tx
        .query_opt(
            "SELECT c.head_oid,c.base_oid,c.job_id,c.storage_generation,c.state,c.attempt, \
               c.lease_generation,c.runner_id,c.source_url, \
               (c.lease_expires_unix>extract(epoch FROM clock_timestamp())) AS lease_active \
             FROM ci_runs c \
             JOIN forge_trusted_check_contexts b ON b.repository_id=c.repository_id \
               AND b.context=c.context AND b.webhook_id=$3 AND b.active=true \
             JOIN forge_webhooks w ON w.id=b.webhook_id AND w.repository_id=c.repository_id \
               AND w.active=true AND w.ci_contexts ? c.context \
             JOIN forge_pulls p ON p.repository_id=c.repository_id AND p.number=c.pull_number \
             JOIN repositories r ON r.id=c.repository_id \
             WHERE c.id=$1 AND c.repository_id=$2 AND p.state='open' \
               AND p.version=c.pull_version AND p.head_oid=c.head_oid AND p.base_oid=c.base_oid \
               AND r.state='ready' AND r.storage_generation=c.storage_generation \
             FOR UPDATE OF c",
            &[&run_id, &repo, &hook_id],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let lease_active: bool = row.get("lease_active");
    if row.get::<_, String>("state") != "leased"
        || !lease_active
        || row.get::<_, i64>("attempt") != input.attempt
        || row.get::<_, i64>("lease_generation") != input.lease_generation
        || row.get::<_, Option<String>>("runner_id").as_deref() != Some(input.runner_id.as_str())
    {
        return Err(Error(StatusCode::CONFLICT, "CI run lease changed"));
    }
    let prev_source: Option<String> = row.get("source_url");
    if let Some(f) = failed_norm.first()
        && prev_source.as_deref() != Some(f.as_str())
    {
        return Err(Error(StatusCode::CONFLICT, "failed_source does not match active lease"));
    }
    if let Some(ref ps) = prev_source
        && !excluded.contains(ps)
    {
        excluded.push(ps.clone());
    }
    let head: String = row.get("head_oid");
    let base: String = row.get("base_oid");
    let generation: i64 = row.get("storage_generation");
    let job_id: Uuid = row.get("job_id");
    let audience = ci_checkouts::audience()?;
    if requeue_only {
        let updated = tx
            .query_one(
                "UPDATE ci_runs SET state='queued',lease_generation=lease_generation+1, \
                 lease_expires_unix=0,source_url=NULL,runner_id=NULL,updated_at=clock_timestamp() \
                 WHERE id=$1 RETURNING attempt,lease_generation",
                &[&run_id],
            )
            .await
            .map_err(Error::internal)?;
        tx.commit().await.map_err(Error::internal)?;
        ci_controller::notify_slot_released(repo);
        let _ = ci_controller::trigger_coalesced_prewarm(state.pool.clone(), repo, audience, head, excluded);
        return Ok(classified_response(
            StatusCode::OK,
            CheckoutStateClass::Waiting,
            json!({
                "run_id": run_id, "state": "queued", "previous_source": prev_source,
                "requeued": true, "attempt": updated.get::<_, i64>(0),
                "lease_generation": updated.get::<_, i64>(1),
                "classification": CheckoutStateClass::Waiting.as_str(),
            }),
        ));
    }
    if head != snap_head || job_id != snapshot.get::<_, Uuid>("job_id") || generation != snap_gen {
        return Err(Error(StatusCode::CONFLICT, "CI candidate changed during checkout preparation"));
    }
    tx.execute("SELECT pg_advisory_xact_lock(1062026)", &[]).await.map_err(Error::internal)?;
    let prefer_mirror = input.prefer_mirror.unwrap_or(false);
    let next_source = match runs::choose_checkout_source(
        &tx,
        CheckoutTarget {
            repo_id: repo,
            storage_generation: generation,
            audience,
            head_oid: &head,
            excluded: &excluded,
        },
        prefer_mirror,
        false,
    )
    .await?
    {
        Ok(src) => src,
        Err(resp) => {
            let _ = ci_controller::trigger_coalesced_prewarm(
                state.pool.clone(), repo, audience, head, excluded,
            );
            return Ok(resp);
        }
    };
    let updated = tx
        .query_one(
            "UPDATE ci_runs SET state='leased',attempt=attempt+1,lease_generation=lease_generation+1, \
             lease_expires_unix=extract(epoch FROM clock_timestamp())::bigint+60,runner_id=$2, \
             source_url=$3,updated_at=clock_timestamp() WHERE id=$1 \
             RETURNING attempt,lease_generation,lease_expires_unix",
            &[&run_id, &input.runner_id, &next_source],
        )
        .await
        .map_err(Error::internal)?;
    let new_attempt: i64 = updated.get(0);
    let new_lease_gen: i64 = updated.get(1);
    let expires_unix: i64 = updated.get(2);
    let checkout = ci_checkouts::integration::persist(
        &tx,
        prepared.expect("prepared plan"),
        hook_id,
        run_id,
        new_attempt,
        new_lease_gen,
        expires_unix + 3600,
    )
    .await?;
    tx.commit().await.map_err(Error::internal)?;
    ci_controller::notify_slot_released(repo);
    Ok(classified_response(
        StatusCode::OK,
        CheckoutStateClass::Ready,
        json!({
            "run_id": run_id, "job_id": job_id, "head_oid": head, "base_oid": base,
            "storage_generation": generation, "previous_source": prev_source, "source": next_source,
            "attempt": new_attempt, "lease_generation": new_lease_gen,
            "lease_expires_unix": expires_unix, "checkout": checkout,
            "classification": CheckoutStateClass::Ready.as_str(),
        }),
    ))
}
