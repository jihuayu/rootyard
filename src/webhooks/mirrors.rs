//! Primary-side registry of mirror target readiness used by the CI scheduler.
use super::ci_classification::MirrorNodeStatus;
use crate::{AppState, Error, auth, ci_pins, members::models::Role, webhooks::ci_controller};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use std::{collections::BTreeSet, sync::Arc};
use tokio_postgres::GenericClient;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Heartbeat {
    pub audience: Uuid,
    pub url: String,
    pub storage_generation: i64,
    pub ready_oids: Vec<String>,
    pub capacity: i64,
    pub active: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListQuery {
    #[serde(default)]
    pub target_oid: Option<String>,
}

pub(crate) async fn list_repo_mirrors(
    client: &(impl GenericClient + Sync),
    repo_id: Uuid,
    expected_audience: Option<Uuid>,
    target_oid: Option<&str>,
) -> Result<Vec<MirrorNodeStatus>, Error> {
    let rows = client
        .query(
            "SELECT m.mirror_id, m.url, m.audience, m.storage_generation, m.active, \
               (m.active=true AND m.heartbeat_unix>extract(epoch FROM clock_timestamp())::bigint-$2) AS alive, \
               m.capacity, m.heartbeat_unix, jsonb_array_length(m.ready_oids)::bigint AS oid_count, \
               CASE WHEN $3::text IS NULL THEN NULL ELSE (m.ready_oids ? $3) END AS target_ready, \
               (SELECT count(*) FROM ci_runs c WHERE c.state='leased' AND c.source_url=m.url \
                 AND c.lease_expires_unix>extract(epoch FROM clock_timestamp())) AS active_leases \
             FROM ci_mirror_nodes m WHERE m.repository_id=$1 \
             ORDER BY m.active DESC, m.heartbeat_unix DESC, m.mirror_id ASC",
            &[&repo_id, &ci_controller::MIRROR_HEARTBEAT_TTL_SECS, &target_oid],
        )
        .await
        .map_err(Error::internal)?;
    Ok(rows
        .into_iter()
        .map(|row| {
            let audience: Uuid = row.get("audience");
            MirrorNodeStatus {
                mirror_id: row.get::<_, Uuid>("mirror_id").to_string(),
                url: row.get("url"),
                audience,
                storage_generation: row.get("storage_generation"),
                active: row.get("active"),
                alive: row.get("alive"),
                audience_matches: expected_audience.is_none_or(|exp| exp == audience),
                capacity: row.get("capacity"),
                active_leases: row.get("active_leases"),
                ready_oid_count: row.get::<_, i64>("oid_count").max(0) as usize,
                target_ready: row.get("target_ready"),
                heartbeat_unix: row.get("heartbeat_unix"),
            }
        })
        .collect())
}

pub async fn heartbeat(
    State(state): State<Arc<AppState>>,
    Path((owner, name, mirror_id)): Path<(String, String, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<Heartbeat>,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(
        &tx,
        &actor,
        &owner,
        &name,
        Role::Maintain,
        crate::token_scopes::RepoAction::CiDispatch,
    )
    .await?;
    if input.ready_oids.len() > 1000
        || input.capacity < 1
        || input.capacity > 10_000
        || input.ready_oids.iter().any(|oid| !ci_pins::valid_oid(oid))
        || input.storage_generation < 1
        || input.url.len() > 512
    {
        return Err(Error::bad_request());
    }
    let mirror_url = ci_controller::validate_mirror_url(&input.url)?;
    let expected_audience = crate::ci_checkouts::audience()?;
    if input.audience != expected_audience {
        return Err(Error(StatusCode::CONFLICT, "mirror audience mismatch"));
    }
    let repo_row = tx
        .query_one("SELECT storage_generation,object_format FROM repositories WHERE id=$1", &[&access.repo_id])
        .await
        .map_err(Error::internal)?;
    let actual_generation: i64 = repo_row.get(0);
    let object_format: String = repo_row.get(1);
    if actual_generation != input.storage_generation {
        return Err(Error(StatusCode::CONFLICT, "repository generation changed"));
    }
    if !ci_pins::valid_format(&object_format)
        || input.ready_oids.iter().any(|oid| !ci_pins::valid_oid_for_format(oid, &object_format))
    {
        return Err(Error::bad_request());
    }
    let deduped_oids: Vec<String> = input.ready_oids.iter().cloned().collect::<BTreeSet<_>>().into_iter().collect();
    let ready = serde_json::to_value(&deduped_oids).map_err(Error::internal)?;
    tx.execute(
        "INSERT INTO ci_mirror_nodes(repository_id,mirror_id,audience,url,storage_generation,ready_oids,capacity,active,heartbeat_unix) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,extract(epoch FROM clock_timestamp())::bigint) \
         ON CONFLICT(repository_id,mirror_id) DO UPDATE SET audience=excluded.audience, \
         url=excluded.url,storage_generation=excluded.storage_generation,ready_oids=excluded.ready_oids, \
         capacity=excluded.capacity,active=excluded.active,heartbeat_unix=excluded.heartbeat_unix",
        &[
            &access.repo_id,
            &mirror_id,
            &input.audience,
            &mirror_url,
            &input.storage_generation,
            &ready,
            &input.capacity,
            &input.active,
        ],
    )
    .await
    .map_err(Error::internal)?;
    auth::finish_tx(tx, &actor, true).await?;
    if input.active {
        ci_controller::notify_mirror_ready(access.repo_id, input.storage_generation, &deduped_oids);
        ci_controller::notify_slot_released(access.repo_id);
    }
    Ok((
        StatusCode::OK,
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({
            "mirror_id": mirror_id,
            "url": mirror_url,
            "audience": input.audience,
            "storage_generation": input.storage_generation,
            "active": input.active,
            "ready_oids": deduped_oids
        })),
    )
        .into_response())
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    Query(query): Query<ListQuery>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(
        &tx,
        &actor,
        &owner,
        &name,
        Role::Read,
        crate::token_scopes::RepoAction::HooksRead,
    )
    .await?;
    if let Some(oid) = query.target_oid.as_deref()
        && !ci_pins::valid_oid(oid)
    {
        return Err(Error::bad_request());
    }
    let expected_audience = crate::ci_checkouts::audience().ok();
    let mirrors = list_repo_mirrors(&*tx, access.repo_id, expected_audience, query.target_oid.as_deref()).await?;
    let origin_budget = ci_controller::query_origin_budget(&*tx, access.repo_id).await?;
    auth::finish_tx(tx, &actor, false).await?;
    Ok((
        StatusCode::OK,
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({
            "repository_id": access.repo_id,
            "origin_budget": origin_budget,
            "mirrors": mirrors
        })),
    )
        .into_response())
}
