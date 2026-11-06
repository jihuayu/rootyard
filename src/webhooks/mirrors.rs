//! Primary-side registry of mirror target readiness used by the CI scheduler.
use crate::{AppState, Error, auth, ci_pins, members::models::Role};
use axum::{Json, extract::{Path,State}, http::{HeaderMap,StatusCode,header}, response::{IntoResponse,Response}};
use serde::Deserialize;
use std::sync::Arc;
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

pub async fn heartbeat(
    State(state): State<Arc<AppState>>,
    Path((owner,name,mirror_id)): Path<(String,String,Uuid)>,
    headers: HeaderMap, Json(input): Json<Heartbeat>,
) -> Result<Response,Error> {
    if input.ready_oids.len()>1000 || input.capacity<1 || input.capacity>10000 ||
        input.ready_oids.iter().any(|oid| !ci_pins::valid_oid(oid)) ||
        input.storage_generation<1 ||
        !(input.url.starts_with("https://") || input.url.starts_with("http://127.0.0.1:") || input.url.starts_with("http://[::1]:")) ||
        input.url.len()>512 || input.url.contains('@') || input.url.contains('#') {
        return Err(Error::bad_request());
    }
    let actor = auth::authenticate(&state.pool,&headers).await?;
    let mut client=state.pool.get().await.map_err(Error::internal)?;
    let tx=client.transaction().await.map_err(Error::internal)?;
    let access=auth::authorize_repo_with_role(&tx,&actor,&owner,&name,Role::Maintain).await?;
    let repo_row = tx.query_one(
        "SELECT storage_generation,object_format FROM repositories WHERE id=$1",&[&access.repo_id],
    ).await.map_err(Error::internal)?;
    let actual_generation: i64 = repo_row.get(0);
    let object_format: String = repo_row.get(1);
    if actual_generation!=input.storage_generation {
        return Err(Error(StatusCode::CONFLICT,"repository generation changed"));
    }
    if !ci_pins::valid_format(&object_format)
        || input.ready_oids.iter().any(|oid| !ci_pins::valid_oid_for_format(oid,&object_format))
    {
        return Err(Error::bad_request());
    }
    let ready=serde_json::to_value(&input.ready_oids).map_err(Error::internal)?;
    tx.execute(
        "INSERT INTO ci_mirror_nodes(repository_id,mirror_id,audience,url,storage_generation,ready_oids,capacity,active,heartbeat_unix) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,extract(epoch FROM clock_timestamp())::bigint) \
         ON CONFLICT(repository_id,mirror_id) DO UPDATE SET audience=excluded.audience, \
         url=excluded.url,storage_generation=excluded.storage_generation,ready_oids=excluded.ready_oids, \
         capacity=excluded.capacity,active=excluded.active,heartbeat_unix=excluded.heartbeat_unix",
        &[&access.repo_id,&mirror_id,&input.audience,&input.url,&input.storage_generation,
          &ready,&input.capacity,&input.active],
    ).await.map_err(Error::internal)?;
    auth::finish_tx(tx,&actor,true).await?;
    Ok((StatusCode::OK,[(header::CACHE_CONTROL,"no-store")],Json(serde_json::json!({"mirror_id":mirror_id,"ready_oids":input.ready_oids}))).into_response())
}
