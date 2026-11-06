//! Administrative binding of CI check contexts to signed webhook integrations.
use crate::{AppState, Error, auth, members::models::Role, pulls::models::context_valid};
use axum::{Json, extract::{Path,State}, http::{HeaderMap,StatusCode}, response::{IntoResponse,Response}};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextInput { pub context: String }

pub async fn bind(
    State(state): State<Arc<AppState>>,
    Path((owner,name,hook_id)): Path<(String,String,Uuid)>,
    headers: HeaderMap, Json(input): Json<ContextInput>,
) -> Result<Response,Error> {
    if !context_valid(&input.context) { return Err(Error::bad_request()); }
    let actor = auth::authenticate(&state.pool,&headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx,&actor,&owner,&name,Role::Maintain).await?;
    let hook = tx.query_opt(
        "SELECT active,ci_contexts FROM forge_webhooks WHERE id=$1 AND repository_id=$2",
        &[&hook_id,&access.repo_id],
    ).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let permitted = hook.get::<_,bool>(0) && hook.get::<_,serde_json::Value>(1).as_array()
        .is_some_and(|a| a.iter().any(|v| v.as_str()==Some(input.context.as_str())));
    if !permitted { return Err(Error(StatusCode::CONFLICT,"integration inactive or context not allowed")); }
    tx.execute(
        "INSERT INTO forge_trusted_check_contexts(tenant_id,repository_id,context,webhook_id,active) \
         VALUES($1,$2,$3,$4,true) ON CONFLICT(repository_id,context) DO UPDATE \
         SET webhook_id=excluded.webhook_id,active=true",
        &[&access.owner_id,&access.repo_id,&input.context,&hook_id],
    ).await.map_err(Error::internal)?;
    auth::finish_tx(tx,&actor,true).await?;
    Ok((StatusCode::OK,Json(serde_json::json!({"context":input.context,"webhook_id":hook_id,"active":true}))).into_response())
}

pub async fn revoke(
    State(state): State<Arc<AppState>>,
    Path((owner,name,hook_id)): Path<(String,String,Uuid)>,
    headers: HeaderMap, Json(input): Json<ContextInput>,
) -> Result<Response,Error> {
    if !context_valid(&input.context) { return Err(Error::bad_request()); }
    let actor = auth::authenticate(&state.pool,&headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx,&actor,&owner,&name,Role::Maintain).await?;
    let changed = tx.execute(
        "UPDATE forge_trusted_check_contexts SET active=false WHERE repository_id=$1 AND context=$2 AND webhook_id=$3",
        &[&access.repo_id,&input.context,&hook_id],
    ).await.map_err(Error::internal)?;
    if changed==0 { return Err(Error::not_found()); }
    auth::finish_tx(tx,&actor,true).await?;
    Ok((StatusCode::OK,Json(serde_json::json!({"context":input.context,"active":false}))).into_response())
}
