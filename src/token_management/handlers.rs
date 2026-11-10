//! JSON API handlers for token and session management.
//!
//! Every handler authenticates with `auth::authenticate`, which only accepts an
//! `Authorization` header. Browser cookies and synthetic "browser" markers are
//! not read here, so a forged marker cannot upgrade an API request.
//!
//! Handlers extract [`MetadataState`] only: one PostgreSQL pool and nothing
//! else. They never read legacy storage, native Git, hooks or any other
//! `AppState` field, so the same handlers run unchanged in the Blob-only
//! gateway profile.

use crate::{Error, application::MetadataState, auth};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use uuid::Uuid;

use super::{
    empty_response, json_response,
    models::{CreateTokenInput, PageQuery, UpdateTokenInput},
    service,
};

type Res = Result<Response, Error>;

pub async fn list_tokens(
    State(state): State<MetadataState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Res {
    let (after, limit) = query.validate()?;
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let page = service::list_tokens(&state.pool, &actor, after, limit).await?;
    Ok(json_response(StatusCode::OK, page))
}

pub async fn create_token(
    State(state): State<MetadataState>,
    headers: HeaderMap,
    Json(input): Json<CreateTokenInput>,
) -> Res {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let issued = service::create_token(&state.pool, &actor, input).await?;
    Ok(json_response(StatusCode::CREATED, issued))
}

pub async fn get_token(State(state): State<MetadataState>, headers: HeaderMap, Path(token_id): Path<Uuid>) -> Res {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let view = service::get_token(&state.pool, &actor, token_id).await?;
    Ok(json_response(StatusCode::OK, view))
}

pub async fn update_token(
    State(state): State<MetadataState>,
    headers: HeaderMap,
    Path(token_id): Path<Uuid>,
    Json(input): Json<UpdateTokenInput>,
) -> Res {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let view = service::update_token(&state.pool, &actor, token_id, input).await?;
    Ok(json_response(StatusCode::OK, view))
}

pub async fn rotate_token(State(state): State<MetadataState>, headers: HeaderMap, Path(token_id): Path<Uuid>) -> Res {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let issued = service::rotate_token(&state.pool, &actor, token_id).await?;
    Ok(json_response(StatusCode::OK, issued))
}

pub async fn revoke_token(State(state): State<MetadataState>, headers: HeaderMap, Path(token_id): Path<Uuid>) -> Res {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    service::revoke_token(&state.pool, &actor, token_id).await?;
    Ok(empty_response(StatusCode::NO_CONTENT))
}

pub async fn list_sessions(
    State(state): State<MetadataState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Res {
    let (after, limit) = query.validate()?;
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let page = service::list_sessions(&state.pool, &actor, after, limit).await?;
    Ok(json_response(StatusCode::OK, page))
}

pub async fn revoke_session(
    State(state): State<MetadataState>,
    headers: HeaderMap,
    Path(session_token_id): Path<Uuid>,
) -> Res {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    service::revoke_session(&state.pool, &actor, session_token_id).await?;
    Ok(empty_response(StatusCode::NO_CONTENT))
}
