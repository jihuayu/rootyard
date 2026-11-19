use super::{models::EventsQuery, service};
use crate::{AppState, Error, members::models::Role};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::sse::{Event, KeepAlive, Sse},
};
use serde_json::{Value, json};
use std::{convert::Infallible, sync::Arc, time::Duration};
use uuid::Uuid;

const PAGE_LIMIT: i64 = 100;

async fn batch(state: &AppState, id: Uuid, after: i64) -> Result<(i64, Vec<Value>), Error> {
    let client = state.pool.get().await.map_err(Error::internal)?;
    // One statement gives the replay and its durable watermark the same snapshot.
    let rows = client
        .query(
            "WITH snapshot AS (SELECT revision FROM workspaces WHERE id=$1) \
             SELECT snapshot.revision,ev.revision,ev.kind,ev.payload \
             FROM snapshot LEFT JOIN LATERAL ( \
                 SELECT revision,kind,payload FROM workspace_events \
                 WHERE workspace_id=$1 AND revision>$2 ORDER BY revision LIMIT $3 \
             ) ev ON true ORDER BY ev.revision",
            &[&id, &after, &PAGE_LIMIT],
        )
        .await
        .map_err(Error::internal)?;
    let snapshot_revision = rows.first().ok_or_else(Error::not_found)?.get::<_, i64>(0);
    let events = rows
        .iter()
        .filter_map(|row| {
            Some(json!({
                "revision": row.get::<_, Option<i64>>(1)?,
                "kind": row.get::<_, Option<String>>(2)?,
                "payload": row.get::<_, Option<Value>>(3)?,
            }))
        })
        .collect();
    Ok((snapshot_revision, events))
}

fn cursor(query: Option<i64>, headers: &HeaderMap) -> i64 {
    // A native EventSource keeps the original query string on reconnect and
    // advances through Last-Event-ID. Use the highest valid cursor so neither
    // the query-only clients nor a reconnect replay an already-seen revision.
    let header = headers
        .get("last-event-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<i64>().ok())
        .filter(|value| *value >= 0);
    match header {
        Some(header) => query.unwrap_or(0).max(header),
        None => query.unwrap_or(0),
    }
}

fn gap(after: i64, snapshot_revision: i64, events: &[Value]) -> bool {
    let mut expected = after.saturating_add(1);
    for event in events {
        let Some(revision) = event["revision"].as_i64() else { return true };
        if revision != expected {
            return true;
        }
        expected = revision.saturating_add(1);
    }
    let ended_at = events.last().and_then(|event| event["revision"].as_i64()).unwrap_or(after);
    (events.len() as i64) < PAGE_LIMIT && ended_at < snapshot_revision
}

fn resync_event(snapshot_revision: i64) -> Event {
    Event::default().event("RESYNC_REQUIRED").data(json!({"snapshot_revision":snapshot_revision}).to_string())
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(query): Query<EventsQuery>,
) -> Result<Json<Value>, Error> {
    let ws =
        service::authorized(&state, &headers, id, Role::Read, crate::token_scopes::RepoAction::WorkspacesRead).await?;
    let after = query.after_revision.unwrap_or(0);
    if after < 0 || after > ws.revision {
        return Err(Error::bad_request());
    }
    let (snapshot_revision, events) = batch(&state, id, after).await?;
    if after > snapshot_revision {
        return Err(Error::bad_request());
    }
    Ok(Json(if gap(after, snapshot_revision, &events) {
        json!({"kind":"RESYNC_REQUIRED","snapshot_revision":snapshot_revision})
    } else {
        json!({"events":events,"snapshot_revision":snapshot_revision})
    }))
}

pub async fn stream(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(query): Query<EventsQuery>,
) -> Result<Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>>, Error> {
    let ws =
        service::authorized(&state, &headers, id, Role::Read, crate::token_scopes::RepoAction::WorkspacesRead).await?;
    let mut after = cursor(query.after_revision, &headers);
    if after < 0 || after > ws.revision {
        return Err(Error::bad_request());
    }
    let output = async_stream::stream! {
        loop {
            if service::authorized(&state,&headers,id,Role::Read, crate::token_scopes::RepoAction::WorkspacesRead).await.is_err() { break; }
            match batch(&state,id,after).await {
                Ok((snapshot_revision,events)) => {
                    if after > snapshot_revision {
                        yield Ok(resync_event(snapshot_revision));
                        break;
                    }
                    if gap(after,snapshot_revision,&events) {
                        yield Ok(resync_event(snapshot_revision));
                        break;
                    }
                    for item in events {
                        if let Some(rev)=item["revision"].as_i64() { after=rev; }
                        yield Ok(Event::default().id(after.to_string()).event("workspace").data(item.to_string()));
                    }
                }
                Err(_) => break,
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    };
    Ok(Sse::new(output).keep_alive(KeepAlive::default()))
}
