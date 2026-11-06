use super::{models::EventsQuery, service};
use crate::{AppState, Error, members::models::Role};
use axum::{Json, extract::{Path, Query, State}, http::HeaderMap, response::sse::{Event, KeepAlive, Sse}};
use serde_json::{Value,json};
use std::{convert::Infallible, sync::Arc, time::Duration};
use uuid::Uuid;

async fn batch(state: &AppState, id: Uuid, after: i64) -> Result<Vec<Value>,Error> {
    let client = state.pool.get().await.map_err(Error::internal)?;
    let rows = client.query("SELECT revision,kind,payload FROM workspace_events WHERE workspace_id=$1 AND revision>$2 ORDER BY revision LIMIT 100", &[&id,&after]).await.map_err(Error::internal)?;
    Ok(rows.iter().map(|r| json!({"revision":r.get::<_,i64>(0),"kind":r.get::<_,String>(1),"payload":r.get::<_,Value>(2)})).collect())
}

pub async fn list(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<Uuid>, Query(query): Query<EventsQuery>) -> Result<Json<Value>,Error> {
    let ws = service::authorized(&state,&headers,id,Role::Read).await?;
    let after = query.after_revision.unwrap_or(0);
    if after<0 || after>ws.revision { return Err(Error::bad_request()); }
    let events = batch(&state,id,after).await?;
    let gap = events.first().and_then(|v|v["revision"].as_i64()).is_some_and(|first| first>after+1);
    Ok(Json(if gap { json!({"kind":"RESYNC_REQUIRED","snapshot_revision":ws.revision}) } else { json!({"events":events,"snapshot_revision":ws.revision}) }))
}

pub async fn stream(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<Uuid>, Query(query): Query<EventsQuery>) -> Result<Sse<impl futures_util::Stream<Item=Result<Event,Infallible>>>,Error> {
    let ws = service::authorized(&state,&headers,id,Role::Read).await?;
    let mut after = query.after_revision.unwrap_or(0);
    if after<0 || after>ws.revision { return Err(Error::bad_request()); }
    let output = async_stream::stream! {
        loop {
            if service::authorized(&state,&headers,id,Role::Read).await.is_err() { break; }
            match batch(&state,id,after).await {
                Ok(events) => {
                    if let Some(first) = events.first().and_then(|v|v["revision"].as_i64()) {
                        if first>after+1 {
                            yield Ok(Event::default().event("RESYNC_REQUIRED").data(json!({"snapshot_revision":first}).to_string()));
                            break;
                        }
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
