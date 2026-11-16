//! Mirror-side prewarm readiness announcement, burst wait coordination,
//! and explicit `waiting`/`denied`/`missing`/`overloaded`/`ready` classification.
use crate::{AppState, Error, ci_pins, db, webhooks::ci_controller};
use axum::{
    http::{HeaderName, HeaderValue, StatusCode},
    response::Response,
};
use serde::{Deserialize, Serialize};
use std::sync::{
    Arc, LazyLock, Mutex,
    atomic::{AtomicBool, Ordering},
};
use uuid::Uuid;

const HEARTBEAT_KEEPALIVE_SECS: u64 = 8;
static HEARTBEAT_STARTED: AtomicBool = AtomicBool::new(false);
static HEARTBEAT_MIRROR_IDS: LazyLock<Mutex<Vec<Uuid>>> = LazyLock::new(|| Mutex::new(Vec::new()));

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MirrorStateClass {
    Ready,
    Waiting,
    Denied,
    Missing,
    Overloaded,
}

impl MirrorStateClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Waiting => "waiting",
            Self::Denied => "denied",
            Self::Missing => "missing",
            Self::Overloaded => "overloaded",
        }
    }
}

pub fn classify_auto_fetch_status(cache_status: &str, waited: bool) -> MirrorStateClass {
    match cache_status {
        "hit" | "miss_fetched" | "coalesced_wait" => MirrorStateClass::Ready,
        _ if waited => MirrorStateClass::Waiting,
        _ => MirrorStateClass::Ready,
    }
}

pub fn classify_auto_fetch_error(status: StatusCode, msg: &str) -> MirrorStateClass {
    match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => MirrorStateClass::Denied,
        StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE => {
            if msg.contains("not ready") {
                MirrorStateClass::Waiting
            } else {
                MirrorStateClass::Overloaded
            }
        }
        StatusCode::NOT_FOUND | StatusCode::CONFLICT | StatusCode::BAD_REQUEST => {
            MirrorStateClass::Missing
        }
        _ => MirrorStateClass::Missing,
    }
}

pub(crate) fn attach_state_header(mut response: Response, class: MirrorStateClass) -> Response {
    if let Ok(val) = HeaderValue::from_str(class.as_str()) {
        response
            .headers_mut()
            .insert(HeaderName::from_static("x-rootyard-ci-state"), val);
    }
    response
}

pub(crate) fn error_response(err: Error) -> Response {
    let class = classify_auto_fetch_error(err.0, err.1);
    let mut obj = serde_json::Map::new();
    obj.insert("error".into(), serde_json::Value::String(err.1.into()));
    obj.insert(
        "classification".into(),
        serde_json::Value::String(class.as_str().into()),
    );
    (
        err.0,
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        axum::Json(serde_json::Value::Object(obj)),
    )
        .into_response_fallback(class)
}

trait IntoClassifiedFallback {
    fn into_response_fallback(self, class: MirrorStateClass) -> Response;
}

impl<T: axum::response::IntoResponse> IntoClassifiedFallback for T {
    fn into_response_fallback(self, class: MirrorStateClass) -> Response {
        attach_state_header(self.into_response(), class)
    }
}

pub(crate) fn parse_mirror_uuid_opt(raw: Option<&str>) -> Option<Uuid> {
    raw.map(str::trim)
        .filter(|id| !id.is_empty() && id.len() <= 128)
        .and_then(|id| Uuid::parse_str(id).ok())
}

fn ensure_heartbeat_keepalive(state: &Arc<AppState>, mirror_uuid: Uuid) {
    if state.mirror_primary.is_none() {
        return;
    }
    if let Ok(mut ids) = HEARTBEAT_MIRROR_IDS.lock()
        && !ids.contains(&mirror_uuid)
    {
        if ids.len() >= 16 {
            ids.remove(0);
        }
        ids.push(mirror_uuid);
    }
    if HEARTBEAT_STARTED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        HEARTBEAT_STARTED.store(false, Ordering::Release);
        return;
    };
    let weak = Arc::downgrade(state);
    handle.spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(HEARTBEAT_KEEPALIVE_SECS));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tick.tick().await;
        loop {
            tick.tick().await;
            let Some(app) = weak.upgrade() else {
                break;
            };
            let ids = HEARTBEAT_MIRROR_IDS
                .lock()
                .map(|v| v.clone())
                .unwrap_or_default();
            if ids.is_empty() {
                continue;
            }
            if let Ok(client) = app.pool.get().await
                && client
                    .query_one("SELECT to_regclass('ci_mirror_nodes') IS NOT NULL", &[])
                    .await
                    .is_ok_and(|r| r.get::<_, bool>(0))
            {
                let _ = client
                    .execute(
                        "UPDATE ci_mirror_nodes SET heartbeat_unix=extract(epoch FROM clock_timestamp())::bigint \
                         WHERE mirror_id = ANY($1) AND active=true",
                        &[&ids],
                    )
                    .await;
            }
        }
        HEARTBEAT_STARTED.store(false, Ordering::Release);
    });
}

pub(crate) async fn publish_ready_oid(
    state: &Arc<AppState>,
    repo: &db::Repository,
    target_oid: &str,
    explicit_mirror_id: Option<&str>,
) {
    if !ci_pins::valid_oid_for_format(target_oid, &repo.object_format) {
        return;
    }
    ci_controller::notify_mirror_ready(
        repo.id,
        repo.storage_generation,
        &[target_oid.to_owned()],
    );
    let env_id = std::env::var("ROOTYARD_CI_MIRROR_ID").ok();
    let Some(mirror_uuid) = parse_mirror_uuid_opt(explicit_mirror_id.or(env_id.as_deref())) else {
        return;
    };
    ensure_heartbeat_keepalive(state, mirror_uuid);
    let Ok(audience) = crate::ci_checkouts::audience() else {
        return;
    };
    let Ok(client) = state.pool.get().await else {
        return;
    };
    let Ok(has_table) = client
        .query_one("SELECT to_regclass('ci_mirror_nodes') IS NOT NULL", &[])
        .await
        .map(|r| r.get::<_, bool>(0))
    else {
        return;
    };
    if !has_table {
        return;
    }
    if let Ok(raw_url) = std::env::var("ROOTYARD_CI_MIRROR_PUBLIC_URL")
        && let Ok(url) = ci_controller::validate_mirror_url(&raw_url)
    {
        let capacity = std::env::var("ROOTYARD_CI_MIRROR_CAPACITY")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(16)
            .clamp(1, 10000);
        let ready = serde_json::json!([target_oid]);
        let _ = client
            .execute(
                "INSERT INTO ci_mirror_nodes(repository_id,mirror_id,audience,url,storage_generation,ready_oids,capacity,active,heartbeat_unix) \
                 VALUES($1,$2,$3,$4,$5,$6,$7,true,extract(epoch FROM clock_timestamp())::bigint) \
                 ON CONFLICT(repository_id,mirror_id) DO UPDATE SET \
                   audience=excluded.audience,url=excluded.url,storage_generation=excluded.storage_generation, \
                   ready_oids=CASE WHEN ci_mirror_nodes.storage_generation=excluded.storage_generation \
                     THEN COALESCE((SELECT jsonb_agg(DISTINCT x) FROM jsonb_array_elements_text(ci_mirror_nodes.ready_oids || excluded.ready_oids) AS x),'[]'::jsonb) \
                     ELSE excluded.ready_oids END, \
                   capacity=excluded.capacity,active=true,heartbeat_unix=excluded.heartbeat_unix",
                &[&repo.id, &mirror_uuid, &audience, &url, &repo.storage_generation, &ready, &capacity],
            )
            .await;
    } else {
        let _ = client
            .execute(
                "UPDATE ci_mirror_nodes SET \
                   ready_oids=COALESCE((SELECT jsonb_agg(DISTINCT x) FROM jsonb_array_elements_text(ready_oids || jsonb_build_array($4::text)) AS x),'[]'::jsonb), \
                   heartbeat_unix=extract(epoch FROM clock_timestamp())::bigint \
                 WHERE repository_id=$1 AND mirror_id=$2 AND storage_generation=$3 AND active=true",
                &[&repo.id, &mirror_uuid, &repo.storage_generation, &target_oid],
            )
            .await;
    }
    ci_controller::notify_slot_released(repo.id);
}

pub(crate) fn validate_mirror_id_opt(v: Option<&str>) -> Result<(), Error> {
    if let Some(id) = v
        && (id.is_empty()
            || id.len() > 128
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')))
    {
        return Err(Error::bad_request());
    }
    Ok(())
}

pub(crate) async fn sync_with_wait(
    state: &Arc<AppState>,
    owner: &str,
    name: &str,
    headers: &axum::http::HeaderMap,
    repo_id: uuid::Uuid,
    wait_ms: u64,
) -> Result<bool, Error> {
    use axum::extract::{Path, State};
    let clamped = wait_ms.min(10_000);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(clamped);
    let mut waited = false;
    loop {
        match crate::mirror::sync::sync(
            State(state.clone()),
            Path((owner.to_owned(), name.to_owned())),
            headers.clone(),
        )
        .await
        {
            Ok(_) => return Ok(waited),
            Err(err) if clamped > 0 && err.0 == StatusCode::TOO_MANY_REQUESTS => {
                let now = tokio::time::Instant::now();
                let rem = deadline.saturating_duration_since(now).as_millis() as u64;
                if rem == 0 {
                    return Err(err);
                }
                crate::mirror::limiter::for_state(state)
                    .wait_for_sync_slot(state, repo_id, rem)
                    .await?;
                waited = true;
            }
            Err(err) => return Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mirror_error_classification_maps_contract_states() {
        assert_eq!(
            classify_auto_fetch_error(StatusCode::UNAUTHORIZED, "denied"),
            MirrorStateClass::Denied
        );
        assert_eq!(
            classify_auto_fetch_error(StatusCode::TOO_MANY_REQUESTS, "origin cap"),
            MirrorStateClass::Overloaded
        );
        assert_eq!(
            classify_auto_fetch_error(StatusCode::SERVICE_UNAVAILABLE, "repository not ready"),
            MirrorStateClass::Waiting
        );
        assert_eq!(
            classify_auto_fetch_error(StatusCode::CONFLICT, "pin missing"),
            MirrorStateClass::Missing
        );
        assert_eq!(
            classify_auto_fetch_status("coalesced_wait", false),
            MirrorStateClass::Ready
        );
    }

    #[test]
    fn mirror_id_validation_rejects_empty_and_bad_chars() {
        assert!(validate_mirror_id_opt(None).is_ok());
        assert!(validate_mirror_id_opt(Some("mirror-us-east-1")).is_ok());
        assert!(validate_mirror_id_opt(Some("")).is_err());
        assert!(validate_mirror_id_opt(Some("mirror/bad")).is_err());
    }

    #[test]
    fn mirror_uuid_parser_accepts_uuid_and_rejects_non_uuid_labels() {
        let id = Uuid::new_v4();
        assert_eq!(parse_mirror_uuid_opt(Some(&format!("  {id}  "))), Some(id));
        assert_eq!(parse_mirror_uuid_opt(Some("mirror-us-east-1")), None);
        assert_eq!(parse_mirror_uuid_opt(Some("")), None);
        assert_eq!(parse_mirror_uuid_opt(None), None);
    }
}
