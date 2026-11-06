//! Coalesced singleflight auto-origin fetch and cross-cluster runner queue for CI read mirrors.
use crate::{
    AppState, Error, db,
    mirror::{
        Snapshot,
        sync::{self, atomic_file, private_directory, read_regular},
        views,
    },
    storage::Storage,
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

type App = State<Arc<AppState>>;
type RepoPath = Path<(String, String)>;
type ApiResult = Result<Response, Error>;

static INFLIGHT_FETCHES: OnceLock<Mutex<BTreeMap<(Uuid, String), Arc<tokio::sync::Notify>>>> =
    OnceLock::new();
static INFLIGHT_WAITERS: OnceLock<Mutex<BTreeMap<(Uuid, String), usize>>> = OnceLock::new();
static RUNNER_QUEUE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[rustfmt::skip]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AutoFetchRequest {
    pub target_oid: String, pub job_id: Option<String>,
    pub storage_generation: Option<i64>, pub force_refresh: Option<bool>,
}

#[rustfmt::skip]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AutoFetchResponse {
    pub repository_id: Uuid, pub storage_generation: i64, pub target_oid: String,
    pub snapshot_id: Uuid, pub cache_status: String, pub coalesced: bool,
    pub coalesced_waiters: usize, pub duration_ms: u64,
}

#[rustfmt::skip]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunnerQueueRequest {
    pub action: String, pub runner_id: String, pub cluster_zone: String,
    pub job_id: Option<String>, pub target_oid: Option<String>,
    pub lease_ttl_secs: Option<u64>, pub now_unix: Option<i64>,
    #[serde(default)] pub attempt: Option<u32>,
    #[serde(default)] pub storage_generation: Option<i64>,
}

#[rustfmt::skip]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunnerRegistration {
    pub runner_id: String, pub cluster_zone: String,
    pub registered_at_unix: i64, pub last_heartbeat_unix: i64, pub lease_expires_unix: i64,
    pub active_job_id: Option<String>, pub active_attempt: Option<u32>,
}

#[rustfmt::skip]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunnerJobClaim {
    pub job_id: String, pub target_oid: String, pub storage_generation: i64,
    pub status: String, pub attempt: u32,
    pub claimed_by: Option<String>, pub cluster_zone: Option<String>,
    pub claimed_at_unix: Option<i64>, pub heartbeat_at_unix: Option<i64>, pub lease_expires_unix: Option<i64>,
}

#[rustfmt::skip]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunnerQueueState {
    pub repository_id: Uuid, pub storage_generation: i64,
    pub runners: Vec<RunnerRegistration>, pub claims: Vec<RunnerJobClaim>,
}

#[rustfmt::skip]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunnerQueueResponse {
    pub repository_id: Uuid, pub storage_generation: i64, pub action: String,
    pub runner_id: Option<String>, pub cluster_zone: Option<String>,
    pub active_claim: Option<RunnerJobClaim>, pub reaped_jobs: Vec<String>,
    pub runners: Vec<RunnerRegistration>, pub claims: Vec<RunnerJobClaim>,
}

pub fn valid_runner_id(v: &str) -> bool {
    let ok = |b: u8| b.is_ascii_alphanumeric() || b"-_.".contains(&b);
    (1..=64).contains(&v.len()) && v.bytes().all(ok)
}

pub fn valid_cluster_zone(v: &str) -> bool {
    let ok = |b: u8| b.is_ascii_alphanumeric() || b"-_.:".contains(&b);
    (1..=64).contains(&v.len()) && v.bytes().all(ok)
}

pub fn pinned_path(storage: &Storage, repo_id: Uuid, generation: i64, oid: &str) -> PathBuf {
    let dir = storage.root.join("repos").join(repo_id.to_string());
    dir.join(format!("pin-{generation}-{oid}.json"))
}

fn read_pin_snap(storage: &Storage, repo: &db::Repository, oid: &str) -> Result<Snapshot, Error> {
    let p = pinned_path(storage, repo.id, repo.storage_generation, oid);
    let bytes = read_regular(&p, 4096).map_err(Error::internal)?;
    let snap: Snapshot = serde_json::from_slice(&bytes).map_err(Error::internal)?;
    if snap.repository_id != repo.id || snap.storage_generation != repo.storage_generation
        || snap.object_format != repo.object_format
        || !crate::ci_pins::valid_oid_for_format(oid, &repo.object_format)
    {
        return Err(Error::internal("mirror pin snapshot identity mismatch"));
    }
    Ok(snap)
}

fn json_no_store(body: impl Serialize) -> Response {
    ([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response()
}

#[rustfmt::skip]
pub async fn auto_fetch(
    State(state): App, Path((owner, name)): RepoPath, headers: HeaderMap, Json(req): Json<AutoFetchRequest>,
) -> ApiResult {
    let t0 = Instant::now();
    if !crate::ci_pins::valid_oid(&req.target_oid)
        || req.target_oid.bytes().all(|b| b == b'0')
        || req.storage_generation.is_some_and(|g| g <= 0)
        || req.job_id.as_ref().is_some_and(|id| !valid_runner_id(id))
    {
        return Err(Error::bad_request());
    }
    let repo = crate::mirror::repository(&state, &headers, &owner, &name).await?;
    if !crate::ci_pins::valid_format(&repo.object_format)
        || !crate::ci_pins::valid_oid_for_format(&req.target_oid, &repo.object_format)
    {
        return Err(Error::bad_request());
    }
    if req.storage_generation.is_some_and(|g| g != repo.storage_generation) {
        return Err(Error(StatusCode::CONFLICT, "repository generation changed"));
    }
    let force = req.force_refresh.unwrap_or(false);
    let pin_meta = pinned_path(&state.storage, repo.id, repo.storage_generation, &req.target_oid);
    let cached = !force && pin_meta.is_file() && views::pinned_path(&state, &repo, &req.target_oid).await.is_ok();
    let (status, w) = if cached && read_pin_snap(&state.storage, &repo, &req.target_oid).is_ok() {
        ("hit", 0)
    } else {
        let key = (repo.id, req.target_oid.clone());
        let fmap = INFLIGHT_FETCHES.get_or_init(Default::default);
        let wmap = INFLIGHT_WAITERS.get_or_init(Default::default);
        let waiter = {
            let mut map = fmap.lock().expect("inflight");
            if let Some(notify) = map.get(&key).cloned() {
                *wmap.lock().expect("waiters").entry(key.clone()).or_insert(0) += 1;
                Some(notify)
            } else {
                map.insert(key.clone(), Arc::new(tokio::sync::Notify::new()));
                wmap.lock().expect("waiters").insert(key.clone(), 0);
                None
            }
        };
        let st = if let Some(notify) = waiter {
            notify.notified().await;
            views::pinned_path(&state, &repo, &req.target_oid).await?;
            "coalesced_wait"
        } else {
            let res = async {
                // Verify active source pins (refs/rootyard-ci/jobs/*) or mirror snapshot
                let _pins = crate::ci_pins::active_pinned_oids(&state, repo.id, repo.storage_generation).await;
                if force && pin_meta.exists() {
                    let _ = std::fs::remove_file(&pin_meta);
                }
                if force || views::pinned_path(&state, &repo, &req.target_oid).await.is_err() {
                    sync::sync(State(state.clone()), Path((owner.clone(), name.clone())), headers.clone()).await?;
                    if force && pin_meta.exists() {
                        let _ = std::fs::remove_file(&pin_meta);
                    }
                    views::pinned_path(&state, &repo, &req.target_oid).await?;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
                Ok::<(), Error>(())
            }
            .await;
            if let Some(notify) = fmap.lock().expect("inflight").remove(&key) {
                notify.notify_waiters();
            }
            res?;
            "miss_fetched"
        };
        let cur = crate::mirror::repository(&state, &headers, &owner, &name).await?;
        if cur.id != repo.id || cur.storage_generation != repo.storage_generation {
            return Err(Error(StatusCode::CONFLICT, "repository generation changed"));
        }
        let waiters = wmap.lock().expect("waiters").get(&key).copied().unwrap_or(0);
        (st, if st == "coalesced_wait" { waiters.max(1) } else { waiters })
    };
    let snap = read_pin_snap(&state.storage, &repo, &req.target_oid)?;
    Ok(json_no_store(AutoFetchResponse {
        repository_id: repo.id, storage_generation: repo.storage_generation,
        target_oid: req.target_oid, snapshot_id: snap.snapshot, cache_status: status.into(),
        coalesced: status == "coalesced_wait" || w > 0, coalesced_waiters: w,
        duration_ms: t0.elapsed().as_millis() as u64,
    }))
}

#[rustfmt::skip]
fn load_runner_state(state: &AppState, repo: &db::Repository) -> Result<RunnerQueueState, Error> {
    let file = state.storage.root.join("mirror-runners").join(format!("{}.json", repo.id));
    if let Some(dir) = file.parent() { private_directory(dir).map_err(Error::internal)?; }
    if !file.is_file() {
        return Ok(RunnerQueueState {
            repository_id: repo.id, storage_generation: repo.storage_generation,
            runners: Vec::new(), claims: Vec::new(),
        });
    }
    let bytes = read_regular(&file, 256 * 1024).map_err(Error::internal)?;
    let mut loaded: RunnerQueueState = serde_json::from_slice(&bytes).map_err(Error::internal)?;
    if loaded.repository_id != repo.id {
        return Err(Error::internal("runner state repository mismatch"));
    }
    if loaded.storage_generation != repo.storage_generation {
        loaded.storage_generation = repo.storage_generation;
        loaded.claims.clear();
    }
    Ok(loaded)
}

fn save_runner_state(state: &AppState, queue: &RunnerQueueState) -> Result<(), Error> {
    let dir = state.storage.root.join("mirror-runners");
    private_directory(&dir).map_err(Error::internal)?;
    let bytes = serde_json::to_vec(queue).map_err(Error::internal)?;
    atomic_file(&dir, &format!("{}.json", queue.repository_id), &bytes).map_err(Error::internal)
}

#[rustfmt::skip]
pub async fn list_runners(State(state): App, Path((owner, name)): RepoPath, headers: HeaderMap) -> ApiResult {
    let repo = crate::mirror::repository(&state, &headers, &owner, &name).await?;
    let q = {
        let _guard = RUNNER_QUEUE_LOCK.get_or_init(Default::default).lock().expect("runner_lock");
        load_runner_state(&state, &repo)?
    };
    Ok(json_no_store(RunnerQueueResponse {
        repository_id: q.repository_id, storage_generation: q.storage_generation,
        action: "list".into(), runner_id: None, cluster_zone: None, active_claim: None,
        reaped_jobs: Vec::new(), runners: q.runners, claims: q.claims,
    }))
}

#[rustfmt::skip]
pub async fn claim_or_heartbeat_runner(
    State(state): App, Path((owner, name)): RepoPath, headers: HeaderMap, Json(req): Json<RunnerQueueRequest>,
) -> ApiResult {
    let ttl = req.lease_ttl_secs.unwrap_or(300);
    let bad_oid = req.target_oid.as_ref().is_some_and(|o| !crate::ci_pins::valid_oid(o) || o.bytes().all(|b| b == b'0'));
    if !valid_runner_id(&req.runner_id) || !valid_cluster_zone(&req.cluster_zone)
        || !(10..=3600).contains(&ttl) || req.now_unix.is_some_and(|n| n <= 0)
        || req.storage_generation.is_some_and(|g| g <= 0)
        || req.job_id.as_ref().is_some_and(|j| !valid_runner_id(j)) || bad_oid
    {
        return Err(Error::bad_request());
    }
    let repo = crate::mirror::repository(&state, &headers, &owner, &name).await?;
    if req.target_oid.as_ref().is_some_and(|o|
        !crate::ci_pins::valid_oid_for_format(o, &repo.object_format))
    {
        return Err(Error::bad_request());
    }
    if req.storage_generation.is_some_and(|g| g != repo.storage_generation) {
        return Err(Error(StatusCode::CONFLICT, "repository generation changed"));
    }
    let now = req.now_unix.unwrap_or_else(|| {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64
    });
    let sql_oid = sql_job_oid(&state, repo.id, &req, now).await?;
    let _guard = RUNNER_QUEUE_LOCK.get_or_init(Default::default).lock().expect("runner_lock");
    let mut queue = load_runner_state(&state, &repo)?;
    let resp = apply_runner_action(&mut queue, &req, sql_oid.as_deref(), now)?;
    save_runner_state(&state, &queue)?;
    Ok(json_no_store(resp))
}

#[rustfmt::skip]
async fn sql_job_oid(state: &AppState, repo_id: Uuid, req: &RunnerQueueRequest, now: i64) -> Result<Option<String>, Error> {
    let Some(Ok(job_uuid)) = req.job_id.as_deref().map(str::parse::<Uuid>) else { return Ok(None) };
    let client = state.pool.get().await.map_err(Error::internal)?;
    let q = "SELECT cancelled, revoked, expires_unix, plan->>'target_oid' FROM ci_checkout_jobs WHERE repository_id = $1 AND job_id = $2";
    if let Some(r) = client.query_opt(q, &[&repo_id, &job_uuid]).await.map_err(Error::internal)? {
        if !crate::ci_checkouts::is_lease_active(r.get(0), r.get(1), r.get(2), now) {
            return Err(Error(StatusCode::CONFLICT, "ci_checkout_jobs lease inactive or expired"));
        }
        let plan_oid: Option<String> = r.get(3);
        if req.target_oid.as_deref().zip(plan_oid.as_deref()).is_some_and(|(a, b)| a != b) {
            return Err(Error(StatusCode::CONFLICT, "job target_oid differs from plan"));
        }
        return Ok(plan_oid);
    }
    Ok(None)
}

#[rustfmt::skip]
pub fn apply_runner_action(
    queue: &mut RunnerQueueState, req: &RunnerQueueRequest, sql_oid: Option<&str>, now: i64,
) -> Result<RunnerQueueResponse, Error> {
    let ttl = req.lease_ttl_secs.unwrap_or(300) as i64;
    let mut active_claim = None;
    let mut reaped_jobs = Vec::new();
    upsert_runner(queue, req, now, ttl)?;
    match req.action.as_str() {
        "register" => {}
        "reap_expired" => {
            for c in &mut queue.claims {
                if c.status == "claimed" && c.lease_expires_unix.is_some_and(|exp| exp <= now) {
                    c.status = "queued".into();
                    c.claimed_by = None;
                    c.cluster_zone = None;
                    c.lease_expires_unix = None;
                    reaped_jobs.push(c.job_id.clone());
                }
            }
            for r in &mut queue.runners {
                if r.active_job_id.as_ref().is_some_and(|j| reaped_jobs.contains(j)) {
                    r.active_job_id = None;
                }
            }
        }
        "claim" => {
            let next_q = || queue.claims.iter().find(|c| c.status == "queued").map(|c| c.job_id.clone());
            let job_id = req.job_id.clone().or_else(next_q).ok_or_else(Error::bad_request)?;
            let idx = match queue.claims.iter().position(|c| c.job_id == job_id) {
                Some(i) => i,
                None => {
                    let oid = req.target_oid.as_deref().or(sql_oid).ok_or_else(Error::bad_request)?;
                    queue.claims.push(RunnerJobClaim {
                        job_id, target_oid: oid.to_owned(), storage_generation: queue.storage_generation,
                        status: "queued".into(), attempt: 0, claimed_by: None, cluster_zone: None,
                        claimed_at_unix: None, heartbeat_at_unix: None, lease_expires_unix: None,
                    });
                    queue.claims.len() - 1
                }
            };
            let c = &mut queue.claims[idx];
            if c.status == "completed" {
                return Err(Error(StatusCode::CONFLICT, "job already completed"));
            }
            if c.status == "claimed" && c.lease_expires_unix.is_some_and(|exp| exp > now) {
                if c.claimed_by.as_deref() != Some(req.runner_id.as_str()) {
                    return Err(Error(StatusCode::CONFLICT, "job claimed by another active runner"));
                }
            } else {
                c.attempt = c.attempt.saturating_add(1);
                c.status = "claimed".into();
                c.claimed_by = Some(req.runner_id.clone());
                c.cluster_zone = Some(req.cluster_zone.clone());
                c.claimed_at_unix = Some(now);
            }
            c.heartbeat_at_unix = Some(now);
            c.lease_expires_unix = Some(now + ttl);
            let claimed = c.clone();
            if let Some(r) = queue.runners.iter_mut().find(|r| r.runner_id == req.runner_id) {
                r.active_job_id = Some(claimed.job_id.clone());
                r.active_attempt = Some(claimed.attempt);
            }
            active_claim = Some(claimed);
        }
        "heartbeat" | "complete" => {
            if let Some(job_id) = &req.job_id {
                let c = queue.claims.iter_mut().find(|c| &c.job_id == job_id).ok_or_else(Error::not_found)?;
                if c.status != "claimed" || c.claimed_by.as_deref() != Some(req.runner_id.as_str())
                    || c.lease_expires_unix.is_none_or(|exp| exp <= now) || req.attempt.is_some_and(|a| a != c.attempt)
                {
                    return Err(Error(StatusCode::CONFLICT, "stale runner lease epoch or expired claim"));
                }
                c.heartbeat_at_unix = Some(now);
                if req.action == "complete" {
                    c.status = "completed".into();
                    c.lease_expires_unix = None;
                    if let Some(r) = queue.runners.iter_mut().find(|r| r.runner_id == req.runner_id) {
                        r.active_job_id = None;
                        r.active_attempt = None;
                    }
                } else {
                    c.lease_expires_unix = Some(now + ttl);
                }
                active_claim = Some(c.clone());
            } else if req.action == "complete" {
                return Err(Error::bad_request());
            }
        }
        _ => return Err(Error::bad_request()),
    }
    Ok(RunnerQueueResponse {
        repository_id: queue.repository_id, storage_generation: queue.storage_generation,
        action: req.action.clone(), runner_id: Some(req.runner_id.clone()),
        cluster_zone: Some(req.cluster_zone.clone()), active_claim, reaped_jobs,
        runners: queue.runners.clone(), claims: queue.claims.clone(),
    })
}

#[rustfmt::skip]
fn upsert_runner(q: &mut RunnerQueueState, req: &RunnerQueueRequest, now: i64, ttl: i64) -> Result<(), Error> {
    if let Some(r) = q.runners.iter_mut().find(|r| r.runner_id == req.runner_id) {
        r.cluster_zone = req.cluster_zone.clone();
        r.last_heartbeat_unix = now;
        r.lease_expires_unix = now + ttl;
        Ok(())
    } else if matches!(req.action.as_str(), "register" | "claim" | "reap_expired") {
        q.runners.push(RunnerRegistration {
            runner_id: req.runner_id.clone(), cluster_zone: req.cluster_zone.clone(),
            registered_at_unix: now, last_heartbeat_unix: now, lease_expires_unix: now + ttl,
            active_job_id: None, active_attempt: None,
        });
        Ok(())
    } else {
        Err(Error::not_found())
    }
}

#[cfg(test)]
#[rustfmt::skip]
mod tests {
    use super::*;

    #[test]
    fn cross_cluster_runner_queue_epochs_and_stale_heartbeat_rejection() {
        let mut q = RunnerQueueState {
            repository_id: Uuid::new_v4(), storage_generation: 1, runners: Vec::new(), claims: Vec::new(),
        };
        let r1 = RunnerQueueRequest {
            action: "claim".into(), runner_id: "runner-a".into(), cluster_zone: "us-east-1a".into(),
            job_id: Some("job-1".into()), target_oid: Some("a".repeat(40)), lease_ttl_secs: Some(60),
            now_unix: Some(1000), attempt: None, storage_generation: Some(1),
        };
        assert_eq!(apply_runner_action(&mut q, &r1, None, 1000).unwrap().active_claim.unwrap().attempt, 1);
        let reap = RunnerQueueRequest { action: "reap_expired".into(), now_unix: Some(1065), ..r1.clone() };
        assert_eq!(apply_runner_action(&mut q, &reap, None, 1065).unwrap().reaped_jobs, vec!["job-1"]);
        let r2 = RunnerQueueRequest { runner_id: "runner-b".into(), cluster_zone: "eu-west-1b".into(), now_unix: Some(1070), ..r1.clone() };
        assert_eq!(apply_runner_action(&mut q, &r2, None, 1070).unwrap().active_claim.unwrap().attempt, 2);
        let stale_hb = RunnerQueueRequest { action: "heartbeat".into(), now_unix: Some(1075), attempt: Some(1), ..r1 };
        assert_eq!(apply_runner_action(&mut q, &stale_hb, None, 1075).unwrap_err().0, StatusCode::CONFLICT);
    }
}
