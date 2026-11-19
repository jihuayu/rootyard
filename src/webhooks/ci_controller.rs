//! Durable CI run reconciliation, multi-mirror selection, coalesced prewarming,
//! and bounded checkout burst waiting.
use super::ci_classification::{AvailabilitySummary, CheckoutTarget, OriginBudgetStatus};
use crate::{AppState, Error, webhooks::models::validate_webhook_url_with_policy};
use axum::http::StatusCode;
use serde_json::json;
use std::{
    collections::{BTreeSet, HashMap},
    sync::{Arc, LazyLock, Mutex, atomic::{AtomicUsize, Ordering}},
    time::Duration,
};
use tokio::sync::Notify;
use tokio_postgres::GenericClient;
use uuid::Uuid;

pub const DEFAULT_ORIGIN_FALLBACK_GLOBAL: i64 = 4;
pub const DEFAULT_ORIGIN_FALLBACK_PER_REPO: i64 = 2;
pub const MIRROR_HEARTBEAT_TTL_SECS: i64 = 30;
pub const DEFAULT_WAIT_QUEUE_LIMIT: usize = 64;
pub const MAX_WAIT_MS: u64 = 10_000;
const PREWARM_TIMEOUT: Duration = Duration::from_secs(4);

pub(crate) fn validate_mirror_url(raw: &str) -> Result<String, Error> {
    if raw.trim() != raw || raw.eq_ignore_ascii_case("origin") || raw.contains('?') {
        return Err(Error(StatusCode::BAD_REQUEST, "invalid mirror url"));
    }
    let parsed = validate_webhook_url_with_policy(raw, true)
        .map_err(|_| Error(StatusCode::BAD_REQUEST, "invalid mirror url"))?;
    if parsed.path_and_query != "/" {
        return Err(Error(StatusCode::BAD_REQUEST, "mirror url must not include a path"));
    }
    Ok(format!("{}://{}", parsed.scheme, parsed.host_header))
}

pub(crate) fn origin_fallback_limits() -> (i64, i64) {
    let global = std::env::var("ROOTYARD_CI_ORIGIN_FALLBACK_GLOBAL")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(DEFAULT_ORIGIN_FALLBACK_GLOBAL)
        .min(1024);
    let per_repo = std::env::var("ROOTYARD_CI_ORIGIN_FALLBACK_PER_REPO")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(DEFAULT_ORIGIN_FALLBACK_PER_REPO)
        .min(1024);
    (global, per_repo)
}

fn wait_queue_limit() -> usize {
    std::env::var("ROOTYARD_CI_CHECKOUT_WAIT_QUEUE")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_WAIT_QUEUE_LIMIT)
        .clamp(1, 1024)
}

pub(crate) struct CheckoutSnapshot {
    pub source: Option<String>,
    pub availability: AvailabilitySummary,
}

/// One statement snapshot for eligibility, capacity, winner, and origin budget.
/// `now_epoch` preserves prior heartbeat/second and lease/fractional comparisons.
const CHECKOUT_SNAPSHOT_SQL: &str = "\
WITH now_fact AS MATERIALIZED (SELECT extract(epoch FROM statement_timestamp()) AS now_epoch), \
lease_counts AS MATERIALIZED (SELECT c.source_url,count(*) AS active_leases FROM ci_runs c CROSS JOIN now_fact \
  WHERE c.state='leased' AND c.source_url IS NOT NULL AND c.lease_expires_unix>now_fact.now_epoch GROUP BY c.source_url), \
mirror_facts AS MATERIALIZED (SELECT m.url,m.mirror_id,m.heartbeat_unix,m.capacity,coalesce(l.active_leases,0) AS active_leases, \
    (m.ready_oids ? $5) AS target_ready FROM ci_mirror_nodes m CROSS JOIN now_fact LEFT JOIN lease_counts l ON l.source_url=m.url \
  WHERE m.repository_id=$1 AND m.storage_generation=$2 AND m.active=true AND m.url<>'origin' AND m.audience=$3 \
    AND m.heartbeat_unix>now_fact.now_epoch::bigint-$4 AND NOT (m.url = ANY($6::text[]))), \
eligible AS MATERIALIZED (SELECT * FROM mirror_facts WHERE target_ready AND active_leases<capacity), \
winner AS MATERIALIZED (SELECT url FROM eligible WHERE $7::boolean \
  ORDER BY active_leases ASC,(capacity-active_leases) DESC,heartbeat_unix DESC,mirror_id ASC LIMIT 1), \
origin_counts AS MATERIALIZED (SELECT count(*) AS global_active,count(*) FILTER (WHERE c.repository_id=$1) AS per_repo_active \
  FROM ci_runs c CROSS JOIN now_fact WHERE c.state='leased' AND c.source_url='origin' AND c.lease_expires_unix>now_fact.now_epoch) \
SELECT (SELECT count(*) FROM eligible) AS ready_avail, \
  (SELECT count(*) FROM mirror_facts WHERE target_ready) AS ready_total, \
  (SELECT count(*) FROM mirror_facts WHERE NOT target_ready) AS healthy_unready, \
  (SELECT url FROM winner) AS selected_url,o.global_active AS origin_global,o.per_repo_active AS origin_repo \
FROM origin_counts o";

pub(crate) async fn select_ready_mirror(
    client: &(impl GenericClient + Sync),
    repo_id: Uuid,
    storage_generation: i64,
    audience: Uuid,
    head_oid: &str,
    excluded: &[String],
    select_winner: bool,
) -> Result<CheckoutSnapshot, Error> {
    let row = client
        .query_one(
            CHECKOUT_SNAPSHOT_SQL,
            &[
                &repo_id,
                &storage_generation,
                &audience,
                &MIRROR_HEARTBEAT_TTL_SECS,
                &head_oid,
                &excluded,
                &select_winner,
            ],
        )
        .await
        .map_err(Error::internal)?;
    let (global_limit, per_repo_limit) = origin_fallback_limits();
    Ok(CheckoutSnapshot {
        source: row.get("selected_url"),
        availability: AvailabilitySummary {
            ready_available_mirrors: row.get::<_, i64>("ready_avail").max(0) as usize,
            ready_total_mirrors: row.get::<_, i64>("ready_total").max(0) as usize,
            healthy_unready_mirrors: row.get::<_, i64>("healthy_unready").max(0) as usize,
            origin_budget: OriginBudgetStatus {
                global_active: row.get("origin_global"),
                global_limit,
                per_repo_active: row.get("origin_repo"),
                per_repo_limit,
            },
        },
    })
}

pub(crate) async fn probe_availability(
    client: &(impl GenericClient + Sync),
    repo_id: Uuid,
    storage_generation: i64,
    audience: Uuid,
    head_oid: &str,
    excluded: &[String],
) -> Result<AvailabilitySummary, Error> {
    // Polling reads the same facts without sorting a winner it cannot use.
    Ok(select_ready_mirror(client, repo_id, storage_generation, audience, head_oid, excluded, false)
        .await?
        .availability)
}

pub(crate) async fn query_origin_budget(
    client: &(impl GenericClient + Sync),
    repo_id: Uuid,
) -> Result<OriginBudgetStatus, Error> {
    let (global_limit, per_repo_limit) = origin_fallback_limits();
    let count = client
        .query_one(
            "SELECT count(*) AS global, count(*) FILTER (WHERE repository_id=$1) AS repo \
             FROM ci_runs WHERE state='leased' AND source_url='origin' \
             AND lease_expires_unix>extract(epoch FROM clock_timestamp())",
            &[&repo_id],
        )
        .await
        .map_err(Error::internal)?;
    Ok(OriginBudgetStatus {
        global_active: count.get("global"),
        global_limit,
        per_repo_active: count.get("repo"),
        per_repo_limit,
    })
}

type ReadyKey = (Uuid, i64, String);
type PrewarmKey = (Uuid, String);

static READY_NOTIFY: LazyLock<Mutex<HashMap<ReadyKey, Arc<Notify>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static SLOT_NOTIFY: LazyLock<Mutex<HashMap<Uuid, Arc<Notify>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static GLOBAL_SLOT_NOTIFY: LazyLock<Arc<Notify>> = LazyLock::new(|| Arc::new(Notify::new()));
static INFLIGHT_PREWARMS: LazyLock<Mutex<HashMap<PrewarmKey, Arc<AtomicUsize>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static WAIT_QUEUE_ACTIVE: AtomicUsize = AtomicUsize::new(0);
static PREWARM_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(PREWARM_TIMEOUT)
        .build()
        .expect("prewarm HTTP client")
});

fn ready_notify_for(key: &ReadyKey) -> Arc<Notify> {
    let mut map = READY_NOTIFY.lock().expect("ready_notify poisoned");
    if map.len() > 4096 {
        map.clear();
    }
    map.entry(key.clone()).or_insert_with(|| Arc::new(Notify::new())).clone()
}

fn slot_notify_for(repo_id: Uuid) -> Arc<Notify> {
    let mut map = SLOT_NOTIFY.lock().expect("slot_notify poisoned");
    if map.len() > 2048 {
        map.clear();
    }
    map.entry(repo_id).or_insert_with(|| Arc::new(Notify::new())).clone()
}

pub(crate) fn notify_mirror_ready(repo_id: Uuid, storage_generation: i64, ready_oids: &[String]) {
    let map = READY_NOTIFY.lock().expect("ready_notify poisoned");
    for oid in ready_oids {
        if let Some(notify) = map.get(&(repo_id, storage_generation, oid.clone())) {
            notify.notify_waiters();
        }
    }
}

pub(crate) fn notify_slot_released(repo_id: Uuid) {
    if let Some(notify) = SLOT_NOTIFY.lock().expect("slot_notify poisoned").get(&repo_id).cloned() {
        notify.notify_waiters();
    }
    GLOBAL_SLOT_NOTIFY.notify_waiters();
}

struct PrewarmGuard(PrewarmKey);
impl Drop for PrewarmGuard {
    fn drop(&mut self) {
        INFLIGHT_PREWARMS.lock().expect("inflight_prewarms poisoned").remove(&self.0);
        notify_slot_released(self.0.0);
    }
}

struct WaitSlotGuard;
impl WaitSlotGuard {
    fn try_acquire() -> Option<Self> {
        let cap = wait_queue_limit();
        let mut cur = WAIT_QUEUE_ACTIVE.load(Ordering::Relaxed);
        loop {
            if cur >= cap {
                return None;
            }
            match WAIT_QUEUE_ACTIVE.compare_exchange_weak(cur, cur + 1, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => return Some(Self),
                Err(actual) => cur = actual,
            }
        }
    }
}
impl Drop for WaitSlotGuard {
    fn drop(&mut self) {
        WAIT_QUEUE_ACTIVE.fetch_sub(1, Ordering::AcqRel);
    }
}

pub(crate) fn parse_prewarm_origins(raw: &str) -> BTreeSet<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .filter_map(|entry| validate_mirror_url(entry).ok())
        .collect()
}

pub(crate) fn validate_prewarm_token(prewarm: Option<&str>, source: Option<&str>) -> Option<String> {
    let token = prewarm?;
    if token.is_empty() || token.len() > 256 || !token.bytes().all(|b| b.is_ascii_graphic()) {
        return None;
    }
    // Never transmit the mirror->primary read credential on outbound mirror triggers.
    if source == Some(token) {
        return None;
    }
    Some(token.to_owned())
}

fn prewarm_config() -> Option<(Vec<String>, String)> {
    let raw_origins = std::env::var("ROOTYARD_CI_MIRROR_PREWARM_ORIGINS").ok()?;
    let origins = parse_prewarm_origins(&raw_origins);
    if origins.is_empty() {
        return None;
    }
    let token = validate_prewarm_token(
        std::env::var("ROOTYARD_CI_MIRROR_PREWARM_TOKEN").ok().as_deref(),
        std::env::var("ROOTYARD_CI_MIRROR_SOURCE_TOKEN").ok().as_deref(),
    )?;
    Some((origins.into_iter().collect(), token))
}

pub(crate) fn prewarm_configured() -> bool {
    prewarm_config().is_some()
}

pub(crate) fn trigger_coalesced_prewarm(
    pool: deadpool_postgres::Pool,
    repo_id: Uuid,
    audience: Uuid,
    head_oid: String,
    excluded: Vec<String>,
) -> (bool, usize) {
    let Some((allowed_origins, token)) = prewarm_config() else {
        return (false, 0);
    };
    let key = (repo_id, head_oid.clone());
    let mut map = INFLIGHT_PREWARMS.lock().expect("inflight_prewarms poisoned");
    if let Some(counter) = map.get(&key) {
        let count = counter.fetch_add(1, Ordering::Relaxed) + 1;
        return (true, count);
    }
    map.insert(key.clone(), Arc::new(AtomicUsize::new(0)));
    drop(map);

    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        INFLIGHT_PREWARMS.lock().expect("inflight_prewarms poisoned").remove(&key);
        return (false, 0);
    };
    handle.spawn(async move {
        let _guard = PrewarmGuard(key);
        let Ok(client) = pool.get().await else {
            return;
        };
        let Ok(rows) = client
            .query(
                "SELECT m.url, u.slug, r.name, r.storage_generation \
                 FROM ci_mirror_nodes m \
                 JOIN repositories r ON r.id=m.repository_id \
                 JOIN namespaces u ON u.id=r.owner_id \
                 WHERE m.repository_id=$1 AND r.state='ready' AND m.storage_generation=r.storage_generation \
                   AND m.audience=$2 AND m.active=true AND m.url<>'origin' \
                   AND m.heartbeat_unix>extract(epoch FROM clock_timestamp())::bigint-$3 \
                   AND NOT (m.ready_oids ? $4) AND NOT (m.url = ANY($5::text[])) \
                   AND m.url = ANY($6::text[]) \
                 ORDER BY (m.capacity - (SELECT count(*) FROM ci_runs c WHERE c.state='leased' \
                     AND c.source_url=m.url AND c.lease_expires_unix>extract(epoch FROM clock_timestamp()))) DESC, \
                   m.heartbeat_unix DESC LIMIT 8",
                &[&repo_id, &audience, &MIRROR_HEARTBEAT_TTL_SECS, &head_oid, &excluded, &allowed_origins],
            )
            .await
        else {
            return;
        };
        drop(client);
        let mut tasks = tokio::task::JoinSet::new();
        for row in rows {
            let Ok(base) = validate_mirror_url(row.get::<_, &str>(0)) else { continue };
            if !allowed_origins.contains(&base) { continue; }
            let endpoint = format!("{base}/api/repos/{}/{}/mirror-auto-fetch", row.get::<_, &str>(1), row.get::<_, &str>(2));
            let (tok, oid, generation) = (token.clone(), head_oid.clone(), row.get::<_, i64>(3));
            tasks.spawn(async move {
                let _ = PREWARM_CLIENT.post(&endpoint).bearer_auth(tok)
                    .json(&json!({ "target_oid": oid, "storage_generation": generation })).send().await;
            });
        }
        while tasks.join_next().await.is_some() {}
    });
    (false, 0)
}

pub(crate) async fn wait_for_checkout_slot(
    state: &AppState,
    target: CheckoutTarget<'_>,
    prefer_mirror: bool,
    wait_ms: u64,
) -> Result<bool, Error> {
    let bounded = wait_ms.min(MAX_WAIT_MS);
    if bounded == 0 {
        return Ok(false);
    }
    let Some(_guard) = WaitSlotGuard::try_acquire() else {
        return Err(Error(StatusCode::TOO_MANY_REQUESTS, "CI checkout wait queue overloaded"));
    };
    let deadline = tokio::time::Instant::now() + Duration::from_millis(bounded);
    let r_notify = ready_notify_for(&(target.repo_id, target.storage_generation, target.head_oid.to_owned()));
    let s_notify = slot_notify_for(target.repo_id);
    let g_notify = GLOBAL_SLOT_NOTIFY.clone();

    loop {
        let ready_fut = r_notify.notified();
        let slot_fut = s_notify.notified();
        let global_fut = g_notify.notified();
        tokio::pin!(ready_fut);
        tokio::pin!(slot_fut);
        tokio::pin!(global_fut);
        ready_fut.as_mut().enable();
        slot_fut.as_mut().enable();
        global_fut.as_mut().enable();

        let client = state.pool.get().await.map_err(Error::internal)?;
        let summary = probe_availability(
            &**client,
            target.repo_id,
            target.storage_generation,
            target.audience,
            target.head_oid,
            target.excluded,
        )
        .await?;
        drop(client);

        let allow_origin = !prefer_mirror && !target.excluded.iter().any(|s| s == "origin");
        let origin_ready = allow_origin
            && summary.origin_budget.global_limit > 0
            && summary.origin_budget.per_repo_limit > 0
            && summary.origin_budget.global_active < summary.origin_budget.global_limit
            && summary.origin_budget.per_repo_active < summary.origin_budget.per_repo_limit;
        if summary.ready_available_mirrors > 0 || origin_ready {
            return Ok(true);
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Ok(false);
        }
        tokio::select! {
            _ = ready_fut => {}
            _ = slot_fut => {}
            _ = global_fut => {}
            _ = tokio::time::sleep_until(deadline.min(now + Duration::from_millis(250))) => {}
        }
    }
}

pub(crate) async fn reconcile_runs(state: &Arc<AppState>) -> Result<(), Error> {
    let client = state.pool.get().await.map_err(Error::internal)?;
    let has_table: bool = client
        .query_one("SELECT to_regclass('ci_runs') IS NOT NULL", &[])
        .await
        .map_err(Error::internal)?
        .get(0);
    if !has_table {
        return Ok(());
    }
    let cancelled = client
        .query(
            "UPDATE ci_runs c SET state='cancelled', lease_generation=c.lease_generation+1, \
               lease_expires_unix=0, source_url=NULL, runner_id=NULL, updated_at=clock_timestamp() \
             WHERE c.state IN ('queued','leased') AND NOT EXISTS ( \
               SELECT 1 FROM forge_pulls p JOIN repositories r ON r.id=p.repository_id \
               WHERE p.repository_id=c.repository_id AND p.number=c.pull_number \
                 AND p.state='open' AND p.version=c.pull_version \
                 AND p.head_oid=c.head_oid AND p.base_oid=c.base_oid \
                 AND r.state='ready' AND r.storage_generation=c.storage_generation \
             ) RETURNING c.repository_id",
            &[],
        )
        .await
        .map_err(Error::internal)?;
    let reaped = client
        .query(
            "UPDATE ci_runs SET state='queued', source_url=NULL, runner_id=NULL, \
               lease_expires_unix=0, updated_at=clock_timestamp() \
             WHERE state='leased' AND lease_expires_unix<=extract(epoch FROM clock_timestamp())::bigint \
             RETURNING repository_id",
            &[],
        )
        .await
        .map_err(Error::internal)?;
    let mut wake_repos = BTreeSet::new();
    for row in cancelled.into_iter().chain(reaped) {
        wake_repos.insert(row.get::<_, Uuid>(0));
    }
    for repo_id in wake_repos {
        notify_slot_released(repo_id);
    }

    if let Ok(audience) = crate::ci_checkouts::audience() {
        let pending = client
            .query(
                "SELECT DISTINCT c.repository_id, c.head_oid \
                 FROM ci_runs c JOIN repositories r ON r.id=c.repository_id \
                 WHERE c.state='queued' AND r.state='ready' AND r.storage_generation=c.storage_generation \
                   AND EXISTS (SELECT 1 FROM ci_mirror_nodes m WHERE m.repository_id=c.repository_id \
                     AND m.storage_generation=c.storage_generation AND m.audience=$1 \
                     AND m.active=true AND m.url<>'origin' \
                     AND m.heartbeat_unix>extract(epoch FROM clock_timestamp())::bigint-$2 \
                     AND NOT (m.ready_oids ? c.head_oid)) \
                 LIMIT 8",
                &[&audience, &MIRROR_HEARTBEAT_TTL_SECS],
            )
            .await
            .map_err(Error::internal)?;
        drop(client);
        for row in pending {
            let _ = trigger_coalesced_prewarm(
                state.pool.clone(),
                row.get("repository_id"),
                audience,
                row.get("head_oid"),
                Vec::new(),
            );
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "ci_controller_tests.rs"]
mod tests;
