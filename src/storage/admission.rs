//! Durable write admission coordinated with physical GC.
//!
//! A writer inserts a lease-backed row while holding `repositories FOR SHARE`.
//! Physical GC takes `repositories FOR UPDATE`, bumps `gc_epoch`, commits a
//! maintenance fence, and waits for every active admission to finish or expire
//! before it touches object storage. The row is not transaction-bound to the
//! caller's later Git child; a heartbeat monitor detects a lost fence and makes
//! `ensure_active` fail so the caller can SIGKILL its process group.
use crate::Error;
use axum::http::StatusCode;
use deadpool_postgres::Pool;
use std::time::Duration;
use tokio::{
    sync::watch,
    task::JoinHandle,
    time::{Instant, timeout, timeout_at},
};
use uuid::Uuid;

const HEARTBEAT: Duration = Duration::from_secs(1);
const FRESHNESS: Duration = Duration::from_secs(3);
const HEARTBEAT_TIMEOUT: Duration = Duration::from_millis(1500);
const MAX_LEASE_SECONDS: i64 = 3600;

fn unavailable() -> Error {
    Error(StatusCode::SERVICE_UNAVAILABLE, "repository maintenance admission unavailable")
}

fn conflict() -> Error {
    Error(StatusCode::CONFLICT, "repository generation or state changed")
}

fn valid_kind(kind: &str) -> bool {
    (1..=64).contains(&kind.len())
        && kind.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        && kind.as_bytes().first().is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// A durable admission lease. Drop is a best-effort abort; the database lease
/// remains authoritative if the process disappears before it is released.
pub struct Admission {
    pool: Pool,
    id: Uuid,
    owner: Uuid,
    repository_id: Uuid,
    generation: i64,
    epoch: i64,
    active: watch::Receiver<Option<Instant>>,
    task: Option<JoinHandle<()>>,
    finished: bool,
}

impl Admission {
    /// Reject once the heartbeat can no longer prove this admission is active.
    /// Callers invoke this before and after every native Git effect.
    pub fn ensure_active(&self) -> Result<(), Error> {
        let fresh = self.active.borrow().as_ref().is_some_and(|seen| Instant::now().duration_since(*seen) < FRESHNESS);
        if fresh && self.task.as_ref().is_some_and(|task| !task.is_finished()) { Ok(()) } else { Err(unavailable()) }
    }

    pub fn repository_id(&self) -> Uuid {
        self.repository_id
    }

    pub fn generation(&self) -> i64 {
        self.generation
    }

    pub fn gc_epoch(&self) -> i64 {
        self.epoch
    }

    /// Publish a clean finish. Errors are deliberately best-effort: the
    /// lease expiry and GC's active-row wait still fail closed.
    pub async fn finish(mut self) {
        self.finished = true;
        if let Some(task) = self.task.take() {
            task.abort();
        }
        let pool = self.pool.clone();
        let id = self.id;
        let owner = self.owner;
        let _ = timeout(Duration::from_millis(750), async move {
            if let Ok(client) = pool.get().await {
                let _ = client
                    .execute(
                        "UPDATE storage_write_admissions SET state='finished', \
                         finished_at=clock_timestamp(), lease_until=clock_timestamp(), \
                         heartbeat_at=clock_timestamp() \
                         WHERE id=$1 AND owner=$2 AND state='active'",
                        &[&id, &owner],
                    )
                    .await;
            }
        })
        .await;
    }
}

impl Drop for Admission {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        if self.finished {
            return;
        }
        let pool = self.pool.clone();
        let id = self.id;
        let owner = self.owner;
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = timeout(Duration::from_millis(750), async {
                    if let Ok(client) = pool.get().await {
                        let _ = client
                            .execute(
                                "UPDATE storage_write_admissions SET state='aborted', \
                                     finished_at=clock_timestamp(), lease_until=clock_timestamp(), \
                                     detail='admission guard dropped without an explicit finish' \
                                     WHERE id=$1 AND owner=$2 AND state='active'",
                                &[&id, &owner],
                            )
                            .await;
                    }
                })
                .await;
            });
        }
    }
}

/// Acquire a durable admission row and start its liveness monitor.
///
/// The transaction takes a short `FOR SHARE NOWAIT` lock on the repository row.
/// A committed physical-GC fence therefore rejects the writer immediately
/// instead of queueing it behind a long native operation.
pub async fn acquire(
    pool: &Pool,
    repository_id: Uuid,
    generation: i64,
    kind: &str,
    deadline: Instant,
) -> Result<Admission, Error> {
    if generation <= 0 || !valid_kind(kind) {
        return Err(Error::bad_request());
    }
    let lease_seconds = deadline
        .saturating_duration_since(Instant::now())
        .as_secs()
        .saturating_add(60)
        .min(MAX_LEASE_SECONDS as u64)
        .max(30) as i64;
    let mut client = timeout_at(deadline, pool.get()).await.map_err(|_| unavailable())?.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    tx.batch_execute("SET LOCAL lock_timeout='750ms'; SET LOCAL statement_timeout='2s'")
        .await
        .map_err(Error::internal)?;
    let row = tx
        .query_opt(
            "SELECT storage_generation,state,gc_epoch, \
             (gc_owner IS NOT NULL AND gc_lease_until > clock_timestamp() - interval '5 seconds') \
             FROM repositories WHERE id=$1 FOR SHARE NOWAIT",
            &[&repository_id],
        )
        .await
        .map_err(|_| unavailable())?
        .ok_or_else(Error::not_found)?;
    let current_generation: i64 = row.get(0);
    let state: String = row.get(1);
    let epoch: i64 = row.get(2);
    let gc_blocked: bool = row.get(3);
    if current_generation != generation || state != "ready" {
        return Err(conflict());
    }
    if gc_blocked {
        return Err(unavailable());
    }
    let id = Uuid::new_v4();
    let owner = Uuid::new_v4();
    tx.execute(
        "INSERT INTO storage_write_admissions(id,repository_id,gc_epoch,owner,kind,lease_until) \
         VALUES($1,$2,$3,$4,$5,clock_timestamp()+make_interval(secs=>($6::bigint)::double precision))",
        &[&id, &repository_id, &epoch, &owner, &kind, &lease_seconds],
    )
    .await
    .map_err(Error::internal)?;
    timeout(Duration::from_secs(2), tx.commit()).await.map_err(|_| unavailable())?.map_err(Error::internal)?;

    let (active_send, active) = watch::channel(Some(Instant::now()));
    let heartbeat_pool = pool.clone();
    let task = tokio::spawn(async move {
        let mut tick = tokio::time::interval(HEARTBEAT);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let result = timeout(HEARTBEAT_TIMEOUT, async {
                let client = heartbeat_pool.get().await?;
                let row = client
                    .query_opt(
                        "WITH heartbeat AS ( \
                           UPDATE storage_write_admissions \
                           SET lease_until=clock_timestamp()+make_interval(secs=>($4::bigint)::double precision), \
                               heartbeat_at=clock_timestamp() \
                           WHERE id=$1 AND owner=$2 AND state='active' \
                           RETURNING repository_id,gc_epoch \
                         ) SELECT r.storage_generation=$3 AND r.state='ready' \
                           AND r.gc_epoch=heartbeat.gc_epoch \
                           AND (r.gc_owner IS NULL OR r.gc_lease_until <= clock_timestamp()) \
                         FROM repositories r JOIN heartbeat ON heartbeat.repository_id=r.id",
                        &[&id, &owner, &generation, &lease_seconds],
                    )
                    .await?;
                let alive = row.as_ref().is_some_and(|row| row.get::<_, bool>(0));
                anyhow::Ok(alive)
            })
            .await;
            match result {
                Ok(Ok(true)) => {
                    let _ = active_send.send_replace(Some(Instant::now()));
                }
                _ => {
                    active_send.send_replace(None);
                    break;
                }
            }
        }
    });

    Ok(Admission {
        pool: pool.clone(),
        id,
        owner,
        repository_id,
        generation,
        epoch,
        active,
        task: Some(task),
        finished: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Duration;

    async fn test_pool() -> Option<Pool> {
        let Ok(base) = std::env::var("ROOTYARD_TEST_DATABASE_URL") else {
            return None;
        };
        let admin = crate::db::pool(&base).ok()?;
        let schema = format!("admission_{}", Uuid::new_v4().simple());
        admin.get().await.ok()?.batch_execute(&format!("CREATE SCHEMA {schema}")).await.ok()?;
        let mut url = reqwest::Url::parse(&base).ok()?;
        url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
        let pool = crate::db::pool(url.as_str()).ok()?;
        let client = pool.get().await.ok()?;
        client
            .batch_execute(
                "CREATE TABLE repositories( \
                   id uuid PRIMARY KEY, storage_generation bigint NOT NULL, state text NOT NULL, \
                   gc_epoch bigint NOT NULL DEFAULT 0, gc_owner uuid, gc_job_id uuid, \
                   gc_lease_until timestamptz, gc_fence_started_at timestamptz, \
                   gc_quiesced_at timestamptz); \
                 CREATE TABLE storage_write_admissions( \
                   id uuid PRIMARY KEY, repository_id uuid NOT NULL REFERENCES repositories(id), \
                   gc_epoch bigint NOT NULL, owner uuid NOT NULL, kind text NOT NULL, \
                   state text NOT NULL, admitted_at timestamptz NOT NULL DEFAULT clock_timestamp(), \
                   heartbeat_at timestamptz NOT NULL DEFAULT clock_timestamp(), \
                   lease_until timestamptz NOT NULL, finished_at timestamptz, detail text)",
            )
            .await
            .ok()?;
        Some(pool)
    }

    #[tokio::test]
    async fn active_gc_fence_rejects_new_writer_without_waiting() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let repo = Uuid::new_v4();
        pool.get()
            .await
            .unwrap()
            .execute(
                "INSERT INTO repositories(id,storage_generation,state,gc_epoch,gc_owner, \
                 gc_lease_until,gc_fence_started_at) \
                 VALUES($1,1,'ready',7,$2,clock_timestamp()+interval '30 seconds',clock_timestamp())",
                &[&repo, &Uuid::new_v4()],
            )
            .await
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        assert!(acquire(&pool, repo, 1, "git-push", deadline).await.is_err(), "writer crossed a committed GC fence");
        pool.get()
            .await
            .unwrap()
            .execute(
                "UPDATE repositories SET gc_owner=NULL,gc_job_id=NULL,gc_lease_until=NULL, \
                 gc_fence_started_at=NULL,gc_quiesced_at=NULL WHERE id=$1",
                &[&repo],
            )
            .await
            .unwrap();
        let admission = acquire(&pool, repo, 1, "git-push", Instant::now() + Duration::from_secs(5)).await.unwrap();
        assert!(admission.ensure_active().is_ok());
        admission.finish().await;
    }

    #[tokio::test]
    async fn heartbeat_loses_admission_when_gc_epoch_advances() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let repo = Uuid::new_v4();
        pool.get()
            .await
            .unwrap()
            .execute("INSERT INTO repositories(id,storage_generation,state) VALUES($1,1,'ready')", &[&repo])
            .await
            .unwrap();
        let admission = acquire(&pool, repo, 1, "git-push", Instant::now() + Duration::from_secs(10)).await.unwrap();
        pool.get()
            .await
            .unwrap()
            .execute(
                "UPDATE repositories SET gc_epoch=1,gc_owner=$2, \
                 gc_lease_until=clock_timestamp()+interval '30 seconds', \
                 gc_fence_started_at=clock_timestamp() WHERE id=$1",
                &[&repo, &Uuid::new_v4()],
            )
            .await
            .unwrap();
        for _ in 0..30 {
            if admission.ensure_active().is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(admission.ensure_active().is_err(), "admission stayed active after the GC epoch advanced");
        admission.finish().await;
    }
}
