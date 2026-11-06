//! Cross-process native object read barrier. A pooled connection owns one
//! PostgreSQL transaction advisory lock for the entire snapshot lifetime.
use crate::Error;
use axum::http::StatusCode;
use deadpool_postgres::Pool;
use std::sync::{Arc, OnceLock};
use tokio::{sync::{oneshot, watch, OwnedSemaphorePermit, Semaphore}, task::JoinHandle, time::{Duration, Instant}};
use uuid::Uuid;

const SHARED: &str = "SELECT pg_try_advisory_xact_lock_shared(hashtextextended('rootyard-data-v1:' || $1::uuid::text, 0))";
const EXCLUSIVE: &str = "SELECT pg_try_advisory_xact_lock(hashtextextended('rootyard-data-v1:' || $1::uuid::text, 0))";

pub struct Lease {
    active: watch::Receiver<bool>,
    task: JoinHandle<()>,
    _slot: OwnedSemaphorePermit,
}

impl Lease {
    /// Call before every emitted chunk and after a native read finishes.
    pub fn ensure_active(&self) -> Result<(), Error> {
        if *self.active.borrow() && !self.task.is_finished() { Ok(()) }
        else { Err(Error(StatusCode::SERVICE_UNAVAILABLE, "storage read lease lost")) }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        // Dropping the transaction sends ROLLBACK; a queued exclusive lock only
        // proceeds after PostgreSQL has released this exact shared lock.
        self.task.abort();
    }
}

fn unavailable() -> Error {
    Error(StatusCode::SERVICE_UNAVAILABLE, "storage snapshot barrier unavailable")
}

async fn acquire(pool: &Pool, repo_id: Uuid, deadline: Instant, write: bool) -> Result<Lease, Error> {
    // The application pool has 16 connections. Leave at least half for
    // authorization, publication, and maintenance queries while streams run.
    static SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    let slots = SLOTS.get_or_init(|| Arc::new(Semaphore::new(8))).clone();
    let slot = tokio::time::timeout_at(deadline, slots.acquire_owned()).await
        .map_err(|_| unavailable())?.map_err(|_| unavailable())?;
    let pool = pool.clone();
    let (ready_send, ready_recv) = oneshot::channel::<Result<(), ()>>();
    let (active_send, active) = watch::channel(true);
    let task = tokio::spawn(async move {
        let mut ready_send = Some(ready_send);
        let result: anyhow::Result<()> = async {
            let mut client = pool.get().await?;
            let tx = client.transaction().await?;
            tx.batch_execute("SET LOCAL idle_in_transaction_session_timeout='5s'; SET LOCAL statement_timeout='3s'").await?;
            let sql = if write { EXCLUSIVE } else { SHARED };
            loop {
                let granted: bool = tx.query_one(sql, &[&repo_id]).await?.get(0);
                if granted { break; }
                if Instant::now() >= deadline { anyhow::bail!("snapshot lease deadline"); }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            if let Some(sender) = ready_send.take() { let _ = sender.send(Ok(())); }
            let mut heartbeat = tokio::time::interval(Duration::from_secs(1));
            heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                heartbeat.tick().await;
                tx.simple_query("SELECT 1").await?;
            }
        }.await;
        if result.is_err() {
            if let Some(sender) = ready_send.take() { let _ = sender.send(Err(())); }
        }
        let _ = active_send.send(false);
    });
    let outcome = tokio::time::timeout_at(deadline, ready_recv).await;
    match outcome {
        Ok(Ok(Ok(()))) => Ok(Lease { active, task, _slot: slot }),
        _ => { task.abort(); Err(unavailable()) }
    }
}

/// Shared, tenant-repository scoped lease for GitFS readers and transfers.
pub async fn shared(pool: &Pool, repo_id: Uuid, deadline: Instant) -> Result<Lease, Error> {
    acquire(pool, repo_id, deadline, false).await
}

/// Exclusive lease for physical GC. Acquire before local write and read gates.
pub async fn exclusive(pool: &Pool, repo_id: Uuid, deadline: Instant) -> Result<Lease, Error> {
    acquire(pool, repo_id, deadline, true).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn postgres_barrier_fences_other_pool_connections() {
        let Ok(url) = std::env::var("ROOTYARD_TEST_DATABASE_URL") else { return; };
        let readers = crate::db::pool(&url).unwrap();
        let collector = crate::db::pool(&url).unwrap();
        let repo = Uuid::new_v4();
        let read = shared(&readers, repo, Instant::now() + Duration::from_secs(3)).await.unwrap();
        assert!(read.ensure_active().is_ok());
        assert!(exclusive(&collector, repo, Instant::now() + Duration::from_millis(200)).await.is_err());
        read.ensure_active().unwrap();
        drop(read);
        let collect = exclusive(&collector, repo, Instant::now() + Duration::from_secs(3)).await.unwrap();
        assert!(shared(&readers, repo, Instant::now() + Duration::from_millis(200)).await.is_err());
        drop(collect);
        let resumed = shared(&readers, repo, Instant::now() + Duration::from_secs(3)).await.unwrap();
        resumed.ensure_active().unwrap();
    }
}
