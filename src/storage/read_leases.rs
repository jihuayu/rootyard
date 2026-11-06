//! Cross-process native object read barrier. A pooled connection owns one
//! PostgreSQL transaction advisory lock for the entire snapshot lifetime.
use crate::Error;
use axum::http::StatusCode;
use deadpool_postgres::Pool;
use std::{
    future::Future,
    sync::{Arc, OnceLock},
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, oneshot, watch},
    task::JoinHandle,
    time::{Duration, Instant},
};
use uuid::Uuid;

const SHARED: &str =
    "SELECT pg_try_advisory_xact_lock_shared(hashtextextended('rootyard-data-v1:' || $1::uuid::text, 0))";
const EXCLUSIVE: &str = "SELECT pg_try_advisory_xact_lock(hashtextextended('rootyard-data-v1:' || $1::uuid::text, 0))";

pub struct Lease {
    active: watch::Receiver<Option<Instant>>,
    task: JoinHandle<()>,
    _slot: OwnedSemaphorePermit,
}

struct PendingTask(Option<JoinHandle<()>>);
impl Drop for PendingTask {
    fn drop(&mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
        }
    }
}

impl Lease {
    /// Call before every emitted chunk and after a native read finishes.
    pub fn ensure_active(&self) -> Result<(), Error> {
        // A blackholed client socket can leave a heartbeat future pending even
        // after PostgreSQL's idle-transaction timer releases the advisory lock.
        // Reject stale observations before that five-second server deadline.
        let fresh = self
            .active
            .borrow()
            .as_ref()
            .is_some_and(|last| Instant::now().duration_since(*last) < Duration::from_secs(3));
        if fresh && !self.task.is_finished() {
            Ok(())
        } else {
            Err(Error(StatusCode::SERVICE_UNAVAILABLE, "storage read lease lost"))
        }
    }

    /// Abort a native read future promptly if its fencing lease is lost.
    /// Git subprocess wrappers use kill-on-drop, so cancellation stops them.
    pub async fn guard<F: Future>(&self, future: F) -> Result<F::Output, Error> {
        tokio::pin!(future);
        let mut tick = tokio::time::interval(Duration::from_millis(500));
        loop {
            self.ensure_active()?;
            tokio::select! {
                result = &mut future => { self.ensure_active()?; return Ok(result); }
                _ = tick.tick() => {}
            }
        }
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
    let slot = tokio::time::timeout_at(deadline, slots.acquire_owned())
        .await
        .map_err(|_| unavailable())?
        .map_err(|_| unavailable())?;
    let pool = pool.clone();
    let (ready_send, ready_recv) = oneshot::channel::<Result<(), ()>>();
    let (active_send, active) = watch::channel(None);
    // The acquisition future itself can be cancelled by an HTTP disconnect.
    // Keep an abort-on-drop owner until ownership moves to a ready Lease.
    let mut pending = PendingTask(Some(tokio::spawn(async move {
        let mut ready_send = Some(ready_send);
        let result: anyhow::Result<()> = async {
            let mut client = pool.get().await?;
            let tx = client.transaction().await?;
            tx.batch_execute("SET LOCAL idle_in_transaction_session_timeout='5s'; SET LOCAL statement_timeout='3s'")
                .await?;
            let sql = if write { EXCLUSIVE } else { SHARED };
            loop {
                let granted: bool = tx.query_one(sql, &[&repo_id]).await?.get(0);
                if granted {
                    break;
                }
                if Instant::now() >= deadline {
                    anyhow::bail!("snapshot lease deadline");
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            active_send.send_replace(Some(Instant::now()));
            if let Some(sender) = ready_send.take() {
                let _ = sender.send(Ok(()));
            }
            let mut heartbeat = tokio::time::interval(Duration::from_secs(1));
            heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                heartbeat.tick().await;
                tokio::time::timeout(Duration::from_millis(1500), tx.simple_query("SELECT 1")).await??;
                active_send.send_replace(Some(Instant::now()));
            }
        }
        .await;
        if result.is_err() {
            if let Some(sender) = ready_send.take() {
                let _ = sender.send(Err(()));
            }
        }
        active_send.send_replace(None);
    })));
    let outcome = tokio::time::timeout_at(deadline, ready_recv).await;
    match outcome {
        Ok(Ok(Ok(()))) => Ok(Lease { active, task: pending.0.take().expect("pending lease task"), _slot: slot }),
        _ => Err(unavailable()),
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
        let Ok(url) = std::env::var("ROOTYARD_TEST_DATABASE_URL") else {
            return;
        };
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

    #[tokio::test]
    async fn cancelled_acquisition_does_not_orphan_postgres_lock() {
        let Ok(url) = std::env::var("ROOTYARD_TEST_DATABASE_URL") else {
            return;
        };
        let waiting_pool = crate::db::pool(&url).unwrap();
        let blocker_pool = crate::db::pool(&url).unwrap();
        let repo = Uuid::new_v4();
        let blocker = exclusive(&blocker_pool, repo, Instant::now() + Duration::from_secs(3)).await.unwrap();
        let worker_pool = waiting_pool.clone();
        let waiting =
            tokio::spawn(async move { shared(&worker_pool, repo, Instant::now() + Duration::from_secs(10)).await });
        for _ in 0..100 {
            if waiting_pool.status().size > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(waiting_pool.status().size > 0, "test waiter never reached PostgreSQL");
        waiting.abort();
        assert!(waiting.await.is_err());
        drop(blocker);
        let after = exclusive(&blocker_pool, repo, Instant::now() + Duration::from_secs(3)).await.unwrap();
        after.ensure_active().unwrap();
    }

    #[tokio::test]
    async fn blackholed_postgres_heartbeat_fails_closed() {
        use tokio::{
            io::copy_bidirectional,
            net::{TcpListener, TcpStream},
        };
        let Ok(url) = std::env::var("ROOTYARD_TEST_DATABASE_URL") else {
            return;
        };
        let mut endpoint = reqwest::Url::parse(&url).unwrap();
        let host = endpoint.host_str().unwrap().to_owned();
        let port = endpoint.port().unwrap_or(5432);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = listener.local_addr().unwrap().port();
        endpoint.set_host(Some("127.0.0.1")).unwrap();
        endpoint.set_port(Some(proxy_port)).unwrap();
        let (pause_send, mut pause) = watch::channel(false);
        let proxy = tokio::spawn(async move {
            let (mut inbound, _) = listener.accept().await.unwrap();
            let mut outbound = TcpStream::connect((host.as_str(), port)).await.unwrap();
            let paused = async {
                loop {
                    if *pause.borrow() {
                        break;
                    }
                    pause.changed().await.unwrap();
                }
            };
            tokio::select! {
                _ = copy_bidirectional(&mut inbound, &mut outbound) => {},
                _ = paused => { tokio::time::sleep(Duration::from_secs(8)).await; },
            }
        });
        let pool = crate::db::pool(endpoint.as_str()).unwrap();
        let lease = shared(&pool, Uuid::new_v4(), Instant::now() + Duration::from_secs(3)).await.unwrap();
        lease.ensure_active().unwrap();
        pause_send.send(true).unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(4),
            lease.guard(async {
                tokio::time::sleep(Duration::from_secs(10)).await;
            }),
        )
        .await
        .unwrap();
        assert!(result.is_err(), "blackholed heartbeat left a native read running");
        assert!(lease.ensure_active().is_err(), "blackholed lease remained active");
        drop(lease);
        proxy.abort();
    }
}
