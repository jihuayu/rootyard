//! Durable GitFS storage maintenance. The server owns this worker because it
//! holds the exclusive local data volume lock; a control-plane-only worker
//! must never open or mutate a repository volume.
#[path = "storage_lifecycle/gc.rs"]
pub mod gc;
#[path = "storage_lifecycle/gitfs.rs"]
pub mod gitfs;
#[path = "storage_lifecycle/jobs.rs"]
pub mod jobs;
#[path = "storage_lifecycle/models.rs"]
pub mod models;
#[path = "storage_lifecycle/scheduler.rs"]
pub mod scheduler;
#[path = "storage_lifecycle/worker.rs"]
pub mod worker;

use crate::AppState;
use anyhow::Result;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// One loop per running native-volume server. Job claims are durable, so a
/// replacement process resumes expired work without trusting in-memory state.
pub async fn run(state: Arc<AppState>, stop: CancellationToken) -> Result<()> {
    let policy = models::Policy::from_env()?;
    if !policy.enabled {
        return Ok(());
    }
    let owner = Uuid::new_v4();
    let mut interval = tokio::time::interval(policy.poll);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! { _=stop.cancelled() => return Ok(()), _=interval.tick() => {} }
        if let Err(error) = scheduler::schedule_once(&state, &policy).await {
            eprintln!("rootyard: storage maintenance scheduler deferred: {error:#}");
        }
        // Drain a bounded batch; no maintenance command consumes the online
        // Git request semaphore. Repository locks still serialize mutations.
        for _ in 0..4 {
            if stop.is_cancelled() {
                return Ok(());
            }
            match worker::run_once(&state, &policy, owner).await {
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(error) => {
                    eprintln!("rootyard: storage maintenance worker deferred: {error:#}");
                    break;
                }
            }
        }
    }
}
