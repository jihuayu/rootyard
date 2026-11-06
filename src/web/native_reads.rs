//! Lease a hosted Git source for browser views. PostgreSQL admission precedes
//! the local reader gate, matching the collector's exclusive lock order.
use crate::{AppState, Error, web::handlers};
use axum::http::{HeaderMap, StatusCode};
use std::{future::Future, time::Duration};
use tokio::sync::OwnedRwLockReadGuard;
use tokio::time::Instant;
use uuid::Uuid;

pub struct Source {
    lease: crate::storage::read_leases::Lease,
    _local: OwnedRwLockReadGuard<()>,
}

impl Source {
    pub fn ensure_active(&self) -> Result<(), Error> { self.lease.ensure_active() }

    /// Stop a native read before the database may release a failed heartbeat's
    /// shared lock. Git child futures use kill_on_drop, so dropping the read
    /// future cancels the child before a collector can obtain exclusivity.
    pub async fn protect<T, F>(&self, read: F) -> Result<T, Error>
    where F: Future<Output=Result<T,Error>> {
        tokio::pin!(read);
        let mut tick=tokio::time::interval(Duration::from_millis(200));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                result=&mut read => { self.ensure_active()?; return result; },
                _=tick.tick() => self.ensure_active()?,
            }
        }
    }
}

pub async fn acquire(state: &AppState, headers: &HeaderMap, owner: &str,
                     name: &str, repo_id: Uuid) -> Result<Source, Error> {
    let deadline=Instant::now()+state.config.git_timeout;
    let lease=crate::storage::read_leases::shared(&state.pool,repo_id,deadline).await?;
    let local=tokio::time::timeout_at(deadline,state.storage.read_snapshot_lock(repo_id))
        .await.map_err(|_| Error::timeout())?;
    lease.ensure_active()?;
    // The first authorization ended before waiting for either barrier. A
    // revoked session or role must not read source objects after admission.
    let (_,fresh,_) = handlers::authorize_web_repo(
        state,headers,owner,name,crate::members::models::Role::Read,
    ).await?;
    if fresh.repo_id!=repo_id { return Err(Error(StatusCode::NOT_FOUND,"not found")); }
    lease.ensure_active()?;
    Ok(Source { lease,_local:local })
}
