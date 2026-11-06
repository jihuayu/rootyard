//! Durable physical-GC fence.
//!
//! Phase 1 serializes against every admitted writer, increments the repository
//! `gc_epoch`, commits a renewable maintenance fence, locks the existing SQL
//! retention-root rows, and anchors all SQL pins as native keep refs. Phase 2
//! runs only while the heartbeat can still prove that the same epoch and worker
//! own the fence.
use super::{
    jobs,
    models::{Job, Policy},
    retention::{self, KeepRefs, RootPin},
};
use crate::{AppState, storage::read_leases::Lease};
use anyhow::{Context, Result, bail, ensure};
use std::{collections::BTreeSet, sync::Arc, time::Duration};
use tokio::{
    sync::watch,
    task::JoinHandle,
    time::{Instant, timeout},
};
use tokio_postgres::GenericClient;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const HEARTBEAT: Duration = Duration::from_secs(1);
const FRESHNESS: Duration = Duration::from_secs(3);
const HEARTBEAT_TIMEOUT: Duration = Duration::from_millis(1500);

fn root_set(roots: &[RootPin]) -> BTreeSet<(String, String)> {
    roots.iter().map(|pin| (pin.kind.clone(), pin.oid.clone())).collect()
}

/// Existing retention rows are held stable through the root snapshot commit.
/// The trigger installed by migration 127 keeps later mutations out until the
/// committed fence expires or is released.
pub async fn lock_retention_rows<C: GenericClient + Sync>(tx: &C, repo: Uuid) -> Result<()> {
    for table in [
        "forge_pulls",
        "forge_pull_reviews",
        "forge_check_runs",
        "ci_runs",
        "ci_checkout_jobs",
        "ci_integration_checkout_jobs",
        "ci_pull_sync_progress",
        "workspaces",
        "workspace_checkpoints",
        "workspace_namespace_mounts",
        "workspace_views",
        "workspace_changeset_steps",
        "repository_ref_projection",
    ] {
        let sql = format!("SELECT 1 FROM {table} WHERE repository_id=$1 LIMIT 10001 FOR UPDATE NOWAIT");
        if tx.query(&sql, &[&repo]).await?.len() > 10_000 {
            bail!("retention root inspection exceeded limit");
        }
    }
    // A sandbox job reaches its repository through a workspace or CI run.
    if tx
        .query(
            "SELECT 1 FROM sandbox_jobs s \
             LEFT JOIN workspaces w ON w.id=s.workspace_id \
             LEFT JOIN ci_runs r ON r.id=s.ci_run_id \
             WHERE w.repository_id=$1 OR r.repository_id=$1 \
             LIMIT 10001 FOR UPDATE OF s NOWAIT",
            &[&repo],
        )
        .await?
        .len()
        > 10_000
    {
        bail!("retention root inspection exceeded limit");
    }
    // View history has no repository_id; its parent view is locked above, and
    // an explicit child lock keeps existing historical pins stable too.
    if tx
        .query(
            "SELECT 1 FROM workspace_view_history h \
             JOIN workspace_views v ON v.id=h.view_id \
             WHERE v.repository_id=$1 LIMIT 10001 FOR UPDATE OF h NOWAIT",
            &[&repo],
        )
        .await?
        .len()
        > 10_000
    {
        bail!("retention root inspection exceeded limit");
    }

    Ok(())
}

async fn release_row(state: &AppState, repository_id: Uuid, owner: Uuid, job_id: Uuid, epoch: i64) {
    let _ = timeout(Duration::from_millis(750), async {
        if let Ok(client) = state.pool.get().await {
            let _ = client
                .execute(
                    "UPDATE repositories SET gc_owner=NULL,gc_job_id=NULL,gc_lease_until=NULL, \
                     gc_fence_started_at=NULL,gc_quiesced_at=NULL \
                     WHERE id=$1 AND gc_owner=$2 AND gc_job_id=$3 AND gc_epoch=$4",
                    &[&repository_id, &owner, &job_id, &epoch],
                )
                .await;
        }
    })
    .await;
}

pub struct Fence {
    state: Arc<AppState>,
    repository_id: Uuid,
    owner: Uuid,
    job_id: Uuid,
    epoch: i64,
    native_roots: Vec<RootPin>,
    sql_roots: Vec<RootPin>,
    keep: Option<KeepRefs>,
    active: watch::Receiver<Option<Instant>>,
    task: Option<JoinHandle<()>>,
    released: bool,
}

impl Fence {
    pub fn epoch(&self) -> i64 {
        self.epoch
    }

    pub fn sql_root_count(&self) -> usize {
        self.sql_roots.len()
    }

    pub fn ensure_active(&self) -> Result<()> {
        let fresh = self.active.borrow().as_ref().is_some_and(|seen| Instant::now().duration_since(*seen) < FRESHNESS);
        if fresh && self.task.as_ref().is_some_and(|task| !task.is_finished()) {
            Ok(())
        } else {
            bail!("physical GC admission fence lost")
        }
    }

    /// Re-verify every durable condition immediately before a destructive
    /// phase. Root snapshots are compared again so a missed trigger or an
    /// out-of-band ref change aborts rather than races.
    pub async fn verify(&self, job: &Job, lease: &Lease, cancel: &CancellationToken) -> Result<()> {
        self.ensure_active()?;
        lease.ensure_active().map_err(|_| anyhow::anyhow!("repository reader barrier lost"))?;
        ensure!(!cancel.is_cancelled(), "maintenance lease lost");
        let row = timeout(Duration::from_millis(1500), async {
            let client = self.state.pool.get().await?;
            client
                .query_opt(
                    "SELECT 1 FROM repositories r \
                         WHERE r.id=$1 AND r.gc_owner=$2 AND r.gc_job_id=$3 \
                           AND r.gc_epoch=$4 AND r.gc_lease_until > clock_timestamp() \
                           AND r.storage_generation=$5 AND r.state='ready' \
                           AND NOT EXISTS ( \
                             SELECT 1 FROM storage_write_admissions a \
                             WHERE a.repository_id=r.id AND a.state='active' \
                               AND a.lease_until > clock_timestamp())",
                    &[&self.repository_id, &self.owner, &self.job_id, &self.epoch, &job.repository_generation],
                )
                .await
                .map_err(anyhow::Error::from)
        })
        .await
        .map_err(|_| anyhow::anyhow!("physical GC fence heartbeat unavailable"))??;
        ensure!(row.is_some(), "physical GC fence or quiescence changed");
        ensure!(jobs::current(&self.state.pool, job).await?, "maintenance claim changed before physical deletion");
        let native = retention::collect_native_roots(&self.state, self.repository_id, cancel).await?;
        ensure!(
            root_set(&native) == root_set(&self.native_roots),
            "native reachability roots changed during physical GC"
        );
        let client = self.state.pool.get().await?;
        let sql = retention::collect_sql_roots(&**client, self.repository_id).await?;
        ensure!(root_set(&sql) == root_set(&self.sql_roots), "SQL reachability roots changed during physical GC");
        if let Some(keep) = &self.keep {
            retention::verify_keep_refs(&self.state, self.repository_id, keep, cancel).await?;
        }
        self.ensure_active()
    }

    /// Remove this epoch's keep refs, then clear the committed fence. Keep-ref
    /// cleanup is best effort; a stale keep ref retains objects and is removed
    /// by the next collection, while an uncleared fence would block writers.
    pub async fn release(mut self) {
        self.released = true;
        if let Some(task) = self.task.take() {
            task.abort();
        }
        if let Some(keep) = self.keep.take() {
            let cancel = CancellationToken::new();
            if let Err(error) = retention::remove_keep_refs(&self.state, self.repository_id, &keep, &cancel).await {
                eprintln!("rootyard: physical GC keep ref cleanup deferred: {error:#}");
            }
        }
        release_row(&self.state, self.repository_id, self.owner, self.job_id, self.epoch).await;
    }
}

impl Drop for Fence {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        if self.released {
            return;
        }
        self.released = true;
        let state = self.state.clone();
        let repository_id = self.repository_id;
        let owner = self.owner;
        let job_id = self.job_id;
        let epoch = self.epoch;
        let keep = self.keep.take();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                if let Some(keep) = keep {
                    let cancel = CancellationToken::new();
                    let _ = retention::remove_keep_refs(&state, repository_id, &keep, &cancel).await;
                }
                release_row(&state, repository_id, owner, job_id, epoch).await;
            });
        }
    }
}

/// Acquire Phase 1. The caller must already hold the exclusive native-read
/// lease and every local writer/reader gate.
pub async fn acquire(
    state: &Arc<AppState>,
    job: &Job,
    lease: &Lease,
    policy: &Policy,
    cancel: &CancellationToken,
) -> Result<Fence> {
    lease.ensure_active().map_err(|_| anyhow::anyhow!("repository reader barrier lost"))?;
    let mut client = state.pool.get().await?;
    let tx = client.transaction().await?;
    tx.batch_execute(
        "SET LOCAL lock_timeout='2s'; SET LOCAL statement_timeout='5s'; \
         SET LOCAL idle_in_transaction_session_timeout='60s'",
    )
    .await?;
    let row = tx
        .query_opt(
            "SELECT storage_generation,state,storage_backend,gc_epoch,gc_owner,gc_job_id, \
             COALESCE(gc_lease_until > clock_timestamp(), false) \
             FROM repositories WHERE id=$1 AND owner_id=$2 FOR UPDATE",
            &[&job.repository_id, &job.tenant_id],
        )
        .await
        .context("lock repository for physical GC")?
        .ok_or_else(|| anyhow::anyhow!("repository changed before collection"))?;
    let generation: i64 = row.get(0);
    let repo_state: String = row.get(1);
    let backend: String = row.get(2);
    let mut epoch: i64 = row.get(3);
    let existing_owner: Option<Uuid> = row.get(4);
    let existing_job: Option<Uuid> = row.get(5);
    let existing_active: bool = row.get(6);
    ensure!(
        generation == job.repository_generation && repo_state == "ready" && backend == "gitfs",
        "repository changed before collection"
    );
    if existing_active && !(existing_job == Some(job.id) && existing_owner == Some(job.lease_owner)) {
        bail!("another physical GC holds the repository fence");
    }
    if !(existing_active && existing_job == Some(job.id) && existing_owner == Some(job.lease_owner)) {
        epoch = epoch.checked_add(1).context("physical GC epoch exhausted")?;
    }
    let lease_seconds = policy.lease_seconds.clamp(5, 300);
    tx.execute(
        "UPDATE repositories SET gc_epoch=$2,gc_owner=$3,gc_job_id=$4, \
         gc_lease_until=clock_timestamp()+make_interval(secs=>($5::bigint)::double precision), \
         gc_fence_started_at=clock_timestamp(),gc_quiesced_at=NULL WHERE id=$1",
        &[&job.repository_id, &epoch, &job.lease_owner, &job.id, &lease_seconds],
    )
    .await?;
    lock_retention_rows(&*tx, job.repository_id).await?;
    // The repository row is exclusively locked, so no new writer can insert an
    // admission. Existing admitted writers may still be finishing; their row
    // updates do not need the repository row, so they can quiesce here.
    let deadline = Instant::now() + Duration::from_secs(policy.quiescence_seconds as u64);
    loop {
        let active: i64 = tx
            .query_one(
                "SELECT count(*) FROM storage_write_admissions \
                 WHERE repository_id=$1 AND state='active' \
                   AND lease_until > clock_timestamp()",
                &[&job.repository_id],
            )
            .await?
            .get(0);
        if active == 0 {
            break;
        }
        if Instant::now() >= deadline {
            bail!("admitted writers did not quiesce before physical GC");
        }
        lease.ensure_active().map_err(|_| anyhow::anyhow!("repository reader barrier lost"))?;
        if !jobs::current(&state.pool, job).await? {
            bail!("maintenance claim expired while waiting for quiescence");
        }
        tx.execute(
            "UPDATE repositories SET gc_lease_until=clock_timestamp() \
             + make_interval(secs=>($2::bigint)::double precision) \
             WHERE id=$1 AND gc_owner=$3 AND gc_job_id=$4 AND gc_epoch=$5",
            &[&job.repository_id, &lease_seconds, &job.lease_owner, &job.id, &epoch],
        )
        .await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tx.execute("UPDATE repositories SET gc_quiesced_at=clock_timestamp() WHERE id=$1", &[&job.repository_id]).await?;
    let sql_roots = retention::collect_sql_roots(&*tx, job.repository_id).await?;
    let native_roots = retention::collect_native_roots(state, job.repository_id, cancel).await?;
    timeout(Duration::from_secs(2), tx.commit())
        .await
        .map_err(|_| anyhow::anyhow!("physical GC fence commit timed out"))??;
    let (active_send, active) = watch::channel(Some(Instant::now()));
    let heartbeat_state = state.clone();
    let heartbeat_owner = job.lease_owner;
    let heartbeat_job = job.id;
    let heartbeat_repo = job.repository_id;
    let heartbeat_epoch = epoch;
    let task = tokio::spawn(async move {
        let mut tick = tokio::time::interval(HEARTBEAT);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let result = timeout(HEARTBEAT_TIMEOUT, async {
                let client = heartbeat_state.pool.get().await?;
                let changed = client
                    .execute(
                        "UPDATE repositories SET gc_lease_until=clock_timestamp() \
                         + make_interval(secs=>($5::bigint)::double precision) \
                         WHERE id=$1 AND gc_owner=$2 AND gc_job_id=$3 AND gc_epoch=$4 \
                           AND gc_lease_until > clock_timestamp()",
                        &[&heartbeat_repo, &heartbeat_owner, &heartbeat_job, &heartbeat_epoch, &lease_seconds],
                    )
                    .await?;
                anyhow::Ok(changed == 1)
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
    let keep = match retention::anchor_keep_refs(state, job.repository_id, epoch, &sql_roots, cancel).await {
        Ok(keep) => keep,
        Err(error) => {
            task.abort();
            release_row(state, job.repository_id, job.lease_owner, job.id, epoch).await;
            return Err(error);
        }
    };
    Ok(Fence {
        state: state.clone(),
        repository_id: job.repository_id,
        owner: job.lease_owner,
        job_id: job.id,
        epoch,
        native_roots,
        sql_roots,
        keep: Some(keep),
        active,
        task: Some(task),
        released: false,
    })
}
