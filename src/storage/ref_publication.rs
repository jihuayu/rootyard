//! Owned, cross-process ref publication admission. The caller retains this
//! guard across native Git's prepare/commit phases; hook subprocesses never
//! attempt to keep a PostgreSQL transaction alive after they exit.
use crate::{
    Error,
    db::Identity,
    storage::{Storage, admission, read_leases},
};
use axum::http::StatusCode;
use deadpool_postgres::Pool;
use std::{
    future::Future,
    sync::{Arc, OnceLock},
};
use tokio::{
    sync::{OwnedMutexGuard, OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch},
    task::JoinHandle,
    time::{Duration, Instant},
};
use uuid::Uuid;

const LOCK_REF: &str =
    "SELECT pg_try_advisory_xact_lock(hashtextextended('rootyard-ref-v1:' || $1::uuid::text || ':' || $2::text, 0))";
const LOCK_REPOSITORY: &str =
    "SELECT pg_try_advisory_xact_lock(hashtextextended('rootyard-publication-v1:' || $1::uuid::text, 0))";

/// Requests handled by the publication owner task. The owner keeps the single
/// PostgreSQL transaction (exact ref advisory locks, repository advisory lock,
/// and later the token `FOR SHARE` row lock) alive for the whole native CAS.
pub(crate) enum WindowRequest {
    Enter(oneshot::Sender<Result<(), Error>>),
    AuthorizeGitWrite {
        actor: Identity,
        repository_id: Uuid,
        storage_generation: i64,
        reply: oneshot::Sender<Result<(), Error>>,
    },
}

pub struct PublicationWindow<'a> {
    guard: &'a PublicationGuard,
    _local: OwnedMutexGuard<()>,
}

/// Repo-only exclusive publication fence for placement/policy transitions.
/// Callers must already hold their data maintenance lease and local exclusive
/// gate, then take the local writer mutex only after this fence is granted.
pub struct RepositoryFence {
    active: watch::Receiver<Option<Instant>>,
    owner: JoinHandle<()>,
    _slot: OwnedSemaphorePermit,
}
impl RepositoryFence {
    pub fn ensure_active(&self) -> Result<(), Error> {
        if self
            .active
            .borrow()
            .as_ref()
            .is_some_and(|seen| Instant::now().duration_since(*seen) < Duration::from_secs(3))
            && !self.owner.is_finished()
        {
            Ok(())
        } else {
            Err(unavailable())
        }
    }
    pub async fn guard<F: Future>(&self, future: F) -> Result<F::Output, Error> {
        tokio::pin!(future);
        let mut tick = tokio::time::interval(Duration::from_millis(500));
        loop {
            self.ensure_active()?;
            tokio::select! {
                result=&mut future=>{self.ensure_active()?;return Ok(result);}
                _=tick.tick()=>{}
            }
        }
    }
}
impl Drop for RepositoryFence {
    fn drop(&mut self) {
        self.owner.abort();
    }
}
impl PublicationWindow<'_> {
    pub fn ensure_active(&self) -> Result<(), Error> {
        self.guard.ensure_active()
    }

    /// Lock this write's token `FOR SHARE` in the owner transaction and
    /// re-verify the live grant, effective `Write` role and repository
    /// generation/state there. No extra pooled connection is opened: the owner
    /// transaction already holds the exact-ref and repository advisory locks,
    /// and everything is held until child quiescence, journal settlement and
    /// guard drop. A canceled caller, timeout or failed check makes the owner
    /// abandon the transaction, so no marker or acknowledgement can publish
    /// refs after a late denial.
    pub async fn authorize_git_write(
        &self,
        actor: Identity,
        repository_id: Uuid,
        storage_generation: i64,
        deadline: Instant,
    ) -> Result<(), Error> {
        self.ensure_active()?;
        if repository_id != self.guard.repository_id || storage_generation != self.guard.storage_generation {
            return Err(Error(StatusCode::CONFLICT, "publication identity differs from admitted operation"));
        }
        let (reply, reply_rx) = oneshot::channel();
        tokio::time::timeout_at(
            deadline,
            self.guard.window_tx.send(WindowRequest::AuthorizeGitWrite {
                actor,
                repository_id,
                storage_generation,
                reply,
            }),
        )
        .await
        .map_err(|_| unavailable())?
        .map_err(|_| unavailable())?;
        tokio::time::timeout_at(deadline, reply_rx).await.map_err(|_| unavailable())?.map_err(|_| unavailable())??;
        self.ensure_active()
    }
}

pub struct PublicationGuard {
    repository_id: Uuid,
    storage_generation: i64,
    refs: Vec<String>,
    data: read_leases::Lease,
    admission: admission::Admission,
    active: watch::Receiver<Option<Instant>>,
    window_tx: mpsc::Sender<WindowRequest>,
    owner: JoinHandle<()>,
    _slot: OwnedSemaphorePermit,
}

impl PublicationGuard {
    pub fn repository_id(&self) -> Uuid {
        self.repository_id
    }
    pub fn storage_generation(&self) -> i64 {
        self.storage_generation
    }
    pub fn refs(&self) -> &[String] {
        &self.refs
    }

    /// Enter the short repository-wide publication window on the SAME PG
    /// session that owns exact-ref locks. This adds no pooled connection.
    /// Call only after input/object preparation; retain through native CAS,
    /// durable journal settlement, and any policy-dependent response.
    pub async fn enter_window<'a>(
        &'a self,
        storage: &Storage,
        deadline: Instant,
    ) -> Result<PublicationWindow<'a>, Error> {
        self.ensure_active()?;
        let (send, recv) = oneshot::channel();
        tokio::time::timeout_at(deadline, self.window_tx.send(WindowRequest::Enter(send)))
            .await
            .map_err(|_| unavailable())?
            .map_err(|_| unavailable())?;
        tokio::time::timeout_at(deadline, recv).await.map_err(|_| unavailable())?.map_err(|_| unavailable())??;
        let local = tokio::time::timeout_at(deadline, storage.write_lock(self.repository_id))
            .await
            .map_err(|_| unavailable())?;
        self.ensure_active()?;
        Ok(PublicationWindow { guard: self, _local: local })
    }

    pub fn ensure_active(&self) -> Result<(), Error> {
        self.data.ensure_active()?;
        self.admission.ensure_active()?;
        if self
            .active
            .borrow()
            .as_ref()
            .is_some_and(|seen| Instant::now().duration_since(*seen) < Duration::from_secs(3))
            && !self.owner.is_finished()
        {
            Ok(())
        } else {
            Err(unavailable())
        }
    }

    /// Cancel native work if either the ref or maintenance lease is lost.
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

impl Drop for PublicationGuard {
    fn drop(&mut self) {
        self.owner.abort();
    }
}

struct Pending(Option<JoinHandle<()>>);
impl Drop for Pending {
    fn drop(&mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
        }
    }
}

fn unavailable() -> Error {
    Error(StatusCode::SERVICE_UNAVAILABLE, "ref publication guard unavailable")
}

fn valid_ref(name: &str) -> bool {
    name.starts_with("refs/") && crate::journal::valid_ref(name)
}

/// The exact key used by `PublicationGuard::enter_window`, without acquiring
/// a ref lock or an extra data lease. This is for migrations and other
/// repository-wide transitions, never normal ref writers.
pub async fn acquire_repository_fence(
    pool: &Pool,
    repository_id: Uuid,
    deadline: Instant,
) -> Result<RepositoryFence, Error> {
    if repository_id.is_nil() {
        return Err(Error::bad_request());
    }
    static SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    let slots = SLOTS.get_or_init(|| Arc::new(Semaphore::new(2))).clone();
    let slot = tokio::time::timeout_at(deadline, slots.acquire_owned())
        .await
        .map_err(|_| unavailable())?
        .map_err(|_| unavailable())?;
    let owner_pool = pool.clone();
    let (ready_send, ready_recv) = oneshot::channel::<Result<(), Error>>();
    let (active_send, active) = watch::channel(None);
    let mut pending = Pending(Some(tokio::spawn(async move {
        let mut ready_send = Some(ready_send);
        let result: Result<(), Error> = async {
            let mut client = owner_pool.get().await.map_err(Error::internal)?;
            let tx = client.transaction().await.map_err(Error::internal)?;
            tx.batch_execute("SET LOCAL idle_in_transaction_session_timeout='5s'; SET LOCAL statement_timeout='3s'")
                .await
                .map_err(Error::internal)?;
            loop {
                let granted: bool =
                    tx.query_one(LOCK_REPOSITORY, &[&repository_id]).await.map_err(Error::internal)?.get(0);
                if granted {
                    break;
                }
                if Instant::now() >= deadline {
                    return Err(unavailable());
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            active_send.send_replace(Some(Instant::now()));
            if let Some(send) = ready_send.take() {
                let _ = send.send(Ok(()));
            }
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                tokio::time::timeout(Duration::from_millis(1500), tx.simple_query("SELECT 1"))
                    .await
                    .map_err(|_| unavailable())?
                    .map_err(Error::internal)?;
                active_send.send_replace(Some(Instant::now()));
            }
        }
        .await;
        if let Some(send) = ready_send.take() {
            let _ = send.send(result);
        }
        active_send.send_replace(None);
    })));
    match tokio::time::timeout_at(deadline, ready_recv).await {
        Ok(Ok(Ok(()))) => Ok(RepositoryFence { active, owner: pending.0.take().unwrap(), _slot: slot }),
        Ok(Ok(Err(error))) => Err(error),
        _ => Err(unavailable()),
    }
}

/// Acquire sorted exact-ref locks and the repository's shared maintenance
/// barrier. Generation is checked before granting and on every heartbeat.
/// At most four guards use pooled PostgreSQL connections at once, leaving
/// capacity for the eight native read leases and ordinary SQL work.
pub async fn acquire(
    pool: &Pool,
    repository_id: Uuid,
    generation: i64,
    refs: &[String],
    deadline: Instant,
) -> Result<PublicationGuard, Error> {
    if generation <= 0 || refs.is_empty() || refs.len() > 128 || refs.iter().any(|name| !valid_ref(name)) {
        return Err(Error::bad_request());
    }
    let mut names = refs.to_vec();
    names.sort();
    names.dedup();
    if names.len() != refs.len() {
        return Err(Error::bad_request());
    }
    static SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    let slots = SLOTS.get_or_init(|| Arc::new(Semaphore::new(4))).clone();
    let slot = tokio::time::timeout_at(deadline, slots.acquire_owned())
        .await
        .map_err(|_| unavailable())?
        .map_err(|_| unavailable())?;
    let data = read_leases::shared(pool, repository_id, deadline).await?;
    // Durable admission records the writer epoch so a committed GC fence
    // cannot be crossed even if a future path stops using advisory locks.
    let admission = admission::acquire(pool, repository_id, generation, "git-push", deadline).await?;
    let owner_pool = pool.clone();
    let owner_names = names.clone();
    let (ready_send, ready_recv) = oneshot::channel::<Result<(), Error>>();
    let (active_send, active) = watch::channel(None);
    let (window_tx, mut window_rx) = mpsc::channel::<WindowRequest>(1);
    let mut pending = Pending(Some(tokio::spawn(async move {
        let mut ready_send = Some(ready_send);
        let result: Result<(), Error> = async {
            // Try the entire sorted set in a fresh transaction each time. A
            // contended multi-ref group never retains a partial lock set.
            loop {
                let mut client = owner_pool.get().await.map_err(Error::internal)?;
                let tx = client.transaction().await.map_err(Error::internal)?;
                tx.batch_execute("SET LOCAL idle_in_transaction_session_timeout='5s'; SET LOCAL statement_timeout='3s'")
                    .await.map_err(Error::internal)?;
                let row = tx.query_opt("SELECT storage_generation,state,transition_state FROM repositories WHERE id=$1",
                    &[&repository_id]).await.map_err(Error::internal)?
                    .ok_or_else(Error::not_found)?;
                if row.get::<_, i64>(0) != generation
                    || row.get::<_, String>(1) != "ready"
                    || row.get::<_, String>(2) != "stable"
                {
                    return Err(Error(StatusCode::CONFLICT, "repository generation or state changed"));
                }
                let mut all = true;
                for name in &owner_names {
                    let granted: bool = tx.query_one(LOCK_REF, &[&repository_id, name])
                        .await.map_err(Error::internal)?.get(0);
                    if !granted { all = false; break; }
                }
                if !all {
                    // Rollback releases every acquired key before retrying.
                    drop(tx);
                    drop(client);
                    if Instant::now() >= deadline { return Err(unavailable()); }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
                active_send.send_replace(Some(Instant::now()));
                if let Some(sender) = ready_send.take() { let _ = sender.send(Ok(())); }
                let mut tick = tokio::time::interval(Duration::from_secs(1));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    tokio::select! {
                        _ = tick.tick() => {},
                        request = window_rx.recv() => {
                            match request {
                                Some(WindowRequest::Enter(request)) => {
                                    loop {
                                        if request.is_closed() { break; }
                                        let granted: bool = tx.query_one(LOCK_REPOSITORY, &[&repository_id])
                                            .await.map_err(Error::internal)?.get(0);
                                        let row = tx.query_opt("SELECT storage_generation,state,transition_state FROM repositories WHERE id=$1",
                                            &[&repository_id]).await.map_err(Error::internal)?
                                            .ok_or_else(Error::not_found)?;
                                        if row.get::<_, i64>(0) != generation
                                            || row.get::<_, String>(1) != "ready"
                                            || row.get::<_, String>(2) != "stable"
                                        {
                                            return Err(Error(StatusCode::CONFLICT, "repository generation or state changed"));
                                        }
                                        active_send.send_replace(Some(Instant::now()));
                                        if granted { let _ = request.send(Ok(())); break; }
                                        tokio::time::sleep(Duration::from_millis(50)).await;
                                    }
                                }
                                Some(WindowRequest::AuthorizeGitWrite { actor, repository_id: requested, storage_generation, reply }) => {
                                    // Lock order: exact ref -> repository advisory -> local writer ->
                                    // token FOR SHARE -> native CAS. The token lock stays on this
                                    // transaction until the child is quiescent and the guard drops.
                                    if requested != repository_id || storage_generation != generation {
                                        let _ = reply.send(Err(Error(StatusCode::CONFLICT,
                                            "publication identity differs from admitted operation")));
                                        return Err(unavailable());
                                    }
                                    match crate::auth::authorize_publication_window(&tx, &actor, repository_id, generation).await {
                                        Ok(()) => {
                                            // A closed caller abandons the authorization and the
                                            // transaction even when the SQL already succeeded: no
                                            // acknowledgement and no usable grant may survive it.
                                            if reply.is_closed() || reply.send(Ok(())).is_err() {
                                                return Err(unavailable());
                                            }
                                        }
                                        Err(error) => {
                                            let _ = reply.send(Err(error));
                                            return Err(unavailable());
                                        }
                                    }
                                }
                                None => return Err(unavailable()),
                            }
                            continue;
                        }
                    }
                    let row = tokio::time::timeout(Duration::from_millis(1500),
                        tx.query_opt("SELECT storage_generation,state,transition_state FROM repositories WHERE id=$1",
                            &[&repository_id])).await.map_err(|_| unavailable())?
                        .map_err(Error::internal)?.ok_or_else(Error::not_found)?;
                    if row.get::<_, i64>(0) != generation
                        || row.get::<_, String>(1) != "ready"
                        || row.get::<_, String>(2) != "stable"
                    {
                        return Err(Error(StatusCode::CONFLICT, "repository generation or state changed"));
                    }
                    active_send.send_replace(Some(Instant::now()));
                }
            }
        }.await;
        if let Some(sender) = ready_send.take() {
            let _ = sender.send(result);
        }
        active_send.send_replace(None);
    })));
    let result = tokio::time::timeout_at(deadline, ready_recv).await;
    match result {
        Ok(Ok(Ok(()))) => Ok(PublicationGuard {
            repository_id,
            storage_generation: generation,
            refs: names,
            data,
            admission,
            active,
            window_tx,
            owner: pending.0.take().expect("pending publication task"),
            _slot: slot,
        }),
        Ok(Ok(Err(error))) => Err(error),
        _ => Err(unavailable()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn postgres_exact_ref_contention_and_atomic_group_admission() {
        let Ok(base_url) = std::env::var("ROOTYARD_TEST_DATABASE_URL") else {
            return;
        };
        let admin = crate::db::pool(&base_url).unwrap();
        let schema = format!("ref_guard_{}", Uuid::new_v4().simple());
        admin.get().await.unwrap().batch_execute(&format!("CREATE SCHEMA {schema}")).await.unwrap();
        let mut url = reqwest::Url::parse(&base_url).unwrap();
        url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
        let pool = crate::db::pool(url.as_str()).unwrap();
        pool.get().await.unwrap().batch_execute("CREATE TABLE repositories(id uuid PRIMARY KEY, storage_generation bigint NOT NULL, state text NOT NULL, transition_state text NOT NULL DEFAULT 'stable', gc_epoch bigint NOT NULL DEFAULT 0, gc_owner uuid, gc_lease_until timestamptz); CREATE TABLE storage_write_admissions(id uuid PRIMARY KEY, repository_id uuid NOT NULL REFERENCES repositories(id), gc_epoch bigint NOT NULL, owner uuid NOT NULL, kind text NOT NULL, state text NOT NULL DEFAULT 'active', admitted_at timestamptz NOT NULL DEFAULT clock_timestamp(), heartbeat_at timestamptz NOT NULL DEFAULT clock_timestamp(), lease_until timestamptz NOT NULL, finished_at timestamptz, detail text)").await.unwrap();
        let repo = Uuid::new_v4();
        pool.get().await.unwrap().execute("INSERT INTO repositories VALUES($1,1,'ready')", &[&repo]).await.unwrap();
        let until = || Instant::now() + Duration::from_secs(2);
        let a = vec!["refs/heads/a".to_string()];
        let b = vec!["refs/heads/b".to_string()];
        let first = acquire(&pool, repo, 1, &a, until()).await.unwrap();
        let independent = acquire(&pool, repo, 1, &b, until()).await.unwrap();
        independent.ensure_active().unwrap();
        let (grant_send, grant_recv) = oneshot::channel();
        first.window_tx.send(WindowRequest::Enter(grant_send)).await.unwrap();
        grant_recv.await.unwrap().unwrap();
        let (blocked_send, blocked_recv) = oneshot::channel();
        independent.window_tx.send(WindowRequest::Enter(blocked_send)).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(150), blocked_recv).await.is_err(),
            "different ref entered repository publication window concurrently"
        );
        assert!(acquire(&pool, repo, 1, &a, Instant::now() + Duration::from_millis(200)).await.is_err());
        let group = vec![a[0].clone(), b[0].clone()];
        assert!(acquire(&pool, repo, 1, &group, Instant::now() + Duration::from_millis(200)).await.is_err());
        drop(first);
        let (after_send, after_recv) = oneshot::channel();
        independent.window_tx.send(WindowRequest::Enter(after_send)).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), after_recv).await.unwrap().unwrap().unwrap();
        let free_a = acquire(&pool, repo, 1, &a, until()).await.unwrap();
        free_a.ensure_active().unwrap();
        drop(free_a);
        assert!(
            acquire_repository_fence(&pool, repo, Instant::now() + Duration::from_millis(150)).await.is_err(),
            "migration fence overlapped a native publication window"
        );
        drop(independent);
        let maintenance = acquire_repository_fence(&pool, repo, until()).await.unwrap();
        maintenance.ensure_active().unwrap();
        drop(maintenance);
        let all = acquire(&pool, repo, 1, &group, until()).await.unwrap();
        assert_eq!(all.refs(), &["refs/heads/a", "refs/heads/b"]);
        drop(all);
        let (ready_send, mut ready_recv) = tokio::sync::mpsc::channel(8);
        let mut writers = Vec::new();
        for index in 0..8 {
            let writer_pool = pool.clone();
            let writer_ready = ready_send.clone();
            writers.push(tokio::spawn(async move {
                let name = vec![format!("refs/heads/parallel-{index}")];
                let guard =
                    acquire(&writer_pool, repo, 1, &name, Instant::now() + Duration::from_secs(5)).await.unwrap();
                writer_ready.send(()).await.unwrap();
                tokio::time::sleep(Duration::from_millis(500)).await;
                guard.ensure_active().unwrap();
            }));
        }
        for _ in 0..4 {
            tokio::time::timeout(Duration::from_secs(3), ready_recv.recv()).await.unwrap().unwrap();
        }
        // Four writers use at most four of the eight data lease slots plus
        // four ref-owner sessions. Authorization still obtains a pool session.
        tokio::time::timeout(Duration::from_millis(500), async {
            pool.get()
                .await
                .unwrap()
                .query_one("SELECT count(*) FROM repositories WHERE id=$1", &[&repo])
                .await
                .unwrap()
        })
        .await
        .expect("writer guard pool starvation");
        for writer in writers {
            writer.await.unwrap();
        }
        pool.get()
            .await
            .unwrap()
            .execute("UPDATE repositories SET storage_generation=2 WHERE id=$1", &[&repo])
            .await
            .unwrap();
        assert!(acquire(&pool, repo, 1, &a, until()).await.is_err());
        drop(pool);
        admin.get().await.unwrap().batch_execute(&format!("DROP SCHEMA {schema} CASCADE")).await.unwrap();
    }
}
