//! A receive hook requests the parent-owned publication window. The hook exits
//! before Git commits refs, so the parent retains both gates until Git stops.
use crate::{
    AppState,
    db::Identity,
    journal, reliability,
    storage::{self, ref_publication::PublicationGuard},
};
use anyhow::{Context, Result, ensure};
use rand::RngCore;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{oneshot, watch},
    task::JoinHandle,
    time::Instant,
};

pub(super) struct Coordinator {
    listener: TcpListener,
    nonce: [u8; 32],
    op: journal::Operation,
    actor: Identity,
}

pub(super) struct Handle {
    task: JoinHandle<()>,
    stop: Option<oneshot::Sender<()>>,
    granted: watch::Receiver<bool>,
}

impl Coordinator {
    pub fn bind(op: &journal::Operation, actor: &Identity) -> Result<Self> {
        ensure!(op.requires_parent_publication, "operation does not require parent publication");
        ensure!(
            op.actor_id == actor.id && op.token_id == actor.token_id,
            "publication actor differs from admitted operation"
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let listener = TcpListener::from_std(listener)?;
        let mut nonce = [0u8; 32];
        rand::rng().fill_bytes(&mut nonce);
        Ok(Self { listener, nonce, op: op.clone(), actor: actor.clone() })
    }

    pub fn endpoint(&self) -> SocketAddr {
        self.listener.local_addr().expect("bound listener")
    }
    pub fn nonce_hex(&self) -> String {
        hex::encode(self.nonce)
    }

    pub fn start(self, guard: Arc<PublicationGuard>, state: Arc<AppState>, deadline: Instant) -> Handle {
        let (stop_send, mut stop_recv) = oneshot::channel();
        let (granted_send, granted) = watch::channel(false);
        let task = tokio::spawn(async move {
            let outcome: Result<()> = async {
                loop {
                    let (mut peer, addr) = tokio::select! {
                        _ = &mut stop_recv => return Ok(()),
                        result = tokio::time::timeout_at(deadline,self.listener.accept()) =>
                            result.context("publication hook deadline")??,
                    };
                    if !addr.ip().is_loopback() {
                        continue;
                    }
                    let mut attempt = [0u8; 32];
                    if tokio::time::timeout(Duration::from_secs(1), peer.read_exact(&mut attempt))
                        .await
                        .ok()
                        .and_then(std::result::Result::ok)
                        .is_none()
                        || attempt != self.nonce
                    {
                        continue;
                    }
                    ensure!(
                        guard.repository_id() == self.op.repository_id
                            && guard.storage_generation() == self.op.storage_generation,
                        "publication guard differs from admitted operation"
                    );
                    let window =
                        guard.enter_window(&state.storage, deadline).await.map_err(|e| anyhow::anyhow!(e.1))?;
                    let repo_path = state.storage.verify_path(self.op.repository_id)?;
                    let quota = state.config.max_repo_bytes;
                    let bytes = tokio::task::spawn_blocking(move || storage::disk_bytes(&repo_path, quota)).await??;
                    ensure!(bytes < quota, "repository quota reached before ref publication");
                    // Late authorization now runs on the owner's own transaction,
                    // which already holds the exact-ref and repository advisory
                    // locks; it takes the token `FOR SHARE` row lock and re-checks
                    // the live grant, current role and repository state there.
                    window
                        .authorize_git_write(
                            self.actor.clone(),
                            self.op.repository_id,
                            self.op.storage_generation,
                            deadline,
                        )
                        .await
                        .map_err(|e| anyhow::anyhow!(e.1))?;
                    window.ensure_active().map_err(|e| anyhow::anyhow!(e.1))?;
                    journal::atomic(&self.op.path.join("publication.grant"), &self.nonce, false)?;
                    peer.write_all(b"1").await?;
                    granted_send.send_replace(true);
                    // The guard remains owned until child quiescence and
                    // journal settlement. A reference-transaction preparing
                    // hook must confirm that the parent still holds it; a
                    // stale marker alone cannot authorize native CAS.
                    loop {
                        let (mut verifier, source) = tokio::select! {
                            _ = &mut stop_recv => break,
                            result = tokio::time::timeout_at(deadline,self.listener.accept()) =>
                                result.context("publication verifier deadline")??,
                        };
                        if !source.ip().is_loopback() {
                            continue;
                        }
                        let mut challenge = [0u8; 32];
                        if tokio::time::timeout(Duration::from_secs(1), verifier.read_exact(&mut challenge))
                            .await
                            .ok()
                            .and_then(std::result::Result::ok)
                            .is_none()
                            || challenge != self.nonce
                        {
                            continue;
                        }
                        window.ensure_active().map_err(|e| anyhow::anyhow!(e.1))?;
                        verifier.write_all(b"1").await?;
                    }
                    window.ensure_active().map_err(|e| anyhow::anyhow!(e.1))?;
                    return Ok(());
                }
            }
            .await;
            if let Err(error) = outcome {
                eprintln!("rootyard: publication coordination failed: {error:#}");
            }
        });
        Handle { task, stop: Some(stop_send), granted }
    }
}

impl Handle {
    pub fn granted(&self) -> bool {
        *self.granted.borrow() && !self.task.is_finished()
    }
    pub async fn close(mut self) {
        if let Some(send) = self.stop.take() {
            let _ = send.send(());
        }
        let _ = (&mut self.task).await;
    }
    pub async fn abort(mut self) {
        self.task.abort();
        let _ = (&mut self.task).await;
    }
}

/// Called only after the native process group has stopped. A granted parent
/// still owns the repo mutex; if no pre-receive hook ran, acquire it now before
/// removing the journal's active marker and reconciling terminal evidence.
pub(super) async fn settle(
    state: &AppState,
    operation: Option<journal::Operation>,
    active: Option<journal::ActiveGuard>,
    coordinator: Option<Handle>,
) -> Result<()> {
    let Some(operation) = operation else {
        return Ok(());
    };
    let granted = coordinator.as_ref().is_some_and(Handle::granted);
    let mut coordinator = coordinator;
    if !granted && let Some(handle) = coordinator.take() {
        handle.abort().await;
    }
    let _fallback = if granted {
        None
    } else {
        Some(
            tokio::time::timeout(state.config.git_timeout, state.storage.write_lock(operation.repository_id))
                .await
                .context("terminal publication mutex timeout")?,
        )
    };
    // The durable admission is authoritative even when native Git already
    // advanced local refs before a SIGSTOP. Never publish SQL ref history for a
    // writer that takeover fenced under a different shard epoch.
    if crate::storage::ref_admission::operation_is_fenced(state, &operation).await? {
        drop(active);
        crate::storage::ref_admission::rollback_fenced(state, &operation).await?;
        if let Some(handle) = coordinator {
            handle.close().await;
        }
        return Ok(());
    }
    journal::finish(&operation)?;
    drop(active);
    let result = reliability::complete(state, Some(operation.clone())).await;
    if result.is_err() && crate::storage::ref_admission::operation_is_fenced(state, &operation).await.unwrap_or(false) {
        crate::storage::ref_admission::rollback_fenced(state, &operation).await?;
        if let Some(handle) = coordinator {
            handle.close().await;
        }
        return Ok(());
    }
    if let Some(handle) = coordinator {
        handle.close().await;
    }
    result
}
impl Drop for Handle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Hook failure is a push refusal if the parent is absent or its window was
/// not granted. The nonce is supplied only in the sanitized child environment.
pub fn await_grant(op: &journal::Operation) -> Result<()> {
    if !op.requires_parent_publication {
        return Ok(());
    }
    let address: SocketAddr = std::env::var("ROOTYARD_PUBLICATION_ENDPOINT")?.parse()?;
    ensure!(address.ip().is_loopback(), "non-loopback publication parent");
    let nonce = hex::decode(std::env::var("ROOTYARD_PUBLICATION_NONCE")?)?;
    ensure!(nonce.len() == 32, "invalid parent publication nonce");
    let timeout = std::env::var("ROOTYARD_GIT_TIMEOUT_SECONDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(120));
    request_grant(op, address, &nonce, timeout)
}

fn request_grant(op: &journal::Operation, address: SocketAddr, nonce: &[u8], timeout: Duration) -> Result<()> {
    let mut peer = TcpStream::connect_timeout(&address, timeout)?;
    peer.set_read_timeout(Some(timeout))?;
    peer.set_write_timeout(Some(timeout))?;
    peer.write_all(nonce)?;
    let mut ack = [0u8];
    peer.read_exact(&mut ack)?;
    ensure!(ack == *b"1", "parent did not grant publication window");
    ensure!(
        journal::read(&op.path.join("publication.grant"))? == nonce,
        "parent publication marker differs from grant"
    );
    Ok(())
}

pub fn verify_grant(op: &journal::Operation) -> Result<()> {
    if !op.requires_parent_publication {
        return Ok(());
    }
    await_grant(op)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::Config, db, dispatch, metrics, storage::Storage};
    use uuid::Uuid;

    #[tokio::test]
    async fn native_hook_handshake_owns_cross_process_publication_window() {
        let Ok(base_url) = std::env::var("ROOTYARD_TEST_DATABASE_URL") else {
            return;
        };
        let admin = db::pool(&base_url).unwrap();
        let schema = format!("hook_window_{}", Uuid::new_v4().simple());
        admin.get().await.unwrap().batch_execute(&format!("CREATE SCHEMA {schema}")).await.unwrap();
        let mut url = reqwest::Url::parse(&base_url).unwrap();
        url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
        let pool = db::pool(url.as_str()).unwrap();
        db::migrate(&pool).await.unwrap();
        let issued = db::issue_token(&pool, "alice", true, false).await.unwrap();
        let actor_id: Uuid = serde_json::from_value(issued["user_id"].clone()).unwrap();
        let token_id: Uuid = serde_json::from_value(issued["token_id"].clone()).unwrap();
        let digest: Vec<u8> = pool
            .get()
            .await
            .unwrap()
            .query_one("SELECT digest FROM tokens WHERE id=$1", &[&token_id])
            .await
            .unwrap()
            .get(0);
        let repo = Uuid::new_v4();
        pool.get()
            .await
            .unwrap()
            .execute(
                "INSERT INTO repositories(id,owner_id,name,state) VALUES($1,$2,'test','ready')",
                &[&repo, &actor_id],
            )
            .await
            .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let config = Config {
            database_url: url.to_string(),
            data_dir: temp.path().join("data"),
            bind: "127.0.0.1:0".parse().unwrap(),
            git: "/usr/bin/git".into(),
            max_request_bytes: 1024,
            max_output_bytes: 1024,
            max_concurrent_git: 1,
            git_timeout: Duration::from_secs(5),
            git_memory_bytes: 1024 * 1024,
            max_repo_bytes: 1024 * 1024,
            max_pending_deliveries: 100,
            outbox_worker: false,
            metrics_bind: None,
        };
        let storage = Storage::open(&config).unwrap();
        let state = Arc::new(AppState {
            mirror_primary: None,
            dispatch: dispatch::Signals::default(),
            config,
            pool: pool.clone(),
            storage,
            hooks: None,
            transfer_metrics: Arc::new(metrics::TransferCounters::default()),
            git_slots: Arc::new(tokio::sync::Semaphore::new(1)),
        });
        std::fs::create_dir_all(state.storage.repo_path(repo)).unwrap();
        let (op, active) =
            journal::begin_active(&state.storage.root, repo, actor_id, "alice".into(), token_id, 1).unwrap();
        let actor =
            Identity { id: actor_id, token_id, username: "alice".into(), read_only: false, token_digest: digest };
        let guard = Arc::new(
            crate::storage::ref_publication::acquire(
                &pool,
                repo,
                1,
                &["refs/heads/topic".to_string()],
                Instant::now() + Duration::from_secs(3),
            )
            .await
            .unwrap(),
        );
        let coordinator = Coordinator::bind(&op, &actor).unwrap();
        let endpoint = coordinator.endpoint();
        let nonce = hex::decode(coordinator.nonce_hex()).unwrap();
        let handle = coordinator.start(guard.clone(), state.clone(), Instant::now() + Duration::from_secs(3));
        let caller = tokio::task::spawn_blocking({
            let op = op.clone();
            let nonce = nonce.clone();
            move || request_grant(&op, endpoint, &nonce, Duration::from_secs(3))
        });
        caller.await.unwrap().unwrap();
        assert!(handle.granted());
        let verifier = tokio::task::spawn_blocking({
            let op = op.clone();
            let nonce = nonce.clone();
            move || request_grant(&op, endpoint, &nonce, Duration::from_secs(3))
        });
        verifier.await.unwrap().unwrap();
        let blocked: bool = pool.get().await.unwrap().query_one(LOCK_TEST, &[&repo]).await.unwrap().get(0);
        assert!(!blocked, "hook ACK escaped without a parent-owned PostgreSQL publication lock");
        handle.close().await;
        let stale = tokio::task::spawn_blocking({
            let op = op.clone();
            let nonce = nonce.clone();
            move || request_grant(&op, endpoint, &nonce, Duration::from_secs(1))
        });
        assert!(stale.await.unwrap().is_err(), "stale grant marker authorized native CAS");
        drop(guard);
        drop(active);
        drop(state);
        drop(pool);
        admin.get().await.unwrap().batch_execute(&format!("DROP SCHEMA {schema} CASCADE")).await.unwrap();
    }

    const LOCK_TEST: &str =
        "SELECT pg_try_advisory_xact_lock(hashtextextended('rootyard-publication-v1:' || $1::uuid::text, 0))";
}
