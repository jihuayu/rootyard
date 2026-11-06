//! A receive hook requests the parent-owned publication window. The hook exits
//! before Git commits refs, so the parent retains both gates until Git stops.
use crate::{AppState,journal, storage::ref_publication::PublicationGuard};
use anyhow::{Context, Result, ensure};
use rand::RngCore;
use std::{io::{Read,Write}, net::{SocketAddr,TcpStream}, sync::Arc, time::Duration};
use tokio::{io::{AsyncReadExt,AsyncWriteExt}, net::TcpListener, sync::{oneshot,watch}, task::JoinHandle, time::Instant};

pub(super) struct Coordinator {
    listener: TcpListener,
    nonce: [u8;32],
    op: journal::Operation,
}

pub(super) struct Handle {
    task: JoinHandle<()>,
    stop: Option<oneshot::Sender<()>>,
    granted: watch::Receiver<bool>,
}

impl Coordinator {
    pub fn bind(op: &journal::Operation) -> Result<Self> {
        ensure!(op.requires_parent_publication, "operation does not require parent publication");
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let listener = TcpListener::from_std(listener)?;
        let mut nonce = [0u8;32];
        rand::rng().fill_bytes(&mut nonce);
        Ok(Self { listener, nonce, op: op.clone() })
    }

    pub fn endpoint(&self) -> SocketAddr { self.listener.local_addr().expect("bound listener") }
    pub fn nonce_hex(&self) -> String { hex::encode(self.nonce) }

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
                    if !addr.ip().is_loopback() { continue; }
                    let mut attempt = [0u8;32];
                    if tokio::time::timeout(Duration::from_secs(1),peer.read_exact(&mut attempt)).await
                        .ok().and_then(std::result::Result::ok).is_none() || attempt != self.nonce { continue; }
                    let window = guard.enter_window(&state.storage,deadline).await
                        .map_err(|e| anyhow::anyhow!(e.1))?;
                    journal::atomic(&self.op.path.join("publication.grant"), &self.nonce, false)?;
                    peer.write_all(b"1").await?;
                    granted_send.send_replace(true);
                    // The guard remains owned until child quiescence and
                    // journal settlement, even though this hook has exited.
                    let _ = stop_recv.await;
                    window.ensure_active().map_err(|e| anyhow::anyhow!(e.1))?;
                    return Ok(());
                }
            }.await;
            if let Err(error) = outcome { eprintln!("rootyard: publication coordination failed: {error:#}"); }
        });
        Handle { task, stop: Some(stop_send), granted }
    }
}

impl Handle {
    pub fn granted(&self) -> bool { *self.granted.borrow() && !self.task.is_finished() }
    pub async fn close(mut self) {
        if let Some(send) = self.stop.take() { let _ = send.send(()); }
        let _ = (&mut self.task).await;
    }
}
impl Drop for Handle {
    fn drop(&mut self) { self.task.abort(); }
}

/// Hook failure is a push refusal if the parent is absent or its window was
/// not granted. The nonce is supplied only in the sanitized child environment.
pub fn await_grant(op: &journal::Operation) -> Result<()> {
    if !op.requires_parent_publication { return Ok(()); }
    let address: SocketAddr = std::env::var("ROOTYARD_PUBLICATION_ENDPOINT")?.parse()?;
    ensure!(address.ip().is_loopback(), "non-loopback publication parent");
    let nonce = hex::decode(std::env::var("ROOTYARD_PUBLICATION_NONCE")?)?;
    ensure!(nonce.len()==32,"invalid parent publication nonce");
    let timeout = std::env::var("ROOTYARD_GIT_TIMEOUT_SECONDS").ok()
        .and_then(|value| value.parse().ok()).map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(120));
    request_grant(op,address,&nonce,timeout)
}

fn request_grant(op:&journal::Operation,address:SocketAddr,nonce:&[u8],timeout:Duration)->Result<()> {
    let mut peer = TcpStream::connect_timeout(&address,timeout)?;
    peer.set_read_timeout(Some(timeout))?;
    peer.set_write_timeout(Some(timeout))?;
    peer.write_all(&nonce)?;
    let mut ack = [0u8];
    peer.read_exact(&mut ack)?;
    ensure!(ack==[b'1'],"parent did not grant publication window");
    ensure!(journal::read(&op.path.join("publication.grant"))? == nonce,
        "parent publication marker differs from grant");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::Config,db,dispatch,metrics,storage::Storage};
    use uuid::Uuid;

    #[tokio::test]
    async fn native_hook_handshake_owns_cross_process_publication_window() {
        let Ok(base_url) = std::env::var("ROOTYARD_TEST_DATABASE_URL") else { return; };
        let admin = db::pool(&base_url).unwrap();
        let schema = format!("hook_window_{}",Uuid::new_v4().simple());
        admin.get().await.unwrap().batch_execute(&format!("CREATE SCHEMA {schema}")).await.unwrap();
        let mut url = reqwest::Url::parse(&base_url).unwrap();
        url.query_pairs_mut().append_pair("options",&format!("-csearch_path={schema}"));
        let pool = db::pool(url.as_str()).unwrap();
        pool.get().await.unwrap().batch_execute("CREATE TABLE repositories(id uuid PRIMARY KEY,storage_generation bigint NOT NULL,state text NOT NULL)").await.unwrap();
        let repo = Uuid::new_v4();
        pool.get().await.unwrap().execute("INSERT INTO repositories VALUES($1,1,'ready')",&[&repo]).await.unwrap();
        let temp = tempfile::tempdir().unwrap();
        let config = Config { database_url:url.to_string(),data_dir:temp.path().join("data"),
            bind:"127.0.0.1:0".parse().unwrap(),git:"/usr/bin/git".into(),
            max_request_bytes:1024,max_output_bytes:1024,max_concurrent_git:1,
            git_timeout:Duration::from_secs(5),git_memory_bytes:1024*1024,
            max_repo_bytes:1024*1024,max_pending_deliveries:100,outbox_worker:false,
            metrics_bind:None };
        let storage = Storage::open(&config).unwrap();
        let state = Arc::new(AppState { mirror_primary:None,dispatch:dispatch::Signals::default(),
            config,pool:pool.clone(),storage,hooks:None,
            transfer_metrics:Arc::new(metrics::TransferCounters::default()),
            git_slots:Arc::new(tokio::sync::Semaphore::new(1)) });
        let (op,active) = journal::begin_active(&state.storage.root,repo,Uuid::new_v4(),
            "alice".into(),Uuid::new_v4(),1).unwrap();
        let guard = Arc::new(crate::storage::ref_publication::acquire(&pool,repo,1,
            &["refs/heads/topic".to_string()],Instant::now()+Duration::from_secs(3)).await.unwrap());
        let coordinator = Coordinator::bind(&op).unwrap();
        let endpoint = coordinator.endpoint();
        let nonce = hex::decode(coordinator.nonce_hex()).unwrap();
        let handle = coordinator.start(guard.clone(),state.clone(),Instant::now()+Duration::from_secs(3));
        let caller = tokio::task::spawn_blocking({let op=op.clone();move ||
            request_grant(&op,endpoint,&nonce,Duration::from_secs(3))});
        caller.await.unwrap().unwrap();
        assert!(handle.granted());
        let blocked: bool = pool.get().await.unwrap().query_one(LOCK_TEST,&[&repo]).await.unwrap().get(0);
        assert!(!blocked,"hook ACK escaped without a parent-owned PostgreSQL publication lock");
        handle.close().await;
        drop(guard);
        drop(active);
        drop(state);
        drop(pool);
        admin.get().await.unwrap().batch_execute(&format!("DROP SCHEMA {schema} CASCADE")).await.unwrap();
    }

    const LOCK_TEST:&str="SELECT pg_try_advisory_xact_lock(hashtextextended('rootyard-publication-v1:' || $1::uuid::text, 0))";
}

pub fn verify_grant(op: &journal::Operation) -> Result<()> {
    if !op.requires_parent_publication { return Ok(()); }
    let expected = hex::decode(std::env::var("ROOTYARD_PUBLICATION_NONCE")?)?;
    ensure!(expected.len()==32 && journal::read(&op.path.join("publication.grant"))? == expected,
        "parent publication window was not granted");
    Ok(())
}
