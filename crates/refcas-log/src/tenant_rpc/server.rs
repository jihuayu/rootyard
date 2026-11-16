//! Authoritative tenant-scoped mTLS Raft RPC server with ReadIndex, leader redirect, and bounded streaming.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use openraft::Raft;
use openraft::error::{CheckIsLeaderError, ClientWriteError, RaftError};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use tokio_rustls::server::TlsStream;

use crate::cluster::{PeerDirectory, read_frame_bounded_async, write_frame_bounded_async};
use crate::mtls::{MtlsServer, TenantCertScope};
use crate::state_machine::PersistentStateMachine;
use crate::streaming::{
    BufferedByteTracker, StreamConfig, StreamPlan, TrackedChunk, serve_bounded_stream, validate_raft_proposal_payload,
};
use crate::tenant_rpc::realm::GroupRealmRegistry;
use crate::tenant_rpc::types::{
    LeaderRedirect, MAX_TENANT_RPC_FRAME_BYTES, RealmEpoch, TenantOp, TenantRpcError, TenantRpcErrorCode,
    TenantRpcRequest, TenantRpcResponse,
};
use crate::{LogTypeConfig, MAX_ENTRY_BYTES};

/// Configuration binding one replica's tenant mTLS listener to its Raft peer directory and realm table.
#[derive(Clone)]
pub struct TenantServerConfig {
    pub node_id: u64,
    pub mtls: MtlsServer,
    pub tenant_peers: PeerDirectory,
    pub registry: Arc<RwLock<GroupRealmRegistry>>,
    pub quorum_timeout: Duration,
    pub write_timeout: Duration,
}

struct StreamRequestArgs<'a> {
    prefix: &'a str,
    planned_chunks: u32,
    chunk_bytes: usize,
    stream_config: StreamConfig,
}

/// Shared handle exposing telemetry and lifecycle shutdown for one node's tenant mTLS RPC listener.
#[derive(Clone)]
pub struct TenantRpcServer {
    node_id: u64,
    addr: String,
    raft: Raft<LogTypeConfig>,
    sm: PersistentStateMachine,
    tenant_peers: PeerDirectory,
    registry: Arc<RwLock<GroupRealmRegistry>>,
    quorum_timeout: Duration,
    write_timeout: Duration,
    stream_seq: AtomicU64Wrapper,
    last_tracker: Arc<RwLock<Option<Arc<BufferedByteTracker>>>>,
    shutdown_tx: watch::Sender<bool>,
}

type AtomicU64Wrapper = Arc<AtomicU64>;

impl TenantRpcServer {
    /// Binds an mTLS tenant-RPC TCP listener backed by `raft` and `sm` and starts serving connections.
    pub async fn spawn(
        raft: Raft<LogTypeConfig>,
        sm: PersistentStateMachine,
        cfg: TenantServerConfig,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?.to_string();
        cfg.tenant_peers.insert(cfg.node_id, addr.clone());
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let mtls = cfg.mtls;
        let handle = Self {
            node_id: cfg.node_id,
            addr,
            raft,
            sm,
            tenant_peers: cfg.tenant_peers,
            registry: cfg.registry,
            quorum_timeout: cfg.quorum_timeout,
            write_timeout: cfg.write_timeout,
            stream_seq: Arc::new(AtomicU64::new(1)),
            last_tracker: Arc::new(RwLock::new(None)),
            shutdown_tx,
        };
        let accept_handle = handle.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    accepted = listener.accept() => {
                        let Ok((tcp, _)) = accepted else { break };
                        let srv = accept_handle.clone();
                        let tls = mtls.clone();
                        tokio::spawn(async move { srv.serve_conn(tls, tcp).await; });
                    }
                }
            }
        });
        Ok(handle)
    }

    pub fn node_id(&self) -> u64 {
        self.node_id
    }

    pub fn addr(&self) -> &str {
        &self.addr
    }

    pub fn last_stream_tracker(&self) -> Option<Arc<BufferedByteTracker>> {
        self.last_tracker.read().expect("tracker lock poisoned").clone()
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    async fn serve_conn(self, mtls: MtlsServer, tcp: tokio::net::TcpStream) {
        let Ok((mut tls, cert_scope)) = mtls.accept_tenant(tcp).await else {
            return;
        };
        while let Ok(Some(req)) =
            read_frame_bounded_async::<_, TenantRpcRequest>(&mut tls, MAX_TENANT_RPC_FRAME_BYTES).await
        {
            if self.dispatch_one(&mut tls, &cert_scope, req).await {
                break;
            }
        }
    }

    async fn dispatch_one(
        &self,
        tls: &mut TlsStream<tokio::net::TcpStream>,
        cert_scope: &TenantCertScope,
        req: TenantRpcRequest,
    ) -> bool {
        let verified = { self.registry.read().expect("realm lock poisoned").verify_request(cert_scope, &req) };
        let auth = match verified {
            Ok(a) => a,
            Err(err) => {
                let _ =
                    write_frame_bounded_async(tls, &TenantRpcResponse::Error(err), MAX_TENANT_RPC_FRAME_BYTES).await;
                return false;
            }
        };

        let term = self.raft.metrics().borrow().current_term;
        match req.op {
            TenantOp::ReadIndex => {
                let resp = self.handle_read_index(term, auth.storage_generation).await;
                write_frame_bounded_async(tls, &resp, MAX_TENANT_RPC_FRAME_BYTES).await.is_err()
            }
            TenantOp::LinearizableGet { key } => {
                let resp = self.handle_linearizable_get(&key, term, auth.storage_generation).await;
                write_frame_bounded_async(tls, &resp, MAX_TENANT_RPC_FRAME_BYTES).await.is_err()
            }
            TenantOp::ProposeKv { command } => {
                let payload = match command.validate_bounds().and_then(|()| command.encode()) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        let resp = TenantRpcResponse::Error(TenantRpcError::new(
                            TenantRpcErrorCode::PayloadTooLarge,
                            e.to_string(),
                        ));
                        return write_frame_bounded_async(tls, &resp, MAX_TENANT_RPC_FRAME_BYTES).await.is_err();
                    }
                };
                let resp = self.handle_propose(payload, term, auth.storage_generation).await;
                write_frame_bounded_async(tls, &resp, MAX_TENANT_RPC_FRAME_BYTES).await.is_err()
            }
            TenantOp::ProposeRaw { payload } => {
                if let Err(e) = validate_raft_proposal_payload(&payload) {
                    let resp = TenantRpcResponse::Error(TenantRpcError::new(
                        TenantRpcErrorCode::PayloadTooLarge,
                        e.to_string(),
                    ));
                    return write_frame_bounded_async(tls, &resp, MAX_TENANT_RPC_FRAME_BYTES).await.is_err();
                }
                let resp = self.handle_propose(payload, term, auth.storage_generation).await;
                write_frame_bounded_async(tls, &resp, MAX_TENANT_RPC_FRAME_BYTES).await.is_err()
            }
            TenantOp::StreamCompute { prefix, planned_chunks, chunk_bytes, stream_config } => {
                let args = StreamRequestArgs { prefix: &prefix, planned_chunks, chunk_bytes, stream_config };
                self.handle_stream_compute(tls, args, &auth, term).await
            }
        }
    }

    async fn read_barrier(&self, raft_term: u64) -> Result<Option<openraft::LogId<u64>>, TenantRpcResponse> {
        let barrier = tokio::time::timeout(self.quorum_timeout, self.raft.ensure_linearizable()).await;
        let read_log_id = match barrier {
            Ok(Ok(id)) => id,
            Ok(Err(RaftError::APIError(CheckIsLeaderError::ForwardToLeader(fwd)))) => {
                return Err(self.redirect_or_unavailable(fwd.leader_id, raft_term, "follower cannot serve ReadIndex"));
            }
            Ok(Err(e)) => {
                return Err(TenantRpcResponse::Error(TenantRpcError::new(
                    TenantRpcErrorCode::QuorumUnavailable,
                    format!("ReadIndex barrier failed: {e}"),
                )));
            }
            Err(_) => {
                return Err(TenantRpcResponse::Error(TenantRpcError::new(
                    TenantRpcErrorCode::QuorumUnavailable,
                    "ReadIndex quorum barrier timed out (no PG/Redis fallback)",
                )));
            }
        };
        let summary =
            self.sm.summary().await.map_err(|e| {
                TenantRpcResponse::Error(TenantRpcError::new(TenantRpcErrorCode::Internal, e.to_string()))
            })?;
        if read_log_id.is_some_and(|req| summary.last_applied.is_none_or(|applied| applied.index < req.index)) {
            return Err(TenantRpcResponse::Error(TenantRpcError::new(
                TenantRpcErrorCode::QuorumUnavailable,
                format!("state machine {:?} behind ReadIndex barrier {:?}", summary.last_applied, read_log_id),
            )));
        }
        Ok(read_log_id)
    }

    async fn handle_read_index(&self, raft_term: u64, storage_generation: u64) -> TenantRpcResponse {
        let read_log_id = match self.read_barrier(raft_term).await {
            Ok(id) => id,
            Err(resp) => return resp,
        };
        match self.sm.summary().await {
            Ok(s) => TenantRpcResponse::ReadIndex {
                read_log_id,
                applied_count: s.applied_count,
                state_digest_hex: s.state_digest_hex,
                raft_term,
                storage_generation,
            },
            Err(e) => TenantRpcResponse::Error(TenantRpcError::new(TenantRpcErrorCode::Internal, e.to_string())),
        }
    }

    async fn handle_linearizable_get(&self, key: &str, raft_term: u64, storage_generation: u64) -> TenantRpcResponse {
        let read_log_id = match self.read_barrier(raft_term).await {
            Ok(id) => id,
            Err(resp) => return resp,
        };
        match self.sm.kv_get(key).await {
            Ok(value) => TenantRpcResponse::LinearizableValue { value, read_log_id, raft_term, storage_generation },
            Err(e) => TenantRpcResponse::Error(TenantRpcError::new(TenantRpcErrorCode::Internal, e.to_string())),
        }
    }

    async fn handle_propose(&self, payload: Vec<u8>, raft_term: u64, storage_generation: u64) -> TenantRpcResponse {
        if payload.len() > MAX_ENTRY_BYTES || validate_raft_proposal_payload(&payload).is_err() {
            return TenantRpcResponse::Error(TenantRpcError::new(
                TenantRpcErrorCode::PayloadTooLarge,
                "proposal rejected prior to Raft WAL append",
            ));
        }
        match tokio::time::timeout(self.write_timeout, self.raft.client_write(payload)).await {
            Ok(Ok(res)) => TenantRpcResponse::CommitReceipt {
                log_index: res.log_id.index,
                raft_term: self.raft.metrics().borrow().current_term,
                storage_generation,
            },
            Ok(Err(RaftError::APIError(ClientWriteError::ForwardToLeader(fwd)))) => {
                self.redirect_or_unavailable(fwd.leader_id, raft_term, "follower rejected direct write")
            }
            Ok(Err(e)) => TenantRpcResponse::Error(TenantRpcError::new(
                TenantRpcErrorCode::QuorumUnavailable,
                format!("raft write refused: {e}"),
            )),
            Err(_) => TenantRpcResponse::Error(TenantRpcError::new(
                TenantRpcErrorCode::QuorumUnavailable,
                "raft write timed out awaiting quorum commit",
            )),
        }
    }

    async fn handle_stream_compute(
        &self,
        tls: &mut TlsStream<tokio::net::TcpStream>,
        args: StreamRequestArgs<'_>,
        auth: &RealmEpoch,
        raft_term: u64,
    ) -> bool {
        let StreamRequestArgs { prefix, planned_chunks, chunk_bytes, stream_config } = args;
        if let Err(e) = stream_config.validate() {
            let resp = TenantRpcResponse::Error(TenantRpcError::new(TenantRpcErrorCode::InvalidRequest, e.to_string()));
            return write_frame_bounded_async(tls, &resp, MAX_TENANT_RPC_FRAME_BYTES).await.is_err();
        }
        let Some(total_bytes) = (planned_chunks as u64).checked_mul(chunk_bytes as u64) else {
            let resp = TenantRpcResponse::Error(TenantRpcError::new(
                TenantRpcErrorCode::PayloadTooLarge,
                "stream size overflow",
            ));
            return write_frame_bounded_async(tls, &resp, MAX_TENANT_RPC_FRAME_BYTES).await.is_err();
        };
        if planned_chunks == 0 || chunk_bytes == 0 || chunk_bytes > stream_config.max_frame_bytes {
            let resp = TenantRpcResponse::Error(TenantRpcError::new(
                TenantRpcErrorCode::PayloadTooLarge,
                "invalid or oversized stream chunk configuration",
            ));
            return write_frame_bounded_async(tls, &resp, MAX_TENANT_RPC_FRAME_BYTES).await.is_err();
        }
        if total_bytes > stream_config.max_total_bytes as u64 {
            let resp = TenantRpcResponse::Error(TenantRpcError::new(
                TenantRpcErrorCode::PayloadTooLarge,
                format!("planned stream bytes {total_bytes} exceed cap {}", stream_config.max_total_bytes),
            ));
            return write_frame_bounded_async(tls, &resp, MAX_TENANT_RPC_FRAME_BYTES).await.is_err();
        }

        let read_log_id = match self.read_barrier(raft_term).await {
            Ok(id) => id,
            Err(resp) => return write_frame_bounded_async(tls, &resp, MAX_TENANT_RPC_FRAME_BYTES).await.is_err(),
        };
        let kv_snap = match self.sm.kv_snapshot().await {
            Ok(map) => map,
            Err(e) => {
                let resp = TenantRpcResponse::Error(TenantRpcError::new(TenantRpcErrorCode::Internal, e.to_string()));
                return write_frame_bounded_async(tls, &resp, MAX_TENANT_RPC_FRAME_BYTES).await.is_err();
            }
        };
        let matching_count = kv_snap.keys().filter(|k| k.starts_with(prefix)).count();

        let stream_id = self.stream_seq.fetch_add(1, Ordering::Relaxed);
        let started = TenantRpcResponse::StreamStarted {
            stream_id,
            planned_chunks: planned_chunks as u64,
            planned_bytes: total_bytes,
            read_log_id,
            raft_term,
            storage_generation: auth.storage_generation,
        };
        if write_frame_bounded_async(tls, &started, MAX_TENANT_RPC_FRAME_BYTES).await.is_err() {
            return true;
        }

        let tracker = BufferedByteTracker::new();
        *self.last_tracker.write().expect("tracker lock poisoned") = Some(tracker.clone());
        let (tx, rx) = mpsc::channel(stream_config.channel_capacity);
        let prod_tracker = tracker.clone();
        let seed_prefix = prefix.to_owned();

        let prod_handle = tokio::spawn(async move {
            for seq in 0..planned_chunks {
                if prod_tracker.is_cancelled() {
                    break;
                }
                let Ok(permit) = tx.reserve().await else {
                    break;
                };
                let mut buf = vec![0u8; chunk_bytes];
                let mut h = Sha256::new();
                h.update(seed_prefix.as_bytes());
                h.update(seq.to_be_bytes());
                h.update((matching_count as u64).to_be_bytes());
                let fill: [u8; 32] = h.finalize().into();
                for (i, slot) in buf.iter_mut().enumerate() {
                    *slot = fill[i % 32];
                }
                permit.send(TrackedChunk::new(buf, prod_tracker.clone()));
            }
        });

        let plan =
            StreamPlan { stream_id, read_log_id, planned_chunks: planned_chunks as u64, planned_bytes: total_bytes };
        let outcome = serve_bounded_stream(tls, &plan, &stream_config, tracker, rx).await;
        let _ = prod_handle.await;
        outcome.cancelled
    }

    fn redirect_or_unavailable(&self, leader_id: Option<u64>, raft_term: u64, msg: &str) -> TenantRpcResponse {
        if let Some(lid) = leader_id
            && lid != self.node_id
            && let Some(leader_addr) = self.tenant_peers.get(lid)
        {
            return TenantRpcResponse::LeaderRedirect(LeaderRedirect { leader_id: lid, leader_addr, raft_term });
        }
        let mut fallback = self.raft.metrics().borrow().current_leader;
        if fallback == Some(self.node_id) {
            fallback = None;
        }
        if let Some(lid) = fallback
            && let Some(leader_addr) = self.tenant_peers.get(lid)
        {
            return TenantRpcResponse::LeaderRedirect(LeaderRedirect { leader_id: lid, leader_addr, raft_term });
        }
        TenantRpcResponse::Error(TenantRpcError::new(
            TenantRpcErrorCode::QuorumUnavailable,
            format!("{msg} (no reachable leader / minority node)"),
        ))
    }
}
