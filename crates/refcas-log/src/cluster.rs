//! Length-framed mTLS JSON Raft peer transport and control RPC client for multi-process clusters.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use openraft::error::{InstallSnapshotError, RPCError, RaftError, Unreachable};
use openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse, VoteRequest,
    VoteResponse,
};
use openraft::{BasicNode, LogId, Vote};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream as ClientTlsStream;

use crate::fault::FaultSpec;
use crate::mtls::{MtlsClient, node_dns_name};
use crate::state_machine::StateMachineSummary;
use crate::{E, LogTypeConfig, Res};

const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
const CLIENT_RPC_TIMEOUT: Duration = Duration::from_secs(10);

/// Sub-store selector for RPC fault injection in multi-process cluster tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum FaultTarget {
    Log,
    StateMachine,
}

/// Wire request accepted by `raft-node` over mTLS length-framed JSON.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum RpcRequest {
    Vote(VoteRequest<u64>),
    AppendEntries(AppendEntriesRequest<LogTypeConfig>),
    InstallSnapshot(InstallSnapshotRequest<LogTypeConfig>),
    UpdatePeers { peers: BTreeMap<u64, String> },
    PartitionPeers { blocked: BTreeSet<u64> },
    Bootstrap { members: BTreeMap<u64, String> },
    AddLearner { node_id: u64, addr: String, blocking: bool },
    ChangeMembership { members: BTreeSet<u64>, retain: bool },
    ClientWrite { payload: Vec<u8> },
    TriggerSnapshot,
    TriggerPurge { upto: u64 },
    Metrics,
    KvGet { key: String },
    EnsureReadIndex,
    InspectReplicaKv { key: String },
    InjectFault { target: FaultTarget, spec: FaultSpec },
    ClearFaults,
    Shutdown,
}

/// Runtime metrics and durable state summary snapshot returned by `RpcRequest::Metrics`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsReport {
    pub node_id: u64,
    pub running_ok: bool,
    pub fatal_error: Option<String>,
    pub current_term: u64,
    pub current_leader: Option<u64>,
    pub last_log_index: Option<u64>,
    pub last_applied: Option<LogId<u64>>,
    pub snapshot: Option<LogId<u64>>,
    pub purged: Option<LogId<u64>>,
    pub membership_voters: Vec<u64>,
    pub persisted_vote: Option<Vote<u64>>,
    pub sm_summary: StateMachineSummary,
}

/// Wire response returned by `raft-node`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum RpcResponse {
    Vote(Box<Result<VoteResponse<u64>, RaftError<u64>>>),
    AppendEntries(Box<Result<AppendEntriesResponse<u64>, RaftError<u64>>>),
    InstallSnapshot(Box<Result<InstallSnapshotResponse<u64>, RaftError<u64, InstallSnapshotError>>>),
    Ok,
    ClientWrite { log_index: u64 },
    Metrics(Box<MetricsReport>),
    KvValue { value: Option<String>, read_log_id: Option<LogId<u64>> },
    ReadIndex { read_log_id: Option<LogId<u64>>, applied_count: u64, state_digest_hex: String },
    Error { message: String, forward_to_leader_id: Option<u64> },
}

#[derive(Default)]
struct PeerState {
    addrs: BTreeMap<u64, String>,
    blocked: BTreeSet<u64>,
}

/// Shared mutable node-id -> TCP address directory and partition blocklist updated when peers respawn.
#[derive(Clone, Default)]
pub struct PeerDirectory {
    inner: Arc<RwLock<PeerState>>,
}

impl PeerDirectory {
    /// Creates an empty peer directory.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces known peer addresses while preserving any active partition filters.
    pub fn update(&self, peers: BTreeMap<u64, String>) {
        let mut guard = self.inner.write().expect("peer directory poisoned");
        guard.addrs = peers;
    }

    /// Upserts a single peer's address.
    pub fn insert(&self, id: u64, addr: String) {
        let mut guard = self.inner.write().expect("peer directory poisoned");
        guard.addrs.insert(id, addr);
    }

    /// Looks up the latest address for `id`.
    pub fn get(&self, id: u64) -> Option<String> {
        self.inner.read().expect("peer directory poisoned").addrs.get(&id).cloned()
    }

    /// Returns a point-in-time copy of all registered peer addresses.
    pub fn snapshot_addrs(&self) -> BTreeMap<u64, String> {
        self.inner.read().expect("peer directory poisoned").addrs.clone()
    }

    /// Updates the set of peer node ids blocked by simulated network partition.
    pub fn set_blocked(&self, blocked: BTreeSet<u64>) {
        self.inner.write().expect("peer directory poisoned").blocked = blocked;
    }

    /// Returns true if traffic to/from peer `id` is currently severed by a partition rule.
    pub fn is_blocked(&self, id: u64) -> bool {
        self.inner.read().expect("peer directory poisoned").blocked.contains(&id)
    }
}

/// `RaftNetworkFactory` opening mTLS length-framed JSON connections per target peer.
#[derive(Clone)]
pub struct MtlsNetworkFactory {
    peers: PeerDirectory,
    client: MtlsClient,
}

impl MtlsNetworkFactory {
    /// Builds an mTLS network factory backed by `peers` and node certificate identity `client`.
    pub fn new(peers: PeerDirectory, client: MtlsClient) -> Self {
        Self { peers, client }
    }
}

impl RaftNetworkFactory<LogTypeConfig> for MtlsNetworkFactory {
    type Network = MtlsPeerClient;

    async fn new_client(&mut self, target: u64, node: &BasicNode) -> Self::Network {
        MtlsPeerClient {
            target,
            fallback_addr: node.addr.clone(),
            peers: self.peers.clone(),
            client: self.client.clone(),
            stream: None,
        }
    }
}

/// Persistent per-target mTLS Raft RPC client implementing `RaftNetwork`.
pub struct MtlsPeerClient {
    target: u64,
    fallback_addr: String,
    peers: PeerDirectory,
    client: MtlsClient,
    stream: Option<ClientTlsStream<TcpStream>>,
}

impl MtlsPeerClient {
    async fn call_raft(&mut self, req: RpcRequest, timeout: Duration) -> io::Result<RpcResponse> {
        if self.peers.is_blocked(self.target) {
            self.stream = None;
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("peer {} isolated by network partition", self.target),
            ));
        }
        let addr = self.peers.get(self.target).unwrap_or_else(|| self.fallback_addr.clone());
        let deadline_fut = async {
            if let Some(mut cached) = self.stream.take() {
                match roundtrip_async(&mut cached, &req).await {
                    Ok(resp) => {
                        self.stream = Some(cached);
                        return Ok(resp);
                    }
                    Err(_) => {
                        // `cached` is dropped here; the existing single fresh-connection
                        // fallback below is preserved without an extra retry.
                    }
                }
            }
            let mut fresh = self.client.connect_peer(&addr, self.target).await?;
            let resp = roundtrip_async(&mut fresh, &req).await?;
            self.stream = Some(fresh);
            Ok(resp)
        };
        match tokio::time::timeout(timeout, deadline_fut).await {
            Ok(res) => res,
            Err(_) => {
                self.stream = None;
                Err(io::Error::new(io::ErrorKind::TimedOut, format!("mTLS Raft RPC to node {} timed out", self.target)))
            }
        }
    }
}

impl RaftNetwork<LogTypeConfig> for MtlsPeerClient {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<LogTypeConfig>,
        option: RPCOption,
    ) -> Result<AppendEntriesResponse<u64>, RPCError<u64, BasicNode, RaftError<u64>>> {
        let timeout = option.hard_ttl().max(Duration::from_millis(50));
        match self.call_raft(RpcRequest::AppendEntries(rpc), timeout).await {
            Ok(RpcResponse::AppendEntries(boxed)) => match *boxed {
                Ok(ok) => Ok(ok),
                Err(err) => Err(RPCError::RemoteError(openraft::error::RemoteError::new(self.target, err))),
            },
            Ok(other) => Err(RPCError::Unreachable(Unreachable::new(&io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected AppendEntries response: {other:?}"),
            )))),
            Err(e) => Err(RPCError::Unreachable(Unreachable::new(&e))),
        }
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<LogTypeConfig>,
        option: RPCOption,
    ) -> Result<InstallSnapshotResponse<u64>, RPCError<u64, BasicNode, RaftError<u64, InstallSnapshotError>>> {
        let timeout = option.hard_ttl().max(Duration::from_secs(2));
        match self.call_raft(RpcRequest::InstallSnapshot(rpc), timeout).await {
            Ok(RpcResponse::InstallSnapshot(boxed)) => match *boxed {
                Ok(ok) => Ok(ok),
                Err(err) => Err(RPCError::RemoteError(openraft::error::RemoteError::new(self.target, err))),
            },
            Ok(other) => Err(RPCError::Unreachable(Unreachable::new(&io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected InstallSnapshot response: {other:?}"),
            )))),
            Err(e) => Err(RPCError::Unreachable(Unreachable::new(&e))),
        }
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<u64>,
        option: RPCOption,
    ) -> Result<VoteResponse<u64>, RPCError<u64, BasicNode, RaftError<u64>>> {
        let timeout = option.hard_ttl().max(Duration::from_millis(50));
        match self.call_raft(RpcRequest::Vote(rpc), timeout).await {
            Ok(RpcResponse::Vote(boxed)) => match *boxed {
                Ok(ok) => Ok(ok),
                Err(err) => Err(RPCError::RemoteError(openraft::error::RemoteError::new(self.target, err))),
            },
            Ok(other) => Err(RPCError::Unreachable(Unreachable::new(&io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected Vote response: {other:?}"),
            )))),
            Err(e) => Err(RPCError::Unreachable(Unreachable::new(&e))),
        }
    }
}

/// Sends one async control/client RPC over a verified mTLS connection to `addr` (`raft-node-{node_id}.refcas.internal`).
pub async fn send_rpc_async(
    client: &MtlsClient,
    addr: &str,
    target_node_id: u64,
    req: &RpcRequest,
) -> Res<RpcResponse> {
    let dns = node_dns_name(target_node_id);
    send_rpc_named_async(client, addr, &dns, req).await
}

/// Sends one async control/client RPC over mTLS verifying server SAN `expected_dns`.
pub async fn send_rpc_named_async(
    client: &MtlsClient,
    addr: &str,
    expected_dns: &str,
    req: &RpcRequest,
) -> Res<RpcResponse> {
    let fut = async {
        let mut tls = client.connect_named(addr, expected_dns).await?;
        let resp = roundtrip_async(&mut tls, req).await?;
        let _ = tls.shutdown().await;
        Ok::<_, io::Error>(resp)
    };
    tokio::time::timeout(CLIENT_RPC_TIMEOUT, fut)
        .await
        .map_err(|_| E::Io(io::Error::new(io::ErrorKind::TimedOut, format!("mTLS RPC to {addr} timed out"))))?
        .map_err(E::Io)
}

/// Synchronous wrapper around `send_rpc_async` for non-async multi-process cluster test harnesses.
pub fn send_rpc(client: &MtlsClient, addr: &str, target_node_id: u64, req: &RpcRequest) -> Res<RpcResponse> {
    if tokio::runtime::Handle::try_current().is_ok() {
        return Err(E::Refused("blocking send_rpc called from inside a Tokio runtime; use send_rpc_async".into()));
    }
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    let rt = RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("build refcas cluster client runtime")
    });
    rt.block_on(send_rpc_async(client, addr, target_node_id, req))
}

async fn roundtrip_async<S>(stream: &mut S, req: &RpcRequest) -> io::Result<RpcResponse>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_frame_async(stream, req).await?;
    read_frame_async(stream)
        .await?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "peer closed mTLS connection before response"))
}

/// Writes a length-prefixed JSON frame (`<= max_bytes`) asynchronously and flushes the stream.
pub async fn write_frame_bounded_async<S, T>(stream: &mut S, value: &T, max_bytes: usize) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
    T: Serialize,
{
    let payload = serde_json::to_vec(value).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if payload.len() > max_bytes || payload.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("frame length {} exceeds cap {max_bytes}", payload.len()),
        ));
    }
    let len = (payload.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(&payload).await?;
    stream.flush().await?;
    Ok(())
}

/// Reads a length-prefixed JSON frame (`<= max_bytes`); returns `Ok(None)` only on clean zero-byte EOF.
pub async fn read_frame_bounded_async<S, T>(stream: &mut S, max_bytes: usize) -> io::Result<Option<T>>
where
    S: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let cap = max_bytes.min(MAX_FRAME_BYTES);
    let mut len_buf = [0u8; 4];
    let first = stream.read(&mut len_buf[..1]).await?;
    if first == 0 {
        return Ok(None);
    }
    stream.read_exact(&mut len_buf[1..]).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > cap {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("invalid RPC frame length {len} (cap {cap})")));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    let value = serde_json::from_slice(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(Some(value))
}

/// Writes a length-prefixed JSON frame (`<= 16 MiB`) asynchronously and flushes the stream.
pub async fn write_frame_async<S, T>(stream: &mut S, value: &T) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
    T: Serialize,
{
    write_frame_bounded_async(stream, value, MAX_FRAME_BYTES).await
}

/// Reads a length-prefixed JSON frame asynchronously; returns `Ok(None)` only on clean zero-byte EOF.
pub async fn read_frame_async<S, T>(stream: &mut S) -> io::Result<Option<T>>
where
    S: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    read_frame_bounded_async(stream, MAX_FRAME_BYTES).await
}

/// Expects `RpcResponse::Ok`, turning any error variant into `E::Refused`.
pub fn rpc_expect_ok(resp: RpcResponse) -> Res<()> {
    match resp {
        RpcResponse::Ok => Ok(()),
        RpcResponse::Error { message, .. } => Err(E::Refused(message)),
        other => Err(E::Refused(format!("unexpected RPC response: {other:?}"))),
    }
}

#[cfg(test)]
mod cancellation_tests;
