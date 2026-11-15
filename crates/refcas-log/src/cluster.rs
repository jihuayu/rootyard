//! Length-framed TCP JSON Raft transport and control RPC client for multi-process clusters.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use openraft::error::{InstallSnapshotError, RPCError, RaftError, RemoteError, Unreachable};
use openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse, VoteRequest,
    VoteResponse,
};
use openraft::{BasicNode, LogId, Vote};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::fault::FaultSpec;
use crate::state_machine::StateMachineSummary;
use crate::{E, LogTypeConfig, Res};

/// Maximum TCP JSON RPC frame size (16 MiB).
pub const MAX_RPC_FRAME_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(5);

/// Target store for dynamic fault injection in multi-process probes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum FaultTarget {
    Log,
    StateMachine,
    Both,
}

/// Wire request accepted by `raft-node` over TCP JSON framing.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum RpcRequest {
    Vote(VoteRequest<u64>),
    AppendEntries(AppendEntriesRequest<LogTypeConfig>),
    InstallSnapshot(InstallSnapshotRequest<LogTypeConfig>),
    UpdatePeers { peers: BTreeMap<u64, String> },
    Bootstrap { members: BTreeMap<u64, String> },
    AddLearner { node_id: u64, addr: String, blocking: bool },
    ChangeMembership { members: BTreeSet<u64>, retain: bool },
    ClientWrite { payload: Vec<u8> },
    TriggerSnapshot,
    TriggerPurge { upto: u64 },
    Metrics,
    KvGet { key: String },
    InjectFault { target: FaultTarget, spec: FaultSpec },
    ClearFaults,
    Shutdown,
}

/// Structured node health, replication, and state-machine metrics returned by `Metrics`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsReport {
    pub node_id: u64,
    pub running_ok: bool,
    pub fatal_error: Option<String>,
    pub current_leader: Option<u64>,
    pub current_term: u64,
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
    KvValue { value: Option<String> },
    Error { message: String, forward_to_leader_id: Option<u64> },
}

/// Shared mutable node-id -> `host:port` directory used across process restarts.
#[derive(Clone, Default)]
pub struct PeerDirectory {
    peers: Arc<RwLock<BTreeMap<u64, String>>>,
}

impl PeerDirectory {
    /// Creates an empty peer directory.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the tracked peer address map atomically.
    pub fn set_all(&self, peers: BTreeMap<u64, String>) {
        let mut guard = self.peers.write().expect("peer directory poisoned");
        *guard = peers;
    }

    /// Inserts or updates one peer's address.
    pub fn upsert(&self, node_id: u64, addr: String) {
        let mut guard = self.peers.write().expect("peer directory poisoned");
        guard.insert(node_id, addr);
    }

    /// Resolves `node_id` using the override table first, falling back to `default_addr`.
    pub fn resolve(&self, node_id: u64, default_addr: &str) -> String {
        let guard = self.peers.read().expect("peer directory poisoned");
        guard.get(&node_id).cloned().unwrap_or_else(|| default_addr.to_owned())
    }
}

/// `RaftNetworkFactory` backed by blocking `TcpStream` JSON RPCs on Tokio's blocking pool.
#[derive(Clone)]
pub struct TcpJsonNetworkFactory {
    peers: PeerDirectory,
}

impl TcpJsonNetworkFactory {
    /// Builds a factory resolving peer addresses through `peers`.
    pub fn new(peers: PeerDirectory) -> Self {
        Self { peers }
    }
}

impl RaftNetworkFactory<LogTypeConfig> for TcpJsonNetworkFactory {
    type Network = TcpPeerClient;

    async fn new_client(&mut self, target: u64, node: &BasicNode) -> Self::Network {
        TcpPeerClient { target, node: node.clone(), peers: self.peers.clone(), cached: None }
    }
}

/// Persistent connection client for one peer target.
pub struct TcpPeerClient {
    target: u64,
    node: BasicNode,
    peers: PeerDirectory,
    cached: Option<(String, TcpStream)>,
}

impl TcpPeerClient {
    fn send_blocking(&mut self, req: RpcRequest, timeout: Duration) -> io::Result<RpcResponse> {
        let addr = self.peers.resolve(self.target, &self.node.addr);
        if let Some((cached_addr, stream)) = self.cached.as_mut() {
            if cached_addr == &addr {
                let _ = stream.set_read_timeout(Some(timeout));
                let _ = stream.set_write_timeout(Some(timeout));
                if let Ok(resp) = roundtrip_on_stream(stream, &req) {
                    return Ok(resp);
                }
            }
            self.cached = None;
        }
        let mut stream = connect_stream(&addr, timeout)?;
        let resp = roundtrip_on_stream(&mut stream, &req)?;
        self.cached = Some((addr, stream));
        Ok(resp)
    }

    async fn call_raft(&mut self, req: RpcRequest, timeout: Duration) -> io::Result<RpcResponse> {
        let target = self.target;
        let node = self.node.clone();
        let peers = self.peers.clone();
        let cached = self.cached.take();
        let (res, next_cached) = tokio::task::spawn_blocking(move || {
            let mut client = TcpPeerClient { target, node, peers, cached };
            let out = client.send_blocking(req, timeout);
            (out, client.cached)
        })
        .await
        .map_err(|e| io::Error::other(format!("rpc join: {e}")))?;
        self.cached = next_cached;
        res
    }
}

impl RaftNetwork<LogTypeConfig> for TcpPeerClient {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<LogTypeConfig>,
        option: RPCOption,
    ) -> Result<AppendEntriesResponse<u64>, RPCError<u64, BasicNode, RaftError<u64>>> {
        let timeout = option.hard_ttl().max(Duration::from_millis(1_500));
        let resp = self
            .call_raft(RpcRequest::AppendEntries(rpc), timeout)
            .await
            .map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))?;
        match resp {
            RpcResponse::AppendEntries(boxed) => match *boxed {
                Ok(r) => Ok(r),
                Err(e) => Err(RPCError::RemoteError(RemoteError::new_with_node(self.target, self.node.clone(), e))),
            },
            other => Err(RPCError::Unreachable(Unreachable::new(&io::Error::other(format!(
                "unexpected response to AppendEntries: {other:?}"
            ))))),
        }
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<LogTypeConfig>,
        option: RPCOption,
    ) -> Result<InstallSnapshotResponse<u64>, RPCError<u64, BasicNode, RaftError<u64, InstallSnapshotError>>> {
        let timeout = option.hard_ttl().max(Duration::from_secs(5));
        let resp = self
            .call_raft(RpcRequest::InstallSnapshot(rpc), timeout)
            .await
            .map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))?;
        match resp {
            RpcResponse::InstallSnapshot(boxed) => match *boxed {
                Ok(r) => Ok(r),
                Err(e) => Err(RPCError::RemoteError(RemoteError::new_with_node(self.target, self.node.clone(), e))),
            },
            other => Err(RPCError::Unreachable(Unreachable::new(&io::Error::other(format!(
                "unexpected response to InstallSnapshot: {other:?}"
            ))))),
        }
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<u64>,
        option: RPCOption,
    ) -> Result<VoteResponse<u64>, RPCError<u64, BasicNode, RaftError<u64>>> {
        let timeout = option.hard_ttl().max(Duration::from_millis(1_500));
        let resp = self
            .call_raft(RpcRequest::Vote(rpc), timeout)
            .await
            .map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))?;
        match resp {
            RpcResponse::Vote(boxed) => match *boxed {
                Ok(r) => Ok(r),
                Err(e) => Err(RPCError::RemoteError(RemoteError::new_with_node(self.target, self.node.clone(), e))),
            },
            other => Err(RPCError::Unreachable(Unreachable::new(&io::Error::other(format!(
                "unexpected response to Vote: {other:?}"
            ))))),
        }
    }
}

/// Sends a synchronous control or protocol RPC to `addr` for tests and management probes.
pub fn send_rpc(addr: &str, req: &RpcRequest) -> Res<RpcResponse> {
    let mut stream = connect_stream(addr, DEFAULT_RPC_TIMEOUT)?;
    Ok(roundtrip_on_stream(&mut stream, req)?)
}

/// Connects a blocking `TcpStream` with bounded connect/read/write timeouts.
fn connect_stream(addr: &str, timeout: Duration) -> io::Result<TcpStream> {
    let sock: SocketAddr =
        addr.parse().map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("bad addr {addr}: {e}")))?;
    let stream = TcpStream::connect_timeout(&sock, timeout)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    Ok(stream)
}

fn roundtrip_on_stream(stream: &mut TcpStream, req: &RpcRequest) -> io::Result<RpcResponse> {
    write_frame(stream, req)?;
    read_frame(stream)?.ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "peer closed stream before reply"))
}

/// Writes a 4-byte length-prefixed JSON frame.
pub fn write_frame<T: Serialize>(stream: &mut TcpStream, msg: &T) -> io::Result<()> {
    let payload = serde_json::to_vec(msg).map_err(|e| io::Error::other(format!("rpc encode: {e}")))?;
    let len = u32::try_from(payload.len())
        .ok()
        .filter(|&n| (n as usize) <= MAX_RPC_FRAME_BYTES)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "rpc frame exceeds size ceiling"))?;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(&payload)?;
    stream.flush()?;
    Ok(())
}

/// Reads a bounded 4-byte length-prefixed JSON frame; returns `Ok(None)` on clean EOF.
pub fn read_frame<T: DeserializeOwned>(stream: &mut TcpStream) -> io::Result<Option<T>> {
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_RPC_FRAME_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("invalid rpc frame length {len}")));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    serde_json::from_slice(&buf)
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("rpc decode: {e}")))
}

/// Helper converting an RPC address/error response into a typed error for harnesses.
pub fn rpc_expect_ok(resp: RpcResponse) -> Res<()> {
    match resp {
        RpcResponse::Ok => Ok(()),
        RpcResponse::Error { message, .. } => Err(E::Refused(message)),
        other => Err(E::Refused(format!("unexpected rpc response: {other:?}"))),
    }
}
