//! Persistent multi-process mTLS Raft node binary with ReadIndex quorum barriers and fail-closed startup.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufReader, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use openraft::error::{CheckIsLeaderError, ClientWriteError, RaftError};
use openraft::storage::RaftLogStorage;
use openraft::{BasicNode, Config, Raft, SnapshotPolicy};
use serde::Serialize;
use tokio::net::TcpListener;
use tokio::sync::watch;

use rootyard_refcas_log::cluster::{
    FaultTarget, MetricsReport, MtlsNetworkFactory, PeerDirectory, RpcRequest, RpcResponse, read_frame_async,
    write_frame_async,
};
use rootyard_refcas_log::fault::FaultController;
use rootyard_refcas_log::fixture::{DEFAULT_MIN_FREE_BYTES, qualify_store_dir};
use rootyard_refcas_log::mtls::{MtlsClient, MtlsPaths, MtlsServer, PeerIdentity, extract_peer_identity};
use rootyard_refcas_log::state_machine::{PersistentStateMachine, SmCommand};
use rootyard_refcas_log::{E, LogTypeConfig, MAX_ENTRY_BYTES, PersistentLog, Res};

struct NodeArgs {
    id: u64,
    dir: PathBuf,
    tls_ca: PathBuf,
    tls_cert: PathBuf,
    tls_key: PathBuf,
    check_on_open: bool,
    heartbeat_ms: u64,
    election_min_ms: u64,
    election_max_ms: u64,
    snapshot_logs: u64,
    lag_threshold: u64,
    write_timeout_ms: u64,
}

impl NodeArgs {
    fn parse() -> Result<Self, String> {
        let mut id: Option<u64> = None;
        let mut dir: Option<PathBuf> = None;
        let mut tls_ca: Option<PathBuf> = None;
        let mut tls_cert: Option<PathBuf> = None;
        let mut tls_key: Option<PathBuf> = None;
        let mut check_on_open = true;
        let mut heartbeat_ms = 80;
        let mut election_min_ms = 260;
        let mut election_max_ms = 460;
        let mut snapshot_logs = 5_000;
        let mut lag_threshold = 5_000;
        let mut write_timeout_ms = 2_500;

        let mut it = std::env::args().skip(1);
        while let Some(arg) = it.next() {
            let val = it.next().ok_or_else(|| format!("missing value for {arg}"))?;
            match arg.as_str() {
                "--id" => id = Some(val.parse().map_err(|e| format!("bad --id: {e}"))?),
                "--dir" => dir = Some(PathBuf::from(val)),
                "--tls-ca" => tls_ca = Some(PathBuf::from(val)),
                "--tls-cert" => tls_cert = Some(PathBuf::from(val)),
                "--tls-key" => tls_key = Some(PathBuf::from(val)),
                "--check-on-open" => {
                    check_on_open = val.parse().map_err(|e| format!("bad --check-on-open: {e}"))?;
                }
                "--heartbeat-ms" => {
                    heartbeat_ms = val.parse().map_err(|e| format!("bad --heartbeat-ms: {e}"))?;
                }
                "--election-min-ms" => {
                    election_min_ms = val.parse().map_err(|e| format!("bad --election-min-ms: {e}"))?;
                }
                "--election-max-ms" => {
                    election_max_ms = val.parse().map_err(|e| format!("bad --election-max-ms: {e}"))?;
                }
                "--snapshot-logs" => {
                    snapshot_logs = val.parse().map_err(|e| format!("bad --snapshot-logs: {e}"))?;
                }
                "--lag-threshold" => {
                    lag_threshold = val.parse().map_err(|e| format!("bad --lag-threshold: {e}"))?;
                }
                "--write-timeout-ms" => {
                    write_timeout_ms = val.parse().map_err(|e| format!("bad --write-timeout-ms: {e}"))?;
                }
                other => return Err(format!("unknown argument {other}")),
            }
        }
        Ok(Self {
            id: id.ok_or_else(|| "--id is required".to_owned())?,
            dir: dir.ok_or_else(|| "--dir is required".to_owned())?,
            tls_ca: tls_ca.ok_or_else(|| "--tls-ca is required for mTLS".to_owned())?,
            tls_cert: tls_cert.ok_or_else(|| "--tls-cert is required for mTLS".to_owned())?,
            tls_key: tls_key.ok_or_else(|| "--tls-key is required for mTLS".to_owned())?,
            check_on_open,
            heartbeat_ms,
            election_min_ms,
            election_max_ms,
            snapshot_logs,
            lag_threshold,
            write_timeout_ms,
        })
    }
}

#[derive(Serialize)]
struct ReadyBanner {
    node_id: u64,
    addr: String,
    fstype: Option<String>,
    mtls: bool,
}

struct NodeCtx {
    raft: Raft<LogTypeConfig>,
    log_store: PersistentLog,
    sm: PersistentStateMachine,
    log_fault: Arc<FaultController>,
    sm_fault: Arc<FaultController>,
    peers: PeerDirectory,
    write_timeout: Duration,
    shutdown_tx: watch::Sender<bool>,
}

fn err_resp(err: impl std::fmt::Display, forward_to_leader_id: Option<u64>) -> RpcResponse {
    RpcResponse::Error { message: err.to_string(), forward_to_leader_id }
}

fn forward_from_write_err(err: &RaftError<u64, ClientWriteError<u64, BasicNode>>) -> Option<u64> {
    match err {
        RaftError::APIError(ClientWriteError::ForwardToLeader(fwd)) => fwd.leader_id,
        _ => None,
    }
}

fn forward_from_read_err(err: &RaftError<u64, CheckIsLeaderError<u64, BasicNode>>) -> Option<u64> {
    match err {
        RaftError::APIError(CheckIsLeaderError::ForwardToLeader(fwd)) => fwd.leader_id,
        _ => None,
    }
}

fn verify_self_node_cert(paths: &MtlsPaths, expected_id: u64) -> Res<()> {
    let file = File::open(&paths.cert)
        .map_err(|e| E::Io(io::Error::new(e.kind(), format!("open node cert {}: {e}", paths.cert.display()))))?;
    let mut reader = BufReader::new(file);
    let leaf = rustls_pemfile::certs(&mut reader)
        .next()
        .ok_or_else(|| E::Refused(format!("node cert {} is empty", paths.cert.display())))?
        .map_err(|e| E::Codec(format!("parse node cert {}: {e}", paths.cert.display())))?;
    let id = extract_peer_identity(leaf.as_ref())?;
    if id != PeerIdentity::Node(expected_id) {
        return Err(E::Refused(format!(
            "node cert {} SAN identity {id:?} does not match --id {expected_id}",
            paths.cert.display()
        )));
    }
    Ok(())
}

fn authorize_rpc(identity: PeerIdentity, req: &RpcRequest) -> Result<(), String> {
    match identity {
        PeerIdentity::Node(sender_id) => match req {
            RpcRequest::Vote(rpc) if rpc.vote.leader_id.node_id == sender_id => Ok(()),
            RpcRequest::AppendEntries(rpc) if rpc.vote.leader_id.node_id == sender_id => Ok(()),
            RpcRequest::InstallSnapshot(rpc) if rpc.vote.leader_id.node_id == sender_id => Ok(()),
            RpcRequest::Vote(_) | RpcRequest::AppendEntries(_) | RpcRequest::InstallSnapshot(_) => {
                Err(format!("peer node {sender_id} attempted forged Raft RPC for mismatched candidate/leader node_id"))
            }
            _ => Err(format!("peer node {sender_id} is not authorized for client/control RPC")),
        },
        PeerIdentity::Client => match req {
            RpcRequest::AppendEntries(_) | RpcRequest::InstallSnapshot(_) => {
                Err("client identity is not authorized for peer log/snapshot replication RPCs".into())
            }
            _ => Ok(()),
        },
    }
}

fn validate_client_write_payload(payload: &[u8]) -> Result<(), String> {
    if payload.len() > MAX_ENTRY_BYTES {
        return Err(format!(
            "payload length {} exceeds metadata WAL limit {MAX_ENTRY_BYTES} (large blobs must use Blob store, not Raft WAL)",
            payload.len()
        ));
    }
    if let Ok(cmd) = serde_json::from_slice::<SmCommand>(payload) {
        cmd.validate_bounds().map_err(|e| e.to_string())?;
    }
    Ok(())
}

async fn handle_client_write(ctx: &Arc<NodeCtx>, payload: Vec<u8>) -> RpcResponse {
    if let Err(msg) = validate_client_write_payload(&payload) {
        return err_resp(msg, None);
    }
    match tokio::time::timeout(ctx.write_timeout, ctx.raft.client_write(payload)).await {
        Ok(Ok(res)) => RpcResponse::ClientWrite { log_index: res.log_id.index },
        Ok(Err(e)) => {
            let fwd = forward_from_write_err(&e);
            err_resp(e, fwd)
        }
        Err(_) => {
            let leader = ctx.raft.metrics().borrow().current_leader;
            err_resp("raft write timed out awaiting commit quorum (no PG/Redis fallback)", leader)
        }
    }
}

async fn handle_kv_get_linearizable(ctx: &Arc<NodeCtx>, key: String) -> RpcResponse {
    let read_log_id = match ctx.raft.ensure_linearizable().await {
        Ok(id) => id,
        Err(e) => {
            let fwd = forward_from_read_err(&e);
            return err_resp(format!("linearizable ReadIndex quorum barrier failed: {e}"), fwd);
        }
    };
    let summary = match ctx.sm.summary().await {
        Ok(s) => s,
        Err(e) => return err_resp(e, None),
    };
    if read_log_id.is_some_and(|req| summary.last_applied.is_none_or(|applied| applied.index < req.index)) {
        return err_resp(
            format!("state machine applied {:?} behind ReadIndex barrier {:?}", summary.last_applied, read_log_id),
            None,
        );
    }
    match ctx.sm.kv_get(key).await {
        Ok(value) => RpcResponse::KvValue { value, read_log_id },
        Err(e) => err_resp(e, None),
    }
}

async fn handle_read_index(ctx: &Arc<NodeCtx>) -> RpcResponse {
    let read_log_id = match ctx.raft.ensure_linearizable().await {
        Ok(id) => id,
        Err(e) => {
            let fwd = forward_from_read_err(&e);
            return err_resp(format!("ReadIndex quorum barrier failed: {e}"), fwd);
        }
    };
    match ctx.sm.summary().await {
        Ok(s) => {
            RpcResponse::ReadIndex { read_log_id, applied_count: s.applied_count, state_digest_hex: s.state_digest_hex }
        }
        Err(e) => err_resp(e, None),
    }
}

async fn handle_metrics(ctx: &Arc<NodeCtx>) -> RpcResponse {
    let m = ctx.raft.metrics().borrow().clone();
    let mut log_handle = ctx.log_store.clone();
    let persisted_vote = log_handle.read_vote().await.ok().flatten();
    let sm_summary = match ctx.sm.summary().await {
        Ok(s) => s,
        Err(e) => return err_resp(e, None),
    };
    let voters = m.membership_config.membership().voter_ids().collect();
    RpcResponse::Metrics(Box::new(MetricsReport {
        node_id: m.id,
        running_ok: m.running_state.is_ok(),
        fatal_error: m.running_state.as_ref().err().map(ToString::to_string),
        current_term: m.current_term,
        current_leader: m.current_leader,
        last_log_index: m.last_log_index,
        last_applied: m.last_applied,
        snapshot: m.snapshot,
        purged: m.purged,
        membership_voters: voters,
        persisted_vote,
        sm_summary,
    }))
}

async fn dispatch_rpc(ctx: &Arc<NodeCtx>, identity: PeerIdentity, req: RpcRequest) -> (RpcResponse, bool) {
    if let Err(reason) = authorize_rpc(identity, &req) {
        return (err_resp(reason, None), false);
    }
    match req {
        RpcRequest::Vote(rpc) => (RpcResponse::Vote(Box::new(ctx.raft.vote(rpc).await)), false),
        RpcRequest::AppendEntries(rpc) => {
            (RpcResponse::AppendEntries(Box::new(ctx.raft.append_entries(rpc).await)), false)
        }
        RpcRequest::InstallSnapshot(rpc) => {
            (RpcResponse::InstallSnapshot(Box::new(ctx.raft.install_snapshot(rpc).await)), false)
        }
        RpcRequest::UpdatePeers { peers } => {
            ctx.peers.update(peers);
            (RpcResponse::Ok, false)
        }
        RpcRequest::PartitionPeers { blocked } => {
            ctx.peers.set_blocked(blocked);
            (RpcResponse::Ok, false)
        }
        RpcRequest::Bootstrap { members } => {
            let mut nodes = BTreeMap::new();
            for (id, addr) in members {
                ctx.peers.insert(id, addr.clone());
                nodes.insert(id, BasicNode { addr });
            }
            match ctx.raft.initialize(nodes).await {
                Ok(()) => (RpcResponse::Ok, false),
                Err(e) => (err_resp(e, None), false),
            }
        }
        RpcRequest::AddLearner { node_id, addr, blocking } => {
            ctx.peers.insert(node_id, addr.clone());
            match ctx.raft.add_learner(node_id, BasicNode { addr }, blocking).await {
                Ok(_) => (RpcResponse::Ok, false),
                Err(e) => {
                    let leader = ctx.raft.metrics().borrow().current_leader;
                    (err_resp(e, leader), false)
                }
            }
        }
        RpcRequest::ChangeMembership { members, retain } => match ctx.raft.change_membership(members, retain).await {
            Ok(_) => (RpcResponse::Ok, false),
            Err(e) => {
                let leader = ctx.raft.metrics().borrow().current_leader;
                (err_resp(e, leader), false)
            }
        },
        RpcRequest::ClientWrite { payload } => (handle_client_write(ctx, payload).await, false),
        RpcRequest::TriggerSnapshot => match ctx.raft.trigger().snapshot().await {
            Ok(()) => (RpcResponse::Ok, false),
            Err(e) => (err_resp(e, None), false),
        },
        RpcRequest::TriggerPurge { upto } => match ctx.raft.trigger().purge_log(upto).await {
            Ok(()) => (RpcResponse::Ok, false),
            Err(e) => (err_resp(e, None), false),
        },
        RpcRequest::Metrics => (handle_metrics(ctx).await, false),
        RpcRequest::KvGet { key } => (handle_kv_get_linearizable(ctx, key).await, false),
        RpcRequest::EnsureReadIndex => (handle_read_index(ctx).await, false),
        RpcRequest::InspectReplicaKv { key } => match ctx.sm.kv_get(key).await {
            Ok(value) => {
                let read_log_id = ctx.sm.summary().await.ok().and_then(|s| s.last_applied);
                (RpcResponse::KvValue { value, read_log_id }, false)
            }
            Err(e) => (err_resp(e, None), false),
        },
        RpcRequest::InjectFault { target, spec } => {
            match target {
                FaultTarget::Log => ctx.log_fault.arm(spec),
                FaultTarget::StateMachine => ctx.sm_fault.arm(spec),
            }
            (RpcResponse::Ok, false)
        }
        RpcRequest::ClearFaults => {
            ctx.log_fault.clear_all();
            ctx.sm_fault.clear_all();
            (RpcResponse::Ok, false)
        }
        RpcRequest::Shutdown => {
            let _ = ctx.shutdown_tx.send(true);
            (RpcResponse::Ok, true)
        }
    }
}

async fn handle_conn(ctx: Arc<NodeCtx>, server: MtlsServer, tcp: tokio::net::TcpStream) {
    let Ok((mut tls, identity)) = server.accept(tcp).await else {
        return;
    };
    while let Ok(Some(req)) = read_frame_async::<_, RpcRequest>(&mut tls).await {
        if let PeerIdentity::Node(sender_id) = identity
            && ctx.peers.is_blocked(sender_id)
        {
            break;
        }
        let (resp, should_exit) = dispatch_rpc(&ctx, identity, req).await;
        if write_frame_async(&mut tls, &resp).await.is_err() || should_exit {
            break;
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = NodeArgs::parse()?;
    let tls_paths = MtlsPaths { ca_cert: args.tls_ca, cert: args.tls_cert, key: args.tls_key };
    verify_self_node_cert(&tls_paths, args.id)?;
    let mtls_server = MtlsServer::from_paths(&tls_paths)?;
    let mtls_client = MtlsClient::from_paths(&tls_paths)?;

    let qual = qualify_store_dir(&args.dir, false, DEFAULT_MIN_FREE_BYTES)?;
    let log_fault = FaultController::noop();
    let sm_fault = FaultController::noop();
    let log = PersistentLog::open_with_faults(&args.dir, args.id, args.check_on_open, log_fault.clone())
        .await
        .map_err(|e| format!("open log: {e}"))?;
    let sm = PersistentStateMachine::open_with_faults(&args.dir, args.id, args.check_on_open, sm_fault.clone())
        .await
        .map_err(|e| format!("open sm: {e}"))?;

    let cfg = Arc::new(
        Config {
            cluster_name: "refcas-log-cluster".to_owned(),
            heartbeat_interval: args.heartbeat_ms,
            election_timeout_min: args.election_min_ms,
            election_timeout_max: args.election_max_ms,
            snapshot_policy: SnapshotPolicy::LogsSinceLast(args.snapshot_logs),
            replication_lag_threshold: args.lag_threshold,
            ..Default::default()
        }
        .validate()?,
    );

    let peers = PeerDirectory::new();
    let net = MtlsNetworkFactory::new(peers.clone(), mtls_client);
    let log_store = log.clone();
    let raft = Raft::new(args.id, cfg, net, log, sm.clone()).await?;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?.to_string();
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let ctx = Arc::new(NodeCtx {
        raft,
        log_store,
        sm,
        log_fault,
        sm_fault,
        peers,
        write_timeout: Duration::from_millis(args.write_timeout_ms),
        shutdown_tx,
    });

    let banner = serde_json::to_string(&ReadyBanner { node_id: args.id, addr, fstype: qual.fstype, mtls: true })?;
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "READY {banner}")?;
    stdout.flush()?;

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (tcp, _) = accepted?;
                let c = ctx.clone();
                let srv = mtls_server.clone();
                tokio::spawn(async move {
                    handle_conn(c, srv, tcp).await;
                });
            }
        }
    }

    let _ = ctx.raft.shutdown().await;
    Ok(())
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("ERR {err}");
            ExitCode::from(1)
        }
    }
}
