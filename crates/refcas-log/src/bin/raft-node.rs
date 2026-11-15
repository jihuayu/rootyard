//! Persistent multi-process Raft node binary for real fault-injection and cluster tests.

use std::collections::BTreeMap;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use openraft::storage::RaftLogStorage;
use openraft::{BasicNode, Config, Raft, SnapshotPolicy};
use serde::Serialize;

use rootyard_refcas_log::cluster::{
    FaultTarget, MetricsReport, PeerDirectory, RpcRequest, RpcResponse, TcpJsonNetworkFactory, read_frame, write_frame,
};
use rootyard_refcas_log::fault::FaultController;
use rootyard_refcas_log::fixture::{DEFAULT_MIN_FREE_BYTES, qualify_store_dir};
use rootyard_refcas_log::state_machine::PersistentStateMachine;
use rootyard_refcas_log::{LogTypeConfig, PersistentLog};

type RaftHandle = Raft<LogTypeConfig>;

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ReadyBanner<'a> {
    node_id: u64,
    addr: String,
    fstype: Option<&'a str>,
}

struct NodeArgs {
    id: u64,
    dir: PathBuf,
    check_on_open: bool,
    heartbeat_ms: u64,
    election_min_ms: u64,
    election_max_ms: u64,
    snapshot_logs: u64,
    lag_threshold: u64,
}

impl NodeArgs {
    fn parse() -> Result<Self, String> {
        let mut id: Option<u64> = None;
        let mut dir: Option<PathBuf> = None;
        let mut check_on_open = true;
        let mut heartbeat_ms = 80;
        let mut election_min_ms = 260;
        let mut election_max_ms = 460;
        let mut snapshot_logs = 5_000;
        let mut lag_threshold = 5_000;

        let mut it = std::env::args().skip(1);
        while let Some(arg) = it.next() {
            let val = it.next().ok_or_else(|| format!("missing value for {arg}"))?;
            match arg.as_str() {
                "--id" => id = Some(val.parse().map_err(|e| format!("bad --id: {e}"))?),
                "--dir" => dir = Some(PathBuf::from(val)),
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
                other => return Err(format!("unknown argument {other}")),
            }
        }
        Ok(Self {
            id: id.ok_or_else(|| "--id is required".to_owned())?,
            dir: dir.ok_or_else(|| "--dir is required".to_owned())?,
            check_on_open,
            heartbeat_ms,
            election_min_ms,
            election_max_ms,
            snapshot_logs,
            lag_threshold,
        })
    }
}

struct NodeCtx {
    node_id: u64,
    raft: RaftHandle,
    peers: PeerDirectory,
    log_store: PersistentLog,
    sm: PersistentStateMachine,
    shutdown: Arc<AtomicBool>,
}

fn err_resp(err: impl std::fmt::Display, forward_to_leader_id: Option<u64>) -> RpcResponse {
    RpcResponse::Error { message: err.to_string(), forward_to_leader_id }
}

async fn dispatch_rpc(ctx: &Arc<NodeCtx>, req: RpcRequest) -> (RpcResponse, bool) {
    match req {
        RpcRequest::Vote(rpc) => (RpcResponse::Vote(Box::new(ctx.raft.vote(rpc).await)), false),
        RpcRequest::AppendEntries(rpc) => {
            (RpcResponse::AppendEntries(Box::new(ctx.raft.append_entries(rpc).await)), false)
        }
        RpcRequest::InstallSnapshot(rpc) => {
            (RpcResponse::InstallSnapshot(Box::new(ctx.raft.install_snapshot(rpc).await)), false)
        }
        RpcRequest::UpdatePeers { peers } => {
            ctx.peers.set_all(peers);
            (RpcResponse::Ok, false)
        }
        RpcRequest::Bootstrap { members } => {
            ctx.peers.set_all(members.clone());
            let nodes: BTreeMap<u64, BasicNode> =
                members.into_iter().map(|(id, addr)| (id, BasicNode { addr })).collect();
            match ctx.raft.initialize(nodes).await {
                Ok(()) => (RpcResponse::Ok, false),
                Err(e) => (err_resp(e, None), false),
            }
        }
        RpcRequest::AddLearner { node_id, addr, blocking } => {
            ctx.peers.upsert(node_id, addr.clone());
            match ctx.raft.add_learner(node_id, BasicNode { addr }, blocking).await {
                Ok(_) => (RpcResponse::Ok, false),
                Err(e) => {
                    let fwd = e.forward_to_leader().and_then(|f| f.leader_id);
                    (err_resp(e, fwd), false)
                }
            }
        }
        RpcRequest::ChangeMembership { members, retain } => match ctx.raft.change_membership(members, retain).await {
            Ok(_) => (RpcResponse::Ok, false),
            Err(e) => {
                let fwd = e.forward_to_leader().and_then(|f| f.leader_id);
                (err_resp(e, fwd), false)
            }
        },
        RpcRequest::ClientWrite { payload } => match ctx.raft.client_write(payload).await {
            Ok(res) => (RpcResponse::ClientWrite { log_index: res.log_id.index }, false),
            Err(e) => {
                let fwd = e.forward_to_leader().and_then(|f| f.leader_id);
                (err_resp(e, fwd), false)
            }
        },
        RpcRequest::TriggerSnapshot => match ctx.raft.trigger().snapshot().await {
            Ok(()) => (RpcResponse::Ok, false),
            Err(e) => (err_resp(e, None), false),
        },
        RpcRequest::TriggerPurge { upto } => match ctx.raft.trigger().purge_log(upto).await {
            Ok(()) => (RpcResponse::Ok, false),
            Err(e) => (err_resp(e, None), false),
        },
        RpcRequest::Metrics => {
            let m = ctx.raft.metrics().borrow().clone();
            let mut log_handle = ctx.log_store.clone();
            let persisted_vote = log_handle.read_vote().await.ok().flatten();
            let sm_summary = match ctx.sm.summary().await {
                Ok(s) => s,
                Err(e) => return (err_resp(e, None), false),
            };
            let (running_ok, fatal_error) = match &m.running_state {
                Ok(()) => (true, None),
                Err(f) => (false, Some(f.to_string())),
            };
            let membership_voters: Vec<u64> = m.membership_config.membership().voter_ids().collect();
            (
                RpcResponse::Metrics(Box::new(MetricsReport {
                    node_id: ctx.node_id,
                    running_ok,
                    fatal_error,
                    current_leader: m.current_leader,
                    current_term: m.current_term,
                    last_log_index: m.last_log_index,
                    last_applied: m.last_applied,
                    snapshot: m.snapshot,
                    purged: m.purged,
                    membership_voters,
                    persisted_vote,
                    sm_summary,
                })),
                false,
            )
        }
        RpcRequest::KvGet { key } => match ctx.sm.kv_get(key).await {
            Ok(value) => (RpcResponse::KvValue { value }, false),
            Err(e) => (err_resp(e, None), false),
        },
        RpcRequest::InjectFault { target, spec } => {
            match target {
                FaultTarget::Log => ctx.log_store.fault_controller().arm(spec),
                FaultTarget::StateMachine => ctx.sm.fault_controller().arm(spec),
                FaultTarget::Both => {
                    ctx.log_store.fault_controller().arm(spec);
                    ctx.sm.fault_controller().arm(spec);
                }
            }
            (RpcResponse::Ok, false)
        }
        RpcRequest::ClearFaults => {
            ctx.log_store.fault_controller().clear_all();
            ctx.sm.fault_controller().clear_all();
            (RpcResponse::Ok, false)
        }
        RpcRequest::Shutdown => {
            ctx.shutdown.store(true, Ordering::SeqCst);
            (RpcResponse::Ok, true)
        }
    }
}

fn handle_client(mut stream: TcpStream, ctx: Arc<NodeCtx>, handle: tokio::runtime::Handle) {
    let _ = stream.set_nodelay(true);
    while let Ok(Some(req)) = read_frame::<RpcRequest>(&mut stream) {
        let (resp, should_exit) = handle.block_on(dispatch_rpc(&ctx, req));
        if write_frame(&mut stream, &resp).is_err() {
            break;
        }
        if should_exit {
            let _ = handle.block_on(ctx.raft.shutdown());
            process::exit(0);
        }
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    if let Err(msg) = run().await {
        eprintln!("ERR {msg}");
        process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let args = NodeArgs::parse()?;
    let qualified = qualify_store_dir(&args.dir, false, DEFAULT_MIN_FREE_BYTES).map_err(|e| format!("qualify: {e}"))?;

    let log_fault = Arc::new(FaultController::default());
    let sm_fault = Arc::new(FaultController::default());
    let log_store = PersistentLog::open_with_faults(&args.dir, args.id, args.check_on_open, log_fault)
        .await
        .map_err(|e| format!("open log: {e}"))?;
    let sm = PersistentStateMachine::open_with_faults(&args.dir, args.id, args.check_on_open, sm_fault)
        .await
        .map_err(|e| format!("open sm: {e}"))?;

    let mut cfg = Config {
        cluster_name: "refcas-log-cluster".to_owned(),
        heartbeat_interval: args.heartbeat_ms,
        election_timeout_min: args.election_min_ms,
        election_timeout_max: args.election_max_ms,
        snapshot_policy: SnapshotPolicy::LogsSinceLast(args.snapshot_logs),
        replication_lag_threshold: args.lag_threshold,
        install_snapshot_timeout: 2_000,
        ..Default::default()
    };
    cfg.max_payload_entries = 128;
    let validated = Arc::new(cfg.validate().map_err(|e| format!("raft config: {e}"))?);

    let peers = PeerDirectory::new();
    let net = TcpJsonNetworkFactory::new(peers.clone());
    let raft = Raft::new(args.id, validated, net, log_store.clone(), sm.clone())
        .await
        .map_err(|e| format!("raft start: {e}"))?;

    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind rpc listener: {e}"))?;
    let local_addr = listener.local_addr().map_err(|e| format!("local_addr: {e}"))?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let ctx = Arc::new(NodeCtx { node_id: args.id, raft, peers, log_store, sm, shutdown: shutdown.clone() });

    let banner = ReadyBanner { node_id: args.id, addr: local_addr.to_string(), fstype: qualified.fstype.as_deref() };
    let banner_json = serde_json::to_string(&banner).map_err(|e| format!("banner encode: {e}"))?;
    println!("READY {banner_json}");
    let _ = std::io::stdout().flush();

    let handle = tokio::runtime::Handle::current();
    for conn in listener.incoming() {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
        match conn {
            Ok(stream) => {
                let c = ctx.clone();
                let h = handle.clone();
                std::thread::spawn(move || handle_client(stream, c, h));
            }
            Err(_) => {
                if shutdown.load(Ordering::SeqCst) {
                    break;
                }
            }
        }
    }
    Ok(())
}
