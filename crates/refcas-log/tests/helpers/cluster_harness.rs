//! Subprocess Raft node lifecycle and RPC test harness for multi-process fault injection.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde::Deserialize;

use rootyard_refcas_log::Res;
use rootyard_refcas_log::cluster::{RpcRequest, RpcResponse, rpc_expect_ok, send_rpc};
use rootyard_refcas_log::fixture::{DEFAULT_MIN_FREE_BYTES, qualify_store_dir};
use rootyard_refcas_log::mtls::MtlsClient;
use rootyard_refcas_log::state_machine::SmCommand;

use super::tls_certs::ClusterPki;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadyBanner {
    node_id: u64,
    addr: String,
    fstype: Option<String>,
    mtls: bool,
}

pub struct NodeConfig {
    pub snapshot_logs: u64,
    pub lag_threshold: u64,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self { snapshot_logs: 5_000, lag_threshold: 5_000 }
    }
}

struct OwnedChild(Option<Child>);

impl OwnedChild {
    fn take(&mut self) -> Option<Child> {
        self.0.take()
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = reap_bounded(&mut child, Duration::from_secs(5));
        }
    }
}

fn reap_bounded(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) | Err(_) => return None,
        }
    }
}

pub struct NodeProc {
    pub id: u64,
    pub dir: PathBuf,
    pub addr: String,
    client: MtlsClient,
    child: OwnedChild,
}

impl NodeProc {
    pub fn spawn(pki: &ClusterPki, id: u64, dir: &Path, cfg: &NodeConfig) -> Self {
        Self::spawn_with_ready_timeout(pki, id, dir, cfg, Duration::from_secs(15))
    }

    pub fn spawn_with_ready_timeout(
        pki: &ClusterPki,
        id: u64,
        dir: &Path,
        cfg: &NodeConfig,
        ready_timeout: Duration,
    ) -> Self {
        qualify_store_dir(dir, true, DEFAULT_MIN_FREE_BYTES).expect("qualify node store dir");
        let tls = pki.node_paths(id);
        let bin = env!("CARGO_BIN_EXE_raft-node");
        let spawned = Command::new(bin)
            .args([
                "--id",
                &id.to_string(),
                "--dir",
                &dir.to_string_lossy(),
                "--tls-ca",
                &tls.ca_cert.to_string_lossy(),
                "--tls-cert",
                &tls.cert.to_string_lossy(),
                "--tls-key",
                &tls.key.to_string_lossy(),
                "--check-on-open",
                "true",
                "--heartbeat-ms",
                "60",
                "--election-min-ms",
                "200",
                "--election-max-ms",
                "380",
                "--snapshot-logs",
                &cfg.snapshot_logs.to_string(),
                "--lag-threshold",
                &cfg.lag_threshold.to_string(),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn raft-node");
        // Establish own-child RAII immediately so pre-READY timeout/panic never strands a child process.
        let mut child = OwnedChild(Some(spawned));
        let stdout = child.0.as_mut().expect("child live").stdout.take().expect("stdout piped");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let res = BufReader::new(stdout).read_line(&mut line).map(|_| line);
            let _ = tx.send(res);
        });
        let raw = rx.recv_timeout(ready_timeout).expect("raft-node READY timeout").expect("read READY");
        let trimmed = raw.trim();
        let json = trimmed
            .strip_prefix("READY ")
            .unwrap_or_else(|| panic!("node {id} did not print READY banner (got {trimmed:?})"));
        let banner: ReadyBanner = serde_json::from_str(json).expect("decode READY banner");
        assert_eq!(banner.node_id, id);
        assert!(banner.mtls, "READY banner must confirm strict mTLS transport");
        if cfg!(target_os = "linux") {
            assert!(banner.fstype.is_some(), "linux READY banner must include fstype");
        }
        Self { id, dir: dir.to_path_buf(), addr: banner.addr, client: pki.client(), child }
    }

    pub fn kill_sigkill(mut self) -> ExitStatus {
        let mut child = self.child.take().expect("child live");
        child.kill().expect("kill child");
        let status = reap_bounded(&mut child, Duration::from_secs(5)).expect("timed out reaping killed child");
        assert!(!status.success(), "killed child unexpectedly exited zero");
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(status.signal(), Some(9), "expected SIGKILL signal 9");
        }
        status
    }

    pub fn shutdown_graceful(mut self) {
        let _ = self.try_rpc(&RpcRequest::Shutdown);
        let status = reap_bounded(self.child.0.as_mut().expect("child live"), Duration::from_secs(10))
            .unwrap_or_else(|| panic!("node {} graceful shutdown timeout", self.id));
        self.child.take();
        assert!(status.success(), "graceful shutdown failed: {status}");
    }

    pub fn try_rpc(&self, req: &RpcRequest) -> Res<RpcResponse> {
        send_rpc(&self.client, &self.addr, self.id, req)
    }

    pub fn rpc(&self, req: &RpcRequest) -> RpcResponse {
        self.try_rpc(req).expect("mTLS rpc")
    }

    pub fn metrics(&self) -> NodeMetrics {
        match self.rpc(&RpcRequest::Metrics) {
            RpcResponse::Metrics(m) => NodeMetrics {
                node_id: m.node_id,
                running_ok: m.running_ok,
                current_leader: m.current_leader,
                last_applied_index: m.last_applied.map(|l| l.index),
                snapshot_index: m.snapshot.map(|l| l.index),
                membership_voters: m.membership_voters,
                persisted_vote: m.persisted_vote,
                state_digest_hex: m.sm_summary.state_digest_hex,
                applied_count: m.sm_summary.applied_count,
            },
            other => panic!("unexpected metrics response: {other:?}"),
        }
    }

    pub fn inspect_replica_kv(&self, key: &str) -> Option<String> {
        match self.rpc(&RpcRequest::InspectReplicaKv { key: key.to_owned() }) {
            RpcResponse::KvValue { value, .. } => value,
            other => panic!("unexpected inspect_replica_kv response: {other:?}"),
        }
    }

    pub fn trigger_snapshot(&self) {
        let resp = self.rpc(&RpcRequest::TriggerSnapshot);
        rpc_expect_ok(resp).expect("trigger_snapshot ok");
    }
}

pub struct NodeMetrics {
    pub node_id: u64,
    pub running_ok: bool,
    pub current_leader: Option<u64>,
    pub last_applied_index: Option<u64>,
    pub snapshot_index: Option<u64>,
    pub membership_voters: Vec<u64>,
    pub persisted_vote: Option<openraft::Vote<u64>>,
    pub state_digest_hex: String,
    pub applied_count: u64,
}

pub fn peer_map(nodes: &[&NodeProc]) -> BTreeMap<u64, String> {
    nodes.iter().map(|n| (n.id, n.addr.clone())).collect()
}

pub fn broadcast_peers(nodes: &[&NodeProc], all_peers: &BTreeMap<u64, String>) {
    for n in nodes {
        let resp = n.rpc(&RpcRequest::UpdatePeers { peers: all_peers.clone() });
        rpc_expect_ok(resp).expect("update_peers ok");
    }
}

pub fn bootstrap_cluster(nodes: &[&NodeProc]) {
    let peers = peer_map(nodes);
    let resp = nodes[0].rpc(&RpcRequest::Bootstrap { members: peers });
    rpc_expect_ok(resp).expect("bootstrap ok");
}

pub fn wait_leader(nodes: &[&NodeProc], timeout: Duration) -> u64 {
    let deadline = Instant::now() + timeout;
    loop {
        for n in nodes {
            if let Ok(RpcResponse::Metrics(m)) = n.try_rpc(&RpcRequest::Metrics)
                && m.running_ok
                && let Some(leader) = m.current_leader
                && nodes.iter().any(|p| p.id == leader)
            {
                return leader;
            }
        }
        assert!(Instant::now() < deadline, "timed out waiting for cluster leader");
        std::thread::sleep(Duration::from_millis(50));
    }
}

pub fn write_kv(nodes: &[&NodeProc], key: &str, value: &str) -> u64 {
    let payload = SmCommand::Put { key: key.to_owned(), value: value.to_owned() }.encode().unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut target_idx = 0usize;
    loop {
        let node = nodes[target_idx % nodes.len()];
        if let Ok(resp) = node.try_rpc(&RpcRequest::ClientWrite { payload: payload.clone() }) {
            match resp {
                RpcResponse::ClientWrite { log_index } => return log_index,
                RpcResponse::Error { forward_to_leader_id: Some(lid), .. } => {
                    if let Some(pos) = nodes.iter().position(|n| n.id == lid) {
                        target_idx = pos;
                        std::thread::sleep(Duration::from_millis(25));
                        continue;
                    }
                }
                RpcResponse::Error { .. } => {}
                other => panic!("unexpected client_write response: {other:?}"),
            }
        }
        target_idx += 1;
        assert!(Instant::now() < deadline, "write_kv timed out for key {key}");
        std::thread::sleep(Duration::from_millis(60));
    }
}

pub fn add_learner_and_promote(nodes: &[&NodeProc], learner: &NodeProc, new_voters: BTreeSet<u64>) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let leader_id = wait_leader(nodes, Duration::from_secs(8));
        let leader = nodes.iter().find(|n| n.id == leader_id).unwrap();
        let res =
            leader.try_rpc(&RpcRequest::AddLearner { node_id: learner.id, addr: learner.addr.clone(), blocking: true });
        if let Ok(RpcResponse::Ok) = res {
            let chg = leader.try_rpc(&RpcRequest::ChangeMembership { members: new_voters.clone(), retain: false });
            if let Ok(RpcResponse::Ok) = chg {
                return;
            }
        }
        assert!(Instant::now() < deadline, "add_learner_and_promote timeout");
        std::thread::sleep(Duration::from_millis(80));
    }
}

pub fn wait_all_converged(nodes: &[&NodeProc], expected_min_idx: u64, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    loop {
        let metrics: Vec<NodeMetrics> = nodes.iter().map(|n| n.metrics()).collect();
        for (node, metric) in nodes.iter().zip(metrics.iter()) {
            assert_eq!(metric.node_id, node.id);
        }
        let all_running = metrics.iter().all(|m| m.running_ok);
        let min_applied_ok = metrics.iter().all(|m| m.last_applied_index.unwrap_or(0) >= expected_min_idx);
        let same_applied = metrics.windows(2).all(|w| w[0].last_applied_index == w[1].last_applied_index);
        let same_digest = metrics.windows(2).all(|w| w[0].state_digest_hex == w[1].state_digest_hex);
        let same_count = metrics.windows(2).all(|w| w[0].applied_count == w[1].applied_count);
        if all_running && min_applied_ok && same_applied && same_digest && same_count {
            return metrics[0].state_digest_hex.clone();
        }
        assert!(Instant::now() < deadline, "cluster failed to converge to index {expected_min_idx}");
        std::thread::sleep(Duration::from_millis(60));
    }
}
