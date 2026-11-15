//! Subprocess Raft node lifecycle and RPC test harness for multi-process fault injection.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde::Deserialize;

use rootyard_refcas_log::cluster::{FaultTarget, RpcRequest, RpcResponse, rpc_expect_ok, send_rpc};
use rootyard_refcas_log::fault::FaultSpec;
use rootyard_refcas_log::fixture::{DEFAULT_MIN_FREE_BYTES, qualify_store_dir};
use rootyard_refcas_log::state_machine::SmCommand;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadyBanner {
    node_id: u64,
    addr: String,
    fstype: Option<String>,
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

pub struct NodeProc {
    pub id: u64,
    pub dir: PathBuf,
    pub addr: String,
    child: Child,
}

impl Drop for NodeProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl NodeProc {
    pub fn spawn(id: u64, dir: &Path, cfg: &NodeConfig) -> Self {
        qualify_store_dir(dir, true, DEFAULT_MIN_FREE_BYTES).expect("qualify node store dir");
        let bin = env!("CARGO_BIN_EXE_raft-node");
        let mut child = Command::new(bin)
            .args([
                "--id",
                &id.to_string(),
                "--dir",
                &dir.to_string_lossy(),
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
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn raft-node");

        let stdout = child.stdout.take().expect("stdout piped");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let res = BufReader::new(stdout).read_line(&mut line).map(|_| line);
            let _ = tx.send(res);
        });
        let raw = rx.recv_timeout(Duration::from_secs(15)).expect("raft-node READY timeout").expect("read READY");
        let trimmed = raw.trim();
        let json = trimmed
            .strip_prefix("READY ")
            .unwrap_or_else(|| panic!("node {id} did not print READY banner (got {trimmed:?})"));
        let banner: ReadyBanner = serde_json::from_str(json).expect("decode READY banner");
        assert_eq!(banner.node_id, id);
        if cfg!(target_os = "linux") {
            assert!(banner.fstype.is_some(), "linux READY banner must include fstype");
        }
        Self { id, dir: dir.to_path_buf(), addr: banner.addr, child }
    }

    pub fn kill_sigkill(mut self) -> ExitStatus {
        self.child.kill().expect("kill child");
        let status = self.child.wait().expect("wait killed child");
        assert!(!status.success(), "killed child unexpectedly exited zero");
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(status.signal(), Some(9), "expected SIGKILL signal 9");
        }
        status
    }

    pub fn shutdown_graceful(mut self) {
        let _ = send_rpc(&self.addr, &RpcRequest::Shutdown);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                assert!(status.success(), "graceful shutdown failed: {status}");
                return;
            }
            assert!(Instant::now() < deadline, "node {} graceful shutdown timeout", self.id);
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    pub fn metrics(&self) -> NodeMetrics {
        match send_rpc(&self.addr, &RpcRequest::Metrics).expect("metrics rpc") {
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

    pub fn kv_get(&self, key: &str) -> Option<String> {
        match send_rpc(&self.addr, &RpcRequest::KvGet { key: key.to_owned() }).expect("kv_get rpc") {
            RpcResponse::KvValue { value } => value,
            other => panic!("unexpected kv_get response: {other:?}"),
        }
    }

    pub fn inject_fault(&self, target: FaultTarget, spec: FaultSpec) {
        let resp = send_rpc(&self.addr, &RpcRequest::InjectFault { target, spec }).expect("inject_fault rpc");
        rpc_expect_ok(resp).expect("inject_fault ok");
    }

    pub fn trigger_snapshot(&self) {
        let resp = send_rpc(&self.addr, &RpcRequest::TriggerSnapshot).expect("trigger_snapshot");
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

pub fn spawn_corrupt_expect_refused(id: u64, dir: &Path) -> String {
    let bin = env!("CARGO_BIN_EXE_raft-node");
    let output = Command::new(bin)
        .args(["--id", &id.to_string(), "--dir", &dir.to_string_lossy(), "--check-on-open", "true"])
        .output()
        .expect("run corrupted raft-node");
    assert!(!output.status.success(), "corrupted store MUST refuse startup for node {id}");
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(stderr.contains("ERR "), "expected explicit refusal on stderr, got: {stderr:?}");
    stderr
}

pub fn peer_map(nodes: &[&NodeProc]) -> BTreeMap<u64, String> {
    nodes.iter().map(|n| (n.id, n.addr.clone())).collect()
}

pub fn broadcast_peers(nodes: &[&NodeProc], all_peers: &BTreeMap<u64, String>) {
    for n in nodes {
        let resp = send_rpc(&n.addr, &RpcRequest::UpdatePeers { peers: all_peers.clone() }).expect("update_peers");
        rpc_expect_ok(resp).expect("update_peers ok");
    }
}

pub fn bootstrap_cluster(nodes: &[&NodeProc]) {
    let peers = peer_map(nodes);
    let resp = send_rpc(&nodes[0].addr, &RpcRequest::Bootstrap { members: peers }).expect("bootstrap");
    rpc_expect_ok(resp).expect("bootstrap ok");
}

pub fn wait_leader(nodes: &[&NodeProc], timeout: Duration) -> u64 {
    let deadline = Instant::now() + timeout;
    loop {
        for n in nodes {
            if let Ok(RpcResponse::Metrics(m)) = send_rpc(&n.addr, &RpcRequest::Metrics)
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
        if let Ok(resp) = send_rpc(&node.addr, &RpcRequest::ClientWrite { payload: payload.clone() }) {
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
        let res = send_rpc(
            &leader.addr,
            &RpcRequest::AddLearner { node_id: learner.id, addr: learner.addr.clone(), blocking: true },
        );
        if let Ok(RpcResponse::Ok) = res {
            let chg =
                send_rpc(&leader.addr, &RpcRequest::ChangeMembership { members: new_voters.clone(), retain: false });
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
