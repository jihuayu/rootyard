//! Multi-process (3 OS nodes) real fault-injection and crash-recovery integration suite.

#[path = "helpers/cluster_harness.rs"]
mod harness;
#[path = "helpers/tls_certs.rs"]
mod tls_certs;

use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use openraft::Vote;
use openraft::raft::VoteRequest;

use rootyard_refcas_log::PersistentLog;
use rootyard_refcas_log::cluster::{FaultTarget, RpcRequest, RpcResponse, rpc_expect_ok};
use rootyard_refcas_log::fault::{FaultMode, FaultPoint, FaultSpec};
use rootyard_refcas_log::fixture::{DEFAULT_MIN_FREE_BYTES, qualify_store_dir};
use rootyard_refcas_log::state_machine::PersistentStateMachine;

use harness::{
    NodeConfig, NodeProc, add_learner_and_promote, bootstrap_cluster, broadcast_peers, peer_map, wait_all_converged,
    wait_leader, write_kv,
};
use tls_certs::ClusterPki;

fn inject_fault(node: &NodeProc, target: FaultTarget, spec: FaultSpec) {
    rpc_expect_ok(node.rpc(&RpcRequest::InjectFault { target, spec })).expect("inject_fault ok");
}

fn spawn_corrupt_expect_refused(pki: &ClusterPki, id: u64, dir: &std::path::Path) -> String {
    let tls = pki.node_paths(id);
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_raft-node"))
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
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("spawn corrupted raft-node");
    assert!(!out.status.success(), "corrupted store MUST refuse startup for node {id}");
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(stderr.contains("ERR "), "expected explicit refusal on stderr, got: {stderr:?}");
    stderr
}

fn assert_all_keys(nodes: &[&NodeProc], prefix: &str, count: usize) {
    for n in nodes {
        for i in 0..count {
            let k = format!("{prefix}-{i:02}");
            let expected = format!("val-{i:02}");
            assert_eq!(n.inspect_replica_kv(&k).as_deref(), Some(expected.as_str()), "node {} lost key {k}", n.id);
        }
    }
}

fn wait_node_fatal(node: &NodeProc, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(RpcResponse::Metrics(m)) = node.try_rpc(&RpcRequest::Metrics)
            && !m.running_ok
            && m.fatal_error.is_some()
        {
            return;
        }
        assert!(Instant::now() < deadline, "node {} did not fail-stop on injected fault", node.id);
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn find_active_snap(dir: &std::path::Path) -> PathBuf {
    let snaps_dir = dir.join("snapshots");
    std::fs::read_dir(&snaps_dir)
        .expect("read snapshots dir")
        .flatten()
        .map(|e| e.path())
        .find(|p| p.file_name().and_then(|s| s.to_str()).is_some_and(|n| n.starts_with("snap-")))
        .expect("missing active snap-* file")
}

#[test]
fn kill_minus_9_follower_and_leader_recovery_zero_loss() {
    let pki = ClusterPki::new();
    let d1 = tempfile::tempdir().unwrap();
    let d2 = tempfile::tempdir().unwrap();
    let d3 = tempfile::tempdir().unwrap();
    let cfg = NodeConfig::default();

    let mut nodes = vec![
        NodeProc::spawn(&pki, 1, d1.path(), &cfg),
        NodeProc::spawn(&pki, 2, d2.path(), &cfg),
        NodeProc::spawn(&pki, 3, d3.path(), &cfg),
    ];
    let refs = [&nodes[0], &nodes[1], &nodes[2]];
    bootstrap_cluster(&refs);
    let leader_id = wait_leader(&refs, Duration::from_secs(10));
    let mut last_idx = 0u64;
    for i in 0..8 {
        last_idx = write_kv(&refs, &format!("k-{i:02}"), &format!("val-{i:02}"));
    }
    let _ = wait_all_converged(&refs, last_idx, Duration::from_secs(10));

    // Step 1: kill -9 a committed follower while surviving 2-node majority commits more entries.
    let follower_pos = nodes.iter().position(|n| n.id != leader_id).unwrap();
    let crashed_follower = nodes.remove(follower_pos);
    let crashed_id = crashed_follower.id;
    let crashed_dir = crashed_follower.dir.clone();
    crashed_follower.kill_sigkill();

    let majority = [&nodes[0], &nodes[1]];
    for i in 8..14 {
        last_idx = write_kv(&majority, &format!("k-{i:02}"), &format!("val-{i:02}"));
    }
    let recovered = NodeProc::spawn(&pki, crashed_id, &crashed_dir, &cfg);
    nodes.push(recovered);
    nodes.sort_by_key(|n| n.id);
    let all_refs = [&nodes[0], &nodes[1], &nodes[2]];
    broadcast_peers(&all_refs, &peer_map(&all_refs));
    let digest_mid = wait_all_converged(&all_refs, last_idx, Duration::from_secs(12));

    // Step 2: kill -9 the current leader, force election + majority writes on survivors, then recover ex-leader.
    let cur_leader_id = wait_leader(&all_refs, Duration::from_secs(10));
    let leader_pos = nodes.iter().position(|n| n.id == cur_leader_id).unwrap();
    let crashed_leader = nodes.remove(leader_pos);
    let crashed_lid = crashed_leader.id;
    let crashed_ldir = crashed_leader.dir.clone();
    crashed_leader.kill_sigkill();

    let survivors = [&nodes[0], &nodes[1]];
    let _new_leader = wait_leader(&survivors, Duration::from_secs(10));
    for i in 14..20 {
        last_idx = write_kv(&survivors, &format!("k-{i:02}"), &format!("val-{i:02}"));
    }
    let ex_leader = NodeProc::spawn(&pki, crashed_lid, &crashed_ldir, &cfg);
    nodes.push(ex_leader);
    nodes.sort_by_key(|n| n.id);
    let final_refs = [&nodes[0], &nodes[1], &nodes[2]];
    broadcast_peers(&final_refs, &peer_map(&final_refs));
    let digest_end = wait_all_converged(&final_refs, last_idx, Duration::from_secs(12));
    assert_ne!(digest_mid, digest_end);
    assert_all_keys(&final_refs, "k", 20);

    for n in nodes {
        n.shutdown_graceful();
    }
}

#[test]
fn fsync_failure_injection_and_recovery_zero_loss() {
    let pki = ClusterPki::new();
    let d1 = tempfile::tempdir().unwrap();
    let d2 = tempfile::tempdir().unwrap();
    let d3 = tempfile::tempdir().unwrap();
    let cfg = NodeConfig::default();

    let n1 = NodeProc::spawn(&pki, 1, d1.path(), &cfg);
    let n2 = NodeProc::spawn(&pki, 2, d2.path(), &cfg);
    let n3 = NodeProc::spawn(&pki, 3, d3.path(), &cfg);
    bootstrap_cluster(&[&n1, &n2, &n3]);
    let _ = wait_leader(&[&n1, &n2, &n3], Duration::from_secs(10));

    let mut last_idx = 0u64;
    for i in 0..5 {
        last_idx = write_kv(&[&n1, &n2, &n3], &format!("fs-{i:02}"), &format!("val-{i:02}"));
    }
    wait_all_converged(&[&n1, &n2, &n3], last_idx, Duration::from_secs(10));

    // Inject log fsync error on follower n3 while majority keeps committing.
    let victim_is_3 = n3.metrics().current_leader != Some(3);
    assert!(victim_is_3 || wait_leader(&[&n1, &n2], Duration::from_secs(2)) > 0);
    // Keep leader on {n1, n2} if n3 was somehow leader, otherwise n3 is already follower.
    let (mut leader_nodes, victim) = if n3.metrics().current_leader == Some(3) {
        n3.shutdown_graceful();
        let n3_re = NodeProc::spawn(&pki, 3, d3.path(), &cfg);
        broadcast_peers(&[&n1, &n2, &n3_re], &peer_map(&[&n1, &n2, &n3_re]));
        let _ = wait_leader(&[&n1, &n2], Duration::from_secs(10));
        (vec![n1, n2], n3_re)
    } else {
        (vec![n1, n2], n3)
    };

    inject_fault(&victim, FaultTarget::Log, FaultSpec { point: FaultPoint::LogAppendSync, mode: FaultMode::Always });
    for i in 5..9 {
        let maj = [&leader_nodes[0], &leader_nodes[1]];
        last_idx = write_kv(&maj, &format!("fs-{i:02}"), &format!("val-{i:02}"));
    }
    wait_node_fatal(&victim, Duration::from_secs(8));
    victim.shutdown_graceful();

    // Restart clean n3 -> verify zero committed loss through LogAppendSync recovery.
    let victim2 = NodeProc::spawn(&pki, 3, d3.path(), &cfg);
    let maj = [&leader_nodes[0], &leader_nodes[1], &victim2];
    broadcast_peers(&maj, &peer_map(&maj));
    wait_all_converged(&maj, last_idx, Duration::from_secs(12));

    // Also inject SmApplySync on n3 while {n1, n2} keep committing.
    inject_fault(
        &victim2,
        FaultTarget::StateMachine,
        FaultSpec { point: FaultPoint::SmApplySync, mode: FaultMode::Always },
    );
    for i in 9..12 {
        let maj2 = [&leader_nodes[0], &leader_nodes[1]];
        last_idx = write_kv(&maj2, &format!("fs-{i:02}"), &format!("val-{i:02}"));
    }
    wait_node_fatal(&victim2, Duration::from_secs(8));
    victim2.shutdown_graceful();

    let victim3 = NodeProc::spawn(&pki, 3, d3.path(), &cfg);
    let all = [&leader_nodes[0], &leader_nodes[1], &victim3];
    broadcast_peers(&all, &peer_map(&all));
    wait_all_converged(&all, last_idx, Duration::from_secs(12));
    assert_all_keys(&all, "fs", 12);

    victim3.shutdown_graceful();
    for n in leader_nodes.drain(..) {
        n.shutdown_graceful();
    }
}

#[test]
fn enospc_failure_and_snapshot_catchup_zero_loss() {
    let pki = ClusterPki::new();
    let d1 = tempfile::tempdir().unwrap();
    let d2 = tempfile::tempdir().unwrap();
    let d3 = tempfile::tempdir().unwrap();
    let cfg = NodeConfig { snapshot_logs: 8, lag_threshold: 10 };

    let n1 = NodeProc::spawn(&pki, 1, d1.path(), &cfg);
    let n2 = NodeProc::spawn(&pki, 2, d2.path(), &cfg);
    let mut n3 = NodeProc::spawn(&pki, 3, d3.path(), &cfg);
    bootstrap_cluster(&[&n1, &n2, &n3]);
    let mut leader_id = wait_leader(&[&n1, &n2, &n3], Duration::from_secs(10));
    if leader_id == 3 {
        n3.shutdown_graceful();
        n3 = NodeProc::spawn(&pki, 3, d3.path(), &cfg);
        broadcast_peers(&[&n1, &n2, &n3], &peer_map(&[&n1, &n2, &n3]));
        leader_id = wait_leader(&[&n1, &n2], Duration::from_secs(10));
    }
    let _ = leader_id;

    let mut last_idx = 0u64;
    for i in 0..4 {
        last_idx = write_kv(&[&n1, &n2, &n3], &format!("en-{i:02}"), &format!("val-{i:02}"));
    }
    wait_all_converged(&[&n1, &n2, &n3], last_idx, Duration::from_secs(10));

    // Inject ENOSPC on n3 log append while {n1, n2} advance well past snapshot_logs threshold.
    inject_fault(&n3, FaultTarget::Log, FaultSpec { point: FaultPoint::LogAppendEnospc, mode: FaultMode::Always });
    for i in 4..20 {
        last_idx = write_kv(&[&n1, &n2], &format!("en-{i:02}"), &format!("val-{i:02}"));
    }
    wait_node_fatal(&n3, Duration::from_secs(8));
    n1.trigger_snapshot();
    n2.trigger_snapshot();
    n3.shutdown_graceful();

    // Recover n3 cleanly -> catches up via snapshot + log tail with zero committed loss.
    let n3_rec = NodeProc::spawn(&pki, 3, d3.path(), &cfg);
    broadcast_peers(&[&n1, &n2, &n3_rec], &peer_map(&[&n1, &n2, &n3_rec]));
    wait_all_converged(&[&n1, &n2, &n3_rec], last_idx, Duration::from_secs(12));

    // Inject SmApplyEnospc on n3 -> fail-stops cleanly without partial state; restart catches up.
    inject_fault(
        &n3_rec,
        FaultTarget::StateMachine,
        FaultSpec { point: FaultPoint::SmApplyEnospc, mode: FaultMode::Always },
    );
    for i in 20..23 {
        last_idx = write_kv(&[&n1, &n2], &format!("en-{i:02}"), &format!("val-{i:02}"));
    }
    wait_node_fatal(&n3_rec, Duration::from_secs(8));
    n3_rec.shutdown_graceful();

    let n3_final = NodeProc::spawn(&pki, 3, d3.path(), &cfg);
    let all = [&n1, &n2, &n3_final];
    broadcast_peers(&all, &peer_map(&all));
    wait_all_converged(&all, last_idx, Duration::from_secs(12));
    assert_all_keys(&all, "en", 23);

    n1.shutdown_graceful();
    n2.shutdown_graceful();
    n3_final.shutdown_graceful();
}

#[test]
fn corrupted_log_sm_or_snapshot_explicitly_refuses_startup() {
    let pki = ClusterPki::new();
    let d1 = tempfile::tempdir().unwrap();
    let d2 = tempfile::tempdir().unwrap();
    let d3 = tempfile::tempdir().unwrap();
    let cfg = NodeConfig::default();

    let n1 = NodeProc::spawn(&pki, 1, d1.path(), &cfg);
    let n2 = NodeProc::spawn(&pki, 2, d2.path(), &cfg);
    let n3 = NodeProc::spawn(&pki, 3, d3.path(), &cfg);
    bootstrap_cluster(&[&n1, &n2, &n3]);
    let _ = wait_leader(&[&n1, &n2, &n3], Duration::from_secs(10));

    let mut last_idx = 0u64;
    for i in 0..6 {
        last_idx = write_kv(&[&n1, &n2, &n3], &format!("cr-{i:02}"), &format!("val-{i:02}"));
    }
    wait_all_converged(&[&n1, &n2, &n3], last_idx, Duration::from_secs(10));
    n3.trigger_snapshot();
    // Wait until snapshot metadata is persisted before shutting down n3.
    let deadline = Instant::now() + Duration::from_secs(8);
    while n3.metrics().snapshot_index.is_none() {
        assert!(Instant::now() < deadline, "n3 did not persist snapshot");
        std::thread::sleep(Duration::from_millis(40));
    }
    n3.shutdown_graceful();

    let snap_path = find_active_snap(d3.path());
    let snap_orig = std::fs::read(&snap_path).unwrap();
    let sm_orig = std::fs::read(d3.path().join("sm.sqlite3")).unwrap();
    let log_orig = std::fs::read(d3.path().join("log.sqlite3")).unwrap();

    // 1. Corrupt active snapshot file -> must refuse startup.
    let mut bad_snap = snap_orig.clone();
    let mid = bad_snap.len() / 2;
    bad_snap[mid] ^= 0xff;
    std::fs::write(&snap_path, &bad_snap).unwrap();
    let err_snap = spawn_corrupt_expect_refused(&pki, 3, d3.path());
    assert!(err_snap.contains("open sm"), "expected sm refusal on corrupt snap: {err_snap}");
    std::fs::write(&snap_path, &snap_orig).unwrap();

    // 2. Corrupt sm.sqlite3 -> must refuse startup.
    {
        let mut f = OpenOptions::new().write(true).open(d3.path().join("sm.sqlite3")).unwrap();
        f.write_all(b"CORRUPT-SM-HEADER").unwrap();
    }
    let err_sm = spawn_corrupt_expect_refused(&pki, 3, d3.path());
    assert!(err_sm.contains("open sm"), "expected sm refusal on corrupt db: {err_sm}");
    std::fs::write(d3.path().join("sm.sqlite3"), &sm_orig).unwrap();

    // 3. Corrupt log.sqlite3 -> must refuse startup.
    {
        let mut f = OpenOptions::new().write(true).open(d3.path().join("log.sqlite3")).unwrap();
        f.write_all(b"CORRUPT-LOG-HEADER").unwrap();
    }
    let err_log = spawn_corrupt_expect_refused(&pki, 3, d3.path());
    assert!(err_log.contains("open log"), "expected log refusal on corrupt db: {err_log}");
    std::fs::write(d3.path().join("log.sqlite3"), &log_orig).unwrap();

    // Restoring intact files succeeds cleanly and keeps all committed keys.
    let n3_restored = NodeProc::spawn(&pki, 3, d3.path(), &cfg);
    let all = [&n1, &n2, &n3_restored];
    broadcast_peers(&all, &peer_map(&all));
    wait_all_converged(&all, last_idx, Duration::from_secs(10));
    assert_all_keys(&all, "cr", 6);

    n1.shutdown_graceful();
    n2.shutdown_graceful();
    n3_restored.shutdown_graceful();
}

#[test]
fn persisted_vote_prevents_double_vote_across_sigkill_and_restart() {
    let pki = ClusterPki::new();
    let dir = tempfile::tempdir().unwrap();
    qualify_store_dir(dir.path(), true, DEFAULT_MIN_FREE_BYTES).unwrap();
    let cfg = NodeConfig::default();

    let n1 = NodeProc::spawn(&pki, 1, dir.path(), &cfg);
    match n1.rpc(&RpcRequest::Vote(VoteRequest::new(Vote::new(5, 7), None))) {
        RpcResponse::Vote(resp) => {
            let resp = resp.unwrap();
            assert!(resp.vote_granted, "initial term 5 vote should be granted");
        }
        other => panic!("unexpected vote response: {other:?}"),
    }
    assert_eq!(n1.metrics().persisted_vote, Some(Vote::new(5, 7)));
    n1.kill_sigkill();

    let n1_restarted = NodeProc::spawn(&pki, 1, dir.path(), &cfg);
    assert_eq!(n1_restarted.metrics().persisted_vote, Some(Vote::new(5, 7)));

    // Lower-rank competing candidate in SAME term 5 and lower-term candidate MUST be rejected after crash recovery.
    for competing in [Vote::new(5, 2), Vote::new(4, 99)] {
        match n1_restarted.rpc(&RpcRequest::Vote(VoteRequest::new(competing, None))) {
            RpcResponse::Vote(resp) => {
                let resp = resp.unwrap();
                assert!(!resp.vote_granted, "MUST NOT double-vote for {competing:?} across kill -9");
                assert_eq!(resp.vote, Vote::new(5, 7));
            }
            other => panic!("unexpected competing vote response: {other:?}"),
        }
    }
    // Same candidate 7 in term 5 still accepted cleanly.
    match n1_restarted.rpc(&RpcRequest::Vote(VoteRequest::new(Vote::new(5, 7), None))) {
        RpcResponse::Vote(resp) => assert!(resp.unwrap().vote_granted),
        other => panic!("unexpected same-candidate vote response: {other:?}"),
    }

    // Injected fsync error on term 6 vote rolls back cleanly; persisted vote stays term 5 node 7.
    inject_fault(&n1_restarted, FaultTarget::Log, FaultSpec { point: FaultPoint::LogVoteSync, mode: FaultMode::Once });
    let term6_res = n1_restarted.rpc(&RpcRequest::Vote(VoteRequest::new(Vote::new(6, 9), None)));
    match term6_res {
        RpcResponse::Vote(boxed) => assert!(boxed.is_err(), "expected vote fsync error, got {boxed:?}"),
        RpcResponse::Error { .. } => {}
        other => panic!("expected vote fsync failure error, got {other:?}"),
    }
    n1_restarted.shutdown_graceful();

    let n1_final = NodeProc::spawn(&pki, 1, dir.path(), &cfg);
    assert_eq!(n1_final.metrics().persisted_vote, Some(Vote::new(5, 7)));
    n1_final.shutdown_graceful();
}

#[test]
fn live_membership_change_with_snapshot_and_restart() {
    let pki = ClusterPki::new();
    let d1 = tempfile::tempdir().unwrap();
    let d2 = tempfile::tempdir().unwrap();
    let d3 = tempfile::tempdir().unwrap();
    let cfg = NodeConfig { snapshot_logs: 8, lag_threshold: 10 };

    let mut n1 = NodeProc::spawn(&pki, 1, d1.path(), &cfg);
    let n2 = NodeProc::spawn(&pki, 2, d2.path(), &cfg);
    bootstrap_cluster(&[&n1, &n2]);
    let _ = wait_leader(&[&n1, &n2], Duration::from_secs(10));

    let mut last_idx = 0u64;
    for i in 0..8 {
        last_idx = write_kv(&[&n1, &n2], &format!("mc-{i:02}"), &format!("val-{i:02}"));
    }
    wait_all_converged(&[&n1, &n2], last_idx, Duration::from_secs(10));
    n1.trigger_snapshot();
    n2.trigger_snapshot();

    // Bring up node 3, add as learner, promote to voter {1, 2, 3}.
    let n3 = NodeProc::spawn(&pki, 3, d3.path(), &cfg);
    let all_peers = peer_map(&[&n1, &n2, &n3]);
    broadcast_peers(&[&n1, &n2, &n3], &all_peers);
    add_learner_and_promote(&[&n1, &n2], &n3, BTreeSet::from([1, 2, 3]));

    for i in 8..12 {
        last_idx = write_kv(&[&n1, &n2, &n3], &format!("mc-{i:02}"), &format!("val-{i:02}"));
    }
    wait_all_converged(&[&n1, &n2, &n3], last_idx, Duration::from_secs(12));

    // Crash n1 via kill -9 and recover: membership {1, 2, 3} + all KV preserved.
    n1.kill_sigkill();
    n1 = NodeProc::spawn(&pki, 1, d1.path(), &cfg);
    let all = [&n1, &n2, &n3];
    broadcast_peers(&all, &peer_map(&all));
    wait_all_converged(&all, last_idx, Duration::from_secs(12));
    for n in all {
        assert_eq!(n.metrics().membership_voters, vec![1, 2, 3]);
    }
    assert_all_keys(&all, "mc", 12);

    n1.shutdown_graceful();
    n2.shutdown_graceful();
    n3.shutdown_graceful();
}

#[test]
fn harness_pre_ready_failure_kills_and_reaps_child_boundedly() {
    let pki = ClusterPki::new();
    let dir = tempfile::tempdir().unwrap();
    let cfg = NodeConfig::default();
    let start = Instant::now();
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = NodeProc::spawn_with_ready_timeout(&pki, 1, dir.path(), &cfg, Duration::from_millis(1));
    }));
    assert!(res.is_err(), "1ms READY timeout must fail loudly");
    assert!(start.elapsed() < Duration::from_secs(6), "OwnedChild drop took too long to kill/reap");

    std::thread::sleep(Duration::from_millis(150));
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let log = PersistentLog::open(dir.path(), 1, true).await.expect("reclaimed log lock after pre-READY kill");
        let sm =
            PersistentStateMachine::open(dir.path(), 1, true).await.expect("reclaimed sm lock after pre-READY kill");
        drop((log, sm));
    });
}
