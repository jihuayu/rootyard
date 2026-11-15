//! Integration checks for #115: mTLS peer/client auth, ReadIndex quorum barriers,
//! minority read/write refusal, bounded metadata WAL, membership changes, and isolation.

#[path = "helpers/cluster_harness.rs"]
mod harness;
#[path = "helpers/tls_certs.rs"]
mod tls_certs;

use std::collections::BTreeSet;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use openraft::Vote;
use openraft::raft::AppendEntriesRequest;

use rootyard_refcas_log::MAX_ENTRY_BYTES;
use rootyard_refcas_log::cluster::{PeerDirectory, RpcRequest, RpcResponse, rpc_expect_ok, send_rpc};
use rootyard_refcas_log::mtls::{CLIENT_DNS_NAME, MtlsClient, node_dns_name};
use rootyard_refcas_log::state_machine::SmCommand;

use harness::{
    NodeConfig, NodeProc, add_learner_and_promote, bootstrap_cluster, broadcast_peers, peer_map, wait_all_converged,
    wait_leader, write_kv,
};
use tls_certs::{ClusterPki, write_ca, write_leaf};

fn linearizable_get(leader: &NodeProc, key: &str) -> (Option<String>, u64) {
    match leader.rpc(&RpcRequest::KvGet { key: key.to_owned() }) {
        RpcResponse::KvValue { value, read_log_id } => (value, read_log_id.expect("ReadIndex log_id").index),
        other => panic!("expected linearizable KvValue from leader {}, got {other:?}", leader.id),
    }
}

fn wait_new_leader_excluding(nodes: &[&NodeProc], excluded_id: u64, timeout: Duration) -> u64 {
    let deadline = Instant::now() + timeout;
    loop {
        for n in nodes {
            if let Ok(RpcResponse::Metrics(m)) = n.try_rpc(&RpcRequest::Metrics)
                && m.running_ok
                && let Some(lid) = m.current_leader
                && lid != excluded_id
                && nodes.iter().any(|p| p.id == lid)
            {
                return lid;
            }
        }
        assert!(Instant::now() < deadline, "timed out waiting for new leader excluding {excluded_id}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn raft_node_refuses_startup_without_mtls_or_with_mismatched_node_cert() {
    let bin = env!("CARGO_BIN_EXE_raft-node");
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(bin)
        .args(["--id", "1", "--dir", &dir.path().to_string_lossy()])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn raft-node without mTLS flags");
    assert!(!out.status.success(), "raft-node MUST refuse startup when --tls-* flags are missing");

    let pki = ClusterPki::new();
    let wrong = pki.node_paths(2);
    let mismatched = Command::new(bin)
        .args([
            "--id",
            "1",
            "--dir",
            &dir.path().to_string_lossy(),
            "--tls-ca",
            &wrong.ca_cert.to_string_lossy(),
            "--tls-cert",
            &wrong.cert.to_string_lossy(),
            "--tls-key",
            &wrong.key.to_string_lossy(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn raft-node with mismatched SAN cert");
    assert!(!mismatched.status.success(), "raft-node MUST refuse mismatched node SAN cert");
    let stderr = String::from_utf8_lossy(&mismatched.stderr);
    assert!(stderr.contains("SAN identity"), "expected SAN mismatch refusal, got: {stderr}");
}

#[test]
fn mtls_cluster_rejects_untrusted_wrong_san_spoofed_peer_and_plaintext() {
    let pki = ClusterPki::new();
    let d1 = tempfile::tempdir().unwrap();
    let d2 = tempfile::tempdir().unwrap();
    let d3 = tempfile::tempdir().unwrap();
    let cfg = NodeConfig::default();

    let n1 = NodeProc::spawn(&pki, 1, d1.path(), &cfg);
    let n2 = NodeProc::spawn(&pki, 2, d2.path(), &cfg);
    let n3 = NodeProc::spawn(&pki, 3, d3.path(), &cfg);
    let all = [&n1, &n2, &n3];
    bootstrap_cluster(&all);
    let leader_id = wait_leader(&all, Duration::from_secs(10));
    let _ = write_kv(&all, "mtls-init", "ok");

    // 1. Plaintext TCP fails cleanly against mTLS listener.
    {
        use std::io::{Read, Write};
        let mut raw = std::net::TcpStream::connect(&n1.addr).unwrap();
        raw.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let _ = raw.write_all(b"\x00\x00\x00\x02{}");
        let mut buf = Vec::new();
        let _ = raw.read_to_end(&mut buf);
        assert!(buf.is_empty() || buf.first().copied() == Some(0x15));
    }

    // 2. Rogue-CA client and same-CA wrong-SAN client fail closed.
    let rogue_dir = tempfile::tempdir().unwrap();
    let (r_key, r_params, r_ca_path) = write_ca(rogue_dir.path(), "rogue-ca");
    let r_issuer = rcgen::CertifiedIssuer::self_signed(r_params, r_key).unwrap();
    let rogue_paths = write_leaf(rogue_dir.path(), "rogue-cli", &r_issuer, &r_ca_path, CLIENT_DNS_NAME);
    let rogue_client = MtlsClient::from_paths(&rogue_paths).unwrap();
    assert!(send_rpc(&rogue_client, &n1.addr, 1, &RpcRequest::Metrics).is_err());

    // 3. Peer node-3 cert fails hostname validation when claiming to reach node-2 at node-1's socket,
    // and when reaching node-1 validly is blocked from control RPCs or forged node-1 Raft RPCs.
    let n3_client = MtlsClient::from_paths(&pki.node_paths(3)).unwrap();
    assert!(send_rpc(&n3_client, &n1.addr, 2, &RpcRequest::Metrics).is_err());

    let denied_ctrl = send_rpc(&n3_client, &n1.addr, 1, &RpcRequest::KvGet { key: "mtls-init".into() }).unwrap();
    assert!(matches!(denied_ctrl, RpcResponse::Error { .. }), "peer cert must not run client RPC: {denied_ctrl:?}");

    let forged_append = RpcRequest::AppendEntries(AppendEntriesRequest {
        vote: Vote::new(99, 1),
        prev_log_id: None,
        entries: Vec::new(),
        leader_commit: None,
    });
    let denied_forge = send_rpc(&n3_client, &n1.addr, 1, &forged_append).unwrap();
    assert!(
        matches!(denied_forge, RpcResponse::Error { ref message, .. } if message.contains("forged")),
        "peer 3 forging leader 1 RPC must fail closed: {denied_forge:?}"
    );

    // 4. Client cert cannot send peer replication RPCs.
    let denied_repl = n1.rpc(&forged_append);
    assert!(matches!(denied_repl, RpcResponse::Error { .. }), "client cert must not invoke peer AppendEntries");

    let leader = all.iter().find(|n| n.id == leader_id).unwrap();
    assert_eq!(linearizable_get(leader, "mtls-init").0.as_deref(), Some("ok"));
    assert_eq!(PeerDirectory::new().get(1), None);
    let _ = node_dns_name(1);

    n1.shutdown_graceful();
    n2.shutdown_graceful();
    n3.shutdown_graceful();
}

#[test]
fn read_index_enforces_quorum_barrier_and_minority_refuses_writes_and_reads() {
    let pki = ClusterPki::new();
    let d1 = tempfile::tempdir().unwrap();
    let d2 = tempfile::tempdir().unwrap();
    let d3 = tempfile::tempdir().unwrap();
    let cfg = NodeConfig::default();

    let n1 = NodeProc::spawn(&pki, 1, d1.path(), &cfg);
    let n2 = NodeProc::spawn(&pki, 2, d2.path(), &cfg);
    let n3 = NodeProc::spawn(&pki, 3, d3.path(), &cfg);
    let all = [&n1, &n2, &n3];
    bootstrap_cluster(&all);
    let leader_id = wait_leader(&all, Duration::from_secs(10));
    let mut last_idx = write_kv(&all, "rk-1", "v1");
    last_idx = write_kv(&all, "rk-2", "v2").max(last_idx);
    wait_all_converged(&all, last_idx, Duration::from_secs(10));

    let old_leader = *all.iter().find(|n| n.id == leader_id).unwrap();
    let majority: Vec<&NodeProc> = all.iter().copied().filter(|n| n.id != leader_id).collect();
    let follower_ids: BTreeSet<u64> = majority.iter().map(|n| n.id).collect();

    // Follower linearizable read fails with leader redirect instead of serving unverified local state.
    let follower_resp = majority[0].rpc(&RpcRequest::KvGet { key: "rk-1".into() });
    assert!(
        matches!(follower_resp, RpcResponse::Error { forward_to_leader_id: Some(lid), .. } if lid == leader_id),
        "follower KvGet must enforce leader/ReadIndex barrier: {follower_resp:?}"
    );

    // Leader linearizable read succeeds via ReadIndex and proves committed boundary >= last_idx.
    let (val, read_idx) = linearizable_get(old_leader, "rk-1");
    assert_eq!(val.as_deref(), Some("v1"));
    assert!(read_idx >= last_idx);
    match old_leader.rpc(&RpcRequest::EnsureReadIndex) {
        RpcResponse::ReadIndex { read_log_id, .. } => assert!(read_log_id.unwrap().index >= last_idx),
        other => panic!("unexpected EnsureReadIndex response: {other:?}"),
    }

    // Partition old_leader into 1-node minority before any new-term traffic reaches it.
    rpc_expect_ok(old_leader.rpc(&RpcRequest::PartitionPeers { blocked: follower_ids })).unwrap();
    for peer in &majority {
        rpc_expect_ok(peer.rpc(&RpcRequest::PartitionPeers { blocked: BTreeSet::from([leader_id]) })).unwrap();
    }

    // Stale/minority old leader MUST refuse both ReadIndex reads and authoritative writes.
    let stale_read = old_leader.rpc(&RpcRequest::KvGet { key: "rk-1".into() });
    assert!(matches!(stale_read, RpcResponse::Error { .. }), "minority stale leader served read: {stale_read:?}");
    let stale_barrier = old_leader.rpc(&RpcRequest::EnsureReadIndex);
    assert!(matches!(stale_barrier, RpcResponse::Error { .. }), "minority stale leader passed ReadIndex");

    let minority_write_payload = SmCommand::Put { key: "rk-stale".into(), value: "bad".into() }.encode().unwrap();
    let minority_write = old_leader.rpc(&RpcRequest::ClientWrite { payload: minority_write_payload });
    assert!(
        matches!(minority_write, RpcResponse::Error { .. }),
        "minority stale leader MUST refuse writes: {minority_write:?}"
    );

    // Surviving 2-voter majority elects a new leader, commits new values, and serves ReadIndex reads.
    let new_leader_id = wait_new_leader_excluding(&majority, leader_id, Duration::from_secs(10));
    last_idx = write_kv(&majority, "rk-1", "v2");
    last_idx = write_kv(&majority, "rk-3", "v3").max(last_idx);
    wait_all_converged(&majority, last_idx, Duration::from_secs(10));
    let new_leader = *majority.iter().find(|n| n.id == new_leader_id).unwrap();
    let (val2, read_idx2) = linearizable_get(new_leader, "rk-1");
    assert_eq!(val2.as_deref(), Some("v2"));
    assert!(read_idx2 >= last_idx);

    // Heal partition -> old leader steps down, reconciles, and converges without minority stale write.
    for n in &all {
        rpc_expect_ok(n.rpc(&RpcRequest::PartitionPeers { blocked: BTreeSet::new() })).unwrap();
    }
    wait_all_converged(&all, last_idx, Duration::from_secs(12));
    assert_eq!(old_leader.inspect_replica_kv("rk-1").as_deref(), Some("v2"));
    assert_eq!(old_leader.inspect_replica_kv("rk-stale"), None);
    assert_eq!(old_leader.inspect_replica_kv("rk-3").as_deref(), Some("v3"));

    // Total quorum loss: shutting down 2 of 3 voters leaves surviving node unable to read or write.
    n2.shutdown_graceful();
    n3.shutdown_graceful();
    let lone_read = n1.rpc(&RpcRequest::KvGet { key: "rk-1".into() });
    assert!(matches!(lone_read, RpcResponse::Error { .. }), "lone survivor served ReadIndex read: {lone_read:?}");
    let lone_write = SmCommand::Put { key: "rk-lone".into(), value: "nope".into() }.encode().unwrap();
    let lone_write_resp = n1.rpc(&RpcRequest::ClientWrite { payload: lone_write });
    assert!(matches!(lone_write_resp, RpcResponse::Error { .. }), "lone survivor accepted write: {lone_write_resp:?}");

    n1.shutdown_graceful();
}

#[test]
fn three_voter_wal_snapshot_membership_restart_and_blob_rejection() {
    let pki = ClusterPki::new();
    let d1 = tempfile::tempdir().unwrap();
    let d2 = tempfile::tempdir().unwrap();
    let d3 = tempfile::tempdir().unwrap();
    let d4 = tempfile::tempdir().unwrap();
    let cfg = NodeConfig { snapshot_logs: 6, lag_threshold: 8 };

    let n1 = NodeProc::spawn(&pki, 1, d1.path(), &cfg);
    let n2 = NodeProc::spawn(&pki, 2, d2.path(), &cfg);
    let n3 = NodeProc::spawn(&pki, 3, d3.path(), &cfg);
    let initial = [&n1, &n2, &n3];
    bootstrap_cluster(&initial);
    let leader_id = wait_leader(&initial, Duration::from_secs(10));
    let leader = *initial.iter().find(|n| n.id == leader_id).unwrap();

    // Oversized / blob-like payloads MUST be rejected before Raft WAL append without harming cluster health.
    let big_raw = leader.rpc(&RpcRequest::ClientWrite { payload: vec![b'B'; MAX_ENTRY_BYTES + 1] });
    assert!(matches!(big_raw, RpcResponse::Error { .. }), "WAL must refuse >1MiB blob payload");
    let big_kv =
        SmCommand::Put { key: "blob-ref".into(), value: "x".repeat(257 * 1024) }.encode().expect("encode big sm cmd");
    let big_kv_resp = leader.rpc(&RpcRequest::ClientWrite { payload: big_kv });
    assert!(matches!(big_kv_resp, RpcResponse::Error { .. }), "WAL must refuse >256KiB KV value");
    assert!(leader.metrics().running_ok);

    let mut last_idx = 0u64;
    for i in 0..10 {
        last_idx = write_kv(&initial, &format!("ref-{i:02}"), &format!("oid-{i:02}"));
    }
    wait_all_converged(&initial, last_idx, Duration::from_secs(10));
    leader.trigger_snapshot();
    assert!(leader.metrics().snapshot_index.is_some(), "leader should persist snapshot");

    // Add node 4 as learner, replicate snapshot + tail, promote to voter {1, 2, 3, 4}, then reconfigure to {2, 3, 4}.
    let n4 = NodeProc::spawn(&pki, 4, d4.path(), &cfg);
    let all_four = [&n1, &n2, &n3, &n4];
    broadcast_peers(&all_four, &peer_map(&all_four));
    add_learner_and_promote(&initial, &n4, BTreeSet::from([1, 2, 3, 4]));
    last_idx = write_kv(&all_four, "ref-promote", "v4");
    wait_all_converged(&all_four, last_idx, Duration::from_secs(12));

    let l_any_id = wait_leader(&all_four, Duration::from_secs(10));
    let l_any = *all_four.iter().find(|n| n.id == l_any_id).unwrap();
    rpc_expect_ok(l_any.rpc(&RpcRequest::ChangeMembership { members: BTreeSet::from([2, 3, 4]), retain: false }))
        .expect("reconfigure to 3 voters {2, 3, 4}");
    n1.shutdown_graceful();

    let three_v2 = [&n2, &n3, &n4];
    last_idx = write_kv(&three_v2, "ref-after-reconf", "v5");
    wait_all_converged(&three_v2, last_idx, Duration::from_secs(12));

    // SIGKILL node 3 and restart cleanly: persisted WAL/snapshot + membership {2, 3, 4} preserved.
    let n3_dir = n3.dir.clone();
    n3.kill_sigkill();
    let n3_rec = NodeProc::spawn(&pki, 3, &n3_dir, &cfg);
    let three_rec = [&n2, &n3_rec, &n4];
    broadcast_peers(&three_rec, &peer_map(&three_rec));
    wait_all_converged(&three_rec, last_idx, Duration::from_secs(12));
    let final_lid = wait_leader(&three_rec, Duration::from_secs(10));
    let final_leader = *three_rec.iter().find(|n| n.id == final_lid).unwrap();
    assert_eq!(linearizable_get(final_leader, "ref-09").0.as_deref(), Some("oid-09"));
    assert_eq!(linearizable_get(final_leader, "ref-promote").0.as_deref(), Some("v4"));
    assert_eq!(linearizable_get(final_leader, "ref-after-reconf").0.as_deref(), Some("v5"));
    assert!(n3_rec.metrics().persisted_vote.is_some());
    for n in three_rec {
        let m = n.metrics();
        assert_eq!(m.membership_voters, vec![2, 3, 4]);
        assert_eq!(m.current_leader, Some(final_lid));
    }

    n2.shutdown_graceful();
    n3_rec.shutdown_graceful();
    n4.shutdown_graceful();
}

#[test]
fn standalone_crate_boundary_excludes_blob_pg_redis_and_root_links() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let crate_lock = std::fs::read_to_string(manifest_dir.join("Cargo.lock")).unwrap();
    for forbidden in ["\"opendal\"", "\"sqlx\"", "\"redis\"", "\"rdkafka\"", "\"postgres\"", "\"rootyard\""] {
        assert!(!crate_lock.contains(forbidden), "refcas-log Cargo.lock must not pull {forbidden}");
    }
    let root_toml = std::fs::read_to_string(manifest_dir.join("../..").join("Cargo.toml")).unwrap();
    assert!(
        !root_toml.contains("refcas-log"),
        "root Cargo.toml must not link refcas-log into standalone serve/serve-blob binary"
    );
}
