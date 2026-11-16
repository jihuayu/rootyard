//! Integration tests for #150: tenant-scoped mTLS SAN binding, wide-token refusal,
//! follower ReadIndex + LeaderRedirect, bounded outage recovery, epoch fences, and stream backpressure.

#[path = "helpers/tenant_cluster.rs"]
mod tenant_cluster;

use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

use rootyard_refcas_log::cluster::{
    RpcRequest, read_frame_bounded_async, send_rpc_named_async, write_frame_bounded_async,
};
use rootyard_refcas_log::mtls::{
    MtlsServer, RpcCapability, extract_peer_identity, extract_tenant_client_scope, node_dns_name,
    tenant_client_dns_name, tenant_scope_uri,
};
use rootyard_refcas_log::state_machine::SmCommand;
use rootyard_refcas_log::streaming::{
    MAX_CHANNEL_CAPACITY, MAX_RAFT_PROPOSAL_BYTES, MAX_STREAM_TOTAL_BYTES, StreamConfig, StreamFrame,
};
use rootyard_refcas_log::tenant_rpc::{
    MAX_TENANT_RPC_FRAME_BYTES, TenantOp, TenantRpcClient, TenantRpcErrorCode, TenantRpcRequest, TenantRpcResponse,
};
use tenant_cluster::{
    AUTH_1, AUTH_2, GROUP_ALPHA, GROUP_BETA, HIST_1, HIST_2, TENANT_A, TENANT_B, TenantTestCluster, default_realm,
    read_der, realm, token,
};

#[tokio::test]
async fn tenant_san_and_mtls_reject_forged_role_confused_unscoped_cross_tenant_and_wide_tokens() {
    let cluster = TenantTestCluster::start_three(default_realm()).await;
    let (leader_id, _) = cluster.wait_leader(Duration::from_secs(5)).await;
    let leader = cluster.node(leader_id);
    let tenant_addr = leader.rpc_server.addr().to_owned();

    // 1. SAN parser role separation & tamper rejection checks.
    let node_der = read_der(&cluster.pki.node_paths(1).cert);
    assert!(extract_tenant_client_scope(&node_der).is_err(), "node cert must not pass tenant SAN check");
    assert!(extract_peer_identity(&node_der).is_ok());

    let tenant_a_paths = cluster.pki.tenant_paths(
        "tenant-a-rws",
        TENANT_A,
        GROUP_ALPHA,
        &[RpcCapability::Read, RpcCapability::Write, RpcCapability::Stream],
    );
    let tenant_a_der = read_der(&tenant_a_paths.cert);
    assert!(extract_peer_identity(&tenant_a_der).is_err(), "tenant cert must not pose as cluster peer");
    let parsed_a = extract_tenant_client_scope(&tenant_a_der).unwrap();
    assert_eq!(parsed_a.tenant_id, TENANT_A);
    assert_eq!(parsed_a.group_id, GROUP_ALPHA);

    // Mixed peer DNS + tenant URI SAN rejected, missing URI SAN rejected, mismatched tenant UUID rejected.
    let mixed_paths = cluster.pki.issue_san_strings(
        "mixed-role",
        vec![node_dns_name(2)],
        vec![tenant_scope_uri(TENANT_A, GROUP_ALPHA, &([RpcCapability::Read].into())).unwrap()],
    );
    assert!(extract_tenant_client_scope(&read_der(&mixed_paths.cert)).is_err());
    assert!(extract_peer_identity(&read_der(&mixed_paths.cert)).is_err());

    let unscoped_tenant =
        cluster.pki.issue_san_strings("unscoped-tenant-dns", vec![tenant_client_dns_name(TENANT_A).unwrap()], vec![]);
    assert!(extract_tenant_client_scope(&read_der(&unscoped_tenant.cert)).is_err());

    let mismatch_san = cluster.pki.issue_san_strings(
        "cross-san",
        vec![tenant_client_dns_name(TENANT_A).unwrap()],
        vec![tenant_scope_uri(TENANT_B, GROUP_ALPHA, &([RpcCapability::Read].into())).unwrap()],
    );
    assert!(extract_tenant_client_scope(&read_der(&mismatch_san.cert)).is_err());

    // 2. Live TLS handshake refusals: rogue CA, peer node cert, unscoped cluster client, mixed cert.
    let rogue_paths = cluster.pki.issue_untrusted(
        "rogue-a",
        &tenant_client_dns_name(TENANT_A).unwrap(),
        &tenant_scope_uri(TENANT_A, GROUP_ALPHA, &([RpcCapability::Read].into())).unwrap(),
    );
    for (label, bad_paths) in [
        ("rogue-ca", &rogue_paths),
        ("peer-node-on-tenant-port", &cluster.pki.node_paths(2)),
        ("unscoped-generic-client", &cluster.pki.generic_client_paths()),
        ("unscoped-tenant-dns-no-uri", &unscoped_tenant),
    ] {
        let cli = TenantRpcClient::new(cluster.pki.client_from(bad_paths), Duration::from_secs(2), 2);
        let req = TenantRpcRequest {
            realm: default_realm(),
            bearer_token: token(TENANT_A, GROUP_ALPHA, AUTH_1, RpcCapability::Read),
            op: TenantOp::ReadIndex,
        };
        assert!(cli.call_once(&tenant_addr, leader_id, &req).await.is_err(), "{label} must fail closed");
    }

    // Tenant cert must also fail on internal Raft peer replication port.
    assert!(
        send_rpc_named_async(
            &cluster.pki.client_from(&tenant_a_paths),
            &leader.raft_addr,
            &node_dns_name(leader_id),
            &RpcRequest::Metrics,
        )
        .await
        .is_err(),
        "tenant client cert cannot talk to internal cluster peer RPC"
    );

    // 3. Cross-tenant reuse, wrong group, capability narrowing, and wide bearer token refusal.
    let cli_a = TenantRpcClient::new(cluster.pki.client_from(&tenant_a_paths), Duration::from_secs(2), 2);
    let cross_tenant_req = TenantRpcRequest {
        realm: realm(TENANT_B, GROUP_ALPHA, AUTH_1, HIST_1, 3, 7),
        bearer_token: token(TENANT_B, GROUP_ALPHA, AUTH_1, RpcCapability::Read),
        op: TenantOp::ReadIndex,
    };
    let resp = cli_a.call_once(&tenant_addr, leader_id, &cross_tenant_req).await.unwrap();
    assert!(matches!(resp, TenantRpcResponse::Error(ref e) if e.code == TenantRpcErrorCode::CrossTenantDenied));

    let wrong_group_req = TenantRpcRequest {
        realm: realm(TENANT_A, GROUP_BETA, AUTH_1, HIST_1, 3, 7),
        bearer_token: token(TENANT_A, GROUP_BETA, AUTH_1, RpcCapability::Read),
        op: TenantOp::ReadIndex,
    };
    let resp = cli_a.call_once(&tenant_addr, leader_id, &wrong_group_req).await.unwrap();
    assert!(matches!(resp, TenantRpcResponse::Error(ref e) if e.code == TenantRpcErrorCode::WrongGroup));

    for wide_tok in [
        "",
        "*",
        "all",
        "global",
        "unscoped",
        "ryt1;tenant=*;group=group-alpha;auth=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa;cap=read",
        "ryt1;tenant=11111111-1111-4111-8111-111111111111;group=group-alpha;auth=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa;cap=*",
    ] {
        let req =
            TenantRpcRequest { realm: default_realm(), bearer_token: wide_tok.to_owned(), op: TenantOp::ReadIndex };
        let r = cli_a.call_once(&tenant_addr, leader_id, &req).await.unwrap();
        assert!(matches!(r, TenantRpcResponse::Error(ref e) if e.code == TenantRpcErrorCode::WideTokenRejected));
    }

    // Read-only tenant cert cannot invoke Write RPC even with write bearer token.
    let ro_paths = cluster.pki.tenant_paths("ro-a", TENANT_A, GROUP_ALPHA, &[RpcCapability::Read]);
    let cli_ro = TenantRpcClient::new(cluster.pki.client_from(&ro_paths), Duration::from_secs(2), 2);
    let write_req = TenantRpcRequest {
        realm: default_realm(),
        bearer_token: token(TENANT_A, GROUP_ALPHA, AUTH_1, RpcCapability::Write),
        op: TenantOp::ProposeKv { command: SmCommand::Put { key: "k".into(), value: "v".into() } },
    };
    let r = cli_ro.call_once(&tenant_addr, leader_id, &write_req).await.unwrap();
    assert!(matches!(r, TenantRpcResponse::Error(ref e) if e.code == TenantRpcErrorCode::ForbiddenCapability));

    cluster.shutdown().await;
}

#[tokio::test]
async fn follower_linearizable_read_via_readindex_leader_redirect_and_bounded_outage() {
    let cluster = TenantTestCluster::start_three(default_realm()).await;
    let (leader_id, _) = cluster.wait_leader(Duration::from_secs(5)).await;
    let follower_id = cluster.first_follower_id(leader_id);
    let follower_addr = cluster.node(follower_id).rpc_server.addr().to_owned();

    let paths =
        cluster.pki.tenant_paths("tenant-a-rw", TENANT_A, GROUP_ALPHA, &[RpcCapability::Read, RpcCapability::Write]);
    let client = TenantRpcClient::new(cluster.pki.client_from(&paths), Duration::from_secs(3), 3);

    // 1. Follower returns structured LeaderRedirect on write & ReadIndex; auto-redirect lands on leader.
    let write_req = TenantRpcRequest {
        realm: default_realm(),
        bearer_token: token(TENANT_A, GROUP_ALPHA, AUTH_1, RpcCapability::Write),
        op: TenantOp::ProposeKv { command: SmCommand::Put { key: "refs/heads/main".into(), value: "oid-1".into() } },
    };
    let direct_follower_resp = client.call_once(&follower_addr, follower_id, &write_req).await.unwrap();
    assert!(
        matches!(direct_follower_resp, TenantRpcResponse::LeaderRedirect(ref r) if r.leader_id == leader_id),
        "follower write must emit LeaderRedirect, got {direct_follower_resp:?}"
    );

    let (committed, served_by, hops) =
        client.call_with_redirect(&follower_addr, follower_id, &write_req).await.unwrap();
    assert_eq!(served_by, leader_id);
    assert_eq!(hops, 1);
    let write_idx = match committed {
        TenantRpcResponse::CommitReceipt { log_index, storage_generation, .. } => {
            assert_eq!(storage_generation, 7);
            log_index
        }
        other => panic!("expected CommitReceipt, got {other:?}"),
    };

    // Immediate linearizable read addressed to follower redirects + satisfies ReadIndex barrier >= write_idx.
    let get_req = TenantRpcRequest {
        realm: default_realm(),
        bearer_token: token(TENANT_A, GROUP_ALPHA, AUTH_1, RpcCapability::Read),
        op: TenantOp::LinearizableGet { key: "refs/heads/main".into() },
    };
    let once_get = client.call_once(&follower_addr, follower_id, &get_req).await.unwrap();
    assert!(matches!(once_get, TenantRpcResponse::LeaderRedirect(ref r) if r.leader_id == leader_id));

    let (read_resp, read_node, read_hops) =
        client.call_with_redirect(&follower_addr, follower_id, &get_req).await.unwrap();
    assert_eq!(read_node, leader_id);
    assert_eq!(read_hops, 1);
    match read_resp {
        TenantRpcResponse::LinearizableValue { value, read_log_id, storage_generation, .. } => {
            assert_eq!(value.as_deref(), Some("oid-1"));
            assert_eq!(storage_generation, 7);
            assert!(read_log_id.unwrap().index >= write_idx);
        }
        other => panic!("expected LinearizableValue, got {other:?}"),
    }

    // 2. Network partition on isolated leader (minority) fails closed in bounded time (zero PG/stale fallback).
    let leader_addr = cluster.node(leader_id).rpc_server.addr().to_owned();
    cluster.partition_node(leader_id);
    let part_read = client.call_once(&leader_addr, leader_id, &get_req).await.unwrap();
    assert!(
        matches!(part_read, TenantRpcResponse::Error(ref e) if e.code == TenantRpcErrorCode::QuorumUnavailable),
        "isolated minority leader must fail closed on ReadIndex without stale local read, got {part_read:?}"
    );
    let part_write = client.call_once(&leader_addr, leader_id, &write_req).await.unwrap();
    assert!(
        matches!(part_write, TenantRpcResponse::Error(ref e) if e.code == TenantRpcErrorCode::QuorumUnavailable),
        "isolated minority leader must fail closed on write, got {part_write:?}"
    );
    // Partitioned follower queried directly via call_once may either refuse QuorumUnavailable or emit
    // LeaderRedirect to the reachable majority, never a stale local LinearizableValue.
    cluster.heal_partitions();
    cluster.partition_node(follower_id);
    let follower_part = client.call_once(&follower_addr, follower_id, &get_req).await.unwrap();
    assert!(
        !matches!(follower_part, TenantRpcResponse::LinearizableValue { .. }),
        "partitioned follower must never return stale local LinearizableValue, got {follower_part:?}"
    );
    cluster.heal_partitions();

    // 3. Stalled/blackholed TLS server hits strict caller deadline deterministically.
    let blackhole = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bh_addr = blackhole.local_addr().unwrap().to_string();
    let _accept_hold = tokio::spawn(async move {
        let (_sock, _) = blackhole.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(5)).await;
    });
    let short_cli = TenantRpcClient::new(cluster.pki.client_from(&paths), Duration::from_millis(120), 2);
    let started = Instant::now();
    let deadline_err = short_cli.call_once(&bh_addr, leader_id, &get_req).await.unwrap_err();
    assert_eq!(deadline_err.code, TenantRpcErrorCode::DeadlineExceeded);
    assert!(started.elapsed() < Duration::from_millis(700));

    cluster.shutdown().await;
}

#[tokio::test]
async fn stale_authority_history_group_epoch_and_term_vs_storage_generation_separation() {
    let cluster = TenantTestCluster::start_three(default_realm()).await;
    let (leader1, term1) = cluster.wait_leader(Duration::from_secs(5)).await;
    let follower_id = cluster.first_follower_id(leader1);

    let paths =
        cluster.pki.tenant_paths("tenant-a-rw2", TENANT_A, GROUP_ALPHA, &[RpcCapability::Read, RpcCapability::Write]);
    let client = TenantRpcClient::new(cluster.pki.client_from(&paths), Duration::from_secs(6), 4);

    // 1. Isolate leader1 so nodes elect leader2 at raft_term > term1 while business storage_generation stays 7.
    cluster.partition_node(leader1);
    let (leader2, term2) = cluster.wait_leader_excluding(leader1, term1 + 1, Duration::from_secs(15)).await;
    assert!(term2 > term1);

    // Client sending stale redirect / querying follower gets safe LeaderRedirect onto leader2 with storage_generation == 7.
    let probe_id = cluster.nodes.iter().find(|n| n.id != leader1 && n.id != leader2).unwrap().id;
    let probe_addr = cluster.node(probe_id).rpc_server.addr().to_owned();
    let valid_req = TenantRpcRequest {
        realm: default_realm(),
        bearer_token: token(TENANT_A, GROUP_ALPHA, AUTH_1, RpcCapability::Read),
        op: TenantOp::ReadIndex,
    };
    let (resp, served_by, _) = client.call_with_redirect(&probe_addr, probe_id, &valid_req).await.unwrap();
    assert_eq!(served_by, leader2);
    match resp {
        TenantRpcResponse::ReadIndex { raft_term, storage_generation, .. } => {
            assert_eq!(raft_term, term2);
            assert_eq!(storage_generation, 7, "raft_term must never mutate business storage_generation");
        }
        other => panic!("expected ReadIndex, got {other:?}"),
    }

    // Passing raft_term as storage_generation MUST fail closed.
    let leader2_addr = cluster.node(leader2).rpc_server.addr().to_owned();
    let confused_gen_req = TenantRpcRequest {
        realm: realm(TENANT_A, GROUP_ALPHA, AUTH_1, HIST_1, 3, term2),
        bearer_token: token(TENANT_A, GROUP_ALPHA, AUTH_1, RpcCapability::Read),
        op: TenantOp::ReadIndex,
    };
    let err = client.call_with_redirect(&leader2_addr, leader2, &confused_gen_req).await.unwrap_err();
    assert_eq!(err.code, TenantRpcErrorCode::StaleStorageGeneration);

    // 2. Rotate authority_id, history_id, group_epoch on nodes -> old coordinates fail closed deterministically.
    cluster.heal_partitions();
    for n in &cluster.nodes {
        let mut reg = n.registry.write().unwrap();
        reg.rotate_authority(TENANT_A, AUTH_2);
        reg.rotate_history(TENANT_A, HIST_2);
        reg.advance_group_epoch(TENANT_A, 4);
    }

    let stale_cases = [
        (
            "stale-authority",
            realm(TENANT_A, GROUP_ALPHA, AUTH_1, HIST_2, 4, 7),
            token(TENANT_A, GROUP_ALPHA, AUTH_1, RpcCapability::Read),
            TenantRpcErrorCode::StaleAuthority,
        ),
        (
            "stale-history",
            realm(TENANT_A, GROUP_ALPHA, AUTH_2, HIST_1, 4, 7),
            token(TENANT_A, GROUP_ALPHA, AUTH_2, RpcCapability::Read),
            TenantRpcErrorCode::StaleHistory,
        ),
        (
            "stale-group-epoch",
            realm(TENANT_A, GROUP_ALPHA, AUTH_2, HIST_2, 3, 7),
            token(TENANT_A, GROUP_ALPHA, AUTH_2, RpcCapability::Read),
            TenantRpcErrorCode::StaleGroupEpoch,
        ),
        (
            "future-group-epoch",
            realm(TENANT_A, GROUP_ALPHA, AUTH_2, HIST_2, 99, 7),
            token(TENANT_A, GROUP_ALPHA, AUTH_2, RpcCapability::Read),
            TenantRpcErrorCode::StaleGroupEpoch,
        ),
    ];
    for (name, rlm, tok, expected_code) in stale_cases {
        let req = TenantRpcRequest { realm: rlm, bearer_token: tok, op: TenantOp::ReadIndex };
        let res = client.call_with_redirect(&leader2_addr, leader2, &req).await.unwrap_err();
        assert_eq!(res.code, expected_code, "{name} expected {expected_code:?}, got {res:?}");
    }

    let fresh_req = TenantRpcRequest {
        realm: realm(TENANT_A, GROUP_ALPHA, AUTH_2, HIST_2, 4, 7),
        bearer_token: token(TENANT_A, GROUP_ALPHA, AUTH_2, RpcCapability::Read),
        op: TenantOp::ReadIndex,
    };
    let (ok_resp, _, _) =
        client.call_with_redirect(cluster.node(follower_id).rpc_server.addr(), follower_id, &fresh_req).await.unwrap();
    assert!(matches!(ok_resp, TenantRpcResponse::ReadIndex { storage_generation: 7, .. }));

    // Closed tenant must fail closed permanently.
    for n in &cluster.nodes {
        n.registry.write().unwrap().close_tenant(TENANT_A);
    }
    let closed_err = client.call_with_redirect(&leader2_addr, leader2, &fresh_req).await.unwrap_err();
    assert_eq!(closed_err.code, TenantRpcErrorCode::CrossTenantDenied);

    cluster.shutdown().await;
}

#[tokio::test]
async fn bounded_streaming_backpressure_cancellation_and_raft_large_payload_fence() {
    let cluster = TenantTestCluster::start_three(default_realm()).await;
    let (leader_id, _) = cluster.wait_leader(Duration::from_secs(5)).await;
    let leader = cluster.node(leader_id);
    let leader_addr = leader.rpc_server.addr().to_owned();
    let follower_id = cluster.first_follower_id(leader_id);
    let follower_addr = cluster.node(follower_id).rpc_server.addr().to_owned();

    let paths = cluster.pki.tenant_paths(
        "tenant-a-rws2",
        TENANT_A,
        GROUP_ALPHA,
        &[RpcCapability::Read, RpcCapability::Write, RpcCapability::Stream],
    );
    let mtls_cli = cluster.pki.client_from(&paths);
    let client = TenantRpcClient::new(mtls_cli.clone(), Duration::from_secs(4), 3);

    // 1. Healthy bounded streaming redirected transparently from follower -> leader.
    let cfg = StreamConfig {
        channel_capacity: 2,
        max_frame_bytes: 32 * 1024,
        max_total_bytes: 1024 * 1024,
        write_deadline_ms: 400,
        stream_deadline_ms: 3000,
    };
    let stream_req = TenantRpcRequest {
        realm: default_realm(),
        bearer_token: token(TENANT_A, GROUP_ALPHA, AUTH_1, RpcCapability::Stream),
        op: TenantOp::StreamCompute {
            prefix: "refs/".into(),
            planned_chunks: 16,
            chunk_bytes: 16_384,
            stream_config: cfg.clone(),
        },
    };
    let (received, _, storage_gen) =
        client.stream_with_redirect(&follower_addr, follower_id, &stream_req, &cfg, None).await.unwrap();
    assert_eq!(storage_gen, 7);
    assert_eq!(received.total_chunks, 16);
    assert_eq!(received.total_bytes, 16 * 16_384);
    let snap_ok = leader.rpc_server.last_stream_tracker().unwrap().snapshot();
    assert!(!snap_ok.cancelled);
    assert_eq!(snap_ok.live_bytes, 0, "all buffered bytes must be freed on completion");
    assert!(snap_ok.peak_bytes <= 4 * 16_384, "peak buffered bytes must remain strictly bounded");

    // 2. Slow consumer stops draining & granting credits -> bounded mpsc backpressure & cancellation frees memory.
    let slow_cfg = StreamConfig {
        channel_capacity: 2,
        max_frame_bytes: 32 * 1024,
        max_total_bytes: 2 * 1024 * 1024,
        write_deadline_ms: 70,
        stream_deadline_ms: 300,
    };
    let slow_req = TenantRpcRequest {
        realm: default_realm(),
        bearer_token: token(TENANT_A, GROUP_ALPHA, AUTH_1, RpcCapability::Stream),
        op: TenantOp::StreamCompute {
            prefix: "refs/".into(),
            planned_chunks: 40,
            chunk_bytes: 16_384,
            stream_config: slow_cfg,
        },
    };
    let mut tls = mtls_cli.connect_peer(&leader_addr, leader_id).await.unwrap();
    write_frame_bounded_async(&mut tls, &slow_req, MAX_TENANT_RPC_FRAME_BYTES).await.unwrap();
    let started: TenantRpcResponse =
        read_frame_bounded_async(&mut tls, MAX_TENANT_RPC_FRAME_BYTES).await.unwrap().unwrap();
    assert!(matches!(started, TenantRpcResponse::StreamStarted { planned_chunks: 40, .. }));
    let _hdr: StreamFrame = read_frame_bounded_async(&mut tls, 256 * 1024).await.unwrap().unwrap();
    let _c0: StreamFrame = read_frame_bounded_async(&mut tls, 256 * 1024).await.unwrap().unwrap();
    tokio::time::sleep(Duration::from_millis(240)).await;
    let _ = tls.shutdown().await;
    tokio::time::sleep(Duration::from_millis(40)).await;

    let snap_slow = leader.rpc_server.last_stream_tracker().unwrap().snapshot();
    assert!(snap_slow.cancelled, "slow consumer must trigger stream cancellation");
    assert!(
        snap_slow.produced_chunks < 40,
        "mpsc backpressure must halt producer early, produced {}",
        snap_slow.produced_chunks
    );
    assert!(snap_slow.peak_bytes <= 4 * 16_384, "slow consumer peak memory {} exceeded bound", snap_slow.peak_bytes);
    assert_eq!(snap_slow.live_bytes, 0, "cancelled stream must deterministically drop buffered memory");

    // 3. Large Git pack / Blob payload bytes rejected before touching Raft WAL.
    let log_before = leader.raft.metrics().borrow().last_log_index;
    let mut pack_bytes = b"PACK\x00\x00\x00\x02".to_vec();
    pack_bytes.extend_from_slice(&[7u8; 1024]);
    for bad_payload in [pack_bytes, vec![b'z'; MAX_RAFT_PROPOSAL_BYTES + 1]] {
        let req = TenantRpcRequest {
            realm: default_realm(),
            bearer_token: token(TENANT_A, GROUP_ALPHA, AUTH_1, RpcCapability::Write),
            op: TenantOp::ProposeRaw { payload: bad_payload },
        };
        let err = client.call_with_redirect(&leader_addr, leader_id, &req).await.unwrap_err();
        assert_eq!(err.code, TenantRpcErrorCode::PayloadTooLarge);
    }
    assert_eq!(
        leader.raft.metrics().borrow().last_log_index,
        log_before,
        "rejected blobs must never append to Raft WAL"
    );

    // Unbounded stream caps refused before streaming.
    let bad_stream = TenantRpcRequest {
        realm: default_realm(),
        bearer_token: token(TENANT_A, GROUP_ALPHA, AUTH_1, RpcCapability::Stream),
        op: TenantOp::StreamCompute {
            prefix: "refs/".into(),
            planned_chunks: 100,
            chunk_bytes: 65_536,
            stream_config: StreamConfig {
                channel_capacity: MAX_CHANNEL_CAPACITY + 1,
                max_frame_bytes: 65_536,
                max_total_bytes: MAX_STREAM_TOTAL_BYTES + 1,
                write_deadline_ms: 200,
                stream_deadline_ms: 1000,
            },
        },
    };
    let cap_err = client.call_with_redirect(&leader_addr, leader_id, &bad_stream).await.unwrap_err();
    assert!(matches!(cap_err.code, TenantRpcErrorCode::InvalidRequest | TenantRpcErrorCode::PayloadTooLarge));

    // Also make unused helper check cleanly referenced cleanly via MtlsServer check:
    assert!(MtlsServer::from_paths(&cluster.pki.node_paths(1)).is_ok());

    cluster.shutdown().await;
}
