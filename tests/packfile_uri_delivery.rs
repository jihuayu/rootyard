//! End-to-end Rust + TLS + Axum + stock Git (SHA-1 & SHA-256) tests for Issue #185.

#[path = "packfile_uri_support/harness.rs"]
mod harness;

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Result, ensure};
use axum::body::Bytes;
use harness::{
    OriginState, StaticAuth, build_ephemeral_tls_cert, git_cmd, now_unix, prepare_dual_pack_repo, public_ips,
    shared_keyring, spawn_git_origin, spawn_tls_cdn_server,
};
use rootyard::{
    browse::packfile_uri::{
        CdnCircuitBreaker, CdnHealthState, DeliveryMode, DeliveryPlanRequest, DeliveryPlanner, FetchAttemptResult,
        OffloadPolicyConfig, PackClosurePlan, PackDeliveryLeaseRegistry, PackDownloaderConfig, PackHttpServerState,
        PackObjectFormat, PackStreamMeta, PackfileClosureMember, PackfileUriError, fetch_pack_with_integrity_and_retry,
        parse_fetch_v2_request, protocol_v2::push_pkt_line,
    },
    cache_wake::replica_cache::DurablePinRegistry,
};
use tempfile::TempDir;
use tokio::sync::Semaphore;
use uuid::Uuid;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stock_git_dual_hash_offload_plus_residual_and_inline_fallback_pass_fsck() -> Result<()> {
    let tmp = TempDir::new()?;
    let tls = build_ephemeral_tls_cert(tmp.path())?;
    for fmt in [PackObjectFormat::Sha1, PackObjectFormat::Sha256] {
        let prep = prepare_dual_pack_repo(tmp.path(), fmt)?;
        let mut policy = OffloadPolicyConfig::strict_production(vec!["cdn.rootyard.test".to_owned()], "kid-v1");
        policy.min_pack_bytes_for_offload = 64;
        let leases = PackDeliveryLeaseRegistry::new(DurablePinRegistry::new());
        let planner = Arc::new(DeliveryPlanner::new(
            shared_keyring(),
            leases.clone(),
            Arc::new(CdnCircuitBreaker::new(2, Duration::from_secs(30))),
        ));
        let allow = Arc::new(AtomicBool::new(true));
        let auth = Arc::new(StaticAuth(Arc::clone(&allow)));
        let tenant = Uuid::new_v4();
        let repo = Uuid::new_v4();
        let pack_state = Arc::new(PackHttpServerState {
            keyring: shared_keyring(),
            leases: leases.clone(),
            policy: policy.clone(),
            allowed_resolved_ips: public_ips(),
            authorizer: auth.clone(),
            packs: Arc::new(Default::default()),
            inflight_limiter: Arc::new(Semaphore::new(4)),
            clock_unix: Arc::new(now_unix),
            served_requests: AtomicU64::new(0),
            rejected_requests: AtomicU64::new(0),
        });
        pack_state.insert_pack(PackStreamMeta {
            tenant_id: tenant,
            repository_id: repo,
            pack_oid: prep.pack_hash.clone(),
            pack_hash_hex: prep.pack_hash.clone(),
            object_format: fmt,
            sha256_hex: prep.sha256_hex.clone(),
            payload: Bytes::from(prep.base_pack.clone()),
        })?;
        let cdn = spawn_tls_cdn_server(
            Arc::clone(&tls.server_cfg),
            Arc::clone(&pack_state),
            tenant,
            repo,
            prep.pack_hash.clone(),
            fmt,
            tokio::runtime::Handle::current(),
        )?;
        let origin_state = Arc::new(OriginState {
            planner: Arc::clone(&planner),
            auth,
            policy: policy.clone(),
            tenant,
            repo,
            fmt,
            head_oid: prep.head_oid.clone(),
            member: PackfileClosureMember {
                pack_oid: prep.pack_hash.clone(),
                pack_hash_hex: prep.pack_hash.clone(),
                sha256_hex: prep.sha256_hex.clone(),
                byte_len: prep.base_pack.len() as u64,
                covered_objects: 3,
                cache_warm: true,
            },
            residual_pack: prep.residual_pack,
            full_pack: prep.full_pack,
            inline_count: AtomicU64::new(0),
            offload_count: AtomicU64::new(0),
        });
        let origin_port = spawn_git_origin(Arc::clone(&origin_state)).await?;

        // Offload + residual inline delta pack via real stock `git clone`.
        let clone_offload = tmp.path().join(format!("clone_offload_{}", fmt.as_str()));
        let proxy_cfg = format!("http.https://cdn.rootyard.test/.proxy=http://127.0.0.1:{}", cdn.port);
        let ca_cfg = format!("http.https://cdn.rootyard.test/.sslCAInfo={}", tls.cert_path.display());
        let repo_url = format!("http://127.0.0.1:{origin_port}/repo.git");
        git_cmd(
            &[
                "-c",
                "protocol.version=2",
                "-c",
                "fetch.uriprotocols=https",
                "-c",
                &ca_cfg,
                "-c",
                &proxy_cfg,
                "clone",
                &repo_url,
                clone_offload.to_str().unwrap(),
            ],
            None,
            None,
        )?;
        git_cmd(&["-C", clone_offload.to_str().unwrap(), "fsck", "--full", "--strict"], None, None)?;
        ensure!(clone_offload.join("delta.txt").exists(), "residual delta missing");
        ensure!(clone_offload.join("base.txt").exists(), "offloaded base missing");
        ensure!(cdn.tls_requests.load(Ordering::SeqCst) == 1);
        ensure!(origin_state.offload_count.load(Ordering::SeqCst) == 1);

        // Deterministic inline fallback when client disables packfile-uris (`fetch.uriprotocols=`).
        let clone_inline = tmp.path().join(format!("clone_inline_{}", fmt.as_str()));
        git_cmd(
            &[
                "-c",
                "protocol.version=2",
                "-c",
                "fetch.uriprotocols=",
                "clone",
                &repo_url,
                clone_inline.to_str().unwrap(),
            ],
            None,
            None,
        )?;
        git_cmd(&["-C", clone_inline.to_str().unwrap(), "fsck", "--full", "--strict"], None, None)?;
        ensure!(cdn.tls_requests.load(Ordering::SeqCst) == 1);
        ensure!(origin_state.inline_count.load(Ordering::SeqCst) == 1);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reqwest_retry_live_auth_and_pin_revocation_over_tls_work_end_to_end() -> Result<()> {
    let tmp = TempDir::new()?;
    let tls = build_ephemeral_tls_cert(tmp.path())?;
    let prep = prepare_dual_pack_repo(tmp.path(), PackObjectFormat::Sha1)?;
    let mut policy = OffloadPolicyConfig::strict_production(vec!["cdn.rootyard.test".to_owned()], "kid-v1");
    policy.min_pack_bytes_for_offload = 64;
    let leases = PackDeliveryLeaseRegistry::new(DurablePinRegistry::new());
    let planner = DeliveryPlanner::new(
        shared_keyring(),
        leases.clone(),
        Arc::new(CdnCircuitBreaker::new(3, Duration::from_secs(10))),
    );
    let allow = Arc::new(AtomicBool::new(true));
    let auth = Arc::new(StaticAuth(Arc::clone(&allow)));
    let tenant = Uuid::new_v4();
    let repo = Uuid::new_v4();
    let now = now_unix();

    let pack_state = Arc::new(PackHttpServerState {
        keyring: shared_keyring(),
        leases: leases.clone(),
        policy: policy.clone(),
        allowed_resolved_ips: public_ips(),
        authorizer: auth.clone(),
        packs: Arc::new(Default::default()),
        inflight_limiter: Arc::new(Semaphore::new(2)),
        clock_unix: Arc::new(now_unix),
        served_requests: AtomicU64::new(0),
        rejected_requests: AtomicU64::new(0),
    });
    pack_state.insert_pack(PackStreamMeta {
        tenant_id: tenant,
        repository_id: repo,
        pack_oid: prep.pack_hash.clone(),
        pack_hash_hex: prep.pack_hash.clone(),
        object_format: PackObjectFormat::Sha1,
        sha256_hex: prep.sha256_hex.clone(),
        payload: Bytes::from(prep.base_pack.clone()),
    })?;
    let cdn = spawn_tls_cdn_server(
        Arc::clone(&tls.server_cfg),
        Arc::clone(&pack_state),
        tenant,
        repo,
        prep.pack_hash.clone(),
        PackObjectFormat::Sha1,
        tokio::runtime::Handle::current(),
    )?;
    cdn.fail_first_n.store(1, Ordering::SeqCst);

    let mut wire = Vec::new();
    push_pkt_line(&mut wire, b"command=fetch")?;
    wire.extend_from_slice(b"0001");
    push_pkt_line(&mut wire, b"packfile-uris https")?;
    push_pkt_line(&mut wire, format!("want {}\n", "a".repeat(40)).as_bytes())?;
    push_pkt_line(&mut wire, b"done\n")?;
    wire.extend_from_slice(b"0000");
    let fetch_req = parse_fetch_v2_request(&wire, PackObjectFormat::Sha1)?;
    let closure = PackClosurePlan {
        total_objects: 3,
        total_inline_bytes: prep.base_pack.len() as u64,
        offload_candidates: vec![PackfileClosureMember {
            pack_oid: prep.pack_hash.clone(),
            pack_hash_hex: prep.pack_hash.clone(),
            sha256_hex: prep.sha256_hex.clone(),
            byte_len: prep.base_pack.len() as u64,
            covered_objects: 3,
            cache_warm: false,
        }],
        residual_inline_objects: 0,
        residual_inline_bytes: 0,
    };
    let planned = planner
        .plan_fetch(
            auth.as_ref(),
            &DeliveryPlanRequest {
                tenant_id: tenant,
                repository_id: repo,
                actor_id: Uuid::new_v4(),
                gate_revision: 1,
                object_format: PackObjectFormat::Sha1,
                fetch_req: &fetch_req,
                closure: &closure,
                cdn_health: CdnHealthState::Healthy,
                allowed_host: "cdn.rootyard.test",
                now_unix: now,
                resolved_ips: &public_ips(),
                policy: &policy,
                active_queue_saturated: false,
            },
        )
        .await?;
    let DeliveryMode::OffloadPlusResidual { offloaded, .. } = planned.mode else {
        anyhow::bail!("expected offload descriptor");
    };
    let desc = &offloaded[0];

    let cert = reqwest::Certificate::from_pem(&std::fs::read(&tls.cert_path)?)?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .add_root_certificate(cert)
        .resolve("cdn.rootyard.test", SocketAddr::from(([127, 0, 0, 1], cdn.port)))
        .timeout(Duration::from_secs(10))
        .build()?;
    let dl_cfg = PackDownloaderConfig {
        client,
        concurrency_limit: Arc::new(Semaphore::new(2)),
        request_deadline: Duration::from_secs(10),
        max_retries: 2,
        max_pack_bytes: 64 * 1024 * 1024,
    };
    // Retry #1 recovers after transient 503 and verifies SHA-256 + trailer cleanly.
    let res =
        fetch_pack_with_integrity_and_retry(&dl_cfg, desc, PackObjectFormat::Sha1, &policy, &public_ips()).await?;
    ensure!(matches!(res, FetchAttemptResult::Verified { attempts: 2, .. }), "unexpected fetch result: {res:?}");

    // Live auth revocation fails closed immediately even while signature & TTL stay valid.
    allow.store(false, Ordering::SeqCst);
    let denied =
        fetch_pack_with_integrity_and_retry(&dl_cfg, desc, PackObjectFormat::Sha1, &policy, &public_ips()).await;
    ensure!(matches!(denied, Err(PackfileUriError::Unauthorized)), "expected Unauthorized, got {denied:?}");

    // Re-enable auth, then revoke active retention pin -> fail closed with RetentionPinMissing.
    allow.store(true, Ordering::SeqCst);
    ensure!(leases.revoke_pin(desc.pin_id));
    let unpinned =
        fetch_pack_with_integrity_and_retry(&dl_cfg, desc, PackObjectFormat::Sha1, &policy, &public_ips()).await;
    ensure!(
        matches!(unpinned, Err(PackfileUriError::RetentionPinMissing(_))),
        "expected RetentionPinMissing, got {unpinned:?}"
    );
    ensure!(pack_state.rejected_requests.load(Ordering::SeqCst) >= 2);
    Ok(())
}
