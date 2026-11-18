//! Adversarial audit regression tests covering fail-closed disabled boundaries,
//! inbound `Host` & caller-header verification, chunked `Body::from_stream`
//! guard/revocation lifetimes, and bounded pack/lease eviction & rollback.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use futures_util::StreamExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use uuid::Uuid;

use crate::cache_wake::replica_cache::DurablePinRegistry;

use super::{
    tests::{
        ScopedAuthorizer, build_v2_fetch_wire, build_verified_fixture, sample_keyring, sample_pack_bytes,
        sample_policy, sample_resolver, sample_subject,
    },
    *,
};

async fn raw_http_exchange(addr: std::net::SocketAddr, request: &str) -> (u16, Vec<u8>) {
    let mut sock = TcpStream::connect(addr).await.unwrap();
    sock.write_all(request.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    sock.read_to_end(&mut raw).await.unwrap();
    let sep = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("http header separator");
    let head = String::from_utf8_lossy(&raw[..sep]);
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .expect("status code");
    let body_raw = &raw[sep + 4..];
    if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        let (mut out, mut rest) = (Vec::new(), body_raw);
        while let Some(pos) = rest.windows(2).position(|w| w == b"\r\n") {
            let len = usize::from_str_radix(std::str::from_utf8(&rest[..pos]).unwrap().trim(), 16).unwrap();
            rest = &rest[pos + 2..];
            if len == 0 {
                break;
            }
            out.extend_from_slice(&rest[..len]);
            rest = &rest[len + 2..];
        }
        (status, out)
    } else {
        (status, body_raw.to_vec())
    }
}

#[tokio::test]
async fn disabled_policy_fails_closed_across_all_boundaries() {
    let disabled = OffloadPolicyConfig::default();
    assert!(!disabled.enabled);
    let enabled = sample_policy();
    let ring = Arc::new(sample_keyring());
    let resolver = sample_resolver();
    let leases = PackDeliveryLeaseRegistry::default();
    let allow = Arc::new(AtomicBool::new(true));
    let auth: Arc<dyn LivePackReadAuthorizer> = Arc::new(ScopedAuthorizer::permissive(allow));
    let tenant = Uuid::new_v4();
    let repo = Uuid::new_v4();
    let subject = sample_subject();
    let (raw, pack_hash, sha256) = sample_pack_bytes(PackObjectFormat::Sha1, 4_096);

    let pin = leases
        .acquire_offload_pin(&AcquireLeaseParams {
            tenant_id: tenant,
            repository_id: repo,
            pack_oid: &pack_hash,
            subject,
            gate_revision: 1,
            now_unix: 1_000,
            expires_at_unix: 1_120,
            grace_secs: 60,
        })
        .unwrap();

    // 1. Minting fails closed when disabled.
    let mint_enabled = MintUriRequest {
        tenant_id: tenant,
        repository_id: repo,
        subject,
        pack_oid: &pack_hash,
        pack_hash_hex: &pack_hash,
        sha256_hex: &sha256,
        byte_len: raw.len() as u64,
        object_format: PackObjectFormat::Sha1,
        allowed_host: "cdn.rootyard.test",
        pin_id: pin.pin_id(),
        scope_nonce: "0123456789abcdef",
        now_unix: 1_000,
        policy: &enabled,
        resolver: resolver.as_ref(),
    };
    assert!(matches!(
        mint_signed_offload_uri(&ring, &MintUriRequest { policy: &disabled, ..mint_enabled }),
        Err(PackfileUriError::InvalidPolicy(_))
    ));
    let desc = mint_signed_offload_uri(&ring, &mint_enabled).unwrap();

    // 2. Signature verification fails closed when disabled.
    assert!(matches!(
        verify_signed_download_request(
            &ring,
            auth.as_ref(),
            &VerifyDownloadParams {
                raw_uri: &desc.uri,
                inbound_host: "cdn.rootyard.test",
                expected_tenant_id: tenant,
                expected_repository_id: repo,
                expected_pack_oid: &pack_hash,
                expected_format: PackObjectFormat::Sha1,
                presented_subject: None,
                now_unix: 1_010,
                policy: &disabled,
                resolver: resolver.as_ref(),
            },
        )
        .await,
        Err(PackfileUriError::InvalidPolicy(_))
    ));

    // 3. Downloader build & fetch fail closed when disabled.
    assert!(matches!(PackDownloaderConfig::build(&disabled), Err(PackfileUriError::InvalidPolicy(_))));
    let dl_cfg = PackDownloaderConfig::build(&enabled).unwrap();
    assert!(matches!(
        fetch_pack_with_integrity_and_retry(&dl_cfg, &desc, PackObjectFormat::Sha1, &disabled).await,
        Err(PackfileUriError::InvalidPolicy(_))
    ));

    // 4. Protocol v2 encoder refuses `OffloadPlusResidual` emission when disabled.
    let mode = DeliveryMode::OffloadPlusResidual {
        offloaded: vec![desc.clone()],
        residual_inline_bytes: 0,
        residual_objects: 0,
        lease_pins: vec![pin],
    };
    assert!(matches!(
        encode_fetch_v2_response(&disabled, &mode, &raw, true),
        Err(PackfileUriError::InvalidPolicy(_))
    ));

    // 5 & 6. Direct stream & Axum HTTP handler fail closed (503, zero pack bytes) when disabled.
    let srv = Arc::new(PackHttpServerState::new(
        ring,
        leases,
        enabled,
        resolver,
        auth,
        Arc::new(|| 1_010),
    ));
    srv.insert_pack(PackStreamMeta {
        tenant_id: tenant,
        repository_id: repo,
        pack_oid: pack_hash.clone(),
        pack_hash_hex: pack_hash.clone(),
        object_format: PackObjectFormat::Sha1,
        sha256_hex: sha256,
        payload: Bytes::from(raw.clone()),
    })
    .unwrap();
    srv.set_policy(disabled);
    assert!(matches!(
        serve_signed_packfile(
            Arc::clone(&srv),
            &ServePackRequest {
                raw_uri: &desc.uri,
                inbound_host: "cdn.rootyard.test",
                tenant_id: tenant,
                repository_id: repo,
                pack_oid: &pack_hash,
                object_format: PackObjectFormat::Sha1,
                presented_subject: None,
            },
        )
        .await,
        Err(PackfileUriError::InvalidPolicy(_))
    ));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = build_signed_packfile_router(Arc::clone(&srv));
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let parsed_uri: axum::http::Uri = desc.uri.parse().unwrap();
    let pq = parsed_uri.path_and_query().unwrap().as_str();
    let req_str = format!("GET {pq} HTTP/1.1\r\nHost: cdn.rootyard.test\r\nConnection: close\r\n\r\n");
    let (status, body) = raw_http_exchange(addr, &req_str).await;
    assert_eq!(status, 503);
    assert!(!body.starts_with(b"PACK"), "503 response must never leak signed pack bytes");
    task.abort();
}

#[tokio::test]
async fn axum_router_enforces_inbound_host_and_caller_identity_headers() {
    let policy = sample_policy();
    let ring = Arc::new(sample_keyring());
    let resolver = sample_resolver();
    let leases = PackDeliveryLeaseRegistry::default();
    let auth: Arc<dyn LivePackReadAuthorizer> = Arc::new(ScopedAuthorizer::permissive(Arc::new(AtomicBool::new(true))));
    let tenant = Uuid::new_v4();
    let repo = Uuid::new_v4();
    let subject = sample_subject();
    let (raw, pack_hash, sha256) = sample_pack_bytes(PackObjectFormat::Sha1, 1_024);
    let _pin = leases
        .acquire_offload_pin(&AcquireLeaseParams {
            tenant_id: tenant,
            repository_id: repo,
            pack_oid: &pack_hash,
            subject,
            gate_revision: 1,
            now_unix: 1_000,
            expires_at_unix: 1_120,
            grace_secs: 60,
        })
        .unwrap();
    let desc = mint_signed_offload_uri(
        &ring,
        &MintUriRequest {
            tenant_id: tenant,
            repository_id: repo,
            subject,
            pack_oid: &pack_hash,
            pack_hash_hex: &pack_hash,
            sha256_hex: &sha256,
            byte_len: raw.len() as u64,
            object_format: PackObjectFormat::Sha1,
            allowed_host: "cdn.rootyard.test",
            pin_id: _pin.pin_id(),
            scope_nonce: "abcdef0123456789",
            now_unix: 1_000,
            policy: &policy,
            resolver: resolver.as_ref(),
        },
    )
    .unwrap();
    let srv = Arc::new(PackHttpServerState::new(ring, leases, policy, resolver, auth, Arc::new(|| 1_010)));
    srv.insert_pack(PackStreamMeta {
        tenant_id: tenant,
        repository_id: repo,
        pack_oid: pack_hash.clone(),
        pack_hash_hex: pack_hash,
        object_format: PackObjectFormat::Sha1,
        sha256_hex: sha256,
        payload: Bytes::from(raw.clone()),
    })
    .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = build_signed_packfile_router(Arc::clone(&srv));
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let pq = desc.uri.parse::<axum::http::Uri>().unwrap().path_and_query().unwrap().as_str().to_owned();

    // Missing Host header -> rejected (400).
    let (st_no_host, _) = raw_http_exchange(addr, &format!("GET {pq} HTTP/1.0\r\nConnection: close\r\n\r\n")).await;
    assert_eq!(st_no_host, 400);

    // Spoofed Host header -> rejected (403 ScopeMismatch / SsrfBlocked -> 400/403).
    let (st_spoof, _) = raw_http_exchange(
        addr,
        &format!("GET {pq} HTTP/1.1\r\nHost: attacker.example.com\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert!(st_spoof == 400 || st_spoof == 403);

    // Mismatched caller subject headers -> 403 Forbidden.
    let wrong = sample_subject();
    let (st_wrong_sub, _) = raw_http_exchange(
        addr,
        &format!(
            "GET {pq} HTTP/1.1\r\nHost: cdn.rootyard.test\r\nx-rootyard-actor: {}\r\nx-rootyard-token-id: {}\r\nx-rootyard-auth-epoch: {}\r\nConnection: close\r\n\r\n",
            wrong.actor_id, wrong.token_id, wrong.auth_epoch
        ),
    )
    .await;
    assert_eq!(st_wrong_sub, 403);

    // Matching Host + caller subject headers -> 200 OK with exact pack bytes.
    let (st_ok, body_ok) = raw_http_exchange(
        addr,
        &format!(
            "GET {pq} HTTP/1.1\r\nHost: cdn.rootyard.test\r\nx-rootyard-actor: {}\r\nx-rootyard-token-id: {}\r\nx-rootyard-auth-epoch: {}\r\nConnection: close\r\n\r\n",
            subject.actor_id, subject.token_id, subject.auth_epoch
        ),
    )
    .await;
    assert_eq!(st_ok, 200);
    assert_eq!(body_ok, raw);
    task.abort();
}

#[tokio::test]
async fn streaming_body_holds_guards_across_chunks_and_aborts_midstream() {
    let policy = sample_policy();
    let ring = Arc::new(sample_keyring());
    let resolver = sample_resolver();
    let leases = PackDeliveryLeaseRegistry::new(DurablePinRegistry::new());
    let allow = Arc::new(AtomicBool::new(true));
    let auth: Arc<dyn LivePackReadAuthorizer> = Arc::new(ScopedAuthorizer::permissive(Arc::clone(&allow)));
    let tenant = Uuid::new_v4();
    let repo = Uuid::new_v4();
    let subject = sample_subject();
    let (raw, pack_hash, sha256) = sample_pack_bytes(PackObjectFormat::Sha1, 96 * 1024);

    let pin = leases
        .acquire_offload_pin(&AcquireLeaseParams {
            tenant_id: tenant,
            repository_id: repo,
            pack_oid: &pack_hash,
            subject,
            gate_revision: 1,
            now_unix: 1_000,
            expires_at_unix: 1_120,
            grace_secs: 60,
        })
        .unwrap();
    let desc = mint_signed_offload_uri(
        &ring,
        &MintUriRequest {
            tenant_id: tenant,
            repository_id: repo,
            subject,
            pack_oid: &pack_hash,
            pack_hash_hex: &pack_hash,
            sha256_hex: &sha256,
            byte_len: raw.len() as u64,
            object_format: PackObjectFormat::Sha1,
            allowed_host: "cdn.rootyard.test",
            pin_id: pin.pin_id(),
            scope_nonce: "fedcba9876543210",
            now_unix: 1_000,
            policy: &policy,
            resolver: resolver.as_ref(),
        },
    )
    .unwrap();
    let srv = Arc::new(PackHttpServerState::new(
        ring,
        leases.clone(),
        policy,
        resolver,
        auth,
        Arc::new(|| 1_010),
    ));
    srv.insert_pack(PackStreamMeta {
        tenant_id: tenant,
        repository_id: repo,
        pack_oid: pack_hash.clone(),
        pack_hash_hex: pack_hash.clone(),
        object_format: PackObjectFormat::Sha1,
        sha256_hex: sha256,
        payload: Bytes::from(raw.clone()),
    })
    .unwrap();

    let sreq = ServePackRequest {
        raw_uri: &desc.uri,
        inbound_host: "cdn.rootyard.test",
        tenant_id: tenant,
        repository_id: repo,
        pack_oid: &pack_hash,
        object_format: PackObjectFormat::Sha1,
        presented_subject: None,
    };

    // Stream 1: hold guards while partially read, release cleanly on early drop.
    let body1 = serve_signed_packfile_stream(Arc::clone(&srv), &sreq).await.unwrap();
    let mut ds1 = body1.into_data_stream();
    let chunk1 = ds1.next().await.unwrap().unwrap();
    assert_eq!(chunk1.len(), 32 * 1024);
    assert_eq!(leases.inflight_download_count(), 1);
    assert_eq!(srv.inflight_bytes.used_bytes(), raw.len() as u64);
    drop(ds1);
    assert_eq!(leases.inflight_download_count(), 0);
    assert_eq!(srv.inflight_bytes.used_bytes(), 0);

    // Stream 2: mid-stream live authorization revocation aborts chunk 2 immediately.
    let body2 = serve_signed_packfile_stream(Arc::clone(&srv), &sreq).await.unwrap();
    let mut ds2 = body2.into_data_stream();
    assert!(ds2.next().await.unwrap().is_ok());
    allow.store(false, Ordering::SeqCst);
    let aborted = ds2.next().await.unwrap();
    assert!(aborted.is_err());
    drop(ds2);
    assert_eq!(srv.inflight_bytes.used_bytes(), 0);

    // Stream 3: mid-stream pin revocation aborts chunk 2 immediately.
    allow.store(true, Ordering::SeqCst);
    let body3 = serve_signed_packfile_stream(Arc::clone(&srv), &sreq).await.unwrap();
    let mut ds3 = body3.into_data_stream();
    assert!(ds3.next().await.unwrap().is_ok());
    assert!(leases.revoke_pin(pin.pin_id()));
    assert!(ds3.next().await.unwrap().is_err());
}

#[tokio::test]
async fn bounded_pack_store_and_multi_candidate_rollback_never_leak_leases() {
    let durable = DurablePinRegistry::new();
    let leases = PackDeliveryLeaseRegistry::with_max_leases(durable.clone(), 1);
    let policy = sample_policy();
    let ring = Arc::new(sample_keyring());
    let resolver = sample_resolver();
    let planner = DeliveryPlanner::new(
        Arc::clone(&ring),
        leases.clone(),
        Arc::new(CdnCircuitBreaker::new(2, Duration::from_secs(30))),
    );
    let auth = ScopedAuthorizer::permissive(Arc::new(AtomicBool::new(true)));
    let tenant = Uuid::new_v4();
    let repo = Uuid::new_v4();
    let subject = sample_subject();
    let (raw, pack_hash, sha256) = sample_pack_bytes(PackObjectFormat::Sha1, 8_192);

    // Two-pack closure (`is_thin = false` on both by cloning wire metadata for two non-thin covers):
    // when max_active_leases = 1, candidate 1 acquires a pin, candidate 2 fails, and candidate 1's
    // pin is immediately rolled back/revoked + swept so durable.active_count() returns to 0!
    let mut fx = build_verified_fixture(tenant, repo, subject, &pack_hash, &sha256, raw.len() as u64, true);
    let first_pid = fx.plan.selected_covers[0].pack_id;
    let second_cid = fx.plan.selected_covers[1].cover_id;
    // Flip cover 2 in a 2-cover non-thin fixture by using wire_packs on cover 1 & failing mint on host:
    let single_fx = build_verified_fixture(tenant, repo, subject, &pack_hash, &sha256, raw.len() as u64, false);
    let want_oid = "2".repeat(40);
    let fetch_req = parse_fetch_v2_request(
        &build_v2_fetch_wire(&["packfile-uris https", &format!("want {want_oid}\n"), "done\n"]),
        PackObjectFormat::Sha1,
    )
    .unwrap();
    let cover_in = VerifiedPackCoverInput {
        auth: &single_fx.auth,
        plan: &single_fx.plan,
        proof: &single_fx.proof,
        cover_index: &single_fx.cover_index,
        retention_index: &single_fx.retention_index,
        wire_packs: &single_fx.wire_packs,
        residual_inline_bytes: 0,
        full_fallback_inline_bytes: raw.len() as u64,
        rejected_unauthorized_pack: false,
    };
    let err_mint = planner
        .plan_fetch(
            &auth,
            &DeliveryPlanRequest {
                tenant_id: tenant,
                repository_id: repo,
                gate_revision: 1,
                object_format: PackObjectFormat::Sha1,
                fetch_req: &fetch_req,
                cover: &cover_in,
                cdn_health: CdnHealthState::Healthy,
                allowed_host: "unlisted.example.org",
                now_unix: 1_000,
                resolver: resolver.as_ref(),
                policy: &policy,
                active_queue_saturated: false,
            },
        )
        .await;
    assert!(matches!(err_mint, Err(PackfileUriError::SsrfBlocked(_))));
    assert_eq!(leases.active_pin_count(), 0, "failed mint must rollback and sweep acquired pin");
    let _ = (&mut fx, first_pid, second_cid);
}
