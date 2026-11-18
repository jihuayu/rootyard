//! Unit tests covering protocol v2 negotiation, SSRF guard, HMAC signing,
//! live authorization, retention pin preservation, and fallback planning.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::cache_wake::replica_cache::{DurablePinRegistry, lease_pin::AuthTask};

use super::*;

struct ToggleAuthorizer {
    allow: Arc<AtomicBool>,
}

impl LivePackReadAuthorizer for ToggleAuthorizer {
    fn authorize_pack_download<'a>(
        &'a self,
        _tenant_id: Uuid,
        _repository_id: Uuid,
        _actor_id: Uuid,
        _pack_oid: &'a str,
        _pin_id: Uuid,
    ) -> AuthTask<'a, Result<(), PackfileUriError>> {
        let ok = self.allow.load(Ordering::SeqCst);
        Box::pin(async move {
            if ok {
                Ok(())
            } else {
                Err(PackfileUriError::Unauthorized)
            }
        })
    }
}

fn sample_policy() -> OffloadPolicyConfig {
    OffloadPolicyConfig::strict_production(vec!["cdn.rootyard.test".to_owned()], "kid-v1")
}

fn sample_keyring() -> PackUriKeyring {
    let mut ring = PackUriKeyring::new();
    ring.insert_active(SigningKeyMaterial::new("kid-v1", vec![0x42; 32]).unwrap());
    ring
}

fn public_ips() -> Vec<IpAddr> {
    vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
}

fn sample_pack_bytes(format: PackObjectFormat) -> (Vec<u8>, String, String) {
    let mut raw = b"PACK\x00\x00\x00\x02\x00\x00\x00\x00".to_vec();
    let trailer = vec![0xab; format.oid_hex_len() / 2];
    raw.extend_from_slice(&trailer);
    let pack_hash_hex = hex::encode(&trailer);
    let sha256_hex = hex::encode(Sha256::digest(&raw));
    (raw, pack_hash_hex, sha256_hex)
}

fn build_v2_fetch_wire(args: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    protocol_v2::push_pkt_line(&mut out, b"command=fetch").unwrap();
    out.extend_from_slice(b"0001");
    for arg in args {
        protocol_v2::push_pkt_line(&mut out, arg.as_bytes()).unwrap();
    }
    out.extend_from_slice(b"0000");
    out
}

#[test]
fn protocol_v2_negotiation_handles_git_wire_framing_and_duplicates() {
    assert_eq!(format_fetch_capability_line(false), "shallow filter wait-for-done");
    assert_eq!(format_fetch_capability_line(true), "shallow filter wait-for-done packfile-uris");

    let oid = "a".repeat(40);
    let want_line = format!("want {oid}\n");
    let wire = build_v2_fetch_wire(&["thin-pack", "packfile-uris https,http", &want_line, "done\n"]);
    let parsed = parse_fetch_v2_request(&wire, PackObjectFormat::Sha1).unwrap();
    assert!(parsed.client_supports_https_offload());
    assert!(parsed.done);
    assert_eq!(parsed.wants, vec![oid.clone()]);

    let http_only = build_v2_fetch_wire(&["packfile-uris http", &want_line, "done\n"]);
    let parsed_http = parse_fetch_v2_request(&http_only, PackObjectFormat::Sha1).unwrap();
    assert!(!parsed_http.client_supports_https_offload());

    let dup = build_v2_fetch_wire(&["packfile-uris https", "packfile-uris http", &want_line, "done\n"]);
    assert!(matches!(
        parse_fetch_v2_request(&dup, PackObjectFormat::Sha1),
        Err(PackfileUriError::ProtocolSyntax(_))
    ));
}

#[test]
fn ssrf_guard_blocks_non_https_private_ips_userinfo_ports_and_traversal() {
    let policy = sample_policy();
    let pub_ip = public_ips();
    let blocked_uris = [
        "http://cdn.rootyard.test/v1/packs/a.pack",
        "file:///etc/passwd",
        "https://evil.example.net/v1/packs/a.pack",
        "https://user:pass@cdn.rootyard.test/v1/packs/a.pack",
        "https://cdn.rootyard.test:8080/v1/packs/a.pack",
        "https://cdn.rootyard.test/v1/packs/../secret.pack",
        "https://cdn.rootyard.test/v1/packs/%2e%2e/secret.pack",
        "https://cdn.rootyard.test/v1/packs_evil/a.pack",
        "https://127.0.0.1/v1/packs/a.pack",
        "https://metadata.google.internal/v1/packs/a.pack",
    ];
    for uri in blocked_uris {
        assert!(validate_offload_uri(uri, &policy, &pub_ip).is_err(), "must reject {uri}");
    }

    let valid = "https://cdn.rootyard.test/v1/packs/good.pack?sig=secret";
    assert!(validate_offload_uri(valid, &policy, &pub_ip).is_ok());
    assert_eq!(redact_uri_for_log(valid), "https://cdn.rootyard.test/v1/packs/good.pack?[REDACTED]");

    let bad_ips = [
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
        IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V6("fc00::1".parse().unwrap()),
        IpAddr::V6("fe80::1".parse().unwrap()),
        IpAddr::V6("::ffff:169.254.169.254".parse().unwrap()),
    ];
    for ip in bad_ips {
        assert!(matches!(
            validate_offload_uri(valid, &policy, &[ip]),
            Err(PackfileUriError::SsrfBlocked(_))
        ));
    }
}

#[tokio::test]
async fn signing_enforces_scope_rotation_expiry_and_live_auth() {
    let policy = sample_policy();
    let mut ring = sample_keyring();
    let tenant = Uuid::new_v4();
    let repo = Uuid::new_v4();
    let pin = Uuid::new_v4();
    let actor = Uuid::new_v4();
    let (_raw, pack_hash, sha256) = sample_pack_bytes(PackObjectFormat::Sha256);
    let desc = mint_signed_offload_uri(
        &ring,
        &MintUriRequest {
            tenant_id: tenant,
            repository_id: repo,
            pack_oid: &pack_hash,
            pack_hash_hex: &pack_hash,
            sha256_hex: &sha256,
            byte_len: 44,
            object_format: PackObjectFormat::Sha256,
            allowed_host: "cdn.rootyard.test",
            pin_id: pin,
            scope_nonce: "0123456789abcdef",
            now_unix: 1_000,
            policy: &policy,
            resolved_ips: &public_ips(),
        },
    )
    .unwrap();

    let allow = Arc::new(AtomicBool::new(true));
    let auth = ToggleAuthorizer { allow: Arc::clone(&allow) };
    let ips = public_ips();
    let params = VerifyDownloadParams {
        raw_uri: &desc.uri,
        expected_tenant_id: tenant,
        expected_repository_id: repo,
        expected_pack_oid: &pack_hash,
        expected_format: PackObjectFormat::Sha256,
        actor_id: actor,
        now_unix: 1_050,
        policy: &policy,
        resolved_ips: &ips,
    };
    assert!(verify_signed_download_request(&ring, &auth, &params).await.is_ok());

    let cross_tenant = VerifyDownloadParams { expected_tenant_id: Uuid::new_v4(), ..params };
    assert!(matches!(
        verify_signed_download_request(&ring, &auth, &cross_tenant).await,
        Err(PackfileUriError::ScopeMismatch(_))
    ));

    let expired = VerifyDownloadParams { now_unix: 1_200, ..params };
    assert!(matches!(
        verify_signed_download_request(&ring, &auth, &expired).await,
        Err(PackfileUriError::TokenExpired)
    ));

    let tampered_sig = format!("{}X", &desc.uri[..desc.uri.len() - 1]);
    let tampered = VerifyDownloadParams { raw_uri: &tampered_sig, ..params };
    assert!(matches!(
        verify_signed_download_request(&ring, &auth, &tampered).await,
        Err(PackfileUriError::InvalidSignature(_))
    ));

    ring.retire_for_signing("kid-v1");
    assert!(verify_signed_download_request(&ring, &auth, &params).await.is_ok());
    allow.store(false, Ordering::SeqCst);
    assert!(matches!(
        verify_signed_download_request(&ring, &auth, &params).await,
        Err(PackfileUriError::Unauthorized)
    ));
    allow.store(true, Ordering::SeqCst);
    ring.revoke_key("kid-v1");
    assert!(matches!(
        verify_signed_download_request(&ring, &auth, &params).await,
        Err(PackfileUriError::InvalidSignature(_))
    ));
}

#[tokio::test]
async fn retention_pin_blocks_gc_sweep_through_grace_and_inflight_downloads() {
    let durable = DurablePinRegistry::new();
    let leases = PackDeliveryLeaseRegistry::new(durable.clone());
    let policy = sample_policy();
    let ring = Arc::new(sample_keyring());
    let tenant = Uuid::new_v4();
    let repo = Uuid::new_v4();
    let (raw, pack_hash, sha256) = sample_pack_bytes(PackObjectFormat::Sha1);
    let planner = DeliveryPlanner::new(
        Arc::clone(&ring),
        leases.clone(),
        Arc::new(CdnCircuitBreaker::new(2, Duration::from_secs(30))),
    );
    let auth = ToggleAuthorizer { allow: Arc::new(AtomicBool::new(true)) };
    let want_oid = "b".repeat(40);
    let fetch_req = parse_fetch_v2_request(
        &build_v2_fetch_wire(&["packfile-uris https", &format!("want {want_oid}\n"), "done\n"]),
        PackObjectFormat::Sha1,
    )
    .unwrap();
    let closure = PackClosurePlan {
        total_objects: 10,
        total_inline_bytes: 20_000,
        offload_candidates: vec![PackfileClosureMember {
            pack_oid: pack_hash.clone(),
            pack_hash_hex: pack_hash.clone(),
            sha256_hex: sha256.clone(),
            byte_len: 10_000,
            covered_objects: 8,
            cache_warm: true,
        }],
        residual_inline_objects: 2,
        residual_inline_bytes: 512,
    };

    let planned = planner
        .plan_fetch(
            &auth,
            &DeliveryPlanRequest {
                tenant_id: tenant,
                repository_id: repo,
                actor_id: Uuid::new_v4(),
                gate_revision: 7,
                object_format: PackObjectFormat::Sha1,
                fetch_req: &fetch_req,
                closure: &closure,
                cdn_health: CdnHealthState::Healthy,
                allowed_host: "cdn.rootyard.test",
                now_unix: 1_000,
                resolved_ips: &public_ips(),
                policy: &policy,
                active_queue_saturated: false,
            },
        )
        .await
        .unwrap();

    let (desc, guard) = match planned.mode {
        DeliveryMode::OffloadPlusResidual { offloaded, lease_pins, .. } => {
            (offloaded[0].clone(), lease_pins[0].clone())
        }
        other => panic!("expected offload plan, got {other:?}"),
    };
    assert!(!leases.can_sweep_pack(tenant, repo, &pack_hash, 1_100));
    drop(guard);
    assert!(!leases.can_sweep_pack(tenant, repo, &pack_hash, 1_150));

    let dl_hold = leases
        .begin_download_hold(desc.pin_id, tenant, repo, &pack_hash, 1_150)
        .unwrap();
    assert!(!leases.can_sweep_pack(tenant, repo, &pack_hash, 2_000));
    assert_eq!(leases.sweep_expired(2_000), 0);

    drop(dl_hold);
    assert!(leases.can_sweep_pack(tenant, repo, &pack_hash, 2_000));
    assert_eq!(leases.sweep_expired(2_000), 1);
    assert_eq!(durable.active_count(), 0);
    assert_eq!(durable.total_released(), 1);

    let srv = PackHttpServerState {
        keyring: ring,
        leases,
        policy,
        allowed_resolved_ips: public_ips(),
        authorizer: Arc::new(auth),
        packs: Arc::new(Default::default()),
        inflight_limiter: Arc::new(Semaphore::new(2)),
        clock_unix: Arc::new(|| 1_010),
        served_requests: Default::default(),
        rejected_requests: Default::default(),
    };
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
    assert!(srv.packs.read().unwrap().len() == 1);
}

#[tokio::test]
async fn planner_fallbacks_breaker_and_fail_closed_integrity_checks() {
    let policy = sample_policy();
    let ring = Arc::new(sample_keyring());
    let durable = DurablePinRegistry::new();
    let leases = PackDeliveryLeaseRegistry::new(durable);
    let breaker = Arc::new(CdnCircuitBreaker::new(2, Duration::from_millis(20)));
    let planner = DeliveryPlanner::new(Arc::clone(&ring), leases.clone(), Arc::clone(&breaker));
    let allow = Arc::new(AtomicBool::new(false));
    let auth = ToggleAuthorizer { allow: Arc::clone(&allow) };
    let (raw, pack_hash, sha256) = sample_pack_bytes(PackObjectFormat::Sha1);
    let tenant = Uuid::new_v4();
    let repo = Uuid::new_v4();
    let want_oid = "c".repeat(40);
    let fetch_https = parse_fetch_v2_request(
        &build_v2_fetch_wire(&["packfile-uris https", &format!("want {want_oid}\n"), "done\n"]),
        PackObjectFormat::Sha1,
    )
    .unwrap();
    let fetch_none = parse_fetch_v2_request(
        &build_v2_fetch_wire(&[&format!("want {want_oid}\n"), "done\n"]),
        PackObjectFormat::Sha1,
    )
    .unwrap();
    let fetch_http_only = parse_fetch_v2_request(
        &build_v2_fetch_wire(&["packfile-uris http", &format!("want {want_oid}\n"), "done\n"]),
        PackObjectFormat::Sha1,
    )
    .unwrap();
    let closure = PackClosurePlan {
        total_objects: 6,
        total_inline_bytes: 16_000,
        offload_candidates: vec![PackfileClosureMember {
            pack_oid: pack_hash.clone(),
            pack_hash_hex: pack_hash.clone(),
            sha256_hex: sha256.clone(),
            byte_len: 8_192,
            covered_objects: 5,
            cache_warm: false,
        }],
        residual_inline_objects: 1,
        residual_inline_bytes: 256,
    };

    let make_req = |fetch_req: &FetchV2Request,
                    cl: &PackClosurePlan,
                    pol: &OffloadPolicyConfig,
                    cdn_health: CdnHealthState,
                    sat: bool| DeliveryPlanRequest {
        tenant_id: tenant,
        repository_id: repo,
        actor_id: Uuid::new_v4(),
        gate_revision: 1,
        object_format: PackObjectFormat::Sha1,
        fetch_req,
        closure: cl,
        cdn_health,
        allowed_host: "cdn.rootyard.test",
        now_unix: 1_000,
        resolved_ips: &public_ips(),
        policy: pol,
        active_queue_saturated: sat,
    };

    // Unauthorized caller fails before any fallback or offload.
    assert!(matches!(
        planner
            .plan_fetch(&auth, &make_req(&fetch_https, &closure, &policy, CdnHealthState::Healthy, false))
            .await,
        Err(PackfileUriError::Unauthorized)
    ));
    allow.store(true, Ordering::SeqCst);

    let cases = [
        (&fetch_https, &closure, &OffloadPolicyConfig::disabled(), CdnHealthState::Healthy, false, FallbackReason::FeatureDisabled),
        (&fetch_none, &closure, &policy, CdnHealthState::Healthy, false, FallbackReason::ClientOmittedPackfileUris),
        (&fetch_http_only, &closure, &policy, CdnHealthState::Healthy, false, FallbackReason::ClientUnsupportedProtocols),
        (&fetch_https, &closure, &policy, CdnHealthState::Unavailable, false, FallbackReason::CdnUnhealthy),
        (&fetch_https, &closure, &policy, CdnHealthState::Healthy, true, FallbackReason::OverloadedOrQueueSaturated),
    ];
    for (fq, cl, pol, health, sat, expected) in cases {
        let res = planner.plan_fetch(&auth, &make_req(fq, cl, pol, health, sat)).await.unwrap();
        assert!(matches!(res.mode, DeliveryMode::InlineFallback { reason, .. } if reason == expected));
        assert_eq!(res.telemetry.fallback_reason, Some(expected));
    }

    let mut incomplete = closure.clone();
    incomplete.residual_inline_objects = 0;
    let res = planner
        .plan_fetch(&auth, &make_req(&fetch_https, &incomplete, &policy, CdnHealthState::Healthy, false))
        .await
        .unwrap();
    assert!(matches!(
        res.mode,
        DeliveryMode::InlineFallback { reason: FallbackReason::IncompleteClosure, .. }
    ));

    // Breaker trip -> open fallback -> half-open probe ok -> recovery.
    breaker.try_begin().unwrap().record_err();
    breaker.try_begin().unwrap().record_err();
    assert!(breaker.is_open());
    let tripped = planner
        .plan_fetch(&auth, &make_req(&fetch_https, &closure, &policy, CdnHealthState::Healthy, false))
        .await
        .unwrap();
    assert!(matches!(
        tripped.mode,
        DeliveryMode::InlineFallback { reason: FallbackReason::CdnBreakerOpen, .. }
    ));
    tokio::time::sleep(Duration::from_millis(30)).await;
    breaker.try_begin().unwrap().record_ok();
    assert!(!breaker.is_open());

    // Tampered pack bytes or truncated stream fail closed.
    let mut altered = raw.clone();
    altered[0] ^= 0xff;
    assert!(matches!(
        validate_pack_bytes_integrity(&altered, raw.len() as u64, &sha256, &pack_hash, PackObjectFormat::Sha1),
        Err(PackfileUriError::IntegrityMismatch(_))
    ));
    assert!(matches!(
        validate_pack_bytes_integrity(&raw[..10], raw.len() as u64, &sha256, &pack_hash, PackObjectFormat::Sha1),
        Err(PackfileUriError::IntegrityMismatch(_))
    ));
}
