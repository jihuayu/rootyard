//! Unit tests covering protocol v2 negotiation & bounds, SSRF & empty-IP fail-closed
//! guards, subject-bound HMAC signing, retention lease bounds/rollback, and
//! #184 `VerifiedFetchPlanProof` delivery planning.

use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    blob_store::BlobLocator,
    cache_wake::replica_cache::{DurablePinRegistry, lease_pin::AuthTask},
    ref_store::{
        GitObjectFormat, GitOid, RefName,
        contract::RequestDigest,
        ref_version::{
            AuthorityKind, CausalVersionNode, MAX_CLOSURE_PACKS, PackSetEntry, ReadConsumer, RefHead, RefVersionRealm,
            VerifiedClosurePack, VersionGraph, VersionRecord,
            pack_cover::{
                AuthorizationContext, CoverArtifactPair, CoverCommitLink, CoverHierarchyIndex, CoverHierarchyRecord,
                CoverHierarchyRecordInput, CoverRetentionHold, CoverTier, FetchPlan, FetchPlanOutcome,
                FetchPlanRequest, HaveSpec, PhysicalBlobStatus, ReadIsolationMode, RetentionClassificationIndex,
                StrongSnapshotCut, VerifiedFetchPlanProof, WantTarget, compute_cover_membership_digest,
                plan_fetch_covers, verify_fetch_plan_closure,
            },
        },
    },
};

use super::{cover_git::seal_synth_version, *};

pub(super) struct ScopedAuthorizer {
    pub allow_all: Arc<AtomicBool>,
    pub denied_actor: Option<Uuid>,
    pub denied_token: Option<Uuid>,
    pub min_epoch: u64,
}

impl ScopedAuthorizer {
    pub(super) fn permissive(allow_all: Arc<AtomicBool>) -> Self {
        Self { allow_all, denied_actor: None, denied_token: None, min_epoch: 1 }
    }
}

impl LivePackReadAuthorizer for ScopedAuthorizer {
    fn authorize_pack_download<'a>(
        &'a self,
        _tenant_id: Uuid,
        _repository_id: Uuid,
        subject: &'a DownloadSubjectContext,
        _pack_oid: &'a str,
        _pin_id: Uuid,
    ) -> AuthTask<'a, Result<(), PackfileUriError>> {
        if let Err(e) = subject.validate() {
            return Box::pin(async move { Err(e) });
        }
        let ok = self.allow_all.load(Ordering::SeqCst)
            && self.denied_actor != Some(subject.actor_id)
            && self.denied_token != Some(subject.token_id)
            && subject.auth_epoch >= self.min_epoch;
        Box::pin(async move { if ok { Ok(()) } else { Err(PackfileUriError::Unauthorized) } })
    }
}

pub(super) fn sample_policy() -> OffloadPolicyConfig {
    OffloadPolicyConfig::strict_production(vec!["cdn.rootyard.test".to_owned()], "kid-v1")
}

pub(super) fn sample_keyring() -> PackUriKeyring {
    let mut ring = PackUriKeyring::new();
    ring.insert_active(SigningKeyMaterial::new("kid-v1", vec![0x42; 32]).unwrap());
    ring
}

pub(super) fn sample_resolver() -> Arc<StaticMapDnsResolver> {
    let res = Arc::new(StaticMapDnsResolver::new());
    res.set_host_addrs("cdn.rootyard.test", vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443)]);
    res
}

pub(super) fn sample_subject() -> DownloadSubjectContext {
    DownloadSubjectContext::new(Uuid::new_v4(), Uuid::new_v4(), 3).unwrap()
}

pub(super) fn sample_pack_bytes(format: PackObjectFormat, extra_pad: usize) -> (Vec<u8>, String, String) {
    let mut raw = b"PACK\x00\x00\x00\x02\x00\x00\x00\x00".to_vec();
    raw.resize(raw.len() + extra_pad, 0x5a);
    let trailer = vec![0xab; format.oid_hex_len() / 2];
    raw.extend_from_slice(&trailer);
    let pack_hash_hex = hex::encode(&trailer);
    let sha256_hex = hex::encode(Sha256::digest(&raw));
    (raw, pack_hash_hex, sha256_hex)
}

pub(super) fn build_v2_fetch_wire(args: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    protocol_v2::push_pkt_line(&mut out, b"command=fetch").unwrap();
    out.extend_from_slice(b"0001");
    for arg in args {
        protocol_v2::push_pkt_line(&mut out, arg.as_bytes()).unwrap();
    }
    out.extend_from_slice(b"0000");
    out
}

pub(super) struct TestProofFixture {
    pub auth: AuthorizationContext,
    pub plan: FetchPlan,
    pub proof: VerifiedFetchPlanProof,
    pub cover_index: CoverHierarchyIndex,
    pub retention_index: RetentionClassificationIndex,
    pub wire_packs: HashMap<Uuid, PackWireMeta>,
    pub cover_id: Uuid,
    pub pack_id: Uuid,
}

pub(super) fn build_verified_fixture(
    tenant: Uuid,
    repo: Uuid,
    subject: DownloadSubjectContext,
    pack_hash: &str,
    sha256: &str,
    byte_len: u64,
    is_thin: bool,
) -> TestProofFixture {
    let realm = RefVersionRealm::new(tenant, repo, Uuid::new_v4(), AuthorityKind::Pg, 1, 0, 1, GitObjectFormat::Sha1);
    let mut auth = AuthorizationContext::for_realm(&realm, subject.actor_id, subject.token_id);
    auth.auth_epoch = subject.auth_epoch;
    auth.min_valid_auth_epoch = subject.auth_epoch;

    let init_mem = compute_cover_membership_digest(&realm, 1, &[]).unwrap();
    let mut cover_index = CoverHierarchyIndex::new(realm, init_mem).unwrap();
    let mut graph = VersionGraph::new();
    let mut retention = RetentionClassificationIndex::new();
    let ref_name = RefName::new("refs/heads/main").unwrap();
    let base_oid = GitOid::parse(GitObjectFormat::Sha1, &"1".repeat(40)).unwrap();
    let tip_oid = GitOid::parse(GitObjectFormat::Sha1, &"2".repeat(40)).unwrap();

    let mut entries = Vec::new();
    let mut cover_ids = Vec::new();
    let mut wire_packs = HashMap::new();
    let mut base_ver: Option<VersionRecord> = None;
    let specs = if is_thin {
        vec![(1i64, base_oid, Vec::new(), false), (2i64, tip_oid, vec![base_oid], true)]
    } else {
        vec![(1i64, tip_oid, Vec::new(), false)]
    };

    for (seq, coid, parents, thin_flag) in specs {
        let pse = PackSetEntry::new(Uuid::new_v4(), Uuid::new_v4(), RequestDigest::of("art", &[&seq.to_be_bytes()])).unwrap();
        let pack_loc = BlobLocator::new(tenant, repo, 1, Uuid::new_v4(), "packs", sha256, byte_len).unwrap();
        let idx_loc = BlobLocator::new(tenant, repo, 1, Uuid::new_v4(), "packs", sha256, 64).unwrap();
        let vcp = VerifiedClosurePack::new(pse, tenant, repo, "s3", "a".repeat(64), byte_len + 64, 2).unwrap();
        let deps = base_ver.as_ref().map(VersionRecord::version_id).into_iter().collect();
        let ver = seal_synth_version(&realm, &ref_name, seq, base_ver.as_ref(), deps, coid, &[pse]).unwrap();
        let vid = ver.version_id();
        graph.insert_active(CausalVersionNode { record: ver.clone(), own_packs: vec![vcp.clone()] });
        entries.push(pse);
        let next_gen = cover_index.membership_generation() + 1;
        let mem = compute_cover_membership_digest(&realm, next_gen, &entries).unwrap();
        let cid = Uuid::new_v4();
        let cov = CoverHierarchyRecord::seal(CoverHierarchyRecordInput {
            cover_id: cid,
            realm,
            tier: CoverTier::Delta,
            pack: vcp,
            artifacts: CoverArtifactPair {
                pack_stem: format!("pack-{pack_hash}"),
                pack_locator: pack_loc,
                idx_locator: idx_loc,
                is_thin_pack: thin_flag,
                delta_base_cover_ids: if thin_flag { cover_ids.clone() } else { Vec::new() },
            },
            covered_versions: vec![vid],
            min_authority_seq: seq,
            max_authority_seq: seq,
            covered_commits: vec![CoverCommitLink { commit_oid: coid, parent_oids: parents, version_id: vid, authority_seq: seq }],
            input_cover_ids: Vec::new(),
            membership_generation: next_gen,
            membership_digest: mem,
            compaction_epoch: 0,
            worker_id: Uuid::new_v4(),
            operation_id: Uuid::new_v4(),
        })
        .unwrap();
        cover_index.register_leaf_cover(cov, mem).unwrap();
        retention.set_physical_status(pse.pack_id(), PhysicalBlobStatus::Present);
        wire_packs.insert(
            pse.pack_id(),
            PackWireMeta {
                pack_oid: pack_hash.to_owned(),
                pack_hash_hex: pack_hash.to_owned(),
                sha256_hex: sha256.to_owned(),
                byte_len,
                cache_warm: true,
            },
        );
        cover_ids.push(cid);
        base_ver = Some(ver);
    }

    let tip = base_ver.unwrap();
    let last_seq = tip.authority_seq();
    let last_cid = *cover_ids.last().unwrap();
    let last_pid = entries.last().unwrap().pack_id();
    retention.add_hold(CoverRetentionHold::ActiveRefHead {
        ref_name: ref_name.clone(),
        version_id: tip.version_id(),
        cover_ids,
    });
    let mut heads = BTreeMap::new();
    heads.insert(ref_name.clone(), RefHead::from_committed(&tip).unwrap());
    let cut = StrongSnapshotCut {
        authority_seq: last_seq,
        snapshot_digest: RequestDigest::of("cut", &[&last_seq.to_be_bytes()]),
        membership_digest: cover_index.membership_digest(),
        heads,
    };
    let mut req = FetchPlanRequest::new(ReadConsumer::SmartHttpFetch, realm, auth.clone(), ReadIsolationMode::StrongSnapshot);
    req.strong_cut = Some(cut.clone());
    req.wants = vec![WantTarget::Ref { ref_name }];
    req.haves = HaveSpec::default();
    let FetchPlanOutcome::Planned(plan_box) = plan_fetch_covers(&req, &graph, &cover_index, &retention).unwrap() else {
        panic!("expected planned cover outcome");
    };
    let proof = verify_fetch_plan_closure(&plan_box, ReadConsumer::SmartHttpFetch, &auth, Some(&cut), &graph, &cover_index, &retention).unwrap();
    TestProofFixture { auth, plan: *plan_box, proof, cover_index, retention_index: retention, wire_packs, cover_id: last_cid, pack_id: last_pid }
}

#[test]
fn protocol_v2_negotiation_bounds_and_policy_gates() {
    let def = OffloadPolicyConfig::default();
    assert_eq!(def, OffloadPolicyConfig::disabled());
    assert!(!def.enabled && !def.advertise_in_capabilities);
    assert!(!should_advertise_packfile_uris(&def));

    let mut adv_off = sample_policy();
    adv_off.advertise_in_capabilities = false;
    assert!(!should_advertise_packfile_uris(&adv_off));
    assert!(should_advertise_packfile_uris(&sample_policy()));

    let mut raw_adv = Vec::new();
    protocol_v2::push_pkt_line(&mut raw_adv, b"version 2\n").unwrap();
    protocol_v2::push_pkt_line(&mut raw_adv, b"fetch=shallow wait-for-done\n").unwrap();
    raw_adv.extend_from_slice(b"0000");
    assert_eq!(inject_packfile_uris_into_v2_advertisement(&raw_adv, &def).unwrap(), raw_adv);
    assert_eq!(inject_packfile_uris_into_v2_advertisement(&raw_adv, &adv_off).unwrap(), raw_adv);
    let injected = inject_packfile_uris_into_v2_advertisement(&raw_adv, &sample_policy()).unwrap();
    assert!(String::from_utf8_lossy(&injected).contains("fetch=shallow wait-for-done packfile-uris\n"));

    let oid = "a".repeat(40);
    let want_line = format!("want {oid}\n");
    let mut too_many_wants = vec!["packfile-uris https"];
    let want_refs: Vec<String> = (0..=MAX_FETCH_WANTS).map(|_| want_line.clone()).collect();
    too_many_wants.extend(want_refs.iter().map(String::as_str));
    assert!(matches!(
        parse_fetch_v2_request(&build_v2_fetch_wire(&too_many_wants), PackObjectFormat::Sha1),
        Err(PackfileUriError::CapacityExceeded(_))
    ));
    let have_line = format!("have {oid}\n");
    let mut too_many_haves = vec!["packfile-uris https", want_line.as_str()];
    let have_refs: Vec<String> = (0..=MAX_FETCH_HAVES).map(|_| have_line.clone()).collect();
    too_many_haves.extend(have_refs.iter().map(String::as_str));
    assert!(matches!(
        parse_fetch_v2_request(&build_v2_fetch_wire(&too_many_haves), PackObjectFormat::Sha1),
        Err(PackfileUriError::CapacityExceeded(_))
    ));
}

#[test]
fn ssrf_guard_blocks_empty_ips_private_ips_and_serde_loopback_bypass() {
    let policy = sample_policy();
    let valid = "https://cdn.rootyard.test/v1/packs/good.pack?sig=secret";
    assert!(matches!(validate_offload_uri(valid, &policy, &[]), Err(PackfileUriError::SsrfBlocked(_))));
    let empty_resolver = StaticMapDnsResolver::new();
    assert!(matches!(
        validate_offload_uri_and_resolve(valid, &policy, &empty_resolver),
        Err(PackfileUriError::SsrfBlocked(_))
    ));
    assert!(!policy.loopback_allowed());
    assert!(policy.clone().with_loopback_localhost_for_test(8443).is_err());
    let localhost_pol = OffloadPolicyConfig::strict_production(vec!["cdn.localhost".to_owned()], "kid-v1")
        .with_loopback_localhost_for_test(8443)
        .unwrap();
    let roundtrip: OffloadPolicyConfig = serde_json::from_str(&serde_json::to_string(&localhost_pol).unwrap()).unwrap();
    assert!(!roundtrip.loopback_allowed(), "serde roundtrip must never preserve test loopback opt-in");

    let bad_ips = [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
        IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V6("fc00::1".parse().unwrap()),
        IpAddr::V6("::ffff:169.254.169.254".parse().unwrap()),
    ];
    for ip in bad_ips {
        assert!(matches!(validate_offload_uri(valid, &policy, &[ip]), Err(PackfileUriError::SsrfBlocked(_))));
    }
}

#[tokio::test]
async fn signing_binds_subject_host_rotation_expiry_and_live_auth() {
    let policy = sample_policy();
    let mut ring = sample_keyring();
    let resolver = sample_resolver();
    let tenant = Uuid::new_v4();
    let repo = Uuid::new_v4();
    let pin = Uuid::new_v4();
    let subject = sample_subject();
    assert!(DownloadSubjectContext::new(Uuid::nil(), subject.token_id, 1).is_err());
    assert!(DownloadSubjectContext::new(subject.actor_id, Uuid::nil(), 1).is_err());
    assert!(DownloadSubjectContext::new(subject.actor_id, subject.token_id, 0).is_err());

    let (_raw, pack_hash, sha256) = sample_pack_bytes(PackObjectFormat::Sha256, 0);
    let desc = mint_signed_offload_uri(
        &ring,
        &MintUriRequest {
            tenant_id: tenant,
            repository_id: repo,
            subject,
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
            resolver: resolver.as_ref(),
        },
    )
    .unwrap();

    let allow = Arc::new(AtomicBool::new(true));
    let mut auth = ScopedAuthorizer::permissive(Arc::clone(&allow));
    let params = VerifyDownloadParams {
        raw_uri: &desc.uri,
        inbound_host: "cdn.rootyard.test",
        expected_tenant_id: tenant,
        expected_repository_id: repo,
        expected_pack_oid: &pack_hash,
        expected_format: PackObjectFormat::Sha256,
        presented_subject: Some(subject),
        now_unix: 1_050,
        policy: &policy,
        resolver: resolver.as_ref(),
    };
    assert!(verify_signed_download_request(&ring, &auth, &params).await.is_ok());

    let spoof_host = VerifyDownloadParams { inbound_host: "evil.example.net", ..params };
    assert!(matches!(verify_signed_download_request(&ring, &auth, &spoof_host).await, Err(PackfileUriError::ScopeMismatch(_))));

    let wrong_caller = VerifyDownloadParams { presented_subject: Some(sample_subject()), ..params };
    assert!(matches!(verify_signed_download_request(&ring, &auth, &wrong_caller).await, Err(PackfileUriError::ScopeMismatch(_))));

    auth.denied_token = Some(subject.token_id);
    assert!(matches!(verify_signed_download_request(&ring, &auth, &params).await, Err(PackfileUriError::Unauthorized)));
    auth.denied_token = None;
    auth.min_epoch = subject.auth_epoch + 1;
    assert!(matches!(verify_signed_download_request(&ring, &auth, &params).await, Err(PackfileUriError::Unauthorized)));
    auth.min_epoch = 1;

    ring.retire_for_signing("kid-v1");
    assert!(verify_signed_download_request(&ring, &auth, &params).await.is_ok());
    ring.revoke_key("kid-v1");
    assert!(matches!(verify_signed_download_request(&ring, &auth, &params).await, Err(PackfileUriError::InvalidSignature(_))));
}

#[tokio::test]
async fn planner_verifies_184_proof_retention_states_and_rollback_bounds() {
    let durable = DurablePinRegistry::new();
    let leases = PackDeliveryLeaseRegistry::with_max_leases(durable.clone(), 1);
    let policy = sample_policy();
    let ring = Arc::new(sample_keyring());
    let resolver = sample_resolver();
    let breaker = Arc::new(CdnCircuitBreaker::new(2, Duration::from_millis(20)));
    let planner = DeliveryPlanner::new(Arc::clone(&ring), leases.clone(), Arc::clone(&breaker));
    let auth = ScopedAuthorizer::permissive(Arc::new(AtomicBool::new(true)));

    let tenant = Uuid::new_v4();
    let repo = Uuid::new_v4();
    let subject = sample_subject();
    let (_raw, pack_hash, sha256) = sample_pack_bytes(PackObjectFormat::Sha1, 8_192);
    let fx = build_verified_fixture(tenant, repo, subject, &pack_hash, &sha256, 8_224, false);
    let want_oid = "2".repeat(40);
    let fetch_req = parse_fetch_v2_request(
        &build_v2_fetch_wire(&["packfile-uris https", &format!("want {want_oid}\n"), "done\n"]),
        PackObjectFormat::Sha1,
    )
    .unwrap();
    let cover_in = VerifiedPackCoverInput {
        auth: &fx.auth,
        plan: &fx.plan,
        proof: &fx.proof,
        cover_index: &fx.cover_index,
        retention_index: &fx.retention_index,
        wire_packs: &fx.wire_packs,
        residual_inline_bytes: 128,
        full_fallback_inline_bytes: 8_352,
    };
    let base_req = DeliveryPlanRequest {
        tenant_id: tenant,
        repository_id: repo,
        gate_revision: 1,
        object_format: PackObjectFormat::Sha1,
        fetch_req: &fetch_req,
        cover: &cover_in,
        cdn_health: CdnHealthState::Healthy,
        allowed_host: "cdn.rootyard.test",
        now_unix: 1_000,
        resolver: resolver.as_ref(),
        policy: &policy,
        active_queue_saturated: false,
    };
    let planned = planner.plan_fetch(&auth, &base_req).await.unwrap();
    let guard = match planned.mode {
        DeliveryMode::OffloadPlusResidual { ref lease_pins, .. } => lease_pins[0].clone(),
        ref other => panic!("expected offload, got {other:?}"),
    };
    // Lease capacity = 1: second concurrent pin acquisition fails cleanly to InlineFallback(PinAcquisitionFailed).
    let saturated = planner.plan_fetch(&auth, &base_req).await.unwrap();
    assert!(matches!(saturated.mode, DeliveryMode::InlineFallback { reason: FallbackReason::PinAcquisitionFailed, .. }));
    drop(guard);
    drop(planned);
    // Auto-sweep in acquire_offload_pin reclaims expired lease after grace window.
    let after_grace = DeliveryPlanRequest { now_unix: 1_500, ..base_req };
    let recovered = planner.plan_fetch(&auth, &after_grace).await.unwrap();
    assert!(matches!(recovered.mode, DeliveryMode::OffloadPlusResidual { .. }));
    drop(recovered);

    // Mismatched auth epoch fails closed with Unauthorized (`binds_live_auth`).
    let mut forged_auth = fx.auth.clone();
    forged_auth.auth_epoch += 1;
    let bad_cover = VerifiedPackCoverInput { auth: &forged_auth, ..cover_in };
    assert!(matches!(
        planner.plan_fetch(&auth, &DeliveryPlanRequest { cover: &bad_cover, now_unix: 2_000, ..base_req }).await,
        Err(PackfileUriError::Unauthorized)
    ));

    // Quarantined (`PhysicallyPresent`, not `PlannableForFetch`) or thin pack shifts out of offload.
    let mut unheld_ret = RetentionClassificationIndex::new();
    unheld_ret.set_physical_status(fx.pack_id, PhysicalBlobStatus::Present);
    let unheld_cover = VerifiedPackCoverInput { retention_index: &unheld_ret, ..cover_in };
    let unheld_res = planner
        .plan_fetch(&auth, &DeliveryPlanRequest { cover: &unheld_cover, now_unix: 2_000, ..base_req })
        .await
        .unwrap();
    assert!(matches!(unheld_res.mode, DeliveryMode::InlineFallback { reason: FallbackReason::BelowOffloadThreshold, .. }));

    // Oversized wire_packs (> MAX_CLOSURE_PACKS) fails closed with CapacityExceeded.
    let mut huge_wires = fx.wire_packs.clone();
    for _ in 0..=MAX_CLOSURE_PACKS {
        huge_wires.insert(Uuid::new_v4(), fx.wire_packs[&fx.pack_id].clone());
    }
    let huge_cover = VerifiedPackCoverInput { wire_packs: &huge_wires, ..cover_in };
    assert!(matches!(
        planner.plan_fetch(&auth, &DeliveryPlanRequest { cover: &huge_cover, now_unix: 2_500, ..base_req }).await,
        Err(PackfileUriError::CapacityExceeded(_))
    ));
    let _ = fx.cover_id;
}
