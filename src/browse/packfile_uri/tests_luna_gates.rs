//! Targeted unit & async cancellation regressions for all 4 production merge gates:
//! (1) advertised-ref `wants` + whole-pack closure authorization,
//! (2) native inline fallback on all unsupported/unknown Protocol v2 `fetch` args,
//! (3) hard bounds on helper `git`, `.pack`/`.idx` scanning, and HTTP responses,
//! (4) RAII cancellation-safe preflight cleanup & bounded concurrent preflights.

use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

use tempfile::TempDir;
use tokio::sync::Notify;
use uuid::Uuid;

use crate::ref_store::GitObjectFormat;

use super::{
    tests::{
        ScopedAuthorizer, build_v2_fetch_wire, build_verified_fixture, sample_keyring, sample_pack_bytes,
        sample_policy, sample_resolver, sample_subject,
    },
    *,
};

fn find_git_bin() -> PathBuf {
    for c in ["/usr/bin/git", "/usr/local/bin/git"] {
        let p = Path::new(c);
        if p.is_file() {
            return p.to_path_buf();
        }
    }
    PathBuf::from("git")
}

fn git_sync(git_bin: &Path, cwd: &Path, args: &[&str]) -> String {
    let out = Command::new(git_bin)
        .current_dir(cwd)
        .arg("-c")
        .arg("core.hooksPath=/dev/null")
        .arg("-c")
        .arg("gc.auto=0")
        .arg("-c")
        .arg("maintenance.auto=false")
        .arg("-c")
        .arg("commit.gpgsign=false")
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("spawn git");
    assert!(out.status.success(), "git {args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

fn setup_two_branch_repacked_bare_repo(root: &Path, git_bin: &Path) -> (PathBuf, String, String) {
    let bare = root.join("bare.git");
    let work = root.join("work");
    std::fs::create_dir_all(&bare).unwrap();
    std::fs::create_dir_all(&work).unwrap();
    git_sync(git_bin, &bare, &["init", "--bare", "."]);
    git_sync(git_bin, &work, &["init", "."]);
    git_sync(git_bin, &work, &["config", "user.name", "Test"]);
    git_sync(git_bin, &work, &["config", "user.email", "test@rootyard.invalid"]);

    let main_bytes: Vec<u8> = (0..8_192u32).map(|i| ((i.wrapping_mul(31) >> 3) & 0xff) as u8).collect();
    std::fs::write(work.join("main.bin"), &main_bytes).unwrap();
    git_sync(git_bin, &work, &["add", "main.bin"]);
    git_sync(git_bin, &work, &["commit", "-m", "main tip"]);
    let main_oid = git_sync(git_bin, &work, &["rev-parse", "HEAD"]);
    git_sync(git_bin, &work, &["push", bare.to_str().unwrap(), "HEAD:refs/heads/main"]);

    git_sync(git_bin, &work, &["checkout", "--orphan", "secret-branch"]);
    git_sync(git_bin, &work, &["rm", "-rf", "."]);
    let secret_bytes: Vec<u8> = (0..8_192u32).map(|i| ((i.wrapping_mul(97) >> 2) & 0xff) as u8).collect();
    std::fs::write(work.join("secret.bin"), &secret_bytes).unwrap();
    git_sync(git_bin, &work, &["add", "secret.bin"]);
    git_sync(git_bin, &work, &["commit", "-m", "secret tip"]);
    let secret_oid = git_sync(git_bin, &work, &["rev-parse", "HEAD"]);
    git_sync(git_bin, &work, &["push", bare.to_str().unwrap(), "HEAD:refs/heads/secret"]);
    // Combine BOTH branches into one shared `.pack` file on disk.
    git_sync(git_bin, &bare, &["repack", "-a", "-d"]);
    (bare, main_oid, secret_oid)
}

fn make_bridge_req<'a>(
    git_binary: &'a Path,
    repo_dir: &'a Path,
    advertised_refs: &'a [(String, String)],
    request_bytes: &'a [u8],
    tenant_id: Uuid,
    repository_id: Uuid,
    subject: DownloadSubjectContext,
    live_revalidator: LiveRevalidatorFn,
) -> GatewayFetchBridgeInput<'a> {
    GatewayFetchBridgeInput {
        git_binary,
        repo_dir,
        advertised_refs,
        object_format: GitObjectFormat::Sha1,
        request_bytes,
        tenant_id,
        repository_id,
        history_incarnation: Uuid::new_v4(),
        authority_epoch: 1,
        group_epoch: 1,
        subject,
        provider: "s3",
        backend_identity_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        request_timeout: Duration::from_secs(10),
        max_response_bytes: 16 * 1024 * 1024,
        live_revalidator,
    }
}

#[tokio::test]
async fn wants_and_whole_pack_closure_must_belong_to_authorized_advertised_refs() {
    let tmp = TempDir::new().unwrap();
    let git_bin = find_git_bin();
    let (bare, main_oid, secret_oid) = setup_two_branch_repacked_bare_repo(tmp.path(), &git_bin);
    let subject = sample_subject();
    let tenant = Uuid::new_v4();
    let repo = Uuid::new_v4();

    let mut policy = sample_policy();
    policy.min_pack_bytes_for_offload = 128;
    let offload = GatewayPackfileOffload::new(Arc::new(sample_keyring()), policy, "cdn.rootyard.test", sample_resolver());
    let ok_reval: LiveRevalidatorFn = Arc::new(|| Box::pin(async { Ok(()) }));

    // 1A: Requesting `secret_oid` when ONLY `refs/heads/main` is advertised -> UnadvertisedWant.
    let adv_main_only = vec![("refs/heads/main".to_owned(), main_oid.clone())];
    let wire_secret = build_v2_fetch_wire(&["packfile-uris https", &format!("want {secret_oid}\n"), "done\n"]);
    let res_unadv = offload
        .try_serve_upload_pack_v2(make_bridge_req(
            &git_bin,
            &bare,
            &adv_main_only,
            &wire_secret,
            tenant,
            repo,
            subject,
            Arc::clone(&ok_reval),
        ))
        .await
        .unwrap();
    assert!(res_unadv.is_none());
    assert_eq!(offload.last_fallback_reason(), Some(FallbackReason::UnadvertisedWant));
    assert_eq!(offload.pack_server().pack_count(), 0);

    // 1B: Requesting `main_oid` when the sole `.pack` ALSO contains `secret` objects -> PackContainsUnauthorizedObjects!
    let wire_main = build_v2_fetch_wire(&["packfile-uris https", &format!("want {main_oid}\n"), "done\n"]);
    let res_mixed = offload
        .try_serve_upload_pack_v2(make_bridge_req(
            &git_bin,
            &bare,
            &adv_main_only,
            &wire_main,
            tenant,
            repo,
            subject,
            Arc::clone(&ok_reval),
        ))
        .await
        .unwrap();
    assert!(res_mixed.is_none(), "mixed pack containing unrequested/unadvertised objects must never be offloaded");
    assert_eq!(offload.last_fallback_reason(), Some(FallbackReason::PackContainsUnauthorizedObjects));
    assert_eq!(offload.pack_server().pack_count(), 0);

    // 1C: When BOTH refs are authorized/advertised AND both are wanted, 100% of pack objects are authorized -> offloads!
    let adv_both = vec![("refs/heads/main".to_owned(), main_oid.clone()), ("refs/heads/secret".to_owned(), secret_oid.clone())];
    let wire_both = build_v2_fetch_wire(&[
        "packfile-uris https",
        &format!("want {main_oid}\n"),
        &format!("want {secret_oid}\n"),
        "done\n",
    ]);
    let res_both = offload
        .try_serve_upload_pack_v2(make_bridge_req(
            &git_bin,
            &bare,
            &adv_both,
            &wire_both,
            tenant,
            repo,
            subject,
            ok_reval,
        ))
        .await
        .unwrap();
    assert!(res_both.is_some(), "pack whose entire object set is within authorized advertised wants should offload");
    assert_eq!(offload.pack_server().pack_count(), 1);
}

#[tokio::test]
async fn unsupported_and_unknown_v2_fetch_args_deterministically_fallback_to_native() {
    let tenant = Uuid::new_v4();
    let repo = Uuid::new_v4();
    let subject = sample_subject();
    let (raw, pack_hash, sha256) = sample_pack_bytes(PackObjectFormat::Sha1, 8_192);
    let fx = build_verified_fixture(tenant, repo, subject, &pack_hash, &sha256, raw.len() as u64, false);
    let policy = sample_policy();
    let resolver = sample_resolver();
    let planner = DeliveryPlanner::new(
        Arc::new(sample_keyring()),
        PackDeliveryLeaseRegistry::default(),
        Arc::new(CdnCircuitBreaker::new(2, Duration::from_secs(30))),
    );
    let auth = ScopedAuthorizer::permissive(Arc::new(AtomicBool::new(true)));
    let want_oid = "2".repeat(40);
    let cover_in = VerifiedPackCoverInput {
        auth: &fx.auth,
        plan: &fx.plan,
        proof: &fx.proof,
        cover_index: &fx.cover_index,
        retention_index: &fx.retention_index,
        wire_packs: &fx.wire_packs,
        residual_inline_bytes: 0,
        full_fallback_inline_bytes: raw.len() as u64,
        rejected_unauthorized_pack: false,
    };

    for bad_arg in [
        "filter blob:none\n",
        "deepen 1\n",
        "deepen-since 1700000000\n",
        "deepen-not refs/heads/old\n",
        "deepen-relative\n",
        &format!("shallow {}\n", "1".repeat(40)),
        "want-ref refs/heads/main\n",
        "sideband-all\n",
        "unknown-future-arg xyz\n",
    ] {
        let wire = build_v2_fetch_wire(&["packfile-uris https\n", &format!("want {want_oid}\n"), bad_arg, "done\n"]);
        let parsed = parse_fetch_v2_request(&wire, PackObjectFormat::Sha1).unwrap();
        assert!(parsed.has_unsupported_args(), "expected unsupported arg for {bad_arg}");
        let stripped = strip_packfile_uris_from_v2_request(&wire).expect("should strip packfile-uris");
        let stripped_str = String::from_utf8_lossy(&stripped);
        assert!(!stripped_str.contains("packfile-uris"));
        assert!(stripped_str.contains(bad_arg.trim()), "native fallback request must preserve {bad_arg}");

        let planned = planner
            .plan_fetch(
                &auth,
                &DeliveryPlanRequest {
                    tenant_id: tenant,
                    repository_id: repo,
                    gate_revision: 1,
                    object_format: PackObjectFormat::Sha1,
                    fetch_req: &parsed,
                    cover: &cover_in,
                    cdn_health: CdnHealthState::Healthy,
                    allowed_host: "cdn.rootyard.test",
                    now_unix: 1_000,
                    resolver: resolver.as_ref(),
                    policy: &policy,
                    active_queue_saturated: false,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            planned.mode,
            DeliveryMode::InlineFallback {
                reason: FallbackReason::UnsupportedFetchArgs,
                total_inline_bytes: raw.len() as u64,
                total_objects: 1,
            }
        );
    }

    // Pre-delim `server-option=...` capability also triggers UnsupportedFetchArgs.
    let mut pre_wire = Vec::new();
    protocol_v2::push_pkt_line(&mut pre_wire, b"command=fetch\n").unwrap();
    protocol_v2::push_pkt_line(&mut pre_wire, b"agent=git/2.56.1\n").unwrap();
    protocol_v2::push_pkt_line(&mut pre_wire, b"server-option=custom\n").unwrap();
    pre_wire.extend_from_slice(b"0001");
    protocol_v2::push_pkt_line(&mut pre_wire, b"packfile-uris https\n").unwrap();
    protocol_v2::push_pkt_line(&mut pre_wire, format!("want {want_oid}\n").as_bytes()).unwrap();
    protocol_v2::push_pkt_line(&mut pre_wire, b"done\n").unwrap();
    pre_wire.extend_from_slice(b"0000");
    let pre_parsed = parse_fetch_v2_request(&pre_wire, PackObjectFormat::Sha1).unwrap();
    assert!(pre_parsed.has_unsupported_args());
}

#[tokio::test]
async fn helper_git_pack_scanner_and_v2_response_enforce_hard_resource_bounds() {
    let tmp = TempDir::new().unwrap();
    let git_bin = find_git_bin();
    let (bare, main_oid, secret_oid) = setup_two_branch_repacked_bare_repo(tmp.path(), &git_bin);
    let subject = sample_subject();

    // 3A: Helper stdout byte cap kills subprocess and fails closed with CapacityExceeded.
    let tiny_out = run_git_bounded(
        &git_bin,
        &bare,
        &["rev-list", "--objects", "--all"],
        None,
        8,
        Duration::from_secs(5),
    )
    .await;
    assert!(matches!(tiny_out, Err(PackfileUriError::CapacityExceeded(_))));

    // 3B: Zero timeout fails closed immediately with Timeout.
    let expired = run_git_bounded(&git_bin, &bare, &["rev-parse", "HEAD"], None, 1024, Duration::ZERO).await;
    assert!(matches!(expired, Err(PackfileUriError::Timeout(_))));

    // 3C: Pack scanner enforces `max_single_pack_bytes` BEFORE reading into memory.
    let adv_both = vec![("refs/heads/main".to_owned(), main_oid.clone()), ("refs/heads/secret".to_owned(), secret_oid.clone())];
    let wants_both = vec![main_oid, secret_oid];
    let tight_limits = HelperResourceLimits { max_single_pack_bytes: 64, ..HelperResourceLimits::default() };
    let scan_res = build_verified_cover_proof_from_repo(&RepoCoverBuildParams {
        git_binary: &git_bin,
        repo_dir: &bare,
        advertised_refs: &adv_both,
        wants: &wants_both,
        haves: &[],
        include_tag: false,
        tenant_id: Uuid::new_v4(),
        repository_id: Uuid::new_v4(),
        history_incarnation: Uuid::new_v4(),
        authority_epoch: 1,
        group_epoch: 1,
        object_format: GitObjectFormat::Sha1,
        subject,
        provider: "s3",
        backend_identity_hex: &"a".repeat(64),
        limits: tight_limits,
    })
    .await;
    assert!(matches!(scan_res, Err(PackfileUriError::CapacityExceeded(_))));

    // 3D: Encoded HTTP v2 response enforces `max_response_bytes`.
    let policy = sample_policy();
    let inline = DeliveryMode::InlineFallback {
        reason: FallbackReason::BelowOffloadThreshold,
        total_inline_bytes: 4096,
        total_objects: 1,
    };
    let oversized_resp = encode_fetch_v2_response_bounded(&policy, &inline, &[], &[0u8; 4096], true, 1024);
    assert!(matches!(oversized_resp, Err(PackfileUriError::CapacityExceeded(_))));
}

#[tokio::test]
async fn cancelled_preflights_release_state_via_raii_and_concurrency_cap_bounds_load() {
    let tmp = TempDir::new().unwrap();
    let git_bin = find_git_bin();
    let (bare, main_oid, secret_oid) = setup_two_branch_repacked_bare_repo(tmp.path(), &git_bin);
    let adv_both = vec![("refs/heads/main".to_owned(), main_oid.clone()), ("refs/heads/secret".to_owned(), secret_oid.clone())];
    let wire_both = build_v2_fetch_wire(&[
        "packfile-uris https",
        &format!("want {main_oid}\n"),
        &format!("want {secret_oid}\n"),
        "done\n",
    ]);

    let mut policy = sample_policy();
    policy.min_pack_bytes_for_offload = 128;
    policy.max_concurrent_preflights = 2;
    let offload = Arc::new(GatewayPackfileOffload::new(
        Arc::new(sample_keyring()),
        policy,
        "cdn.rootyard.test",
        sample_resolver(),
    ));
    assert_eq!(offload.available_preflight_permits(), 2);

    let entered = Arc::new(Notify::new());
    let hold_gate = Arc::new(Notify::new());
    let make_slow_reval = || -> LiveRevalidatorFn {
        let e = Arc::clone(&entered);
        let h = Arc::clone(&hold_gate);
        Arc::new(move || {
            let e = Arc::clone(&e);
            let h = Arc::clone(&h);
            Box::pin(async move {
                e.notify_one();
                h.notified().await;
                Ok(())
            })
        })
    };

    let spawn_inflight = |off: Arc<GatewayPackfileOffload>,
                          gb: PathBuf,
                          br: PathBuf,
                          adv: Vec<(String, String)>,
                          wb: Vec<u8>,
                          rv: LiveRevalidatorFn| {
        tokio::spawn(async move {
            off.try_serve_upload_pack_v2(make_bridge_req(
                &gb,
                &br,
                &adv,
                &wb,
                Uuid::new_v4(),
                Uuid::new_v4(),
                sample_subject(),
                rv,
            ))
            .await
        })
    };

    let t1 = spawn_inflight(
        Arc::clone(&offload),
        git_bin.clone(),
        bare.clone(),
        adv_both.clone(),
        wire_both.clone(),
        make_slow_reval(),
    );
    entered.notified().await;
    let t2 = spawn_inflight(
        Arc::clone(&offload),
        git_bin.clone(),
        bare.clone(),
        adv_both.clone(),
        wire_both.clone(),
        make_slow_reval(),
    );
    entered.notified().await;

    assert_eq!(offload.active_preflight_count(), 2);
    assert_eq!(offload.available_preflight_permits(), 0);

    // 3rd concurrent request hits preflight saturation -> deterministic native fallback!
    let fast_reval: LiveRevalidatorFn = Arc::new(|| Box::pin(async { Ok(()) }));
    let third = offload
        .try_serve_upload_pack_v2(make_bridge_req(
            &git_bin,
            &bare,
            &adv_both,
            &wire_both,
            Uuid::new_v4(),
            Uuid::new_v4(),
            sample_subject(),
            Arc::clone(&fast_reval),
        ))
        .await
        .unwrap();
    assert!(third.is_none());
    assert_eq!(offload.last_fallback_reason(), Some(FallbackReason::OverloadedOrQueueSaturated));
    assert_eq!(offload.preflight_saturation_fallbacks(), 1);

    // Cancel/abort both inflight futures mid-`.await`: RAII drop must clean up 100% of state & permits!
    t1.abort();
    t2.abort();
    let _ = t1.await;
    let _ = t2.await;

    assert_eq!(offload.active_preflight_count(), 0, "cancelled preflight must not leak auth entry");
    assert_eq!(offload.available_preflight_permits(), 2, "cancelled preflight must restore semaphore permits");
    assert_eq!(offload.planner().leases().active_pin_count(), 0, "cancelled preflight must hold zero pins");

    // Subsequent request succeeds cleanly with full capacity restored.
    let recovered = offload
        .try_serve_upload_pack_v2(make_bridge_req(
            &git_bin,
            &bare,
            &adv_both,
            &wire_both,
            Uuid::new_v4(),
            Uuid::new_v4(),
            sample_subject(),
            fast_reval,
        ))
        .await
        .unwrap();
    assert!(recovered.is_some());
    assert_eq!(offload.active_preflight_count(), 0);
    assert_eq!(offload.available_preflight_permits(), 2);
}
