//! Regressions for raw `.pack` <-> `.idx` stream bijection (`git index-pack --strict -o`),
//! pre-commit atomic reservation/rollback in `GatewayPackfileOffload`, pre-`0001`
//! `is_v2_fetch_command_request` parsing, and dynamic `set_policy` arming.

use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use sha2::{Digest, Sha256};
use tempfile::TempDir;
use uuid::Uuid;

use crate::ref_store::GitObjectFormat;

use super::{
    pack_bijection::{parse_and_verify_idx_v2_oids, verify_raw_pack_stream_bijection},
    protocol_v2::push_pkt_line,
    tests::{build_v2_fetch_wire, sample_keyring, sample_policy, sample_resolver, sample_subject},
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
    let dev_null = if cfg!(unix) { "/dev/null" } else { "NUL" };
    let hooks_cfg = format!("core.hooksPath={dev_null}");
    let out = Command::new(git_bin)
        .current_dir(cwd)
        .arg("-c")
        .arg(&hooks_cfg)
        .arg("-c")
        .arg("gc.auto=0")
        .arg("-c")
        .arg("maintenance.auto=false")
        .arg("-c")
        .arg("commit.gpgsign=false")
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", dev_null)
        .output()
        .expect("spawn git");
    assert!(out.status.success(), "git {args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

fn create_repacked_bare_repo(root: &Path, git_bin: &Path, fmt: PackObjectFormat) -> (PathBuf, String) {
    let bare = root.join(format!("bare_{}.git", fmt.as_str()));
    let work = root.join(format!("work_{}", fmt.as_str()));
    std::fs::create_dir_all(&bare).unwrap();
    std::fs::create_dir_all(&work).unwrap();
    git_sync(git_bin, &bare, &["init", "--bare", fmt.git_init_flag(), "."]);
    git_sync(git_bin, &work, &["init", fmt.git_init_flag(), "."]);
    git_sync(git_bin, &work, &["config", "user.name", "Test"]);
    git_sync(git_bin, &work, &["config", "user.email", "test@rootyard.invalid"]);
    let payload: Vec<u8> = (0..18_432u32).map(|i| ((i.wrapping_mul(1_664_525) >> 16) & 0xff) as u8).collect();
    std::fs::write(work.join("blob.bin"), &payload).unwrap();
    git_sync(git_bin, &work, &["add", "blob.bin"]);
    git_sync(git_bin, &work, &["commit", "-m", "initial pack"]);
    let tip = git_sync(git_bin, &work, &["rev-parse", "HEAD"]);
    git_sync(git_bin, &work, &["push", bare.to_str().unwrap(), "HEAD:refs/heads/main"]);
    git_sync(git_bin, &bare, &["repack", "-a", "-d"]);
    (bare, tip)
}

fn overwrite_pack_file(path: &Path, data: &[u8]) {
    #[cfg(not(unix))]
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_readonly(false);
        let _ = std::fs::set_permissions(path, perms);
    }
    std::fs::remove_file(path).unwrap();
    std::fs::write(path, data).unwrap();
}

#[tokio::test]
async fn raw_pack_trailing_gap_bytes_rejected_by_bijection_and_never_offloaded() {
    let git_bin = find_git_bin();
    let tmp = TempDir::new().unwrap();
    let (bare, tip) = create_repacked_bare_repo(tmp.path(), &git_bin, PackObjectFormat::Sha256);
    let pack_dir = bare.join("objects").join("pack");
    let pack_path = std::fs::read_dir(&pack_dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|x| x == "pack"))
        .expect("repacked .pack file");
    let idx_path = pack_path.with_extension("idx");
    let orig_pack = std::fs::read(&pack_path).unwrap();
    let orig_idx = std::fs::read(&idx_path).unwrap();

    // Valid pack passes raw stream bijection before tampering.
    verify_raw_pack_stream_bijection(&git_bin, &bare, &pack_path, &orig_idx, &HelperResourceLimits::default())
        .await
        .expect("untampered pack must pass bijection");

    // Splice unindexed smuggled bytes immediately before the 32-byte SHA-256 pack trailer,
    // and recompute both the .pack trailer and .idx embedded+outer SHA-256 trailers.
    let body_without_trailer = &orig_pack[..orig_pack.len() - 32];
    let mut tampered_pack = Vec::with_capacity(orig_pack.len() + 64);
    tampered_pack.extend_from_slice(body_without_trailer);
    tampered_pack.extend_from_slice(b"UNINDEXED-GAP-OBJECT-BYTES-SMUGGLED-PAST-IDX-TABLE!!");
    let new_pack_cksum = Sha256::digest(&tampered_pack);
    tampered_pack.extend_from_slice(&new_pack_cksum);

    let mut tampered_idx = orig_idx[..orig_idx.len() - 64].to_vec();
    tampered_idx.extend_from_slice(&new_pack_cksum);
    let new_idx_cksum = Sha256::digest(&tampered_idx);
    tampered_idx.extend_from_slice(&new_idx_cksum);

    // Header + fanout + OID table + checksums still match superficially...
    assert!(parse_and_verify_idx_v2_oids(&tampered_pack, &tampered_idx, PackObjectFormat::Sha256, 1024).is_ok());

    overwrite_pack_file(&pack_path, &tampered_pack);
    overwrite_pack_file(&idx_path, &tampered_idx);

    // ...but `verify_raw_pack_stream_bijection` (`git index-pack --strict -o`) catches the unindexed bytes!
    assert!(
        verify_raw_pack_stream_bijection(&git_bin, &bare, &pack_path, &tampered_idx, &HelperResourceLimits::default())
            .await
            .is_err()
    );

    let outcome = build_verified_cover_proof_from_repo(&RepoCoverBuildParams {
        git_binary: &git_bin,
        repo_dir: &bare,
        advertised_refs: &[("refs/heads/main".to_owned(), tip)],
        wants: &[],
        haves: &[],
        include_tag: false,
        tenant_id: Uuid::new_v4(),
        repository_id: Uuid::new_v4(),
        history_incarnation: Uuid::new_v4(),
        authority_epoch: 1,
        group_epoch: 1,
        object_format: GitObjectFormat::Sha256,
        subject: sample_subject(),
        provider: "s3",
        backend_identity_hex: &"ab".repeat(32),
        limits: HelperResourceLimits::default(),
    })
    .await
    .unwrap();
    assert!(matches!(outcome, CoverBuildOutcome::Fallback(FallbackReason::IncompleteClosure)));

    // Now pass the real advertised `want` so `discover_repo_packs` runs on the tampered pack.
    let tip_hex = git_sync(&git_bin, &bare, &["rev-parse", "refs/heads/main"]);
    let outcome_want = build_verified_cover_proof_from_repo(&RepoCoverBuildParams {
        git_binary: &git_bin,
        repo_dir: &bare,
        advertised_refs: &[("refs/heads/main".to_owned(), tip_hex.clone())],
        wants: std::slice::from_ref(&tip_hex),
        haves: &[],
        include_tag: false,
        tenant_id: Uuid::new_v4(),
        repository_id: Uuid::new_v4(),
        history_incarnation: Uuid::new_v4(),
        authority_epoch: 1,
        group_epoch: 1,
        object_format: GitObjectFormat::Sha256,
        subject: sample_subject(),
        provider: "s3",
        backend_identity_hex: &"ab".repeat(32),
        limits: HelperResourceLimits::default(),
    })
    .await
    .unwrap();
    assert!(matches!(outcome_want, CoverBuildOutcome::Fallback(FallbackReason::PackContainsUnauthorizedObjects)));
}

#[tokio::test]
async fn pre_commit_revalidation_and_reservation_failures_leave_zero_packs_and_zero_pins() {
    let git_bin = find_git_bin();
    let tmp = TempDir::new().unwrap();
    let (bare, tip) = create_repacked_bare_repo(tmp.path(), &git_bin, PackObjectFormat::Sha1);
    let mut policy = sample_policy();
    policy.min_pack_bytes_for_offload = 64;
    let offload =
        GatewayPackfileOffload::new(Arc::new(sample_keyring()), policy, "cdn.rootyard.test", sample_resolver());
    let wire = build_v2_fetch_wire(&["packfile-uris https", &format!("want {tip}\n"), "done\n"]);
    let adv = vec![("refs/heads/main".to_owned(), tip)];

    // 1. Live revalidator succeeds during `plan_fetch` (call #1) and fails right before `staged.commit()` (call #2).
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_c = Arc::clone(&calls);
    let reval_fail_second: LiveRevalidatorFn = Arc::new(move || {
        let n = calls_c.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { if n == 0 { Ok(()) } else { Err(PackfileUriError::Unauthorized) } })
    });
    let res_unauth = offload
        .try_serve_upload_pack_v2_with_guard(
            GatewayFetchBridgeInput {
                git_binary: &git_bin,
                repo_dir: &bare,
                advertised_refs: &adv,
                object_format: GitObjectFormat::Sha1,
                request_bytes: &wire,
                tenant_id: Uuid::new_v4(),
                repository_id: Uuid::new_v4(),
                history_incarnation: Uuid::new_v4(),
                authority_epoch: 1,
                group_epoch: 1,
                subject: sample_subject(),
                provider: "s3",
                backend_identity_hex: &"cd".repeat(32),
                request_timeout: Duration::from_secs(10),
                max_response_bytes: 4 * 1024 * 1024,
                live_revalidator: reval_fail_second,
            },
            |_| Ok(()),
        )
        .await;
    assert!(matches!(res_unauth, Err(PackfileUriError::Unauthorized)));
    assert_eq!(offload.pack_server().pack_count(), 0, "no pack may be inserted before revalidation + reservation");
    assert_eq!(offload.planner().leases().active_pin_count(), 0);
    assert_eq!(offload.active_preflight_count(), 0);

    // 2. Response byte reservation fails right before `insert_packs_atomic` + `staged.commit()`.
    let res_budget = offload
        .try_serve_upload_pack_v2_with_guard(
            GatewayFetchBridgeInput {
                git_binary: &git_bin,
                repo_dir: &bare,
                advertised_refs: &adv,
                object_format: GitObjectFormat::Sha1,
                request_bytes: &wire,
                tenant_id: Uuid::new_v4(),
                repository_id: Uuid::new_v4(),
                history_incarnation: Uuid::new_v4(),
                authority_epoch: 1,
                group_epoch: 1,
                subject: sample_subject(),
                provider: "s3",
                backend_identity_hex: &"cd".repeat(32),
                request_timeout: Duration::from_secs(10),
                max_response_bytes: 4 * 1024 * 1024,
                live_revalidator: Arc::new(|| Box::pin(async { Ok(()) })),
            },
            |_| Err::<(), _>(PackfileUriError::CapacityExceeded("response budget exhausted".to_owned())),
        )
        .await;
    assert!(matches!(res_budget, Err(PackfileUriError::CapacityExceeded(_))));
    assert_eq!(offload.pack_server().pack_count(), 0);
    assert_eq!(offload.planner().leases().active_pin_count(), 0);
    assert_eq!(offload.active_preflight_count(), 0);
}

#[tokio::test]
async fn pre_delim_fetch_header_detection_and_dynamic_set_policy_arming_work() {
    let mut ls_refs_wire = Vec::new();
    push_pkt_line(&mut ls_refs_wire, b"command=ls-refs\n").unwrap();
    ls_refs_wire.extend_from_slice(b"0001");
    push_pkt_line(&mut ls_refs_wire, b"ref-prefix refs/heads/command=fetch\n").unwrap();
    ls_refs_wire.extend_from_slice(b"0000");
    assert!(!is_v2_fetch_command_request(&ls_refs_wire), "post-0001 command=fetch substring must be ignored");

    let mut fetch_hdr_wire = Vec::new();
    push_pkt_line(&mut fetch_hdr_wire, b"agent=git/2.56.1\n").unwrap();
    push_pkt_line(&mut fetch_hdr_wire, b"command=fetch").unwrap();
    fetch_hdr_wire.extend_from_slice(b"00010000");
    assert!(is_v2_fetch_command_request(&fetch_hdr_wire));

    // Construct default-off offload with empty `allowed_host`, then dynamically arm via `set_policy`.
    let git_bin = find_git_bin();
    let tmp = TempDir::new().unwrap();
    let (bare, tip) = create_repacked_bare_repo(tmp.path(), &git_bin, PackObjectFormat::Sha1);
    let offload =
        GatewayPackfileOffload::new(Arc::new(sample_keyring()), OffloadPolicyConfig::disabled(), "", sample_resolver());
    let mut armed = sample_policy();
    armed.min_pack_bytes_for_offload = 64;
    armed.max_inflight_bytes = 128 * 1024 * 1024;
    offload.set_policy(armed);
    assert_eq!(offload.pack_server().max_cached_bytes.load(Ordering::Acquire), 128 * 1024 * 1024);
    assert_eq!(offload.pack_server().inflight_bytes.max_bytes(), 128 * 1024 * 1024);

    let wire = build_v2_fetch_wire(&["packfile-uris https", &format!("want {tip}\n"), "done\n"]);
    let resp = offload
        .try_serve_upload_pack_v2(GatewayFetchBridgeInput {
            git_binary: &git_bin,
            repo_dir: &bare,
            advertised_refs: &[("refs/heads/main".to_owned(), tip)],
            object_format: GitObjectFormat::Sha1,
            request_bytes: &wire,
            tenant_id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            history_incarnation: Uuid::new_v4(),
            authority_epoch: 1,
            group_epoch: 1,
            subject: sample_subject(),
            provider: "s3",
            backend_identity_hex: &"ef".repeat(32),
            request_timeout: Duration::from_secs(10),
            max_response_bytes: 4 * 1024 * 1024,
            live_revalidator: Arc::new(|| Box::pin(async { Ok(()) })),
        })
        .await
        .unwrap()
        .expect("dynamically armed offload should emit packfile-uris using policy.allowed_hosts[0]");
    let uris = decode_packfile_uris_section(&resp, PackObjectFormat::Sha1).unwrap();
    assert_eq!(uris.len(), 1);
    assert!(uris[0].1.starts_with("https://cdn.rootyard.test/"));
}
