//! Regressions for confined `objects/pack` traversal/symlink rejection, bounded artifact
//! reads, and zero-TOCTOU `Bytes` verification/serving after on-disk pack tampering.

use std::{
    collections::HashMap,
    ffi::OsStr,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    time::Duration,
};

use tempfile::TempDir;
use uuid::Uuid;

use crate::ref_store::GitObjectFormat;

use super::{
    cover_git::discover_repo_packs,
    pack_bijection::PinnedPackDir,
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
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", dev_null)
        .output()
        .expect("spawn git");
    assert!(out.status.success(), "git {args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

fn create_repacked_bare_repo(root: &Path, git_bin: &Path) -> (PathBuf, String) {
    let bare = root.join("bare_sha1.git");
    let work = root.join("work_sha1");
    std::fs::create_dir_all(&bare).unwrap();
    std::fs::create_dir_all(&work).unwrap();
    git_sync(git_bin, &bare, &["init", "--bare", "--object-format=sha1", "."]);
    git_sync(git_bin, &work, &["init", "--object-format=sha1", "."]);
    git_sync(git_bin, &work, &["config", "user.name", "Test"]);
    git_sync(git_bin, &work, &["config", "user.email", "test@rootyard.invalid"]);
    let payload: Vec<u8> = (0..8_192u32).map(|i| ((i.wrapping_mul(1_664_525) >> 16) & 0xff) as u8).collect();
    std::fs::write(work.join("blob.bin"), &payload).unwrap();
    git_sync(git_bin, &work, &["add", "blob.bin"]);
    git_sync(git_bin, &work, &["commit", "-m", "initial pack"]);
    let tip = git_sync(git_bin, &work, &["rev-parse", "HEAD"]);
    git_sync(git_bin, &work, &["push", bare.to_str().unwrap(), "HEAD:refs/heads/main"]);
    git_sync(git_bin, &bare, &["repack", "-a", "-d"]);
    (bare, tip)
}

fn pack_dir_of(bare: &Path) -> PathBuf {
    bare.join("objects").join("pack")
}

fn only_pack_path(bare: &Path) -> PathBuf {
    std::fs::read_dir(pack_dir_of(bare))
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|ext| ext == "pack"))
        .expect("repacked .pack file")
}

fn remove_pack_file(path: &Path) {
    #[cfg(not(unix))]
    {
        if let Ok(meta) = std::fs::metadata(path) {
            let mut perms = meta.permissions();
            perms.set_readonly(false);
            let _ = std::fs::set_permissions(path, perms);
        }
    }
    std::fs::remove_file(path).unwrap();
}

fn index_pack_strict_succeeds(git_bin: &Path, scratch: &Path, pack_bytes: &[u8]) -> bool {
    let pack = scratch.join("served.pack");
    let idx = scratch.join("served.idx");
    std::fs::write(&pack, pack_bytes).unwrap();
    let dev_null = if cfg!(unix) { "/dev/null" } else { "NUL" };
    let out = Command::new(git_bin)
        .arg("-C")
        .arg(scratch)
        .arg("index-pack")
        .arg("--strict")
        .arg("-o")
        .arg(&idx)
        .arg(&pack)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", dev_null)
        .output()
        .expect("spawn git index-pack");
    out.status.success()
}

#[tokio::test]
async fn confined_pack_open_rejects_symlinks_traversal_and_nonregular_entries_with_safe_fallback() {
    let git_bin = find_git_bin();
    let tmp = TempDir::new().unwrap();
    let (bare, tip) = create_repacked_bare_repo(tmp.path(), &git_bin);
    let pinned = PinnedPackDir::open_confined(&bare).unwrap().expect("pinned pack dir");

    for bad in ["../outside.pack", "sub/evil.pack", "."] {
        let mut total = 0u64;
        let res = pinned.read_regular_artifact(OsStr::new(bad), 1 << 20, &mut total, 1 << 20);
        assert!(matches!(res, Err(PackfileUriError::IntegrityMismatch(_))), "accepted traversal name {bad}");
        assert_eq!(total, 0);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let pack_dir = pack_dir_of(&bare);
        let outside = tmp.path().join("outside.pack");
        let outside_bytes = b"PACK-OUTSIDE-SECRET-MUST-NEVER-BE-READ";
        std::fs::write(&outside, outside_bytes).unwrap();
        let evil = pack_dir.join("pack-evil.pack");
        symlink(&outside, &evil).unwrap();
        let mut total = 0u64;
        let res = pinned.read_regular_artifact(OsStr::new("pack-evil.pack"), 1 << 20, &mut total, 1 << 20);
        assert!(matches!(res, Err(PackfileUriError::IntegrityMismatch(_))));
        assert_eq!(total, 0, "symlink target must never be opened or read");
        assert_eq!(std::fs::read(&outside).unwrap(), &outside_bytes[..]);

        let subject = sample_subject();
        let mut policy = sample_policy();
        policy.min_pack_bytes_for_offload = 64;
        let offload =
            GatewayPackfileOffload::new(Arc::new(sample_keyring()), policy, "cdn.rootyard.test", sample_resolver());
        let wire = build_v2_fetch_wire(&["packfile-uris https", &format!("want {tip}\n"), "done\n"]);
        let adv = vec![("refs/heads/main".to_owned(), tip.clone())];
        let res = offload
            .try_serve_upload_pack_v2(GatewayFetchBridgeInput {
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
                subject,
                provider: "s3",
                backend_identity_hex: &"ab".repeat(32),
                request_timeout: Duration::from_secs(10),
                max_response_bytes: 4 * 1024 * 1024,
                live_revalidator: Arc::new(|| Box::pin(async { Ok(()) })),
            })
            .await
            .unwrap();
        assert!(res.is_none());
        assert_eq!(offload.last_fallback_reason(), Some(FallbackReason::PackContainsUnauthorizedObjects));
        assert_eq!(offload.pack_server().pack_count(), 0);
        assert_eq!(offload.active_preflight_count(), 0);
        assert_eq!(offload.planner().leases().active_pin_count(), 0);

        // Replacing `objects/pack` itself with a symlinked directory must fail closed too.
        std::fs::remove_file(&evil).unwrap();
        drop(pinned);
        std::fs::remove_dir_all(&pack_dir).unwrap();
        let attacker_dir = tmp.path().join("attacker-pack-dir");
        std::fs::create_dir_all(&attacker_dir).unwrap();
        symlink(&attacker_dir, &pack_dir).unwrap();
        assert!(matches!(PinnedPackDir::open_confined(&bare), Err(PackfileUriError::IntegrityMismatch(_))));
        let res = offload
            .try_serve_upload_pack_v2(GatewayFetchBridgeInput {
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
                backend_identity_hex: &"ab".repeat(32),
                request_timeout: Duration::from_secs(10),
                max_response_bytes: 4 * 1024 * 1024,
                live_revalidator: Arc::new(|| Box::pin(async { Ok(()) })),
            })
            .await
            .unwrap();
        assert!(res.is_none());
        assert_eq!(offload.pack_server().pack_count(), 0);
    }

    #[cfg(not(unix))]
    {
        let _ = (&bare, &tip);
    }
}

#[tokio::test]
async fn bounded_artifact_reader_enforces_single_file_and_cumulative_byte_caps() {
    let tmp = TempDir::new().unwrap();
    let pack_dir = tmp.path().join("objects").join("pack");
    std::fs::create_dir_all(&pack_dir).unwrap();
    std::fs::write(pack_dir.join("big.pack"), vec![0x5au8; 4096]).unwrap();
    let pinned = PinnedPackDir::open_dir_direct(&pack_dir).unwrap();
    let name = OsStr::new("big.pack");

    let mut total = 0u64;
    let res = pinned.read_regular_artifact(name, 2048, &mut total, 1 << 20);
    assert!(matches!(res, Err(PackfileUriError::CapacityExceeded(_))));
    assert_eq!(total, 0);

    let mut total = 3000u64;
    let res = pinned.read_regular_artifact(name, 8192, &mut total, 5000);
    assert!(matches!(res, Err(PackfileUriError::CapacityExceeded(_))));
    assert_eq!(total, 3000);

    let mut total = 1000u64;
    let bytes = pinned.read_regular_artifact(name, 4096, &mut total, 10_000).unwrap().expect("within-cap artifact");
    assert_eq!(bytes.len(), 4096);
    assert_eq!(total, 5096);
}

#[tokio::test]
async fn verified_pack_bytes_pointer_equals_served_payload_and_survives_post_scan_disk_tamper() {
    let git_bin = find_git_bin();
    let tmp = TempDir::new().unwrap();
    let (bare, tip) = create_repacked_bare_repo(tmp.path(), &git_bin);
    let tenant = Uuid::new_v4();
    let repository = Uuid::new_v4();
    let subject = sample_subject();

    let (mut packs, rejected) =
        discover_repo_packs(&git_bin, &bare, PackObjectFormat::Sha1, &HelperResourceLimits::default())
            .await
            .unwrap();
    assert!(!rejected);
    assert_eq!(packs.len(), 1);
    let pack_oid = packs[0].pack_oid.clone();
    let pack_hash_hex = packs[0].pack_hash_hex.clone();
    let len = packs[0].pack_bytes.len();
    let expected = packs[0].pack_bytes.to_vec();
    let ptr = packs[0].pack_bytes.as_ptr();
    let dp = packs.pop().unwrap();
    let mut materialized: HashMap<String, bytes::Bytes> = HashMap::new();
    materialized.insert(dp.pack_oid.clone(), dp.pack_bytes);
    assert_eq!(materialized[&pack_oid].as_ptr(), ptr, "Bytes must move without reallocation");
    assert_eq!(materialized[&pack_oid].len(), len);
    drop(materialized);

    let outcome = build_verified_cover_proof_from_repo(&RepoCoverBuildParams {
        git_binary: &git_bin,
        repo_dir: &bare,
        advertised_refs: &[("refs/heads/main".to_owned(), tip.clone())],
        wants: std::slice::from_ref(&tip),
        haves: &[],
        include_tag: false,
        tenant_id: tenant,
        repository_id: repository,
        history_incarnation: Uuid::new_v4(),
        authority_epoch: 1,
        group_epoch: 1,
        object_format: GitObjectFormat::Sha1,
        subject,
        provider: "s3",
        backend_identity_hex: &"cd".repeat(32),
        limits: HelperResourceLimits::default(),
    })
    .await
    .unwrap();
    let bundle = match outcome {
        CoverBuildOutcome::Planned(b) => b,
        CoverBuildOutcome::Fallback(reason) => panic!("expected planned bundle, got fallback {reason:?}"),
    };
    let bundled = bundle.raw_pack_bytes.get(&pack_oid).expect("verified raw pack bytes");
    assert_eq!(&bundled[..], expected.as_slice());
    let shared: bytes::Bytes = (*bundled).clone();
    assert_eq!(shared.as_ptr(), bundled.as_ptr(), "clone must share the verified allocation");
    assert_eq!(shared.len(), len);

    let mut policy = sample_policy();
    policy.min_pack_bytes_for_offload = 64;
    let offload =
        GatewayPackfileOffload::new(Arc::new(sample_keyring()), policy, "cdn.rootyard.test", sample_resolver());
    let wire = build_v2_fetch_wire(&["packfile-uris https", &format!("want {tip}\n"), "done\n"]);
    let adv = vec![("refs/heads/main".to_owned(), tip.clone())];
    let resp = offload
        .try_serve_upload_pack_v2(GatewayFetchBridgeInput {
            git_binary: &git_bin,
            repo_dir: &bare,
            advertised_refs: &adv,
            object_format: GitObjectFormat::Sha1,
            request_bytes: &wire,
            tenant_id: tenant,
            repository_id: repository,
            history_incarnation: Uuid::new_v4(),
            authority_epoch: 1,
            group_epoch: 1,
            subject,
            provider: "s3",
            backend_identity_hex: &"cd".repeat(32),
            request_timeout: Duration::from_secs(10),
            max_response_bytes: 4 * 1024 * 1024,
            live_revalidator: Arc::new(|| Box::pin(async { Ok(()) })),
        })
        .await
        .unwrap()
        .expect("offload path should emit a v2 response");
    let uris = decode_packfile_uris_section(&resp, PackObjectFormat::Sha1).unwrap();
    assert_eq!(uris.len(), 1);
    let (signed_hash, signed_uri) = &uris[0];
    assert_eq!(signed_hash, &pack_hash_hex);

    // Corrupt/remove the on-disk pack AFTER verification: serving must use the already-read Bytes.
    let disk_pack = only_pack_path(&bare);
    remove_pack_file(&disk_pack);
    assert!(!disk_pack.exists());
    let served = serve_signed_packfile(
        Arc::clone(offload.pack_server()),
        &ServePackRequest {
            raw_uri: signed_uri.as_str(),
            inbound_host: "cdn.rootyard.test",
            tenant_id: tenant,
            repository_id: repository,
            pack_oid: pack_oid.as_str(),
            object_format: PackObjectFormat::Sha1,
            presented_subject: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(served, expected);
    validate_pack_bytes_integrity(&served, len as u64, &pack_oid, &pack_hash_hex, PackObjectFormat::Sha1).unwrap();
    let scratch = TempDir::new().unwrap();
    assert!(index_pack_strict_succeeds(&git_bin, scratch.path(), &served));

    let bad_helper = offload
        .try_serve_upload_pack_v2(GatewayFetchBridgeInput {
            git_binary: Path::new("/nonexistent-git-helper-bin"),
            repo_dir: &bare,
            advertised_refs: &adv,
            object_format: GitObjectFormat::Sha1,
            request_bytes: &wire,
            tenant_id: tenant,
            repository_id: repository,
            history_incarnation: Uuid::new_v4(),
            authority_epoch: 1,
            group_epoch: 1,
            subject,
            provider: "s3",
            backend_identity_hex: &"cd".repeat(32),
            request_timeout: Duration::from_secs(10),
            max_response_bytes: 4 * 1024 * 1024,
            live_revalidator: Arc::new(|| Box::pin(async { Ok(()) })),
        })
        .await
        .unwrap();
    assert!(bad_helper.is_none());
    assert_eq!(offload.last_fallback_reason(), Some(FallbackReason::IncompleteClosure));
}
