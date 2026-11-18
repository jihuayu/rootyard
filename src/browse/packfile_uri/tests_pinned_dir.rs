//! Regressions for the retained `PinnedPackDir` directory handle (`[pinned-pack-dir-cd010506]`):
//! enumeration and `.pack` opens must stay bound to the verified `objects/pack` descriptor, and
//! any directory-handle failure must fall back deterministically to inline `git upload-pack`.

use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use tempfile::TempDir;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::ref_store::GitObjectFormat;

use super::{
    cover_git::{discover_repo_packs, discover_repo_packs_with_capability},
    pack_bijection::{PinnedPackDir, ScopedDisableHandleConfinement, is_handle_confinement_available},
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

fn only_pack_path(bare: &Path) -> PathBuf {
    std::fs::read_dir(bare.join("objects").join("pack"))
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|ext| ext == "pack"))
        .expect("repacked .pack file")
}

#[tokio::test]
async fn pinned_pack_dir_reads_verified_fd_after_parent_path_swapped_to_attacker_symlink() {
    let git_bin = find_git_bin();
    let tmp = TempDir::new().unwrap();
    let (bare, _tip) = create_repacked_bare_repo(tmp.path(), &git_bin);
    let real_pack_path = only_pack_path(&bare);
    let pack_file_name = real_pack_path.file_name().expect("pack file name").to_os_string();
    let real_pack_bytes = std::fs::read(&real_pack_path).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let pinned = PinnedPackDir::open_confined(&bare).unwrap().expect("pinned pack dir");
        let pack_dir = bare.join("objects").join("pack");
        let moved_real = bare.join("objects").join("pack.moved_real");
        std::fs::rename(&pack_dir, &moved_real).unwrap();
        let attacker_dir = tmp.path().join("attacker-pack-dir");
        std::fs::create_dir_all(&attacker_dir).unwrap();
        let forged = b"FORGED-ATTACKER-PACK-VIA-PATH-RE-RESOLUTION";
        std::fs::write(attacker_dir.join(&pack_file_name), forged).unwrap();
        symlink(&attacker_dir, &pack_dir).unwrap();

        let listed: Vec<std::ffi::OsString> =
            pinned.read_dir().unwrap().map(|entry| entry.unwrap().file_name()).collect();
        assert!(listed.contains(&pack_file_name), "pinned dir fd must list the real pack entry: {listed:?}");

        let mut total = 0u64;
        let got = pinned
            .read_regular_artifact(pack_file_name.as_os_str(), 1 << 20, &mut total, 1 << 20)
            .unwrap()
            .expect("pack bytes via pinned dirfd");
        assert_eq!(&got[..], real_pack_bytes.as_slice(), "pinned openat must never re-resolve bare/objects/pack");
        assert_eq!(total, real_pack_bytes.len() as u64);
    }

    #[cfg(not(unix))]
    {
        assert!(PinnedPackDir::open_confined(&bare).unwrap().is_none());
        assert!(PinnedPackDir::open_dir_direct(&bare).is_err());
        let _ = (&pack_file_name, &real_pack_bytes);
    }
}

#[cfg(unix)]
async fn assert_inline_fallback(
    offload: &GatewayPackfileOffload,
    git_bin: &Path,
    bare: &Path,
    adv: &[(String, String)],
    wire: &[u8],
) {
    let res = offload
        .try_serve_upload_pack_v2(GatewayFetchBridgeInput {
            git_binary: git_bin,
            repo_dir: bare,
            advertised_refs: adv,
            object_format: GitObjectFormat::Sha1,
            request_bytes: wire,
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
    assert_eq!(offload.last_fallback_reason(), Some(FallbackReason::PackContainsUnauthorizedObjects));
    assert_eq!(offload.pack_server().pack_count(), 0);
    assert_eq!(offload.active_preflight_count(), 0);
    assert_eq!(offload.planner().leases().active_pin_count(), 0);
}

#[tokio::test]
async fn parent_objects_or_pack_dir_symlink_and_openat_failures_fallback_to_inline_git() {
    let git_bin = find_git_bin();
    let tmp = TempDir::new().unwrap();
    let (bare, tip) = create_repacked_bare_repo(tmp.path(), &git_bin);
    let mut policy = sample_policy();
    policy.min_pack_bytes_for_offload = 64;
    let offload =
        GatewayPackfileOffload::new(Arc::new(sample_keyring()), policy, "cdn.rootyard.test", sample_resolver());
    let wire = build_v2_fetch_wire(&["packfile-uris https", &format!("want {tip}\n"), "done\n"]);
    let adv = vec![("refs/heads/main".to_owned(), tip)];

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let pack_dir = bare.join("objects").join("pack");
        let moved_pack = bare.join("objects").join("pack.real");
        std::fs::rename(&pack_dir, &moved_pack).unwrap();
        symlink(&moved_pack, &pack_dir).unwrap();
        assert!(matches!(PinnedPackDir::open_confined(&bare), Err(PackfileUriError::IntegrityMismatch(_))));
        assert_inline_fallback(&offload, &git_bin, &bare, &adv, &wire).await;

        // Case B: the intermediate `repo_dir -> objects` openat hop must fail closed too.
        std::fs::remove_file(&pack_dir).unwrap();
        std::fs::rename(&moved_pack, &pack_dir).unwrap();
        let objects_dir = bare.join("objects");
        let moved_objects = bare.join("objects.real");
        std::fs::rename(&objects_dir, &moved_objects).unwrap();
        symlink(&moved_objects, &objects_dir).unwrap();
        assert!(matches!(PinnedPackDir::open_confined(&bare), Err(PackfileUriError::IntegrityMismatch(_))));
        assert_inline_fallback(&offload, &git_bin, &bare, &adv, &wire).await;
    }

    #[cfg(not(unix))]
    {
        // Hosts without `openat` still exercise the shared setup (no dead-code/unused warnings).
        let _ = (&offload, &wire, &adv, &bare, sample_subject(), Duration::from_secs(10), Uuid::new_v4());
    }
}

#[tokio::test]
async fn platforms_without_handle_confinement_fallback_cleanly_to_standard_inline_git_response() {
    let git_bin = find_git_bin();
    let tmp = TempDir::new().unwrap();
    let (bare, tip) = create_repacked_bare_repo(tmp.path(), &git_bin);
    let wire = build_v2_fetch_wire(&["packfile-uris https", &format!("want {tip}\n"), "done\n"]);
    let adv = vec![("refs/heads/main".to_owned(), tip.clone())];

    #[cfg(unix)]
    {
        let mut policy = sample_policy();
        policy.min_pack_bytes_for_offload = 64;
        let armed =
            GatewayPackfileOffload::new(Arc::new(sample_keyring()), policy, "cdn.rootyard.test", sample_resolver());
        let resp = armed
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
            .unwrap()
            .expect("handle-confined host must emit an offload response");
        let uris = decode_packfile_uris_section(&resp, PackObjectFormat::Sha1).unwrap();
        assert_eq!(uris.len(), 1);
        assert!(uris[0].1.starts_with("https://cdn.rootyard.test/"));
    }

    let guard = ScopedDisableHandleConfinement::new();
    assert!(!is_handle_confinement_available());
    assert!(PinnedPackDir::open_confined_with_capability(&bare, false).unwrap().is_none());
    assert!(PinnedPackDir::open_confined(&bare).unwrap().is_none());
    assert!(matches!(PinnedPackDir::open_dir_direct(&bare), Err(PackfileUriError::IntegrityMismatch(_))));

    let limits = HelperResourceLimits::default();
    let (packs_cap, rej_cap) =
        discover_repo_packs_with_capability(&git_bin, &bare, PackObjectFormat::Sha1, &limits, false).await.unwrap();
    assert!(packs_cap.is_empty() && !rej_cap);
    let (packs_def, rej_def) = discover_repo_packs(&git_bin, &bare, PackObjectFormat::Sha1, &limits).await.unwrap();
    assert!(packs_def.is_empty() && !rej_def);

    let outcome = build_verified_cover_proof_from_repo(&RepoCoverBuildParams {
        git_binary: &git_bin,
        repo_dir: &bare,
        advertised_refs: &adv,
        wants: std::slice::from_ref(&tip),
        haves: &[],
        include_tag: false,
        tenant_id: Uuid::new_v4(),
        repository_id: Uuid::new_v4(),
        history_incarnation: Uuid::new_v4(),
        authority_epoch: 1,
        group_epoch: 1,
        object_format: GitObjectFormat::Sha1,
        subject: sample_subject(),
        provider: "s3",
        backend_identity_hex: &"ab".repeat(32),
        limits: HelperResourceLimits::default(),
    })
    .await
    .unwrap();
    assert!(matches!(outcome, CoverBuildOutcome::Fallback(FallbackReason::HandleConfinementUnavailable)));

    let mut policy = sample_policy();
    policy.min_pack_bytes_for_offload = 64;
    let offload =
        GatewayPackfileOffload::new(Arc::new(sample_keyring()), policy, "cdn.rootyard.test", sample_resolver());
    let reval_calls = Arc::new(AtomicUsize::new(0));
    let reval_counter = Arc::clone(&reval_calls);
    let live_revalidator: LiveRevalidatorFn = Arc::new(move || {
        let counter = Arc::clone(&reval_counter);
        Box::pin(async move {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    });
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
            live_revalidator,
        })
        .await
        .unwrap();
    assert!(res.is_none());
    assert_eq!(offload.last_fallback_reason(), Some(FallbackReason::HandleConfinementUnavailable));
    assert_eq!(offload.offload_responses.load(Ordering::SeqCst), 0);
    assert_eq!(offload.inline_fallback_responses.load(Ordering::SeqCst), 1);
    assert_eq!(reval_calls.load(Ordering::SeqCst), 0);
    assert_eq!(offload.active_preflight_count(), 0);
    assert_eq!(offload.pack_server().pack_count(), 0);
    assert_eq!(offload.planner().leases().active_pin_count(), 0);

    let stripped = strip_packfile_uris_from_v2_request(&wire).expect("strip packfile-uris");
    let dev_null = if cfg!(unix) { "/dev/null" } else { "NUL" };
    let mut cmd = tokio::process::Command::new(&git_bin);
    cmd.env_clear();
    #[cfg(unix)]
    cmd.env("PATH", "/usr/bin:/bin");
    #[cfg(not(unix))]
    {
        if let Some(p) = std::env::var_os("PATH") {
            cmd.env("PATH", p);
        }
        if let Some(sr) = std::env::var_os("SystemRoot") {
            cmd.env("SystemRoot", sr);
        }
    }
    let mut child = cmd
        .current_dir(&bare)
        .env("GIT_PROTOCOL", "version=2")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", dev_null)
        .args(["upload-pack", "--stateless-rpc", "."])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn git upload-pack");
    {
        let mut sin = child.stdin.take().expect("upload-pack stdin");
        sin.write_all(&stripped).await.expect("write stripped v2 request");
        sin.shutdown().await.expect("close upload-pack stdin");
    }
    let output = child.wait_with_output().await.expect("wait git upload-pack");
    assert!(output.status.success(), "upload-pack failed: {}", String::from_utf8_lossy(&output.stderr));
    let inline_resp = output.stdout;
    assert!(decode_packfile_uris_section(&inline_resp, PackObjectFormat::Sha1).unwrap().is_empty());
    assert!(inline_resp.windows(9).any(|w| w == b"packfile\n"));
    assert!(inline_resp.windows(4).any(|w| w == b"PACK"));

    drop(guard);
    #[cfg(unix)]
    {
        assert!(is_handle_confinement_available());
        assert!(PinnedPackDir::open_confined(&bare).unwrap().is_some());
    }
    #[cfg(not(unix))]
    {
        assert!(!is_handle_confinement_available());
    }
}
