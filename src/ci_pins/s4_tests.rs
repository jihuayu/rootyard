//! Offline unit tests for the pure S4 decision functions.
//!
//! These run without PostgreSQL, Blob or `git`: every test here covers a rule
//! that must hold before any IO, so a regression is caught by the ordinary
//! `cargo test --lib ci_pins::` job.
use super::s4_models::{
    GrantExpectation, NewGrant, S4ClosureGrant, fixed_oid, is_digest_hex, is_lower_hex, oid_width,
};
use super::s4_authority::{StreamSlot, wide_credential};
use super::s4_transport::{guarded_chunks, refused_want};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use bytes::Bytes;
use futures_util::StreamExt;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::Semaphore;
use uuid::Uuid;

fn sample_grant(target: &str) -> S4ClosureGrant {
    let packs = "b".repeat(64);
    S4ClosureGrant::new(NewGrant {
        job_id: Uuid::new_v4(),
        repository_id: Uuid::new_v4(),
        owner_tenant_id: Uuid::new_v4(),
        storage_generation: 11,
        authority_epoch: 4,
        history_incarnation: Uuid::new_v4(),
        group_epoch: 2,
        cluster_incarnation: Uuid::new_v4(),
        object_format: "sha1",
        target_oid: target,
        retention_root_id: Uuid::new_v4(),
        pack_set_digest: &packs,
        mirror_audience: Uuid::new_v4(),
        expires_unix: 1_700_003_600,
    })
    .expect("valid grant")
}

fn expectation<'a>(grant: &S4ClosureGrant, target: &'a str) -> GrantExpectation<'a> {
    GrantExpectation {
        repository_id: grant.repository_id,
        owner_tenant_id: grant.owner_tenant_id,
        storage_generation: grant.storage_generation,
        authority_epoch: grant.authority_epoch,
        history_incarnation: grant.history_incarnation,
        group_epoch: grant.group_epoch,
        cluster_incarnation: grant.cluster_incarnation,
        mirror_audience: grant.mirror_audience,
        target_oid: target,
        now_unix: 1_700_000_000,
    }
}

fn bearer(value: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::AUTHORIZATION, HeaderValue::from_str(value).expect("header"));
    headers
}

#[test]
fn fixed_oid_rejects_branches_zeroes_case_and_width() {
    let sha1 = "0123456789abcdef0123456789abcdef01234567";
    assert_eq!(fixed_oid(sha1, "sha1").expect("exact"), sha1);
    for refused in [
        "main",
        "refs/heads/main",
        "HEAD",
        "0123456789ABCDEF0123456789abcdef01234567",
        "0000000000000000000000000000000000000000",
        "0123456789abcdef0123456789abcdef0123456",
    ] {
        assert!(fixed_oid(refused, "sha1").is_err(), "accepted {refused}");
    }
    assert!(fixed_oid(sha1, "sha256").is_err());
    assert_eq!(oid_width("sha256"), Some(64));
    assert_eq!(oid_width("sha1"), Some(40));
    assert_eq!(oid_width("md5"), None);
}

#[test]
fn closure_grant_rejects_every_tampered_field() {
    let target = "0123456789abcdef0123456789abcdef01234567";
    let grant = sample_grant(target);
    assert!(grant.authorize(&expectation(&grant, target)).is_ok());

    let other = "fedcba9876543210fedcba9876543210fedcba98";
    assert!(grant.authorize(&expectation(&grant, other)).is_err());

    let mut wrong = expectation(&grant, target);
    wrong.mirror_audience = Uuid::new_v4();
    assert!(grant.authorize(&wrong).is_err());

    let mut wrong = expectation(&grant, target);
    wrong.owner_tenant_id = Uuid::new_v4();
    assert!(grant.authorize(&wrong).is_err());

    let mut wrong = expectation(&grant, target);
    wrong.now_unix = grant.expires_unix;
    assert!(grant.authorize(&wrong).is_err());

    let mut wrong = expectation(&grant, target);
    wrong.authority_epoch += 1;
    assert!(grant.authorize(&wrong).is_err());

    let mut wrong = expectation(&grant, target);
    wrong.history_incarnation = Uuid::new_v4();
    assert!(grant.authorize(&wrong).is_err());

    let mut wrong = expectation(&grant, target);
    wrong.group_epoch += 1;
    assert!(grant.authorize(&wrong).is_err());

    let mut wrong = expectation(&grant, target);
    wrong.cluster_incarnation = Uuid::new_v4();
    assert!(grant.authorize(&wrong).is_err());
}

#[test]
fn only_narrow_job_credentials_reach_the_data_plane() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let wide = format!("Bearer ryu_{}", "a".repeat(64));
    let narrow = format!("Bearer ryj_{}", "b".repeat(64));
    assert!(wide_credential(&bearer(&wide)));
    assert!(!wide_credential(&bearer(&narrow)));
    assert!(!wide_credential(&HeaderMap::new()));

    for prefix in ["ryt_", "ryu_", "rys_", "ryb_"] {
        let value = format!("Bearer {prefix}{}", "a".repeat(64));
        assert!(wide_credential(&bearer(&value)), "accepted Bearer {prefix}");
        let basic = STANDARD.encode(format!("alice:{prefix}{}", "a".repeat(64)));
        assert!(wide_credential(&bearer(&format!("Basic {basic}"))), "accepted Basic {prefix}");
    }

    let narrow_basic = STANDARD.encode(format!("alice:ryj_{}", "b".repeat(64)));
    assert!(!wide_credential(&bearer(&format!("Basic {narrow_basic}"))));
    assert!(!wide_credential(&bearer(&format!("Bearer ryj_{}", "b".repeat(64)))));

    // The narrow prefix is the only one `credentials_for` accepts.
    assert!(crate::auth::credentials_for(&bearer(&wide), "ryj_").is_err());
    assert!(crate::auth::credentials_for(&bearer(&narrow), "ryj_").is_ok());
}

#[test]
fn upload_pack_wants_must_equal_the_granted_commit() {
    let granted = "0123456789abcdef0123456789abcdef01234567";
    let other = "fedcba9876543210fedcba9876543210fedcba98";
    let granted_line = format!("0032want {granted}\n");
    let other_line = format!("0032want {other}\n");
    assert!(!refused_want(granted_line.as_bytes(), granted));
    assert!(refused_want(other_line.as_bytes(), granted));

    let cap = format!("want {granted} multi_ack_detailed side-band-64k\n");
    let pkt = format!("{:04x}{cap}00000009done\n", 4 + cap.len());
    assert!(!refused_want(pkt.as_bytes(), granted));

    let mut mixed = Vec::new();
    mixed.extend_from_slice(granted_line.as_bytes());
    mixed.extend_from_slice(b"0000");
    mixed.extend_from_slice(other_line.as_bytes());
    assert!(refused_want(&mixed, granted));

    let uppercase = format!("0032want {}\n", granted.to_ascii_uppercase());
    assert!(refused_want(uppercase.as_bytes(), granted));
    assert!(refused_want(b"001dwant-ref refs/heads/main\n", granted));

    for refused in [b"".as_slice(), b"0000".as_slice(), b"zzzz".as_slice(), b"0032want ".as_slice()] {
        assert!(refused_want(refused, granted), "accepted {refused:?}");
    }
}

#[test]
fn stream_slot_returns_its_permit_when_dropped() {
    let semaphore = Arc::new(Semaphore::new(1));
    let permit = semaphore.clone().try_acquire_owned().expect("one slot");
    {
        let _slot = StreamSlot::from_permit(permit);
        assert!(semaphore.clone().try_acquire_owned().is_err());
    }
    assert!(semaphore.clone().try_acquire_owned().is_ok());
}

#[tokio::test]
async fn revoked_stream_aborts_on_next_chunk_and_releases_slot() {
    let live = Arc::new(AtomicBool::new(true));
    let semaphore = Arc::new(Semaphore::new(1));
    let permit = semaphore.clone().try_acquire_owned().expect("one slot");
    let source = futures_util::stream::iter([
        Ok::<_, std::io::Error>(Bytes::from_static(b"first-chunk")),
        Ok(Bytes::from_static(b"second-chunk")),
    ]);
    let gate = live.clone();
    let check = move || {
        let value = gate.load(Ordering::SeqCst);
        Box::pin(std::future::ready(value)) as std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>>
    };
    let mut stream = Box::pin(guarded_chunks(source, check, StreamSlot::from_permit(permit)));
    assert_eq!(stream.next().await.expect("first").expect("chunk"), Bytes::from_static(b"first-chunk"));
    live.store(false, Ordering::SeqCst);
    assert!(stream.next().await.expect("second").is_err(), "revocation must abort the next chunk");
    // The generator dropped its owned permit at the exact point it returned the
    // error, so the shared Git capacity is immediately reusable.
    assert!(semaphore.clone().try_acquire_owned().is_ok());
}

#[test]
fn digest_and_hex_width_helpers_are_exact() {
    assert!(is_lower_hex(&"a".repeat(64), 64));
    assert!(!is_lower_hex(&"A".repeat(64), 64));
    assert!(!is_lower_hex(&"a".repeat(63), 64));
    assert!(is_digest_hex(&"0123456789abcdef".repeat(4)));
    assert!(!is_digest_hex(&"g".repeat(64)));
}

#[cfg(unix)]
const FINAL_SCRIPT: &str = r#"#!/bin/sh
exec >/dev/null; sh -c 'trap "" TERM; while :; do sleep 1; done' & echo $$ $! > "$0.pids"
trap "" TERM; while :; do sleep 1; done
"#;

#[cfg(unix)]
fn wait_pids(path: &std::path::Path) -> (i32, i32) {
    for _ in 0..200 {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let mut values = text.split_whitespace().filter_map(|value| value.parse::<i32>().ok());
        if let (Some(leader), Some(grandchild)) = (values.next(), values.next()) {
            return (leader, grandchild);
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    panic!("the Git wrapper did not publish its process group");
}

#[cfg(unix)]
#[tokio::test]
async fn run_git_dir_bounded_enforces_deadline_on_final_wait_after_stdout_closes() {
    use super::s4_authority::{DisposableCiView, run_git_dir_bounded};
    use std::os::unix::fs::PermissionsExt;
    let view = DisposableCiView::create().expect("disposable view");
    let root = view.path().to_path_buf();
    let wrapper = root.join("git");
    std::fs::write(&wrapper, FINAL_SCRIPT).expect("write wrapper");
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).expect("chmod wrapper");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(250);
    let error = run_git_dir_bounded(
        &wrapper,
        None,
        &[],
        deadline,
        || super::Error(StatusCode::CONFLICT, "failed"),
        Some(view.hold()),
    )
    .await
    .unwrap_err();
    assert_eq!(error.0, StatusCode::GATEWAY_TIMEOUT);
    let (leader, grandchild) = wait_pids(&wrapper.with_extension("pids"));
    assert!(root.exists(), "the disposable view vanished before the final wait was confirmed");
    assert!(!std::path::PathBuf::from(format!("/proc/{leader}")).exists());
    assert!(!std::path::PathBuf::from(format!("/proc/{grandchild}")).exists());
    drop(view);
    assert!(!root.exists());
}

#[cfg(unix)]
#[tokio::test]
async fn expired_timeout_cleanup_hands_scratch_to_reaper_until_group_exits() {
    use super::s4_authority::{DisposableCiView, UploadPackGroup};
    use std::os::unix::fs::PermissionsExt;
    let view = DisposableCiView::create().expect("disposable view");
    let root = view.path().to_path_buf();
    let wrapper = root.join("git");
    std::fs::write(&wrapper, FINAL_SCRIPT).expect("write wrapper");
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).expect("chmod wrapper");
    let mut group = UploadPackGroup::spawn(&wrapper, &root, Some(view.hold())).expect("spawn");
    let (leader, grandchild) = wait_pids(&wrapper.with_extension("pids"));
    drop(view);
    group.kill_and_reap_bounded(std::time::Duration::ZERO).await;
    drop(group);
    for _ in 0..200 {
        if !root.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert!(!root.exists(), "the disposable view outlived the timed-out reaper handoff");
    assert!(!std::path::PathBuf::from(format!("/proc/{leader}")).exists());
    assert!(!std::path::PathBuf::from(format!("/proc/{grandchild}")).exists());
}

#[tokio::test]
async fn upload_pack_advertise_and_spawn_pass_positional_directory() {
    use super::s4_authority::{DisposableCiView, UploadPackGroup, run_git_dir_bounded};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let git_bin = std::env::var("ROOTYARD_TEST_GIT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("git"));
    let view = DisposableCiView::create().expect("disposable view");
    let repo_dir = view.path().to_str().expect("utf8 disposable path");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
    let init_args = ["init", "--bare", "--quiet", "--object-format=sha1", repo_dir];
    let init_error = || super::Error(StatusCode::CONFLICT, "init failed");
    run_git_dir_bounded(&git_bin, None, &init_args, deadline, init_error, Some(view.hold()))
        .await
        .expect("git init --bare");
    let advertise_args = ["upload-pack", "--stateless-rpc", "--advertise-refs", repo_dir];
    let advertise_error = || super::Error(StatusCode::CONFLICT, "advertise failed");
    run_git_dir_bounded(&git_bin, Some(view.path()), &advertise_args, deadline, advertise_error, Some(view.hold()))
        .await
        .expect("upload-pack --advertise-refs");
    let mut group = UploadPackGroup::spawn(&git_bin, view.path(), Some(view.hold())).expect("spawn upload-pack");
    let (mut stdin, mut stdout) = group.take_pipes().expect("upload-pack pipes");
    stdin.write_all(b"0000").await.expect("write flush packet");
    stdin.shutdown().await.expect("close upload-pack stdin");
    drop(stdin);
    let mut out = Vec::new();
    stdout.read_to_end(&mut out).await.expect("drain upload-pack stdout");
    drop(stdout);
    let status = group.finish(deadline).await.expect("finish upload-pack");
    assert!(status.success(), "upload-pack failed: {status}");
}

#[cfg(unix)]
#[tokio::test]
async fn spawn_reaper_failure_bounds_caller_and_reaps_without_zombies() {
    use super::s4_authority::DisposableCiView;
    use std::{os::unix::fs::PermissionsExt, process::Stdio};
    let view = DisposableCiView::create().expect("disposable view");
    let root = view.path().to_path_buf();
    let wrapper = root.join("git");
    std::fs::write(&wrapper, FINAL_SCRIPT).expect("write wrapper");
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).expect("chmod wrapper");
    let mut cmd = tokio::process::Command::new(&wrapper);
    cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true).process_group(0);
    let child = cmd.spawn().expect("spawn wrapper");
    let pid = child.id().and_then(|id| i32::try_from(id).ok()).expect("wrapper pid");
    let (leader, grandchild) = wait_pids(&wrapper.with_extension("pids"));
    let holds = vec![view.hold()];
    drop(view);
    let started = std::time::Instant::now();
    super::s4_git_runner::spawn_reaper_with(child, pid, holds, |_| {
        Err(std::io::Error::other("simulated thread limit"))
    });
    assert!(started.elapsed() < std::time::Duration::from_millis(200), "spawn failure blocked caller");
    for _ in 0..300 {
        if !root.exists()
            && !std::path::PathBuf::from(format!("/proc/{leader}")).exists()
            && !std::path::PathBuf::from(format!("/proc/{grandchild}")).exists()
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(!std::path::PathBuf::from(format!("/proc/{leader}")).exists(), "leader was left as a zombie");
    assert!(!std::path::PathBuf::from(format!("/proc/{grandchild}")).exists(), "grandchild survived cleanup");
    assert!(!root.exists(), "confirmed-quiescent disposable view was not removed");
}

#[cfg(unix)]
#[tokio::test]
async fn spawn_reaper_failure_with_unknown_group_preserves_scratch_and_reaps_child() {
    use super::s4_authority::DisposableCiView;
    use std::{os::unix::fs::PermissionsExt, process::Stdio};
    fn unknown_group(_pid: i32) -> std::io::Result<bool> {
        Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "simulated procfs error"))
    }
    let view = DisposableCiView::create().expect("disposable view");
    let root = view.path().to_path_buf();
    let wrapper = root.join("git");
    std::fs::write(&wrapper, FINAL_SCRIPT).expect("write wrapper");
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).expect("chmod wrapper");
    let mut cmd = tokio::process::Command::new(&wrapper);
    cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true).process_group(0);
    let child = cmd.spawn().expect("spawn wrapper");
    let pid = child.id().and_then(|id| i32::try_from(id).ok()).expect("wrapper pid");
    let (leader, grandchild) = wait_pids(&wrapper.with_extension("pids"));
    let holds = vec![view.hold()];
    drop(view);
    let started = std::time::Instant::now();
    super::s4_git_runner::spawn_reaper_with_probe(
        child,
        pid,
        holds,
        |_| Err(std::io::Error::other("simulated thread limit")),
        unknown_group,
    );
    assert!(started.elapsed() < std::time::Duration::from_millis(200), "spawn failure blocked caller");
    for _ in 0..300 {
        if !std::path::PathBuf::from(format!("/proc/{leader}")).exists()
            && !std::path::PathBuf::from(format!("/proc/{grandchild}")).exists()
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(!std::path::PathBuf::from(format!("/proc/{leader}")).exists(), "leader was left as a zombie");
    assert!(!std::path::PathBuf::from(format!("/proc/{grandchild}")).exists(), "grandchild survived cleanup");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(root.exists(), "uncertain disposable view was deleted despite unknown group outcome");
    std::fs::remove_dir_all(&root).expect("cleanup preserved disposable view");
}
