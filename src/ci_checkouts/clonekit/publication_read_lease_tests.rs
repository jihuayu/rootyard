//! Source-only deterministic and independent-process tests for the local read lease.

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use tempfile::TempDir;
use uuid::Uuid;

use super::publication_tests::empty_artifacts;
use super::{CloneKitPublicationStore, publish_clonekit_versioned, test_seam};
use crate::blob_store::disposable_view::DisposableViewRoot;
use crate::ci_checkouts::clonekit::{
    CheckoutPolicy, CheckoutRequest, CheckoutStrategy, CloneKitAuthorityOracle, CloneKitError, CloneKitGrantClaims,
    CloneKitStatus, FallbackReason, GrantVerificationContext, InMemoryAuthorityOracle, RetentionPinLedger,
    checkout::release_lease_before_fallback, execute_ci_checkout, sign_grant,
};

static SECRET: [u8; 32] = [0x42; 32];

#[path = "publication_child_fixture.rs"]
mod child_fixture;
use child_fixture::OwnedChild;

#[path = "publication_active_fixture.rs"]
mod fixture;

#[path = "publication_read_lease_guard_tests.rs"]
mod guard_tests;

fn publish(store: &CloneKitPublicationStore, repository_id: Uuid, kit_generation: u64) {
    publish_clonekit_versioned(
        store,
        &empty_artifacts(repository_id, kit_generation),
        Path::new("/usr/bin/git"),
        None,
        None,
    )
    .expect("publish test generation");
}

fn publish_active(td: &TempDir, store: &CloneKitPublicationStore, ids: (Uuid, Uuid, Uuid), label: &str) {
    let candidate = fixture::build_active_candidate(td, ids, 1, label, b"active-generation-lease-payload")
        .expect("active candidate");
    publish_clonekit_versioned(store, &candidate, &fixture::git_binary(), None, None)
        .expect("publish active generation");
}

fn run_git(dir: Option<&Path>, args: &[&str]) -> String {
    let mut command = Command::new(fixture::git_binary());
    if let Some(dir) = dir {
        command.current_dir(dir);
    }
    let output = command.args(args).output().expect("run git");
    assert!(output.status.success(), "git {args:?} failed: {}", String::from_utf8_lossy(&output.stderr).trim());
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

#[test]
fn leased_selection_blocks_gc_until_verified_copy_and_release() {
    let _serial = test_seam::serial();
    test_seam::reset();
    let td = TempDir::new().expect("tempdir");
    let store = CloneKitPublicationStore::open(&td.path().join("catalog")).expect("store");
    let ids = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let repository_id = ids.1;
    let ledger = RetentionPinLedger::new();
    publish_active(&td, &store, ids, "lease-active");

    let leased = store.load_latest_leased(repository_id).expect("lease").expect("current generation");
    assert_eq!(leased.manifest().kit_generation, 1);
    let (pack_path, idx_path) = store.artifact_paths(repository_id, 1);
    assert!(!fs::read(&pack_path).expect("active pack under lease").is_empty());
    assert!(!fs::read(&idx_path).expect("active idx under lease").is_empty());
    publish(&store, repository_id, 2);
    let error = store.try_gc_generation(repository_id, 1, &ledger).expect_err("active read lease must defer gc");
    assert!(
        matches!(error, CloneKitError::GitFailed(ref message) if message.contains("read lease") && message.contains("busy"))
    );
    assert!(store.version_dir(repository_id, 1).is_dir());

    drop(leased);
    assert!(store.try_gc_generation(repository_id, 1, &ledger).expect("gc after lease release"));
    assert!(!store.version_dir(repository_id, 1).exists());
    test_seam::reset();
}

#[test]
fn vanished_or_symlinked_selected_generation_is_rejected() {
    let _serial = test_seam::serial();
    test_seam::reset();
    let td = TempDir::new().expect("tempdir");
    let store = CloneKitPublicationStore::open(&td.path().join("catalog")).expect("store");

    let vanished_repo = Uuid::new_v4();
    publish(&store, vanished_repo, 1);
    fs::rename(store.version_dir(vanished_repo, 1), store.version_dir(vanished_repo, 9)).expect("move generation");
    let error = store.load_latest_leased(vanished_repo).expect_err("vanished generation must fail");
    assert!(matches!(error, CloneKitError::CorruptArtifact(_)));

    let symlinked_repo = Uuid::new_v4();
    publish(&store, symlinked_repo, 1);
    let version_dir = store.version_dir(symlinked_repo, 1);
    let real_dir = store.version_dir(symlinked_repo, 9);
    fs::rename(&version_dir, &real_dir).expect("move generation");
    std::os::unix::fs::symlink(&real_dir, &version_dir).expect("symlink generation");
    let error = store.load_latest_leased(symlinked_repo).expect_err("symlinked generation must fail");
    assert!(matches!(error, CloneKitError::CorruptArtifact(_)));
    test_seam::reset();
}

#[test]
fn symlinked_read_lease_file_is_rejected() {
    let _serial = test_seam::serial();
    test_seam::reset();
    let td = TempDir::new().expect("tempdir");
    let store = CloneKitPublicationStore::open(&td.path().join("catalog")).expect("store");
    let repository_id = Uuid::new_v4();
    publish(&store, repository_id, 1);
    let target = td.path().join("not-a-lease");
    fs::write(&target, b"target").expect("lease target");
    std::os::unix::fs::symlink(&target, store.repo_dir(repository_id).join(".read.lock")).expect("lease symlink");
    let error = store.load_latest_leased(repository_id).expect_err("symlinked read lease must fail");
    assert!(matches!(error, CloneKitError::GitFailed(_)));
    test_seam::reset();
}

#[test]
fn fallback_boundary_releases_lease_before_stock_git_await() {
    let _serial = test_seam::serial();
    test_seam::reset();
    let td = TempDir::new().expect("tempdir");
    let store = CloneKitPublicationStore::open(&td.path().join("catalog")).expect("store");
    let repository_id = Uuid::new_v4();
    let ledger = RetentionPinLedger::new();
    publish(&store, repository_id, 1);

    let leased = store.load_latest_leased(repository_id).expect("lease").expect("current generation");
    let (manifest, lease) = leased.into_parts();
    let loaded = Some((manifest, lease));
    publish(&store, repository_id, 2);
    // This helper is the exact pre-await boundary in `execute_ci_checkout`; immediate GC
    // eligibility proves the awaited stock fallback cannot inherit the local generation lease.
    let reason = release_lease_before_fallback(loaded, FallbackReason::ExpiredKit, true)
        .expect("fallback allowed after lease release");
    assert_eq!(reason, FallbackReason::ExpiredKit);
    assert!(store.try_gc_generation(repository_id, 1, &ledger).expect("gc after fallback lease release"));
    assert!(!store.version_dir(repository_id, 1).exists());
    test_seam::reset();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_empty_fallback_does_not_hold_read_lease() {
    let serial = test_seam::serial();
    test_seam::reset();
    let td = TempDir::new().expect("tempdir");
    let store = CloneKitPublicationStore::open(&td.path().join("catalog")).expect("store");
    let repository_id = Uuid::new_v4();
    publish(&store, repository_id, 1);
    publish(&store, repository_id, 2);
    let manifest = store.load_latest(repository_id).expect("latest").expect("current generation");
    assert_eq!(manifest.status, CloneKitStatus::EmptyRepository);
    // The remaining work does not use the publication seam; release the serial guard before
    // awaiting so the async test does not hold a std MutexGuard across `.await`.
    drop(serial);

    let source = td.path().join("source");
    fs::create_dir_all(&source).expect("source repo");
    run_git(Some(&source), &["init", "--quiet", "-b", "main"]);
    run_git(Some(&source), &["config", "user.name", "clonekit"]);
    run_git(Some(&source), &["config", "user.email", "clonekit@test.invalid"]);
    fs::write(source.join("file.txt"), b"fallback").expect("source file");
    run_git(Some(&source), &["add", "file.txt"]);
    run_git(Some(&source), &["commit", "--quiet", "-m", "fallback target"]);
    let target = run_git(Some(&source), &["rev-parse", "HEAD"]);
    let origin = td.path().join("origin.git");
    run_git(
        None,
        &["clone", "--bare", "--quiet", source.to_str().expect("source utf8"), origin.to_str().expect("origin utf8")],
    );
    run_git(Some(&origin), &["config", "uploadpack.allowAnySHA1InWant", "true"]);

    let views = td.path().join("views");
    fs::create_dir_all(&views).expect("views");
    fs::set_permissions(&views, std::fs::Permissions::from_mode(0o700)).expect("views mode");
    let view_root = DisposableViewRoot::open(&views, 32, 64 << 20, Duration::from_secs(300)).expect("view root");

    let ready = td.path().join("fallback-git-started");
    let wrapper = td.path().join("slow-git.sh");
    let real_git = fixture::git_binary();
    let script = format!(
        "#!/bin/sh\nif [ ! -e \"{}\" ]; then\n  : > \"{}\"\n  sleep 2\nfi\nexec \"{}\" \"$@\"\n",
        ready.display(),
        ready.display(),
        real_git.display()
    );
    fs::write(&wrapper, script).expect("slow git wrapper");
    fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).expect("wrapper mode");

    let now = 1_750_000_000i64;
    let job_id = Uuid::new_v4();
    let audience = Uuid::new_v4();
    let claims = CloneKitGrantClaims {
        schema: 1,
        grant_id: Uuid::new_v4(),
        tenant_id: manifest.tenant_id,
        repository_id: manifest.repository_id,
        owner_id: manifest.owner_id,
        history_id: manifest.history_id,
        storage_generation: manifest.storage_generation,
        object_format: manifest.object_format,
        target_oid: target.clone(),
        job_id,
        audience,
        issued_unix: now - 10,
        not_after_unix: now + 600,
        min_kit_generation: 1,
        allow_git_fallback: true,
        dependencies: Default::default(),
    };
    let grant = sign_grant(claims, &SECRET).expect("signed grant");
    let ctx = GrantVerificationContext {
        tenant_id: manifest.tenant_id,
        repository_id: manifest.repository_id,
        history_id: manifest.history_id,
        storage_generation: manifest.storage_generation,
        object_format: manifest.object_format,
        target_oid: target.clone(),
        job_id,
        audience,
        now_unix: now,
    };
    let authority: Arc<dyn CloneKitAuthorityOracle> = Arc::new(InMemoryAuthorityOracle::new());

    let store_for_gc = store.clone();
    let observer = std::thread::spawn(move || -> Result<bool, String> {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready.exists() {
            if Instant::now() >= deadline {
                return Err("stock Git fallback did not start".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        store_for_gc.try_gc_generation(repository_id, 1, &RetentionPinLedger::new()).map_err(|err| err.to_string())
    });

    let origin_remote = origin.to_str().expect("origin utf8").to_owned();
    let store_for_checkout = store.clone();
    let checkout = tokio::spawn(async move {
        let request = CheckoutRequest {
            grant: &grant,
            signing_secret: &SECRET,
            expected_context: &ctx,
            authority,
            policy: CheckoutPolicy {
                use_clonekit: true,
                fallback_to_git_on_unusable_kit: true,
                require_full_fsck: true,
            },
            git_binary: &wrapper,
            origin_remote: &origin_remote,
            http_bearer: None,
            view_root: &view_root,
            pub_store: Some(&store_for_checkout),
            manifest_override: None,
            blob_store: None,
            pin_ledger: None,
            lfs_objects_dir: None,
            destination_root: None,
            cancel: None,
        };
        execute_ci_checkout(&request).await
    });
    let checkout = tokio::time::timeout(Duration::from_secs(30), checkout)
        .await
        .expect("checkout timeout")
        .expect("checkout join");
    let gc = observer.join().expect("observer join");
    let outcome = checkout.expect("checkout");
    assert!(matches!(
        outcome.telemetry.strategy,
        CheckoutStrategy::StockGitFallback { reason: FallbackReason::EmptyRepository }
    ));
    assert!(matches!(gc, Ok(true)), "gc during actual empty fallback: {gc:?}");
    assert!(!store.version_dir(repository_id, 1).exists());
    let _serial = test_seam::serial();
    test_seam::reset();
}

#[test]
fn descriptor_copy_reads_verified_generation_after_path_replacement() {
    let _serial = test_seam::serial();
    test_seam::reset();
    let td = TempDir::new().expect("tempdir");
    let store = CloneKitPublicationStore::open(&td.path().join("catalog")).expect("store");
    let ids = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let repository_id = ids.1;
    publish_active(&td, &store, ids, "lease-descriptor");
    let leased = store.load_latest_leased(repository_id).expect("lease").expect("current generation");
    let (manifest, lease) = leased.into_parts();
    let lease = lease.expect("current lease");
    let pack_meta = manifest.pack.as_ref().expect("pack metadata");
    let idx_meta = manifest.idx.as_ref().expect("idx metadata");
    let pack_len = usize::try_from(pack_meta.length).expect("pack length");
    let idx_len = usize::try_from(idx_meta.length).expect("idx length");
    let version_dir = store.version_dir(repository_id, 1);
    let original_dir = store.version_dir(repository_id, 9);
    let original_pack = fs::read(version_dir.join("clonekit.pack")).expect("original pack");
    let original_idx = fs::read(version_dir.join("clonekit.idx")).expect("original idx");
    fs::rename(&version_dir, &original_dir).expect("move verified generation");
    fs::create_dir(&version_dir).expect("replacement generation");
    fs::write(version_dir.join("clonekit.pack"), vec![0xAA; pack_len]).expect("replacement pack");
    fs::write(version_dir.join("clonekit.idx"), vec![0xBB; idx_len]).expect("replacement idx");

    let scratch = td.path().join("scratch");
    let dest_pack = scratch.join("pack");
    let dest_idx = scratch.join("idx");
    lease.copy_pack_to(&dest_pack, pack_meta.length).expect("copy pack via verified descriptor");
    lease.copy_idx_to(&dest_idx, idx_meta.length).expect("copy idx via verified descriptor");
    assert_eq!(fs::read(&dest_pack).expect("copied pack"), original_pack);
    assert_eq!(fs::read(&dest_idx).expect("copied idx"), original_idx);
    drop(lease);
    test_seam::reset();
}

#[test]
fn two_shared_readers_coexist_and_each_release_controls_gc() {
    let _serial = test_seam::serial();
    test_seam::reset();
    let td = TempDir::new().expect("tempdir");
    let store = CloneKitPublicationStore::open(&td.path().join("catalog")).expect("store");
    let ids = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let repository_id = ids.1;
    let ledger = RetentionPinLedger::new();
    publish_active(&td, &store, ids, "lease-two-readers");
    let first = store.load_latest_leased(repository_id).expect("first lease").expect("current generation");
    let second = store.load_latest_leased(repository_id).expect("second lease").expect("current generation");
    let (first_manifest, first_lease) = first.into_parts();
    let (_, second_lease) = second.into_parts();
    let first_lease = first_lease.expect("first lease");
    let second_lease = second_lease.expect("second lease");
    let pack_meta = first_manifest.pack.as_ref().expect("pack metadata");
    let idx_meta = first_manifest.idx.as_ref().expect("idx metadata");
    let scratch = td.path().join("scratch");
    let first_pack = scratch.join("first.pack");
    let second_idx = scratch.join("second.idx");
    first_lease.copy_pack_to(&first_pack, pack_meta.length).expect("first reader pack copy");
    second_lease.copy_idx_to(&second_idx, idx_meta.length).expect("second reader idx copy");
    let (installed_pack, installed_idx) = store.artifact_paths(repository_id, 1);
    assert_eq!(fs::read(&first_pack).expect("first copied pack"), fs::read(&installed_pack).expect("installed pack"));
    assert_eq!(fs::read(&second_idx).expect("second copied idx"), fs::read(&installed_idx).expect("installed idx"));

    publish(&store, repository_id, 2);
    let error = store.try_gc_generation(repository_id, 1, &ledger).expect_err("two readers must defer gc");
    assert!(
        matches!(error, CloneKitError::GitFailed(ref message) if message.contains("read lease") && message.contains("busy"))
    );
    drop(first_lease);
    let error = store.try_gc_generation(repository_id, 1, &ledger).expect_err("second reader must defer gc");
    assert!(matches!(error, CloneKitError::GitFailed(ref message) if message.contains("busy")));
    drop(second_lease);
    assert!(store.try_gc_generation(repository_id, 1, &ledger).expect("gc after both readers release"));
    assert!(!store.version_dir(repository_id, 1).exists());
    test_seam::reset();
}

#[test]
fn cross_process_reader_lease_blocks_gc_and_releases_on_child_exit() {
    let _serial = test_seam::serial();
    test_seam::reset();
    let td = TempDir::new().expect("tempdir");
    let root = td.path().join("catalog");
    let store = CloneKitPublicationStore::open(&root).expect("store");
    let repository_id = Uuid::new_v4();
    publish(&store, repository_id, 1);
    publish(&store, repository_id, 2);
    let ready = td.path().join("reader-ready");
    let mut child = OwnedChild::new(
        Command::new(std::env::current_exe().expect("current exe"))
            .arg("--nocapture")
            .arg("publication_read_lease_child_helper")
            .env("ROOTYARD_CK_READ_LEASE_ROOT", &root)
            .env("ROOTYARD_CK_READ_LEASE_REPO", repository_id.to_string())
            .env("ROOTYARD_CK_READ_LEASE_READY", &ready)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("child reader"),
    );
    let mut ready_seen = false;
    for _ in 0..1000 {
        if ready.exists() {
            ready_seen = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if !ready_seen {
        panic!("child reader did not acquire the read lease");
    }

    let ledger = RetentionPinLedger::new();
    let error = store.try_gc_generation(repository_id, 1, &ledger).expect_err("child lease must defer gc");
    assert!(matches!(error, CloneKitError::GitFailed(ref message) if message.contains("busy")));
    assert!(store.version_dir(repository_id, 1).is_dir());

    assert!(child.kill_and_reap().is_some(), "child reader did not exit after kill");
    assert!(store.try_gc_generation(repository_id, 1, &ledger).expect("gc after child death"));
    assert!(!store.version_dir(repository_id, 1).exists());
    test_seam::reset();
}

#[test]
fn publication_read_lease_child_helper() {
    let Some(root) = std::env::var_os("ROOTYARD_CK_READ_LEASE_ROOT") else {
        return;
    };
    let Some(repository_id) =
        std::env::var("ROOTYARD_CK_READ_LEASE_REPO").ok().and_then(|raw| Uuid::parse_str(&raw).ok())
    else {
        return;
    };
    let Some(ready) = std::env::var_os("ROOTYARD_CK_READ_LEASE_READY") else {
        return;
    };
    let store = CloneKitPublicationStore::open(Path::new(&root)).expect("child store");
    let leased = store.load_latest_leased(repository_id).expect("child lease").expect("child current");
    assert_eq!(leased.manifest().kit_generation, 2);
    fs::write(Path::new(&ready), b"ready").expect("ready");
    std::thread::sleep(Duration::from_secs(30));
}
