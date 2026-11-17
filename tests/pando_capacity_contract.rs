//! Real OpenDAL S3 + stock Git (SHA-1 & SHA-256) capacity integration tests (#177).

use std::{
    collections::BTreeMap,
    fs::{self, DirBuilder},
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

use anyhow::{Result, ensure};
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Method, StatusCode, Uri, header},
    response::Response,
};
use bytes::Bytes;
use rootyard::blob_store::{
    BlobLocator,
    capacity_contract::{
        AdmissionClass, AdmissionController, AdmissionLimits, AdmissionRejection, AdmissionRequest, EngineScope,
        GrowthEngineError, IncrementalPushRequest, LedgerBudgetPolicy, LedgerEntryKind, LedgerRetentionError,
        ObjectFormat, PandoCapacityContract, ProtectionHold, RefMutation, RetentionClassification, RetentionLedger,
        StreamingGrowthEngine,
    },
    config::BlobProfile,
    disposable_view::DisposableViewRoot,
    opendal::BlobStore,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use uuid::Uuid;

#[cfg(unix)]
const NULL_GIT_CONFIG: &str = "/dev/null";
#[cfg(not(unix))]
const NULL_GIT_CONFIG: &str = "NUL";

#[derive(Default)]
struct S3State {
    objects: Mutex<BTreeMap<String, Vec<u8>>>,
}

struct LoopbackS3 {
    endpoint: String,
    state: Arc<S3State>,
}

static SHARED_S3: OnceLock<LoopbackS3> = OnceLock::new();
static ENV_LOCK: Mutex<()> = Mutex::new(());

impl LoopbackS3 {
    fn shared() -> &'static Self {
        SHARED_S3.get_or_init(|| {
            let state = Arc::new(S3State::default());
            let server_state = Arc::clone(&state);
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback s3");
            listener.set_nonblocking(true).expect("nonblocking");
            let port = listener.local_addr().expect("addr").port();
            let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
                rt.block_on(async move {
                    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                    let _ = ready_tx.send(());
                    let _ = axum::serve(listener, Router::new().fallback(handle_s3).with_state(server_state)).await;
                });
            });
            ready_rx.recv().unwrap();
            Self { endpoint: format!("http://127.0.0.1:{port}"), state }
        })
    }

    fn key(locator: &BlobLocator) -> String {
        format!("pando-cap-bucket/pando-cap-it/{}", locator.path())
    }

    fn open_store(&self) -> Result<BlobStore> {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let vars = [
            ("ROOTYARD_BLOB_DRIVER", Some("opendal")),
            ("ROOTYARD_BLOB_SERVICE", Some("s3")),
            ("ROOTYARD_BLOB_BUCKET", Some("pando-cap-bucket")),
            ("ROOTYARD_BLOB_REGION", Some("us-east-1")),
            ("ROOTYARD_BLOB_ROOT", Some("pando-cap-it")),
            ("ROOTYARD_BLOB_ENDPOINT", Some(self.endpoint.as_str())),
            ("ROOTYARD_BLOB_ACCESS_KEY_ID", Some("test-ak")),
            ("ROOTYARD_BLOB_SECRET_ACCESS_KEY", Some("test-sk")),
            ("ROOTYARD_BLOB_ENCRYPTION_MODE", Some("provider-managed")),
            ("ROOTYARD_BLOB_RETRY_MAX_TIMES", Some("0")),
            ("ROOTYARD_BLOB_MAX_OBJECT_BYTES", Some("67108864")),
            ("ROOTYARD_BLOB_KEYRING_DIR", None),
        ];
        let saved: Vec<_> = vars.iter().map(|(k, _)| (*k, std::env::var_os(k))).collect();
        for &(k, v) in &vars {
            // SAFETY: serialized via ENV_LOCK across tests in this integration binary.
            unsafe { if let Some(val) = v { std::env::set_var(k, val) } else { std::env::remove_var(k) } }
        }
        let res = BlobStore::open(BlobProfile::from_env()?);
        for (k, old) in saved {
            // SAFETY: serialized via ENV_LOCK across tests in this integration binary.
            unsafe { if let Some(val) = old { std::env::set_var(k, val) } else { std::env::remove_var(k) } }
        }
        Ok(res?)
    }

    fn exists(&self, locator: &BlobLocator) -> bool {
        self.state.objects.lock().unwrap().contains_key(&Self::key(locator))
    }
}

fn s3_resp(status: StatusCode, etag: Option<&str>, len: usize, body: Body) -> Response {
    let mut b = Response::builder().status(status).header(header::CONTENT_LENGTH, len.to_string());
    if let Some(tag) = etag {
        b = b.header(header::ETAG, tag);
    }
    b.body(body).unwrap()
}

async fn handle_s3(State(state): State<Arc<S3State>>, method: Method, uri: Uri, body: Bytes) -> Response {
    let full_key = uri.path().trim_start_matches('/').to_owned();
    if !full_key.contains('/') {
        return Response::new(Body::from("<ListBucketResult/>"));
    }
    match method {
        Method::PUT => {
            let etag = format!("\"{}\"", &hex::encode(Sha256::digest(&body))[..32]);
            state.objects.lock().unwrap().insert(full_key, body.to_vec());
            s3_resp(StatusCode::OK, Some(&etag), 0, Body::empty())
        }
        Method::HEAD | Method::GET => match state.objects.lock().unwrap().get(&full_key).cloned() {
            Some(data) => {
                let etag = format!("\"{}\"", &hex::encode(Sha256::digest(&data))[..32]);
                let payload = if method == Method::HEAD { Body::empty() } else { Body::from(data.clone()) };
                s3_resp(StatusCode::OK, Some(&etag), data.len(), payload)
            }
            None => s3_resp(StatusCode::NOT_FOUND, None, 0, Body::empty()),
        },
        _ => s3_resp(StatusCode::METHOD_NOT_ALLOWED, None, 0, Body::empty()),
    }
}

fn open_private_views(root: &TempDir) -> Result<DisposableViewRoot> {
    let views = root.path().join("views");
    let mut builder = DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&views)?;
    Ok(DisposableViewRoot::open(&views, 4, 256 * 1024 * 1024, Duration::from_secs(120))?)
}

fn git_run(repo: &Path, args: &[&str], stdin_bytes: Option<&[u8]>) -> Result<String> {
    let mut cmd = Command::new("git");
    cmd.args(["-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "--no-replace-objects", "-C"])
        .arg(repo)
        .args(args)
        .envs([
            ("GIT_CONFIG_NOSYSTEM", "1"),
            ("GIT_CONFIG_GLOBAL", NULL_GIT_CONFIG),
            ("GIT_TERMINAL_PROMPT", "0"),
            ("GIT_AUTHOR_NAME", "rootyard"),
            ("GIT_AUTHOR_EMAIL", "rootyard@example.com"),
            ("GIT_COMMITTER_NAME", "rootyard"),
            ("GIT_COMMITTER_EMAIL", "rootyard@example.com"),
        ]);
    if stdin_bytes.is_some() {
        cmd.stdin(std::process::Stdio::piped());
    }
    cmd.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn()?;
    if let Some(bytes) = stdin_bytes {
        use std::io::Write;
        if let Some(mut sin) = child.stdin.take() {
            sin.write_all(bytes)?;
        }
    }
    let out = child.wait_with_output()?;
    ensure!(out.status.success(), "git {:?} failed: {}", args, String::from_utf8_lossy(&out.stderr));
    Ok(String::from_utf8(out.stdout)?.trim().to_owned())
}

struct SeedRepo {
    _dir: TempDir,
    repo: PathBuf,
    packs_dir: PathBuf,
    prev_oid: String,
    step: usize,
}

impl SeedRepo {
    fn new(format: ObjectFormat) -> Result<Self> {
        let dir = TempDir::new()?;
        let (repo, packs_dir) = (dir.path().join("seed"), dir.path().join("packs"));
        fs::create_dir_all(&repo)?;
        fs::create_dir_all(&packs_dir)?;
        git_run(&repo, &["init", &format!("--object-format={}", format.as_str()), "--initial-branch=main"], None)?;
        Ok(Self { _dir: dir, repo, packs_dir, prev_oid: "0".repeat(format.oid_hex_len()), step: 0 })
    }

    fn next_commit_pack(&mut self) -> Result<(String, String, PathBuf, PathBuf)> {
        self.step += 1;
        let idx = self.step;
        fs::write(self.repo.join("history.txt"), format!("commit-step-{idx}\n"))?;
        git_run(&self.repo, &["add", "."], None)?;
        git_run(&self.repo, &["commit", "-m", &format!("step {idx}")], None)?;
        let new_oid = git_run(&self.repo, &["rev-parse", "HEAD"], None)?;
        let range = if idx == 1 { new_oid.clone() } else { format!("{}..{}", self.prev_oid, new_oid) };
        let oid_input: String = git_run(&self.repo, &["rev-list", "--objects", &range], None)?
            .lines()
            .filter_map(|line| line.split_whitespace().next())
            .map(|oid| format!("{oid}\n"))
            .collect();
        let step_dir = self.packs_dir.join(format!("s-{idx:03}"));
        fs::create_dir_all(&step_dir)?;
        let prefix = step_dir.join("inc");
        git_run(
            &self.repo,
            &["-c", "pack.writeReverseIndex=false", "pack-objects", "-q", &prefix.to_string_lossy()],
            Some(oid_input.as_bytes()),
        )?;
        let mut pack = None;
        let mut index = None;
        for entry in fs::read_dir(&step_dir)? {
            let p = entry?.path();
            if p.extension().and_then(|e| e.to_str()) == Some("pack") {
                pack = Some(p);
            } else if p.extension().and_then(|e| e.to_str()) == Some("idx") {
                index = Some(p);
            }
        }
        let old = std::mem::replace(&mut self.prev_oid, new_oid.clone());
        Ok((old, new_oid, pack.unwrap(), index.unwrap()))
    }
}

fn push_req(
    op_id: Uuid,
    digest: &str,
    ref_name: &str,
    old_oid: String,
    new_oid: String,
    packs: Vec<(PathBuf, PathBuf)>,
) -> IncrementalPushRequest {
    IncrementalPushRequest {
        operation_id: op_id,
        request_digest: digest.to_owned(),
        caller_authorized: true,
        ref_mutations: vec![RefMutation { ref_name: ref_name.to_owned(), old_oid, new_oid }],
        new_pack_paths: packs,
        free_disk_bytes: 512 * 1024 * 1024,
        max_single_object_bytes: 1024 * 1024,
    }
}

#[test]
fn multi_layer_contract_separates_gateway_ledger_blob_and_verifier_limits() {
    let contract = PandoCapacityContract::current_standalone();
    assert!(contract.validate().is_ok());
    assert!(contract.gateway_exceeds_verifier_window());
    assert_eq!(contract.metadata_ledger.repo_max_logical_bytes, 8 * 1024 * 1024);
    assert_eq!(contract.metadata_ledger.repo_max_active_memberships, 16);
    assert_eq!(contract.verifier.max_total_bytes_per_window, 64 * 1024 * 1024);
    assert_eq!(contract.verifier.max_objects_per_window, 16_384);
    assert_eq!(contract.verifier.view_max_logical_bytes, 160 * 1024 * 1024);
    assert!(!contract.streaming.delete_during_compaction_enabled);
}

#[tokio::test]
async fn streaming_growth_beyond_16_packs_sha1_and_sha256_lifecycle() -> Result<()> {
    let s3 = LoopbackS3::shared();
    let store = s3.open_store()?;
    let dl = Instant::now() + Duration::from_secs(90);

    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let view_dir = TempDir::new()?;
        let mut contract = PandoCapacityContract::current_standalone();
        contract.streaming.compact_trigger_packs = 10;
        let engine = StreamingGrowthEngine::new(
            contract,
            store.clone(),
            open_private_views(&view_dir)?,
            EngineScope {
                tenant_id: Uuid::new_v4(),
                repo_id: Uuid::new_v4(),
                authority_id: Uuid::new_v4(),
                object_format: format,
                auto_compact: true,
            },
        )?;

        let mut seeder = SeedRepo::new(format)?;
        let mut commit_oids = Vec::new();
        let zero = "0".repeat(format.oid_hex_len());
        let (pin_id, root_id, backup_id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());

        for i in 1..=20usize {
            let (old_oid, new_oid, pack_p, idx_p) = seeder.next_commit_pack()?;
            commit_oids.push(new_oid.clone());
            let req =
                push_req(Uuid::new_v4(), &format!("d-{i}"), "refs/heads/main", old_oid, new_oid, vec![(pack_p, idx_p)]);
            let out = engine.apply_push(req.clone(), dl).await?;
            assert_eq!((out.added_packs, out.no_new_pack, out.replayed), (1, false, false));

            if i == 3 {
                engine
                    .attach_hold(ProtectionHold::Pin { pin_id, purpose: "ci".into() }, Some(commit_oids[2].clone()))?;
                engine.attach_hold(ProtectionHold::RetentionRoot { root_id, kind: "pitr".into() }, None)?;
                engine.attach_hold(ProtectionHold::BackupManifest { backup_id }, None)?;
                assert!(engine.apply_push(req.clone(), dl).await?.replayed);
                let mut bad = req.clone();
                bad.request_digest = "tampered".into();
                assert!(matches!(engine.apply_push(bad, dl).await, Err(GrowthEngineError::DigestConflict(_))));
            }
            if i == 5 {
                let np = push_req(
                    Uuid::new_v4(),
                    "no-pack",
                    "refs/heads/release",
                    zero.clone(),
                    commit_oids[1].clone(),
                    vec![],
                );
                assert!(engine.apply_push(np, dl).await?.no_new_pack);

                let cancel_id = Uuid::new_v4();
                engine.cancel_operation(cancel_id)?;
                let cancelled =
                    push_req(cancel_id, "cancel", "refs/heads/never", zero.clone(), commit_oids[1].clone(), vec![]);
                assert!(matches!(
                    engine.apply_push(cancelled, dl).await,
                    Err(GrowthEngineError::OperationCancelled(_))
                ));
                assert!(!engine.acked_refs().contains_key("refs/heads/never"));
            }
        }

        let corrupt_dir = TempDir::new()?;
        let (bad_pack, bad_idx) = (corrupt_dir.path().join("bad.pack"), corrupt_dir.path().join("bad.idx"));
        fs::write(&bad_pack, b"NOT_A_VALID_PACK")?;
        fs::write(&bad_idx, b"NOT_A_VALID_IDX")?;
        let bad_pack_req = push_req(
            Uuid::new_v4(),
            "corrupt-pack",
            "refs/heads/broken",
            zero.clone(),
            commit_oids[0].clone(),
            vec![(bad_pack, bad_idx)],
        );
        assert!(engine.apply_push(bad_pack_req, dl).await.is_err());

        let bad_ref = push_req(
            Uuid::new_v4(),
            "dangling",
            "refs/heads/broken",
            zero.clone(),
            "f".repeat(format.oid_hex_len()),
            vec![],
        );
        assert!(engine.apply_push(bad_ref, dl).await.is_err());
        assert!(!engine.acked_refs().contains_key("refs/heads/broken"));

        let snap = engine.snapshot();
        assert_eq!((snap.cumulative_packs_added, snap.no_new_pack_pushes), (20, 1));
        assert!(snap.compactions_completed >= 1 && snap.active_frontier_len <= 16);
        assert!(snap.historical_retained_pack_bytes > 0 && snap.ledger.compacted_protected_memberships == 3);
        // Archiving released entries (packs 4..=19) must leave pin/root/backup-protected packs (1..=3) untouched.
        assert!(engine.archive_released_ledger() > 0);
        assert_eq!(engine.snapshot().ledger.compacted_protected_memberships, 3);
        for old_loc in engine.retained_pack_locators() {
            assert!(s3.exists(&old_loc), "compaction must never delete retained old pack");
        }
        assert!(engine.verify_full_serving_closure(dl).await? >= 3);
        engine.release_hold(pin_id)?;
        engine.release_hold(root_id)?;
        engine.release_hold(backup_id)?;
        assert_eq!(engine.snapshot().ledger.compacted_protected_memberships, 0);
        assert!(engine.archive_released_ledger() > 0);
        assert!(engine.snapshot().ledger.archived_memberships >= 20);
    }
    Ok(())
}

#[tokio::test]
async fn fail_closed_boundary_faults_and_backpressure() -> Result<()> {
    let mut contract = PandoCapacityContract::current_standalone();
    contract.verifier.max_concurrent_native = 1;
    contract.streaming.max_queue_waiters = 1;
    let limits = AdmissionLimits::from_contract(&contract)?;
    let ctrl = Arc::new(AdmissionController::new(limits)?);
    let dl = Instant::now() + Duration::from_secs(5);
    let base = AdmissionRequest {
        tenant_id: Uuid::new_v4(),
        repo_id: Uuid::new_v4(),
        caller_authorized: true,
        class: AdmissionClass::ForegroundPush,
        new_pack_count: 1,
        active_frontier_packs: 4,
        declared_pack_bytes: 4096,
        declared_objects: 8,
        max_single_object_bytes: 1024,
        estimated_memory_bytes: 128 * 1024,
        estimated_workspace_bytes: 8192,
        required_fds: 16,
        free_disk_bytes: 64 * 1024 * 1024,
    };

    let cases: [(&str, fn(&mut AdmissionRequest, AdmissionLimits)); 9] = [
        ("unauthorized", |r, _| r.caller_authorized = false),
        ("oversized_object", |r, l| r.max_single_object_bytes = l.max_object_bytes + 1),
        ("pack_bytes_exceeded", |r, l| r.declared_pack_bytes = l.max_pack_bytes_per_push + 1),
        ("too_many_objects", |r, l| r.declared_objects = l.max_objects_per_window + 1),
        ("pack_count_limit_reached", |r, _| r.active_frontier_packs = 16),
        ("workspace_budget_exceeded", |r, l| r.estimated_workspace_bytes = l.max_workspace_bytes + 1),
        ("memory_budget_exceeded", |r, l| r.estimated_memory_bytes = l.max_memory_bytes + 1),
        ("fd_budget_exceeded", |r, l| r.required_fds = l.max_open_fds + 1),
        ("disk_headroom_exhausted", |r, _| r.free_disk_bytes = 1024),
    ];
    for (expected, mutate) in cases {
        let mut req = base.clone();
        mutate(&mut req, limits);
        assert_eq!(ctrl.acquire(&req, dl).await.err().unwrap().reason_key(), expected);
    }

    let active = ctrl.acquire(&base, dl).await?;
    let c2 = Arc::clone(&ctrl);
    let b2 = base.clone();
    let queued = tokio::spawn(async move { c2.acquire(&b2, Instant::now() + Duration::from_secs(5)).await });
    while ctrl.telemetry().queued_waiters == 0 {
        tokio::task::yield_now().await;
    }
    assert!(matches!(ctrl.acquire(&base, dl).await, Err(AdmissionRejection::QueueFull { .. })));
    drop(active);
    let _p2 = queued.await??;
    assert_eq!(ctrl.telemetry().rejected_by_reason.get("queue_full").copied(), Some(1));
    Ok(())
}

#[test]
fn retention_ledger_protects_pins_roots_backups_and_enforces_hot_budget() {
    let mut policy = LedgerBudgetPolicy::from_contract(&PandoCapacityContract::current_standalone());
    policy.repo_max_registrations = 2;
    let mut ledger = RetentionLedger::new(policy);

    let (p1, p2, m1, r1, r2) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    ledger.record_entry(m1, LedgerEntryKind::Membership, Some(p1), None, 512, 1).unwrap();
    ledger.record_entry(r1, LedgerEntryKind::Registration, Some(p1), None, 1024, 1).unwrap();
    ledger.record_entry(r2, LedgerEntryKind::Registration, Some(p2), None, 1024, 2).unwrap();

    let backup_id = Uuid::new_v4();
    ledger.attach_hold_to_pack(p1, ProtectionHold::BackupManifest { backup_id }).unwrap();
    ledger.record_compaction_superseded(3, &std::collections::BTreeSet::from([p1, p2]));

    assert_eq!(ledger.get(r1).unwrap().classification(), RetentionClassification::CompactedProtected);
    assert_eq!(ledger.get(r2).unwrap().classification(), RetentionClassification::ReleasedEligibleForArchive);
    assert!(matches!(ledger.attempt_delete_entry(r1), Err(LedgerRetentionError::ProtectedByHold { .. })));
    assert!(matches!(
        ledger.attempt_delete_entry(r2),
        Err(LedgerRetentionError::CompactionDoesNotAuthorizeDelete { .. })
    ));
    assert!(matches!(
        ledger.record_entry(Uuid::new_v4(), LedgerEntryKind::Registration, Some(Uuid::new_v4()), None, 1024, 3),
        Err(LedgerRetentionError::LedgerBudgetExhausted { resource: "registrations", .. })
    ));
    assert_eq!(ledger.archive_released_entries(), 1);
    assert!(
        ledger.record_entry(Uuid::new_v4(), LedgerEntryKind::Registration, Some(Uuid::new_v4()), None, 1024, 3).is_ok()
    );

    ledger.release_hold(backup_id).unwrap();
    assert_eq!(ledger.get(r1).unwrap().classification(), RetentionClassification::ReleasedEligibleForArchive);
    assert_eq!(ledger.archive_released_entries(), 2);
}
