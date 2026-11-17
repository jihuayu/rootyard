//! Real OpenDAL S3 + stock Git (SHA-1 & SHA-256) capacity integration tests (#177).

use std::{
    collections::BTreeMap,
    fs::{self, DirBuilder},
    path::{Path, PathBuf},
    process::{Command, Stdio},
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
use rootyard::blob_store::capacity_contract::{
    git_ops::{hash_file_bounded, inspect_pack_file},
    *,
};
use rootyard::blob_store::{BlobLocator, config::BlobProfile, disposable_view::DisposableViewRoot, opendal::BlobStore};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::sync::Notify;
use uuid::Uuid;

#[cfg(unix)]
const NULL_GIT_CONFIG: &str = "/dev/null";
#[cfg(not(unix))]
const NULL_GIT_CONFIG: &str = "NUL";

type Gate = (String, Arc<Notify>, Arc<Notify>);

#[derive(Default)]
struct S3State {
    objects: Mutex<BTreeMap<String, Vec<u8>>>,
    gate: Mutex<Option<Gate>>,
}

struct LoopbackS3 {
    endpoint: String,
    state: Arc<S3State>,
}

static SHARED_S3: OnceLock<LoopbackS3> = OnceLock::new();
static ENV_LOCK: Mutex<()> = Mutex::new(());

impl LoopbackS3 {
    fn shared() -> &'static Self {
        SHARED_S3.get_or_init(Self::new_isolated)
    }

    fn new_isolated() -> Self {
        let state = Arc::new(S3State::default());
        let srv = Arc::clone(&state);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback s3");
        listener.set_nonblocking(true).expect("nonblocking");
        let port = listener.local_addr().expect("addr").port();
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
            rt.block_on(async move {
                let l = tokio::net::TcpListener::from_std(listener).unwrap();
                let _ = tx.send(());
                let _ = axum::serve(l, Router::new().fallback(handle_s3).with_state(srv)).await;
            });
        });
        rx.recv().unwrap();
        Self { endpoint: format!("http://127.0.0.1:{port}"), state }
    }

    fn arm_get_gate(&self, substr: &str) -> (Arc<Notify>, Arc<Notify>) {
        let (entered, release) = (Arc::new(Notify::new()), Arc::new(Notify::new()));
        *self.state.gate.lock().unwrap() = Some((substr.into(), Arc::clone(&entered), Arc::clone(&release)));
        (entered, release)
    }

    fn open_store(&self) -> Result<BlobStore> {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let spec = "DRIVER=opendal SERVICE=s3 BUCKET=pando-cap-bucket REGION=us-east-1 ROOT=pando-cap-it ACCESS_KEY_ID=test-ak SECRET_ACCESS_KEY=test-sk ENCRYPTION_MODE=provider-managed RETRY_MAX_TIMES=0 MAX_OBJECT_BYTES=67108864";
        let mut pairs: Vec<(String, Option<String>)> = spec
            .split_ascii_whitespace()
            .map(|s| {
                let (k, v) = s.split_once('=').unwrap();
                (format!("ROOTYARD_BLOB_{k}"), Some(v.into()))
            })
            .collect();
        pairs.push(("ROOTYARD_BLOB_ENDPOINT".into(), Some(self.endpoint.clone())));
        pairs.push(("ROOTYARD_BLOB_KEYRING_DIR".into(), None));
        let saved: Vec<_> = pairs.iter().map(|(k, _)| (k.as_str(), std::env::var_os(k))).collect();
        let set = |k: &str, v: Option<&std::ffi::OsStr>| unsafe {
            if let Some(val) = v { std::env::set_var(k, val) } else { std::env::remove_var(k) }
        };
        for (k, v) in &pairs {
            set(k, v.as_deref().map(std::ffi::OsStr::new));
        }
        let res = BlobStore::open(BlobProfile::from_env()?);
        for (k, old) in saved {
            set(k, old.as_deref());
        }
        Ok(res?)
    }

    fn exists(&self, locator: &BlobLocator) -> bool {
        self.state.objects.lock().unwrap().contains_key(&format!("pando-cap-bucket/pando-cap-it/{}", locator.path()))
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
    let key = uri.path().trim_start_matches('/').to_owned();
    if !key.contains('/') {
        return Response::new(Body::from("<ListBucketResult/>"));
    }
    if method == Method::GET {
        let hit = state.gate.lock().unwrap().take_if(|g| key.contains(&g.0));
        if let Some((_, entered, release)) = hit {
            entered.notify_one();
            release.notified().await;
        }
    }
    match method {
        Method::PUT => {
            let etag = format!("\"{}\"", &hex::encode(Sha256::digest(body.as_ref()))[..32]);
            state.objects.lock().unwrap().insert(key, body.to_vec());
            s3_resp(StatusCode::OK, Some(&etag), 0, Body::empty())
        }
        Method::HEAD | Method::GET => match state.objects.lock().unwrap().get(&key).cloned() {
            Some(data) => {
                let etag = format!("\"{}\"", &hex::encode(Sha256::digest(data.as_slice()))[..32]);
                let payload = if method == Method::HEAD { Body::empty() } else { Body::from(data.clone()) };
                s3_resp(StatusCode::OK, Some(&etag), data.len(), payload)
            }
            None => s3_resp(StatusCode::NOT_FOUND, None, 0, Body::empty()),
        },
        _ => s3_resp(StatusCode::METHOD_NOT_ALLOWED, None, 0, Body::empty()),
    }
}

fn open_engine(
    s3: &LoopbackS3,
    dir: &TempDir,
    contract: PandoCapacityContract,
    fmt: ObjectFormat,
    auto_compact: bool,
) -> Result<Arc<StreamingGrowthEngine>> {
    let views = dir.path().join("views");
    let mut b = DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(&views)?;
    let vr = DisposableViewRoot::open(&views, 4, 256 * 1024 * 1024, Duration::from_secs(120))?;
    let scope = EngineScope {
        tenant_id: Uuid::new_v4(),
        repo_id: Uuid::new_v4(),
        authority_id: Uuid::new_v4(),
        object_format: fmt,
        auto_compact,
    };
    Ok(Arc::new(StreamingGrowthEngine::new(contract, s3.open_store()?, vr, scope)?))
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
            ("GIT_AUTHOR_NAME", "ry"),
            ("GIT_AUTHOR_EMAIL", "ry@ex"),
            ("GIT_COMMITTER_NAME", "ry"),
            ("GIT_COMMITTER_EMAIL", "ry@ex"),
        ])
        .stdin(if stdin_bytes.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
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

    fn next_blob_pack(&mut self, file: &str, bytes: &[u8]) -> Result<(String, String, PathBuf, PathBuf)> {
        self.step += 1;
        let idx = self.step;
        fs::write(self.repo.join(file), bytes)?;
        git_run(&self.repo, &["add", "."], None)?;
        git_run(&self.repo, &["commit", "-m", &format!("step {idx}")], None)?;
        let new_oid = git_run(&self.repo, &["rev-parse", "HEAD"], None)?;
        let range = if idx == 1 { new_oid.clone() } else { format!("{}..{}", self.prev_oid, new_oid) };
        let oids: String = git_run(&self.repo, &["rev-list", "--objects", &range], None)?
            .lines()
            .filter_map(|l| l.split_whitespace().next())
            .map(|o| format!("{o}\n"))
            .collect();
        let step_dir = self.packs_dir.join(format!("s-{idx:03}"));
        fs::create_dir_all(&step_dir)?;
        git_run(
            &self.repo,
            &["-c", "pack.writeReverseIndex=false", "pack-objects", "-q", &step_dir.join("inc").to_string_lossy()],
            Some(oids.as_bytes()),
        )?;
        let paths: Vec<_> = fs::read_dir(&step_dir)?.filter_map(Result::ok).map(|e| e.path()).collect();
        let pack = paths.iter().find(|p| p.extension().and_then(|e| e.to_str()) == Some("pack")).unwrap().clone();
        let index = paths.iter().find(|p| p.extension().and_then(|e| e.to_str()) == Some("idx")).unwrap().clone();
        Ok((std::mem::replace(&mut self.prev_oid, new_oid.clone()), new_oid, pack, index))
    }

    fn next_commit_pack(&mut self) -> Result<(String, String, PathBuf, PathBuf)> {
        self.next_blob_pack("history.txt", format!("commit-step-{}\n", self.step + 1).as_bytes())
    }
}

fn push_with(
    op_id: Uuid,
    digest: &str,
    ref_name: &str,
    old_oid: &str,
    new_oid: &str,
    packs: Vec<(PathBuf, PathBuf)>,
) -> IncrementalPushRequest {
    IncrementalPushRequest {
        operation_id: op_id,
        request_digest: digest.to_owned(),
        caller_authorized: true,
        ref_mutations: vec![RefMutation {
            ref_name: ref_name.to_owned(),
            old_oid: old_oid.to_owned(),
            new_oid: new_oid.to_owned(),
        }],
        new_pack_paths: packs,
        free_disk_bytes: 512 * 1024 * 1024,
        max_single_object_bytes: 1024 * 1024,
    }
}

fn push_req(ref_name: &str, old_oid: &str, new_oid: &str, packs: Vec<(PathBuf, PathBuf)>) -> IncrementalPushRequest {
    push_with(Uuid::new_v4(), &Uuid::new_v4().to_string(), ref_name, old_oid, new_oid, packs)
}

fn noisy_bytes(seed: usize, len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i.wrapping_mul(131) ^ seed.wrapping_mul(37) ^ (i >> 3)) & 0xff) as u8).collect()
}

fn pack_meta(pack: &Path, idx: &Path) -> Result<(String, u64, u64)> {
    let (sha, plen, objs) = inspect_pack_file(pack)?;
    Ok((sha, plen + hash_file_bounded(idx)?.1, objs))
}

#[test]
fn multi_layer_contract_separates_gateway_ledger_blob_and_verifier_limits() {
    let c = PandoCapacityContract::current_standalone();
    assert!(
        c.validate().is_ok() && c.gateway_exceeds_verifier_window() && !c.streaming.delete_during_compaction_enabled
    );
    assert_eq!(
        (c.metadata_ledger.repo_max_logical_bytes, c.metadata_ledger.repo_max_active_memberships),
        (8 * 1024 * 1024, 16)
    );
    assert_eq!(
        (c.verifier.max_total_bytes_per_window, c.verifier.max_objects_per_window, c.verifier.view_max_logical_bytes),
        (64 * 1024 * 1024, 16_384, 160 * 1024 * 1024)
    );
}

#[tokio::test]
async fn streaming_growth_beyond_16_packs_sha1_and_sha256_lifecycle() -> Result<()> {
    let (s3, dl) = (LoopbackS3::shared(), Instant::now() + Duration::from_secs(90));
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let dir = TempDir::new()?;
        let mut contract = PandoCapacityContract::current_standalone();
        contract.streaming.compact_trigger_packs = 10;
        let engine = open_engine(s3, &dir, contract, format, true)?;
        let (mut seeder, mut oids, z) = (SeedRepo::new(format)?, Vec::new(), "0".repeat(format.oid_hex_len()));
        let (pin_id, root_id, backup_id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());

        for i in 1..=20usize {
            let (old, new, pack_p, idx_p) = seeder.next_commit_pack()?;
            oids.push(new.clone());
            let req =
                push_with(Uuid::new_v4(), &format!("d-{i}"), "refs/heads/main", &old, &new, vec![(pack_p, idx_p)]);
            let out = engine.apply_push(req.clone(), dl).await?;
            assert_eq!((out.added_packs, out.no_new_pack, out.replayed), (1, false, false));
            if i == 3 {
                engine.attach_hold(ProtectionHold::Pin { pin_id, purpose: "ci".into() }, Some(oids[2].clone()))?;
                engine.attach_hold(ProtectionHold::RetentionRoot { root_id, kind: "pitr".into() }, None)?;
                engine.attach_hold(ProtectionHold::BackupManifest { backup_id }, None)?;
                assert!(engine.apply_push(req.clone(), dl).await?.replayed);
                let mut bad = req;
                bad.request_digest = "tampered".into();
                assert!(matches!(engine.apply_push(bad, dl).await, Err(GrowthEngineError::DigestConflict(_))));
            }
            if i == 5 {
                assert!(engine.apply_push(push_req("refs/heads/release", &z, &oids[1], vec![]), dl).await?.no_new_pack);
                let cid = Uuid::new_v4();
                engine.cancel_operation(cid)?;
                let c = push_with(cid, "cancel", "refs/heads/never", &z, &oids[1], vec![]);
                assert!(matches!(engine.apply_push(c, dl).await, Err(GrowthEngineError::OperationCancelled(_))));
                assert!(!engine.acked_refs().contains_key("refs/heads/never"));
            }
        }
        let cdir = TempDir::new()?;
        let (bp, bi) = (cdir.path().join("bad.pack"), cdir.path().join("bad.idx"));
        fs::write(&bp, b"NOT_A_VALID_PACK")?;
        fs::write(&bi, b"NOT_A_VALID_IDX")?;
        assert!(engine.apply_push(push_req("refs/heads/broken", &z, &oids[0], vec![(bp, bi)]), dl).await.is_err());
        assert!(
            engine
                .apply_push(push_req("refs/heads/broken", &z, &"f".repeat(format.oid_hex_len()), vec![]), dl)
                .await
                .is_err()
        );
        assert!(!engine.acked_refs().contains_key("refs/heads/broken"));

        let snap = engine.snapshot();
        assert_eq!((snap.cumulative_packs_added, snap.no_new_pack_pushes), (20, 1));
        assert!(snap.compactions_completed >= 1 && snap.active_frontier_len <= 16);
        assert!(snap.historical_retained_pack_bytes > 0 && snap.ledger.compacted_protected_memberships == 3);
        assert!(engine.archive_released_ledger() > 0);
        assert_eq!(engine.snapshot().ledger.compacted_protected_memberships, 3);
        for old_loc in engine.retained_pack_locators() {
            assert!(s3.exists(&old_loc));
        }
        assert!(engine.verify_full_serving_closure(dl).await? >= 3);
        for id in [pin_id, root_id, backup_id] {
            engine.release_hold(id)?;
        }
        assert_eq!(engine.snapshot().ledger.compacted_protected_memberships, 0);
        assert!(engine.archive_released_ledger() > 0 && engine.snapshot().ledger.archived_memberships >= 20);
    }
    Ok(())
}

#[tokio::test]
async fn compaction_and_push_budget_failures_preserve_ledger_and_frontier() -> Result<()> {
    let (s3, dl) = (LoopbackS3::shared(), Instant::now() + Duration::from_secs(60));
    for (regs, rcpts, bytes, expected, compact) in [
        (2, 16, 8 * 1024 * 1024, "registrations", true),
        (16, 16, 4608, "logical_bytes", true),
        (16, 1, 8 * 1024 * 1024, "receipts", false),
        (1, 16, 8 * 1024 * 1024, "registrations", false),
    ] {
        let dir = TempDir::new()?;
        let mut c = PandoCapacityContract::current_standalone();
        c.metadata_ledger.repo_max_registrations = regs;
        c.metadata_ledger.repo_max_receipts = rcpts;
        c.metadata_ledger.repo_max_logical_bytes = bytes;
        let engine = open_engine(s3, &dir, c, ObjectFormat::Sha1, false)?;
        let mut seeder = SeedRepo::new(ObjectFormat::Sha1)?;
        for _ in 0..(if compact { 2 } else { 1 }) {
            let (old, new, pp, ip) = seeder.next_commit_pack()?;
            engine.apply_push(push_req("refs/heads/main", &old, &new, vec![(pp, ip)]), dl).await?;
        }
        let snap = (engine.snapshot(), engine.acked_refs(), engine.active_pack_locators());
        let err = if compact {
            engine.compact_serving_frontier(dl).await.unwrap_err()
        } else {
            let (old, new, pp, ip) = seeder.next_commit_pack()?;
            engine.apply_push(push_req("refs/heads/main", &old, &new, vec![(pp, ip)]), dl).await.unwrap_err()
        };
        assert!(
            matches!(err, GrowthEngineError::Ledger(LedgerRetentionError::LedgerBudgetExhausted { resource, .. }) if resource == expected)
        );
        assert_eq!(engine.archive_released_ledger(), 0);
        assert_eq!((engine.snapshot(), engine.acked_refs(), engine.active_pack_locators()), snap);
    }
    Ok(())
}

#[tokio::test]
async fn concurrent_commit_rejects_window_overflow_and_compacted_base() -> Result<()> {
    let (dl, z) = (Instant::now() + Duration::from_secs(60), "0".repeat(40));
    for limit_objects in [false, true] {
        let (s3, dir) = (LoopbackS3::new_isolated(), TempDir::new()?);
        let (mut s0, mut sa, mut sb) = (
            SeedRepo::new(ObjectFormat::Sha1)?,
            SeedRepo::new(ObjectFormat::Sha1)?,
            SeedRepo::new(ObjectFormat::Sha1)?,
        );
        let (_, o0, p0, i0) = s0.next_blob_pack("base.bin", &noisy_bytes(1, 256))?;
        let (_, oa, pa, ia) = sa.next_blob_pack("a.bin", &noisy_bytes(2, 4096))?;
        let (_, ob, pb, ib) = sb.next_blob_pack("b.bin", &noisy_bytes(3, 4096))?;
        let ((_, b0, o0_cnt), (pa_sha, ba, oa_cnt), (pb_sha, bb, ob_cnt)) =
            (pack_meta(&p0, &i0)?, pack_meta(&pa, &ia)?, pack_meta(&pb, &ib)?);
        assert_ne!(pa_sha, pb_sha);
        let mut c = PandoCapacityContract::current_standalone();
        if limit_objects {
            c.verifier.max_objects_per_window = o0_cnt + oa_cnt.max(ob_cnt);
        } else {
            c.verifier.max_total_bytes_per_window = b0 + ba.max(bb) + 64;
        }
        let engine = open_engine(&s3, &dir, c, ObjectFormat::Sha1, false)?;
        engine.apply_push(push_req("refs/heads/base", &z, &o0, vec![(p0, i0)]), dl).await?;

        let (entered, release) = s3.arm_get_gate(&pa_sha);
        let (eng_a, req_a) = (Arc::clone(&engine), push_req("refs/heads/a", &z, &oa, vec![(pa, ia)]));
        let task_a = tokio::spawn(async move { eng_a.apply_push(req_a, dl).await });
        entered.notified().await;
        engine.apply_push(push_req("refs/heads/b", &z, &ob, vec![(pb, ib)]), dl).await?;
        release.notify_one();
        let err = task_a.await?.unwrap_err();
        if limit_objects {
            assert!(matches!(err, GrowthEngineError::Admission(AdmissionRejection::TooManyObjects { .. })));
        } else {
            assert!(matches!(err, GrowthEngineError::Admission(AdmissionRejection::PackBytesExceeded { .. })));
        }
        assert!(!engine.acked_refs().contains_key("refs/heads/a"));
        assert_eq!(
            (
                engine.snapshot().epoch,
                engine.snapshot().active_frontier_len,
                engine.snapshot().ledger.protected_registrations
            ),
            (2, 2, 2)
        );
    }

    let (s3, dir) = (LoopbackS3::new_isolated(), TempDir::new()?);
    let engine = open_engine(&s3, &dir, PandoCapacityContract::current_standalone(), ObjectFormat::Sha1, false)?;
    let (mut sk, mut sp) = (SeedRepo::new(ObjectFormat::Sha1)?, SeedRepo::new(ObjectFormat::Sha1)?);
    let (_, ok, pk, ik) = sk.next_blob_pack("keep.txt", b"keep")?;
    let (_, op, pp, ip) = sp.next_blob_pack("prune.txt", b"prune")?;
    let (pp_sha, _, _) = pack_meta(&pp, &ip)?;
    engine.apply_push(push_req("refs/heads/keep", &z, &ok, vec![(pk, ik)]), dl).await?;
    engine.apply_push(push_req("refs/heads/prune", &z, &op, vec![(pp, ip)]), dl).await?;
    let (entered, release) = s3.arm_get_gate(&pp_sha);
    let (eng_np, np) = (Arc::clone(&engine), push_req("refs/heads/release", &z, &op, vec![]));
    let task_np = tokio::spawn(async move { eng_np.apply_push(np, dl).await });
    entered.notified().await;
    engine.apply_push(push_req("refs/heads/prune", &op, &z, vec![]), dl).await?;
    engine.compact_serving_frontier(dl).await?;
    release.notify_one();
    assert!(matches!(task_np.await?.unwrap_err(), GrowthEngineError::CompactionConflict));
    assert!(!engine.acked_refs().contains_key("refs/heads/release"));
    assert_eq!(engine.verify_full_serving_closure(dl).await?, 1);
    Ok(())
}
