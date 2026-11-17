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
use rootyard::blob_store::disposable_view::DisposableViewRoot;
use rootyard::blob_store::{BlobLocator, config::BlobProfile, opendal::BlobStore};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::{sync::Notify, task::JoinHandle};
use uuid::Uuid;

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
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind s3");
        listener.set_nonblocking(true).expect("nonblocking");
        let port = listener.local_addr().expect("addr").port();
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap().block_on(
                async move {
                    let l = tokio::net::TcpListener::from_std(listener).unwrap();
                    let _ = tx.send(());
                    let _ = axum::serve(l, Router::new().fallback(handle_s3).with_state(srv)).await;
                },
            );
        });
        rx.recv().unwrap();
        Self { endpoint: format!("http://127.0.0.1:{port}"), state }
    }

    fn spawn_gated<T: Send + 'static>(
        &self,
        substr: &str,
        bg: impl std::future::Future<Output = T> + Send + 'static,
    ) -> (Arc<Notify>, Arc<Notify>, JoinHandle<T>) {
        let (entered, release) = (Arc::new(Notify::new()), Arc::new(Notify::new()));
        *self.state.gate.lock().unwrap() = Some((substr.into(), Arc::clone(&entered), Arc::clone(&release)));
        (entered, release, tokio::spawn(bg))
    }

    fn open_store(&self) -> Result<BlobStore> {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let spec = "DRIVER=opendal SERVICE=s3 BUCKET=pando-cap-bucket REGION=us-east-1 ROOT=pando-cap-it ACCESS_KEY_ID=test-ak SECRET_ACCESS_KEY=test-sk ENCRYPTION_MODE=provider-managed RETRY_MAX_TIMES=0 MAX_OBJECT_BYTES=67108864";
        let mut saved = vec![("ROOTYARD_BLOB_KEYRING_DIR".into(), std::env::var_os("ROOTYARD_BLOB_KEYRING_DIR"))];
        unsafe { std::env::remove_var("ROOTYARD_BLOB_KEYRING_DIR") };
        let kvs = spec.split_ascii_whitespace().map(|s| s.split_once('=').unwrap());
        for (k, v) in kvs.chain([("ENDPOINT", self.endpoint.as_str())]) {
            let ek = format!("ROOTYARD_BLOB_{k}");
            saved.push((ek.clone(), std::env::var_os(&ek)));
            unsafe { std::env::set_var(&ek, v) };
        }
        let res = BlobStore::open(BlobProfile::from_env()?);
        for (k, old) in saved {
            unsafe { if let Some(v) = old { std::env::set_var(&k, v) } else { std::env::remove_var(&k) } }
        }
        Ok(res?)
    }

    fn exists(&self, locator: &BlobLocator) -> bool {
        self.state.objects.lock().unwrap().contains_key(&format!("pando-cap-bucket/pando-cap-it/{}", locator.path()))
    }
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
    let resp = |st: StatusCode, tag: Option<String>, len: usize, b: Body| {
        let r = Response::builder().status(st).header(header::CONTENT_LENGTH, len.to_string());
        (if let Some(t) = tag { r.header(header::ETAG, t) } else { r }).body(b).unwrap()
    };
    let tag = |b: &[u8]| format!("\"{}\"", &hex::encode(Sha256::digest(b))[..32]);
    match method {
        Method::PUT => {
            let etag = tag(body.as_ref());
            state.objects.lock().unwrap().insert(key, body.to_vec());
            resp(StatusCode::OK, Some(etag), 0, Body::empty())
        }
        Method::HEAD | Method::GET => match state.objects.lock().unwrap().get(&key).cloned() {
            Some(d) => {
                let len = d.len();
                let b = if method == Method::HEAD { Body::empty() } else { Body::from(d.clone()) };
                resp(StatusCode::OK, Some(tag(&d)), len, b)
            }
            None => resp(StatusCode::NOT_FOUND, None, 0, Body::empty()),
        },
        _ => resp(StatusCode::METHOD_NOT_ALLOWED, None, 0, Body::empty()),
    }
}

fn open_engine(
    s3: &LoopbackS3,
    dir: &TempDir,
    contract: PandoCapacityContract,
    object_format: ObjectFormat,
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
    let u = Uuid::new_v4;
    let scope = EngineScope { tenant_id: u(), repo_id: u(), authority_id: u(), object_format, auto_compact };
    Ok(Arc::new(StreamingGrowthEngine::new(contract, s3.open_store()?, vr, scope)?))
}

fn git_run(repo: &Path, args: &[&str], stdin_bytes: Option<&[u8]>) -> Result<String> {
    let envs = "GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0 GIT_AUTHOR_NAME=ry GIT_AUTHOR_EMAIL=ry@ex GIT_COMMITTER_NAME=ry GIT_COMMITTER_EMAIL=ry@ex";
    let mut child = Command::new("git")
        .args(["-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "--no-replace-objects", "-C"])
        .arg(repo)
        .args(args)
        .envs(envs.split_ascii_whitespace().map(|s| s.split_once('=').unwrap()))
        .env("GIT_CONFIG_GLOBAL", if cfg!(unix) { "/dev/null" } else { "NUL" })
        .stdin(if stdin_bytes.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(bytes) = stdin_bytes
        && let Some(mut sin) = child.stdin.take()
    {
        use std::io::Write;
        sin.write_all(bytes)?;
    }
    let out = child.wait_with_output()?;
    ensure!(out.status.success(), "git {:?} failed: {}", args, String::from_utf8_lossy(&out.stderr));
    Ok(String::from_utf8(out.stdout)?.trim().to_owned())
}

struct SeedRepo {
    repo: PathBuf,
    packs: PathBuf,
    prev: String,
    step: usize,
}

impl SeedRepo {
    fn at(base: PathBuf, fmt: ObjectFormat) -> Result<Self> {
        let (repo, packs) = (base.join("seed"), base.join("packs"));
        fs::create_dir_all(&repo)?;
        fs::create_dir_all(&packs)?;
        git_run(&repo, &["init", &format!("--object-format={}", fmt.as_str()), "--initial-branch=main"], None)?;
        Ok(Self { repo, packs, prev: "0".repeat(fmt.oid_hex_len()), step: 0 })
    }

    fn next(&mut self, file: &str, bytes: &[u8]) -> Result<(String, String, PathBuf, PathBuf)> {
        self.step += 1;
        fs::write(self.repo.join(file), bytes)?;
        git_run(&self.repo, &["add", "."], None)?;
        git_run(&self.repo, &["commit", "-m", &format!("s{}", self.step)], None)?;
        let oid = git_run(&self.repo, &["rev-parse", "HEAD"], None)?;
        let range = if self.step == 1 { oid.clone() } else { format!("{}..{oid}", self.prev) };
        let oids: String = git_run(&self.repo, &["rev-list", "--objects", &range], None)?
            .lines()
            .filter_map(|l| l.split_whitespace().next())
            .map(|o| format!("{o}\n"))
            .collect();
        let sdir = self.packs.join(format!("s-{:03}", self.step));
        fs::create_dir_all(&sdir)?;
        git_run(
            &self.repo,
            &["-c", "pack.writeReverseIndex=false", "pack-objects", "-q", &sdir.join("inc").to_string_lossy()],
            Some(oids.as_bytes()),
        )?;
        let paths: Vec<_> = fs::read_dir(&sdir)?.filter_map(Result::ok).map(|e| e.path()).collect();
        let pack = paths.iter().find(|p| p.extension().and_then(|e| e.to_str()) == Some("pack")).unwrap().clone();
        let index = paths.iter().find(|p| p.extension().and_then(|e| e.to_str()) == Some("idx")).unwrap().clone();
        Ok((std::mem::replace(&mut self.prev, oid.clone()), oid, pack, index))
    }
}

fn push_with(
    op_id: Uuid,
    digest: &str,
    r: &str,
    old: &str,
    new: &str,
    packs: Vec<(PathBuf, PathBuf)>,
) -> IncrementalPushRequest {
    IncrementalPushRequest {
        operation_id: op_id,
        request_digest: digest.into(),
        caller_authorized: true,
        ref_mutations: vec![RefMutation { ref_name: r.into(), old_oid: old.into(), new_oid: new.into() }],
        new_pack_paths: packs,
        free_disk_bytes: 512 * 1024 * 1024,
        max_single_object_bytes: 1024 * 1024,
    }
}

fn push_req(r: &str, old: &str, new: &str, packs: Vec<(PathBuf, PathBuf)>) -> IncrementalPushRequest {
    push_with(Uuid::new_v4(), &Uuid::new_v4().to_string(), r, old, new, packs)
}

fn noisy_bytes(seed: usize, len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i.wrapping_mul(131) ^ seed.wrapping_mul(37) ^ (i >> 3)) & 0xff) as u8).collect()
}

fn pack_meta(pack: &Path, idx: &Path) -> Result<(String, u64, u64)> {
    let (sha, plen, objs) = inspect_pack_file(pack)?;
    Ok((sha, plen + hash_file_bounded(idx)?.1, objs))
}

fn seed_one(dir: &TempDir, tag: &str, file: &str, bytes: &[u8]) -> Result<(String, PathBuf, PathBuf)> {
    let (_, oid, p, i) = SeedRepo::at(dir.path().join(tag), ObjectFormat::Sha1)?.next(file, bytes)?;
    Ok((oid, p, i))
}

async fn await_gate(entered: &Notify) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(25), entered.notified()).await?;
    Ok(())
}

#[tokio::test]
async fn streaming_growth_beyond_16_packs_sha1_and_sha256_lifecycle() -> Result<()> {
    let (s3, dl) = (LoopbackS3::shared(), Instant::now() + Duration::from_secs(90));
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let dir = TempDir::new()?;
        let mut contract = PandoCapacityContract::current_standalone();
        contract.streaming.compact_trigger_packs = 10;
        let engine = open_engine(s3, &dir, contract, format, true)?;
        let (mut seeder, mut oids, z) =
            (SeedRepo::at(dir.path().join("grow"), format)?, Vec::new(), "0".repeat(format.oid_hex_len()));
        let (pin_id, root_id, backup_id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());

        for i in 1..=20usize {
            let (old, new, pp, ip) = seeder.next("h.txt", format!("step-{i}\n").as_bytes())?;
            oids.push(new.clone());
            let req = push_with(Uuid::new_v4(), &format!("d-{i}"), "refs/heads/main", &old, &new, vec![(pp, ip)]);
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
        let (bp, bi) = (dir.path().join("bad.pack"), dir.path().join("bad.idx"));
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
        assert!(engine.archive_released_ledger() > 0 && engine.snapshot().ledger.compacted_protected_memberships == 3);
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
        let mut seeder = SeedRepo::at(dir.path().join("seed"), ObjectFormat::Sha1)?;
        for s in 0..(if compact { 2 } else { 1 }) {
            let (old, new, pp, ip) = seeder.next("h.txt", format!("b-{s}\n").as_bytes())?;
            engine.apply_push(push_req("refs/heads/main", &old, &new, vec![(pp, ip)]), dl).await?;
        }
        let (before, bref, bpack) = (engine.snapshot(), engine.acked_refs(), engine.active_pack_locators());
        let err = if compact {
            engine.compact_serving_frontier(dl).await.unwrap_err()
        } else {
            let (old, new, pp, ip) = seeder.next("h.txt", b"b-fail\n")?;
            engine.apply_push(push_req("refs/heads/main", &old, &new, vec![(pp, ip)]), dl).await.unwrap_err()
        };
        assert!(
            matches!(err, GrowthEngineError::Ledger(LedgerRetentionError::LedgerBudgetExhausted { resource, .. }) if resource == expected)
        );
        assert_eq!(engine.archive_released_ledger(), 0);
        let s = engine.snapshot();
        assert_eq!(
            (s.epoch, s.closure_revision, s.active_frontier_len, s.ledger),
            (before.epoch, before.closure_revision, before.active_frontier_len, before.ledger)
        );
        assert_eq!((engine.acked_refs(), engine.active_pack_locators()), (bref, bpack));
        assert_eq!(s.failed_attempt_count, before.failed_attempt_count + 1);
        assert!(s.failed_attempt_blob_bytes > before.failed_attempt_blob_bytes);
    }
    Ok(())
}

#[tokio::test]
async fn concurrent_commit_rejects_window_overflow_and_compacted_base() -> Result<()> {
    let (dl, z) = (Instant::now() + Duration::from_secs(60), "0".repeat(40));
    for limit_objects in [false, true] {
        let (s3, dir) = (LoopbackS3::new_isolated(), TempDir::new()?);
        let (o0, p0, i0) = seed_one(&dir, "s0", "base.bin", &noisy_bytes(1, 256))?;
        let (oa, pa, ia) = seed_one(&dir, "sa", "a.bin", &noisy_bytes(2, 4096))?;
        let (ob, pb, ib) = seed_one(&dir, "sb", "b.bin", &noisy_bytes(3, 4096))?;
        let ((_, b0, o0_cnt), (pa_sha, ba, oa_cnt), (_, bb, ob_cnt)) =
            (pack_meta(&p0, &i0)?, pack_meta(&pa, &ia)?, pack_meta(&pb, &ib)?);
        let mut c = PandoCapacityContract::current_standalone();
        if limit_objects {
            c.verifier.max_objects_per_window = o0_cnt + oa_cnt.max(ob_cnt);
        } else {
            c.verifier.max_total_bytes_per_window = b0 + ba.max(bb) + 64;
        }
        let engine = open_engine(&s3, &dir, c, ObjectFormat::Sha1, false)?;
        engine.apply_push(push_req("refs/heads/base", &z, &o0, vec![(p0, i0)]), dl).await?;

        let (eng_a, req_a) = (Arc::clone(&engine), push_req("refs/heads/a", &z, &oa, vec![(pa, ia)]));
        let (entered, release, task_a) = s3.spawn_gated(&pa_sha, async move { eng_a.apply_push(req_a, dl).await });
        await_gate(&entered).await?;
        engine.apply_push(push_req("refs/heads/b", &z, &ob, vec![(pb, ib)]), dl).await?;
        release.notify_one();
        let err = task_a.await?.unwrap_err();
        match (limit_objects, &err) {
            (true, GrowthEngineError::Admission(AdmissionRejection::TooManyObjects { .. }))
            | (false, GrowthEngineError::Admission(AdmissionRejection::PackBytesExceeded { .. })) => {}
            _ => panic!("unexpected rejection: {err}"),
        }
        assert!(!engine.acked_refs().contains_key("refs/heads/a"));
        let s = engine.snapshot();
        assert_eq!((s.epoch, s.active_frontier_len, s.ledger.protected_registrations), (2, 2, 2));
    }

    let (s3, dir) = (LoopbackS3::new_isolated(), TempDir::new()?);
    let engine = open_engine(&s3, &dir, PandoCapacityContract::current_standalone(), ObjectFormat::Sha1, false)?;
    let (ok, pk, ik) = seed_one(&dir, "sk", "keep.txt", b"keep")?;
    let (op, pp, ip) = seed_one(&dir, "sp", "prune.txt", b"prune")?;
    let (pp_sha, _, _) = pack_meta(&pp, &ip)?;
    engine.apply_push(push_req("refs/heads/keep", &z, &ok, vec![(pk, ik)]), dl).await?;
    engine.apply_push(push_req("refs/heads/prune", &z, &op, vec![(pp, ip)]), dl).await?;
    let (eng_np, np) = (Arc::clone(&engine), push_req("refs/heads/release", &z, &op, vec![]));
    let (entered, release, task_np) = s3.spawn_gated(&pp_sha, async move { eng_np.apply_push(np, dl).await });
    await_gate(&entered).await?;
    engine.apply_push(push_req("refs/heads/prune", &op, &z, vec![]), dl).await?;
    engine.compact_serving_frontier(dl).await?;
    release.notify_one();
    assert!(matches!(task_np.await?.unwrap_err(), GrowthEngineError::CompactionConflict));
    assert!(!engine.acked_refs().contains_key("refs/heads/release"));
    assert_eq!(engine.verify_full_serving_closure(dl).await?, 1);
    Ok(())
}

#[tokio::test]
async fn compaction_barriers_pins_cancel_and_spoofed_object_bounds() -> Result<()> {
    let (s3, dir, dl, z) =
        (LoopbackS3::new_isolated(), TempDir::new()?, Instant::now() + Duration::from_secs(60), "0".repeat(40));
    let engine = open_engine(&s3, &dir, PandoCapacityContract::current_standalone(), ObjectFormat::Sha1, false)?;
    let (o1, p1, i1) = seed_one(&dir, "s1", "k.txt", b"main")?;
    let (o2, p2, i2) = seed_one(&dir, "s2", "r.txt", b"resurrect")?;
    let (o3, p3, i3) = seed_one(&dir, "s3", "p.txt", b"late-pin")?;
    let (p1_sha, p3_sha) = (pack_meta(&p1, &i1)?.0, pack_meta(&p3, &i3)?.0);

    let pin_err = engine.apply_push(push_req("refs/pando-pins/pin-0000", &z, &o1, vec![]), dl).await.unwrap_err();
    assert!(matches!(pin_err, GrowthEngineError::InvalidInput(_)));
    let op1 = Uuid::new_v4();
    let req1 = push_with(op1, "acked-op", "refs/heads/main", &z, &o1, vec![(p1, i1)]);
    engine.apply_push(req1.clone(), dl).await?;
    assert!(matches!(engine.cancel_operation(op1), Err(GrowthEngineError::InvalidInput(_))));
    assert!(engine.apply_push(req1, dl).await?.replayed);

    engine.apply_push(push_req("refs/heads/temp", &z, &o2, vec![(p2, i2)]), dl).await?;
    engine.apply_push(push_req("refs/heads/temp", &o2, &z, vec![]), dl).await?;
    let eng_c = Arc::clone(&engine);
    let (entered, release, task_c) = s3.spawn_gated(&p1_sha, async move { eng_c.compact_serving_frontier(dl).await });
    await_gate(&entered).await?;
    engine.apply_push(push_req("refs/heads/resurrect", &z, &o2, vec![]), dl).await?;
    release.notify_one();
    assert!(matches!(task_c.await?.unwrap_err(), GrowthEngineError::CompactionConflict));
    engine.compact_serving_frontier(dl).await?;
    assert_eq!(engine.verify_full_serving_closure(dl).await?, 2);

    engine.apply_push(push_req("refs/heads/pin-tmp", &z, &o3, vec![(p3, i3)]), dl).await?;
    engine.apply_push(push_req("refs/heads/pin-tmp", &o3, &z, vec![]), dl).await?;
    let eng_p = Arc::clone(&engine);
    let (entered, release, task_p) = s3.spawn_gated(&p3_sha, async move { eng_p.compact_serving_frontier(dl).await });
    await_gate(&entered).await?;
    engine.attach_hold(ProtectionHold::Pin { pin_id: Uuid::new_v4(), purpose: "late".into() }, Some(o3))?;
    release.notify_one();
    assert!(matches!(task_p.await?.unwrap_err(), GrowthEngineError::CompactionConflict));
    engine.compact_serving_frontier(dl).await?;
    assert_eq!(engine.verify_full_serving_closure(dl).await?, 3);

    let (dir2, mut c2) = (TempDir::new()?, PandoCapacityContract::current_standalone());
    c2.streaming.max_single_object_bytes = 1024;
    let eng2 = open_engine(&s3, &dir2, c2, ObjectFormat::Sha1, false)?;
    let (obig, pbig, ibig) = seed_one(&dir2, "big", "big.bin", &noisy_bytes(9, 2048))?;
    let mut spoof = push_req("refs/heads/main", &z, &obig, vec![(pbig, ibig)]);
    spoof.max_single_object_bytes = 64;
    let spoof_err = eng2.apply_push(spoof, dl).await.unwrap_err();
    assert!(matches!(spoof_err, GrowthEngineError::GitOps(GitOpsError::LimitExceeded(_))));

    let (o_fail, p_fail, i_fail) = seed_one(&dir2, "fail", "f.txt", b"fail")?;
    let (o_win, p_win, i_win) = seed_one(&dir2, "win", "w.txt", b"win")?;
    let (p_fail_sha, _, _) = pack_meta(&p_fail, &i_fail)?;
    let (eng_f, mut req_f) = (Arc::clone(&eng2), push_req("refs/heads/main", &z, &o_fail, vec![(p_fail, i_fail)]));
    let mut req_win = push_req("refs/heads/main", &z, &o_win, vec![(p_win, i_win)]);
    (req_f.max_single_object_bytes, req_win.max_single_object_bytes) = (512, 512);
    let (entered, release, task_f) = s3.spawn_gated(&p_fail_sha, async move { eng_f.apply_push(req_f, dl).await });
    await_gate(&entered).await?;
    eng2.apply_push(req_win, dl).await?;
    release.notify_one();
    assert!(matches!(task_f.await?.unwrap_err(), GrowthEngineError::CasPreconditionFailed { .. }));
    let snap = eng2.snapshot();
    assert_eq!((snap.failed_attempt_count, eng2.failed_attempt_pack_locators().len()), (2, 2));
    assert!(snap.failed_attempt_blob_bytes > 0 && eng2.failed_attempt_pack_locators().iter().all(|l| s3.exists(l)));
    assert_eq!(eng2.acked_refs().get("refs/heads/main"), Some(&o_win));
    Ok(())
}
