//! Real OpenDAL S3 + stock Git (SHA-1 & SHA-256) capacity integration tests (#177).

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Result, ensure};
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Method, Uri},
    response::Response,
};
use bytes::Bytes;
use rootyard::blob_store::{
    BlobLocator, capacity_contract::*, disposable_view::DisposableViewRoot, opendal::BlobStore,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::sync::Notify;
use uuid::Uuid;

type Packs = Vec<(PathBuf, PathBuf)>;
type Gate = (String, Arc<Notify>, Arc<Notify>);
type Cfg = PandoCapacityContract;

#[derive(Default)]
struct S3State {
    objects: Mutex<BTreeMap<String, Vec<u8>>>,
    gate: Mutex<Option<Gate>>,
    fail_put: Mutex<Option<String>>,
}
struct LoopbackS3 {
    endpoint: String,
    state: Arc<S3State>,
}
static ENV_LOCK: Mutex<()> = Mutex::new(());

impl LoopbackS3 {
    fn new() -> Self {
        let (st, lis) = (Arc::new(S3State::default()), std::net::TcpListener::bind("127.0.0.1:0").unwrap());
        lis.set_nonblocking(true).unwrap();
        let (port, srv, (tx, rx)) =
            (lis.local_addr().unwrap().port(), Arc::clone(&st), std::sync::mpsc::sync_channel(1));
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async move {
                let l = tokio::net::TcpListener::from_std(lis).unwrap();
                let _ = tx.send(());
                let _ = axum::serve(l, Router::new().fallback(handle_s3).with_state(srv)).await;
            });
        });
        rx.recv().unwrap();
        Self { endpoint: format!("http://127.0.0.1:{port}"), state: st }
    }

    async fn race<T: Send + 'static, M, E: Into<anyhow::Error>>(
        &self,
        sub: &str,
        bg: impl std::future::Future<Output = T> + Send + 'static,
        mid: impl std::future::Future<Output = std::result::Result<M, E>>,
    ) -> Result<T> {
        let (entered, release) = (Arc::new(Notify::new()), Arc::new(Notify::new()));
        *self.state.gate.lock().unwrap() = Some((sub.into(), Arc::clone(&entered), Arc::clone(&release)));
        let task = tokio::spawn(bg);
        tokio::time::timeout(Duration::from_secs(25), entered.notified()).await?;
        let r = mid.await;
        release.notify_one();
        r.map_err(Into::into)?;
        Ok(task.await?)
    }

    fn arm_fail_next_put(&self, sub: &str) {
        *self.state.fail_put.lock().unwrap() = Some(sub.into());
    }

    fn open_store(&self) -> Result<BlobStore> {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let spec = "DRIVER=opendal SERVICE=s3 BUCKET=pando-cap-bucket REGION=us-east-1 ROOT=pando-cap-it ACCESS_KEY_ID=test-ak SECRET_ACCESS_KEY=test-sk ENCRYPTION_MODE=provider-managed RETRY_MAX_TIMES=0 MAX_OBJECT_BYTES=67108864";
        let mut saved = vec![("ROOTYARD_BLOB_KEYRING_DIR".into(), std::env::var_os("ROOTYARD_BLOB_KEYRING_DIR"))];
        unsafe { std::env::remove_var("ROOTYARD_BLOB_KEYRING_DIR") };
        for kv in spec.split(' ').chain([&*format!("ENDPOINT={}", self.endpoint)]) {
            let (k, v) = kv.split_once('=').unwrap();
            let ek = format!("ROOTYARD_BLOB_{k}");
            saved.push((ek.clone(), std::env::var_os(&ek)));
            unsafe { std::env::set_var(&ek, v) };
        }
        let res = BlobStore::open(rootyard::blob_store::config::BlobProfile::from_env()?);
        for (k, old) in saved {
            unsafe { if let Some(v) = old { std::env::set_var(&k, v) } else { std::env::remove_var(&k) } }
        }
        Ok(res?)
    }

    fn exists(&self, loc: &BlobLocator) -> bool {
        self.state.objects.lock().unwrap().contains_key(&format!("pando-cap-bucket/pando-cap-it/{}", loc.path()))
    }
}

async fn handle_s3(State(st): State<Arc<S3State>>, method: Method, uri: Uri, body: Bytes) -> Response {
    let key = uri.path().trim_start_matches('/').to_owned();
    if !key.contains('/') {
        return Response::new(Body::from("<ListBucketResult/>"));
    }
    if method == Method::GET {
        let hit = st.gate.lock().unwrap().take_if(|g| key.contains(&g.0));
        if let Some((_, entered, release)) = hit {
            entered.notify_one();
            release.notified().await;
        }
    }
    let ok = |b: &[u8], body: Body| -> Response {
        let tag = format!("\"{}\"", &hex::encode(Sha256::digest(b))[..32]);
        Response::builder().status(200u16).header("etag", tag).header("content-length", b.len()).body(body).unwrap()
    };
    match method {
        Method::PUT => {
            if st.fail_put.lock().unwrap().take_if(|s| key.contains(s.as_str())).is_some() {
                return Response::builder().status(500u16).body(Body::empty()).unwrap();
            }
            let r = ok(body.as_ref(), Body::empty());
            st.objects.lock().unwrap().insert(key, body.to_vec());
            r
        }
        Method::HEAD | Method::GET => match st.objects.lock().unwrap().get(&key).cloned() {
            Some(d) => ok(&d.clone(), if method == Method::HEAD { Body::empty() } else { Body::from(d) }),
            None => Response::builder().status(404u16).body(Body::empty()).unwrap(),
        },
        _ => Response::builder().status(405u16).body(Body::empty()).unwrap(),
    }
}

fn open_eng(s3: &LoopbackS3, dir: &TempDir, c: Cfg, fmt: ObjectFormat, ac: bool) -> Result<Arc<StreamingGrowthEngine>> {
    let views = dir.path().join("views");
    let mut b = fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(&views)?;
    let vr = DisposableViewRoot::open(&views, 4, 256 * 1024 * 1024, Duration::from_secs(120))?;
    let u = Uuid::new_v4;
    let sc = EngineScope { tenant_id: u(), repo_id: u(), authority_id: u(), object_format: fmt, auto_compact: ac };
    Ok(Arc::new(StreamingGrowthEngine::new(c, s3.open_store()?, vr, sc)?))
}

fn git_run(repo: &Path, args: &[&str], stdin: &[u8]) -> Result<String> {
    use std::process::{Command, Stdio};
    let mut cmd = Command::new("git");
    cmd.args(["-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "--no-replace-objects", "-C"])
        .arg(repo)
        .args(args);
    for kv in "GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0 GIT_AUTHOR_NAME=ry GIT_AUTHOR_EMAIL=ry@ex GIT_COMMITTER_NAME=ry GIT_COMMITTER_EMAIL=ry@ex".split(' ') {
        let (k, v) = kv.split_once('=').unwrap();
        cmd.env(k, v);
    }
    cmd.env("GIT_CONFIG_GLOBAL", if cfg!(unix) { "/dev/null" } else { "NUL" });
    if !stdin.is_empty() {
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    }
    let out = if stdin.is_empty() {
        cmd.output()?
    } else {
        let mut ch = cmd.spawn()?;
        std::io::Write::write_all(&mut ch.stdin.take().unwrap(), stdin)?;
        ch.wait_with_output()?
    };
    ensure!(out.status.success(), "git {:?} failed: {}", args, String::from_utf8_lossy(&out.stderr));
    Ok(String::from_utf8(out.stdout)?.trim().to_owned())
}

struct SeedRepo {
    repo: PathBuf,
    prev: String,
    step: usize,
}
impl SeedRepo {
    fn at(base: PathBuf, fmt: ObjectFormat) -> Result<Self> {
        let repo = base.join("seed");
        fs::create_dir_all(&repo)?;
        git_run(&repo, &["init", &format!("--object-format={}", fmt.as_str()), "--initial-branch=main"], &[])?;
        Ok(Self { repo, prev: "0".repeat(fmt.oid_hex_len()), step: 0 })
    }

    fn next(&mut self, file: &str, bytes: &[u8]) -> Result<(String, String, PathBuf, PathBuf)> {
        self.step += 1;
        fs::write(self.repo.join(file), bytes)?;
        let git = |a: &[&str], sin: &[u8]| git_run(&self.repo, a, sin);
        git(&["add", "."], &[])?;
        git(&["commit", "-m", &format!("s{}", self.step)], &[])?;
        let oid = git(&["rev-parse", "HEAD"], &[])?;
        let range = if self.step == 1 { oid.clone() } else { format!("{}..{oid}", self.prev) };
        let rl = git(&["rev-list", "--objects", &range], &[])?;
        let oids: String = rl.lines().filter_map(|l| l.split(' ').next()).map(|o| format!("{o}\n")).collect();
        let sdir = self.repo.with_file_name(format!("p-{:03}", self.step));
        fs::create_dir_all(&sdir)?;
        let pfx = sdir.join("inc").to_string_lossy().into_owned();
        git(&["-c", "pack.writeReverseIndex=false", "pack-objects", "-q", &pfx], oids.as_bytes())?;
        let ps: Vec<_> = fs::read_dir(&sdir)?.filter_map(Result::ok).map(|e| e.path()).collect();
        let pick = |ext| ps.iter().find(|p| p.extension() == Some(std::ffi::OsStr::new(ext))).unwrap().clone();
        Ok((std::mem::replace(&mut self.prev, oid.clone()), oid, pick("pack"), pick("idx")))
    }
}

fn push_with(op: Uuid, d: &str, r: &str, o: &str, n: &str, p: Packs) -> IncrementalPushRequest {
    IncrementalPushRequest {
        operation_id: op,
        request_digest: d.into(),
        caller_authorized: true,
        ref_mutations: vec![RefMutation { ref_name: r.into(), old_oid: o.into(), new_oid: n.into() }],
        new_pack_paths: p,
        free_disk_bytes: 512 * 1024 * 1024,
        max_single_object_bytes: 1024 * 1024,
    }
}
fn push_req(r: &str, o: &str, n: &str, p: Packs) -> IncrementalPushRequest {
    push_with(Uuid::new_v4(), &Uuid::new_v4().to_string(), r, o, n, p)
}
fn noisy(seed: usize, len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i.wrapping_mul(131) ^ seed.wrapping_mul(37) ^ (i >> 3)) & 0xff) as u8).collect()
}
fn pack_meta(p: &Path, i: &Path) -> Result<(String, u64, u64)> {
    let (s, l, o) = git_ops::inspect_pack_file(p)?;
    Ok((s, l + git_ops::hash_file_bounded(i)?.1, o))
}
fn seed_one(dir: &TempDir, tag: &str, file: &str, b: &[u8]) -> Result<(String, PathBuf, PathBuf)> {
    let (_, o, p, i) = SeedRepo::at(dir.path().join(tag), ObjectFormat::Sha1)?.next(file, b)?;
    Ok((o, p, i))
}
fn err_budget<T: std::fmt::Debug>(r: std::result::Result<T, GrowthEngineError>, want: &str) {
    assert!(
        matches!(r, Err(GrowthEngineError::Ledger(LedgerRetentionError::LedgerBudgetExhausted { resource, .. })) if resource == want),
        "{r:?}"
    );
}
fn err_invalid<T: std::fmt::Debug>(r: std::result::Result<T, GrowthEngineError>) {
    assert!(matches!(r, Err(GrowthEngineError::InvalidInput(_))), "{r:?}");
}
fn pin_hold(p: &str) -> ProtectionHold {
    ProtectionHold::Pin { pin_id: Uuid::new_v4(), purpose: p.into() }
}

#[tokio::test]
async fn streaming_growth_beyond_16_packs_sha1_and_sha256_lifecycle() -> Result<()> {
    let (s3, dl) = (LoopbackS3::new(), Instant::now() + Duration::from_secs(90));
    for fmt in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let dir = TempDir::new()?;
        let mut c = PandoCapacityContract::current_standalone();
        c.streaming.compact_trigger_packs = 10;
        let eng = open_eng(&s3, &dir, c, fmt, true)?;
        let (mut sr, mut oids, z) =
            (SeedRepo::at(dir.path().join("grow"), fmt)?, Vec::new(), "0".repeat(fmt.oid_hex_len()));
        let (pin_id, root_id, backup_id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());

        for i in 1..=20usize {
            let (old, new, pp, ip) = sr.next("h.txt", format!("step-{i}\n").as_bytes())?;
            oids.push(new.clone());
            let req = push_with(Uuid::new_v4(), &format!("d-{i}"), "refs/heads/main", &old, &new, vec![(pp, ip)]);
            let out = eng.apply_push(req.clone(), dl).await?;
            assert_eq!((out.added_packs, out.no_new_pack, out.replayed), (1, false, false));
            if i == 3 {
                eng.attach_hold(ProtectionHold::Pin { pin_id, purpose: "ci".into() }, Some(oids[2].clone()))?;
                eng.attach_hold(ProtectionHold::RetentionRoot { root_id, kind: "pitr".into() }, None)?;
                eng.attach_hold(ProtectionHold::BackupManifest { backup_id }, None)?;
                assert!(eng.apply_push(req.clone(), dl).await?.replayed);
                let mut bad = req;
                bad.request_digest = "tampered".into();
                assert!(matches!(eng.apply_push(bad, dl).await, Err(GrowthEngineError::DigestConflict(_))));
            }
            if i == 5 {
                assert!(eng.apply_push(push_req("refs/heads/release", &z, &oids[1], vec![]), dl).await?.no_new_pack);
                let cid = Uuid::new_v4();
                eng.cancel_operation(cid)?;
                let c = push_with(cid, "cancel", "refs/heads/never", &z, &oids[1], vec![]);
                assert!(matches!(eng.apply_push(c, dl).await, Err(GrowthEngineError::OperationCancelled(_))));
                assert!(!eng.acked_refs().contains_key("refs/heads/never"));
            }
        }
        let (bp, bi) = (dir.path().join("bad.pack"), dir.path().join("bad.idx"));
        fs::write(&bp, b"NOT_A_VALID_PACK")?;
        fs::write(&bi, b"NOT_A_VALID_IDX")?;
        assert!(eng.apply_push(push_req("refs/heads/broken", &z, &oids[0], vec![(bp, bi)]), dl).await.is_err());
        assert!(
            eng.apply_push(push_req("refs/heads/broken", &z, &"f".repeat(fmt.oid_hex_len()), vec![]), dl)
                .await
                .is_err()
        );
        assert!(!eng.acked_refs().contains_key("refs/heads/broken"));

        let s = eng.snapshot();
        assert_eq!((s.cumulative_packs_added, s.no_new_pack_pushes), (20, 1));
        assert!(s.compactions_completed >= 1 && s.active_frontier_len <= 16);
        assert!(s.historical_retained_pack_bytes > 0 && s.ledger.compacted_protected_memberships == 3);
        assert!(eng.archive_released_ledger() > 0 && eng.snapshot().ledger.compacted_protected_memberships == 3);
        assert!(eng.retained_pack_locators().iter().all(|l| s3.exists(l)));
        assert!(eng.verify_full_serving_closure(dl).await? >= 3);
        for id in [pin_id, root_id, backup_id] {
            eng.release_hold(id)?;
        }
        assert_eq!(eng.snapshot().ledger.compacted_protected_memberships, 0);
        assert!(eng.archive_released_ledger() > 0 && eng.snapshot().ledger.archived_memberships >= 20);
    }
    Ok(())
}

#[tokio::test]
async fn compaction_and_push_budget_failures_preserve_ledger_and_frontier() -> Result<()> {
    let (s3, dl) = (LoopbackS3::new(), Instant::now() + Duration::from_secs(60));
    for (regs, rcpts, bytes, expected, compact) in [
        (2, 16, 8 * 1024 * 1024, "registrations", true),
        (16, 16, 4608, "logical_bytes", true),
        (16, 1, 8 * 1024 * 1024, "receipts", false),
        (1, 16, 8 * 1024 * 1024, "registrations", false),
    ] {
        let dir = TempDir::new()?;
        let mut c = PandoCapacityContract::current_standalone();
        (
            c.metadata_ledger.repo_max_registrations,
            c.metadata_ledger.repo_max_receipts,
            c.metadata_ledger.repo_max_logical_bytes,
        ) = (regs, rcpts, bytes);
        let eng = open_eng(&s3, &dir, c, ObjectFormat::Sha1, false)?;
        let mut sr = SeedRepo::at(dir.path().join("seed"), ObjectFormat::Sha1)?;
        for s in 0..(if compact { 2 } else { 1 }) {
            let (old, new, pp, ip) = sr.next("h.txt", format!("b-{s}\n").as_bytes())?;
            eng.apply_push(push_req("refs/heads/main", &old, &new, vec![(pp, ip)]), dl).await?;
        }
        let (before, bref, bpack) = (eng.snapshot(), eng.acked_refs(), eng.active_pack_locators());
        let err = if compact {
            eng.compact_serving_frontier(dl).await.unwrap_err()
        } else {
            let (old, new, pp, ip) = sr.next("h.txt", b"b-fail\n")?;
            eng.apply_push(push_req("refs/heads/main", &old, &new, vec![(pp, ip)]), dl).await.unwrap_err()
        };
        err_budget(Err::<(), _>(err), expected);
        assert_eq!(eng.archive_released_ledger(), 0);
        let s = eng.snapshot();
        assert_eq!(
            (s.epoch, s.closure_revision, s.active_frontier_len, s.ledger),
            (before.epoch, before.closure_revision, before.active_frontier_len, before.ledger)
        );
        assert_eq!((eng.acked_refs(), eng.active_pack_locators()), (bref, bpack));
        assert_eq!(s.failed_attempt_count, before.failed_attempt_count + 1);
        assert!(s.failed_attempt_blob_bytes > before.failed_attempt_blob_bytes);
    }
    Ok(())
}

#[tokio::test]
async fn concurrent_commit_rejects_window_overflow_and_compacted_base() -> Result<()> {
    let (dl, z, pr) = (Instant::now() + Duration::from_secs(60), "0".repeat(40), push_req);
    for limit_objs in [false, true] {
        let (s3, dir) = (LoopbackS3::new(), TempDir::new()?);
        let (o0, p0, i0) = seed_one(&dir, "s0", "base.bin", &noisy(1, 256))?;
        let (oa, pa, ia) = seed_one(&dir, "sa", "a.bin", &noisy(2, 4096))?;
        let (ob, pb, ib) = seed_one(&dir, "sb", "b.bin", &noisy(3, 4096))?;
        let ((_, b0, o0c), (pa_sha, ba, oac), (_, bb, obc)) =
            (pack_meta(&p0, &i0)?, pack_meta(&pa, &ia)?, pack_meta(&pb, &ib)?);
        let mut c = PandoCapacityContract::current_standalone();
        if limit_objs {
            c.verifier.max_objects_per_window = o0c + oac.max(obc);
        } else {
            c.verifier.max_total_bytes_per_window = b0 + ba.max(bb) + 64;
        }
        let eng = open_eng(&s3, &dir, c, ObjectFormat::Sha1, false)?;
        eng.apply_push(pr("refs/heads/base", &z, &o0, vec![(p0, i0)]), dl).await?;
        let ea = Arc::clone(&eng);
        let req_a = pr("refs/heads/a", &z, &oa, vec![(pa, ia)]);
        let req_b = pr("refs/heads/b", &z, &ob, vec![(pb, ib)]);
        let err = s3
            .race(&pa_sha, async move { ea.apply_push(req_a, dl).await }, eng.apply_push(req_b, dl))
            .await?
            .unwrap_err();
        match (limit_objs, &err) {
            (true, GrowthEngineError::Admission(AdmissionRejection::TooManyObjects { .. }))
            | (false, GrowthEngineError::Admission(AdmissionRejection::PackBytesExceeded { .. })) => {}
            _ => panic!("unexpected rejection: {err}"),
        }
        assert!(!eng.acked_refs().contains_key("refs/heads/a"));
        let s = eng.snapshot();
        assert_eq!((s.epoch, s.active_frontier_len, s.ledger.protected_registrations), (2, 2, 2));
    }

    let (s3, dir) = (LoopbackS3::new(), TempDir::new()?);
    let eng = open_eng(&s3, &dir, PandoCapacityContract::current_standalone(), ObjectFormat::Sha1, false)?;
    let ((ok, pk, ik), (op, pp, ip)) =
        (seed_one(&dir, "sk", "k.txt", b"keep")?, seed_one(&dir, "sp", "p.txt", b"prune")?);
    let pp_sha = pack_meta(&pp, &ip)?.0;
    eng.apply_push(pr("refs/heads/keep", &z, &ok, vec![(pk, ik)]), dl).await?;
    eng.apply_push(pr("refs/heads/prune", &z, &op, vec![(pp, ip)]), dl).await?;
    let enp = Arc::clone(&eng);
    let rel = pr("refs/heads/release", &z, &op, vec![]);
    let r = s3
        .race(&pp_sha, async move { enp.apply_push(rel, dl).await }, async {
            eng.apply_push(pr("refs/heads/prune", &op, &z, vec![]), dl).await?;
            eng.compact_serving_frontier(dl).await?;
            Ok::<_, anyhow::Error>(())
        })
        .await?;
    assert!(matches!(r, Err(GrowthEngineError::CompactionConflict)));
    assert!(!eng.acked_refs().contains_key("refs/heads/release"));
    assert_eq!(eng.verify_full_serving_closure(dl).await?, 1);
    Ok(())
}

#[tokio::test]
async fn compaction_barriers_pins_cancel_spoof_and_tight_caps() -> Result<()> {
    let (s3, dir, dl, z, pr) =
        (LoopbackS3::new(), TempDir::new()?, Instant::now() + Duration::from_secs(60), "0".repeat(40), push_req);
    let eng = open_eng(&s3, &dir, PandoCapacityContract::current_standalone(), ObjectFormat::Sha1, false)?;
    let ((o1, p1, i1), (o2, p2, i2), (o3, p3, i3)) = (
        seed_one(&dir, "s1", "k.txt", b"main")?,
        seed_one(&dir, "s2", "r.txt", b"resurrect")?,
        seed_one(&dir, "s3", "p.txt", b"late-pin")?,
    );
    let (p1_sha, p3_sha) = (pack_meta(&p1, &i1)?.0, pack_meta(&p3, &i3)?.0);

    err_invalid(eng.apply_push(pr("refs/pando-pins/pin-0000", &z, &o1, vec![]), dl).await);
    let op1 = Uuid::new_v4();
    let req1 = push_with(op1, "acked-op", "refs/heads/main", &z, &o1, vec![(p1, i1)]);
    eng.apply_push(req1.clone(), dl).await?;
    err_invalid(eng.cancel_operation(op1));
    assert!(eng.apply_push(req1, dl).await?.replayed);

    eng.apply_push(pr("refs/heads/temp", &z, &o2, vec![(p2, i2)]), dl).await?;
    eng.apply_push(pr("refs/heads/temp", &o2, &z, vec![]), dl).await?;
    let ec = Arc::clone(&eng);
    let mid_res = eng.apply_push(pr("refs/heads/resurrect", &z, &o2, vec![]), dl);
    let rc = s3.race(&p1_sha, async move { ec.compact_serving_frontier(dl).await }, mid_res).await?;
    assert!(matches!(rc, Err(GrowthEngineError::CompactionConflict)));
    eng.compact_serving_frontier(dl).await?;
    assert_eq!(eng.verify_full_serving_closure(dl).await?, 2);

    eng.apply_push(pr("refs/heads/pin-tmp", &z, &o3, vec![(p3, i3)]), dl).await?;
    eng.apply_push(pr("refs/heads/pin-tmp", &o3, &z, vec![]), dl).await?;
    let (ep, late) = (Arc::clone(&eng), async { eng.attach_hold(pin_hold("late"), Some(o3)) });
    let rp = s3.race(&p3_sha, async move { ep.compact_serving_frontier(dl).await }, late).await?;
    assert!(matches!(rp, Err(GrowthEngineError::CompactionConflict)));
    eng.compact_serving_frontier(dl).await?;
    assert_eq!(eng.verify_full_serving_closure(dl).await?, 3);

    let (dir2, mut c2) = (TempDir::new()?, PandoCapacityContract::current_standalone());
    c2.streaming.max_single_object_bytes = 1024;
    let eng2 = open_eng(&s3, &dir2, c2, ObjectFormat::Sha1, false)?;
    let (obig, pbig, ibig) = seed_one(&dir2, "big", "big.bin", &noisy(9, 2048))?;
    let mut spoof = pr("refs/heads/main", &z, &obig, vec![(pbig, ibig)]);
    spoof.max_single_object_bytes = 64;
    assert!(matches!(eng2.apply_push(spoof, dl).await, Err(GrowthEngineError::GitOps(GitOpsError::LimitExceeded(_)))));

    let (o_fail, p_fail, i_fail) = seed_one(&dir2, "fail", "f.txt", b"fail")?;
    let (o_win, p_win, i_win) = seed_one(&dir2, "win", "w.txt", b"win")?;
    let p_fail_sha = pack_meta(&p_fail, &i_fail)?.0;
    let mut rf = pr("refs/heads/main", &z, &o_fail, vec![(p_fail, i_fail)]);
    let mut rw = pr("refs/heads/main", &z, &o_win, vec![(p_win, i_win)]);
    (rf.max_single_object_bytes, rw.max_single_object_bytes) = (512, 512);
    let ef = Arc::clone(&eng2);
    let rf_res = s3.race(&p_fail_sha, async move { ef.apply_push(rf, dl).await }, eng2.apply_push(rw, dl)).await?;
    assert!(matches!(rf_res, Err(GrowthEngineError::CasPreconditionFailed { .. })));
    let (s2, l2) = (eng2.snapshot(), eng2.failed_attempt_pack_locators());
    assert_eq!((s2.failed_attempt_count, l2.len()), (2, 2));
    assert!(s2.failed_attempt_blob_bytes > 0 && l2.iter().all(|l| s3.exists(l)));
    assert_eq!(eng2.acked_refs().get("refs/heads/main"), Some(&o_win));

    let (o_idx, p_idx, i_idx) = seed_one(&dir2, "idx", "idx.txt", b"idx-fail")?;
    let idx_pack_len = fs::metadata(&p_idx)?.len();
    s3.arm_fail_next_put("/pack-idx/");
    assert!(eng2.apply_push(pr("refs/heads/idx-fail", &z, &o_idx, vec![(p_idx, i_idx)]), dl).await.is_err());
    let (a, locs) = (eng2.snapshot(), eng2.failed_attempt_pack_locators());
    assert_eq!((a.failed_attempt_count, locs.len()), (3, 3));
    assert_eq!(a.failed_attempt_blob_bytes, s2.failed_attempt_blob_bytes + idx_pack_len);
    assert!(s3.exists(&locs[2]));

    let (dir3, mut c3) = (TempDir::new()?, PandoCapacityContract::current_standalone());
    let mut sr = SeedRepo::at(dir3.path().join("seed"), ObjectFormat::Sha1)?;
    let ((_, o1, p1, i1), (_, o2, p2, i2)) = (sr.next("a.txt", b"a1")?, sr.next("b.txt", b"b2")?);
    (c3.metadata_ledger.max_capture_refs, c3.metadata_ledger.repo_max_holds) = (1, 1);
    let st = &mut c3.streaming;
    (st.max_retained_pack_records, st.max_resident_replay_ops, st.max_resident_op_fences) = (2, 1, 4);
    let eng3 = open_eng(&s3, &dir3, c3, ObjectFormat::Sha1, false)?;
    let op3 = Uuid::new_v4();
    let r3 = push_with(op3, "op3", "refs/heads/main", &z, &o1, vec![(p1, i1)]);
    eng3.apply_push(r3.clone(), dl).await?;
    err_budget(eng3.apply_push(pr("refs/heads/extra", &z, &o1, vec![]), dl).await, "acked_refs");
    eng3.apply_push(pr("refs/heads/main", &o1, &z, vec![]), dl).await?;
    err_invalid(eng3.cancel_operation(op3));
    err_invalid(eng3.apply_push(r3, dl).await);
    eng3.attach_hold(pin_hold("p1"), Some(o1.clone()))?;
    err_budget(eng3.attach_hold(pin_hold("p2"), Some(o1)), "pins");
    let p2_bytes = fs::metadata(&p2)?.len();
    s3.arm_fail_next_put("/pack-idx/");
    assert!(eng3.apply_push(pr("refs/heads/main", &z, &o2, vec![(p2.clone(), i2.clone())]), dl).await.is_err());
    assert_eq!(eng3.snapshot().failed_attempt_blob_bytes, p2_bytes);
    assert!(eng3.failed_attempt_pack_locators().len() == 1 && s3.exists(&eng3.failed_attempt_pack_locators()[0]));
    err_budget(eng3.apply_push(pr("refs/heads/main", &z, &o2, vec![(p2, i2)]), dl).await, "retained_packs");
    assert_eq!((eng3.failed_attempt_pack_locators().len(), eng3.snapshot().failed_attempt_count), (1, 1));
    Ok(())
}
