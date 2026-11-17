//! Real OpenDAL S3 + stock Git (`SHA-1` & `SHA-256`) integration, fault, and concurrency tests (#162).

use std::{
    collections::BTreeMap,
    io::Write,
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
use rootyard::{
    blob_store::{config::BlobProfile, disposable_view::DisposableViewRoot, opendal::BlobStore, read_accel::*, *},
    storage_lifecycle::rubicon_compaction::{lease::BoxFuture, *},
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::sync::Semaphore;
use uuid::Uuid;

type S3Objects = Arc<Mutex<BTreeMap<String, Vec<u8>>>>;

struct LoopbackS3 {
    endpoint: String,
    objects: S3Objects,
}

static SHARED_S3: OnceLock<LoopbackS3> = OnceLock::new();
static ENV_LOCK: Mutex<()> = Mutex::new(());

impl LoopbackS3 {
    fn shared() -> &'static Self {
        SHARED_S3.get_or_init(|| {
            let objects = Arc::new(Mutex::new(BTreeMap::new()));
            let state = Arc::clone(&objects);
            let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind s3");
            l.set_nonblocking(true).expect("nonblocking");
            let port = l.local_addr().expect("addr").port();
            let (tx, rx) = std::sync::mpsc::sync_channel(1);
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
                rt.block_on(async move {
                    let tl = tokio::net::TcpListener::from_std(l).unwrap();
                    let _ = tx.send(());
                    let _ = axum::serve(tl, Router::new().fallback(handle_s3).with_state(state)).await;
                });
            });
            rx.recv().unwrap();
            Self { endpoint: format!("http://127.0.0.1:{port}"), objects }
        })
    }

    fn key(loc: &BlobLocator) -> String {
        format!("compaction-test-bucket/compaction-it/{}", loc.path())
    }

    fn open_store(&self) -> Result<BlobStore> {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let ep = self.endpoint.as_str();
        let spec = "DRIVER=opendal SERVICE=s3 BUCKET=compaction-test-bucket REGION=us-east-1 ROOT=compaction-it ACCESS_KEY_ID=test-ak SECRET_ACCESS_KEY=test-sk ENCRYPTION_MODE=provider-managed RETRY_MAX_TIMES=0 MAX_OBJECT_BYTES=8388608";
        let mut pairs: Vec<(String, Option<std::ffi::OsString>)> = spec
            .split(' ')
            .map(|s| s.split_once('=').unwrap())
            .map(|(k, v)| (format!("ROOTYARD_BLOB_{k}"), Some(v.into())))
            .collect();
        pairs.extend([("ROOTYARD_BLOB_ENDPOINT".into(), Some(ep.into())), ("ROOTYARD_BLOB_KEYRING_DIR".into(), None)]);
        let saved: Vec<_> = pairs.iter().map(|(k, _)| (k.clone(), std::env::var_os(k))).collect();
        let apply = |items: &[(String, Option<std::ffi::OsString>)]| {
            // SAFETY: serialized via ENV_LOCK across tests in this integration binary.
            unsafe {
                items
                    .iter()
                    .for_each(|(k, v)| if let Some(x) = v { std::env::set_var(k, x) } else { std::env::remove_var(k) });
            }
        };
        apply(&pairs);
        let res = BlobStore::open(BlobProfile::from_env()?);
        apply(&saved);
        Ok(res?)
    }

    fn put_raw(&self, loc: &BlobLocator, data: Vec<u8>) {
        self.objects.lock().unwrap().insert(Self::key(loc), data);
    }

    fn has_key(&self, loc: &BlobLocator) -> bool {
        self.objects.lock().unwrap().contains_key(&Self::key(loc))
    }
}

async fn handle_s3(State(objs): State<S3Objects>, m: Method, u: Uri, b: Bytes) -> Response {
    let key = u.path().trim_start_matches('/').to_owned();
    if !key.contains('/') {
        return Response::new(Body::from("<ListBucketResult/>"));
    }
    let etag = |d: &[u8]| format!("\"{}\"", &hex::encode(Sha256::digest(d))[..32]);
    let (st, tag, len, body) = match m {
        Method::PUT => {
            let tag = etag(&b);
            objs.lock().unwrap().insert(key, b.to_vec());
            (StatusCode::OK, Some(tag), 0, Body::empty())
        }
        Method::HEAD | Method::GET => match objs.lock().unwrap().get(&key).cloned() {
            Some(d) => {
                (StatusCode::OK, Some(etag(&d)), d.len(), if m == Method::HEAD { Body::empty() } else { Body::from(d) })
            }
            None => (StatusCode::NOT_FOUND, None, 0, Body::empty()),
        },
        _ => (StatusCode::METHOD_NOT_ALLOWED, None, 0, Body::empty()),
    };
    let mut rb = Response::builder().status(st).header(header::CONTENT_LENGTH, len.to_string());
    if let Some(t) = tag {
        rb = rb.header(header::ETAG, t);
    }
    rb.body(body).unwrap()
}

fn put_s3_blob(ids: (Uuid, Uuid, i64), path: &Path, flip: bool) -> Result<BlobLocator, CompactionError> {
    let mut bytes = std::fs::read(path).map_err(|e| CompactionError::Io(e.to_string()))?;
    let sha = hex::encode(Sha256::digest(&bytes));
    let loc = BlobLocator::new(
        ids.0,
        ids.1,
        ids.2,
        Uuid::new_v4(),
        DEFAULT_COMPACTED_PACK_NAMESPACE,
        &sha,
        bytes.len() as u64,
    )?;
    if flip && !bytes.is_empty() {
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xff;
    }
    LoopbackS3::shared().put_raw(&loc, bytes);
    Ok(loc)
}

#[derive(Default)]
struct TestS3Uploader {
    corrupt: bool,
}

impl CompactionBlobUploader for TestS3Uploader {
    fn upload_pack_pair<'a>(
        &'a self,
        _s: &'a BlobStore,
        tenant: Uuid,
        repo: Uuid,
        blob_gen: i64,
        pack: &'a Path,
        idx: &'a Path,
        _dl: Instant,
    ) -> BoxFuture<'a, UploadedPackPair> {
        Box::pin(async move {
            Ok(UploadedPackPair {
                pack_locator: put_s3_blob((tenant, repo, blob_gen), pack, self.corrupt)?,
                idx_locator: put_s3_blob((tenant, repo, blob_gen), idx, false)?,
            })
        })
    }
}

fn git_run(repo: &Path, args: &[&str], stdin_data: Option<&str>) -> Result<String> {
    let null = if cfg!(unix) { "/dev/null" } else { "NUL" };
    let cfg = "core.hooksPath=/dev/null gc.auto=0 gc.autoDetach=false maintenance.auto=0 maintenance.autoDetach=false";
    let env_spec =
        "GIT_CONFIG_NOSYSTEM=1 GIT_AUTHOR_NAME=r GIT_AUTHOR_EMAIL=r@e GIT_COMMITTER_NAME=r GIT_COMMITTER_EMAIL=r@e";
    let mut cmd = Command::new("git");
    cmd.args(cfg.split(' ').flat_map(|c| ["-c", c]))
        .args(["--no-replace-objects", "-C"])
        .arg(repo)
        .args(args)
        .envs(env_spec.split(' ').map(|s| s.split_once('=').unwrap()))
        .envs([("GIT_CONFIG_SYSTEM", null), ("GIT_CONFIG_GLOBAL", null)])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(if stdin_data.is_some() { Stdio::piped() } else { Stdio::null() });
    let mut child = cmd.spawn()?;
    if let Some(payload) = stdin_data
        && let Some(mut pipe) = child.stdin.take()
    {
        pipe.write_all(payload.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    ensure!(out.status.success(), "git {:?} failed: {}", args, String::from_utf8_lossy(&out.stderr));
    Ok(String::from_utf8(out.stdout)?.trim().to_owned())
}

fn git_ok(repo: &Path, args: &[&str]) -> Result<String> {
    git_run(repo, args, None)
}

fn make_commit_pack(
    work: &Path,
    stage: &Path,
    msg: &str,
    range: &str,
    m: (Uuid, Uuid, u64, u16),
) -> Result<CompactionPackEntry> {
    git_ok(work, &["add", "."])?;
    git_ok(work, &["commit", "-m", msg])?;
    let oids: String = git_ok(work, &["rev-list", "--objects", range])?
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .map(|o| format!("{o}\n"))
        .collect();
    std::fs::create_dir_all(stage)?;
    git_run(work, &["pack-objects", "-q", stage.join("pack").to_str().unwrap()], Some(&oids))?;
    let stem = std::fs::read_dir(stage)?
        .filter_map(|e| {
            e.ok()?.file_name().to_str()?.strip_suffix(".pack").filter(|s| s.starts_with("pack-")).map(str::to_owned)
        })
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing pack"))?;
    let p = put_s3_blob((m.0, m.1, 1), &stage.join(format!("{stem}.pack")), false)?;
    let i = put_s3_blob((m.0, m.1, 1), &stage.join(format!("{stem}.idx")), false)?;
    Ok(CompactionPackEntry::from_locators(Uuid::new_v4(), stem, &p, &i, m.2, m.3)?)
}

#[derive(Clone)]
struct MultiPackRepo {
    work: PathBuf,
    tenant: Uuid,
    repo: Uuid,
    history: Uuid,
    packs: Vec<CompactionPackEntry>,
    refs: Vec<AuthoritativeRef>,
    roots: Vec<String>,
    oid_count: usize,
}

fn seed_repo(dir: &Path, fmt: ReadAccelObjectFormat, num_packs: usize, shards: u16) -> Result<MultiPackRepo> {
    let (work, stage) = (dir.join("work"), dir.join("stage"));
    std::fs::create_dir_all(&work)?;
    git_ok(&work, &["init", fmt.git_init_flag(), "--initial-branch=main"])?;
    let (tenant, repo, history) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let (mut packs, mut root_oid) = (Vec::with_capacity(num_packs), String::new());
    for idx in 0..num_packs {
        std::fs::write(work.join("base.txt"), format!("{}-delta-{idx}", "shared-delta-base-".repeat(40)))?;
        std::fs::write(work.join(format!("f-{idx}.txt")), format!("payload-{idx}\n"))?;
        let range = if idx == 0 { "HEAD" } else { "HEAD~1..HEAD" };
        packs.push(make_commit_pack(
            &work,
            &stage.join(format!("p{idx}")),
            &format!("s{idx}"),
            range,
            (tenant, repo, 1, shards),
        )?);
        if idx == 0 {
            root_oid = git_ok(&work, &["rev-parse", "HEAD"])?;
        }
    }
    ensure!(packs.len() == num_packs, "expected {num_packs} packs");
    let refs = vec![AuthoritativeRef::new("refs/heads/main", git_ok(&work, &["rev-parse", "refs/heads/main"])?)];
    let oid_count = git_ok(&work, &["cat-file", "--batch-check", "--batch-all-objects"])?.lines().count();
    Ok(MultiPackRepo { work, tenant, repo, history, packs, refs, roots: vec![root_oid], oid_count })
}

fn push_extra_pack(repo: &mut MultiPackRepo, tag: &str, shards: u16, gen_num: u64) -> Result<CompactionPackEntry> {
    std::fs::write(repo.work.join(format!("{tag}.txt")), format!("concurrent-{tag}\n"))?;
    let stage = repo.work.parent().unwrap().join(format!("extra-{gen_num}-{tag}-{}", repo.packs.len()));
    let added = make_commit_pack(&repo.work, &stage, tag, "HEAD~1..HEAD", (repo.tenant, repo.repo, gen_num, shards))?;
    repo.refs = vec![AuthoritativeRef::new("refs/heads/main", git_ok(&repo.work, &["rev-parse", "refs/heads/main"])?)];
    repo.packs.push(added.clone());
    Ok(added)
}

#[derive(Clone)]
struct Harness {
    blob: BlobStore,
    views: DisposableViewRoot,
    budget: CompactionResourceBudget,
    policy: SegmentTriggerPolicy,
    dl: Instant,
}

impl Harness {
    fn open() -> Result<(Self, TempDir)> {
        let dir = TempDir::new()?;
        let views = DisposableViewRoot::open(&dir.path().join("views"), 8, 64 << 20, Duration::from_secs(120))?;
        let budget = CompactionResourceBudget::new(CompactionBudgetConfig::default())?;
        let policy = SegmentTriggerPolicy { max_segment_packs: 2, ..SegmentTriggerPolicy::default() };
        Ok((
            Self {
                blob: LoopbackS3::shared().open_store()?,
                views,
                budget,
                policy,
                dl: Instant::now() + Duration::from_secs(60),
            },
            dir,
        ))
    }

    fn seed(&self, store: &DurableCompactionStore, r: &MultiPackRepo, fmt: &str, shards: u16) -> Result<()> {
        store.seed_repository(
            r.tenant,
            r.repo,
            r.history,
            1,
            fmt,
            shards,
            r.packs.clone(),
            r.refs.clone(),
            r.roots.clone(),
            1_000,
            &self.policy,
        )?;
        Ok(())
    }

    fn mk_req(&self, r: &MultiPackRepo, hook: CompactionFaultHook) -> CompactionRunRequest<'_> {
        CompactionRunRequest {
            tenant_id: r.tenant,
            repo_id: r.repo,
            history_id: r.history,
            blob_generation: 1,
            shard_id: 0,
            owner_id: "c1",
            now_ms: 2_000,
            lease_ttl_ms: 30_000,
            policy: self.policy.clone(),
            max_cas_retries: 4,
            op_id_override: None,
            retention_registry: None,
            fault_hook: hook,
        }
    }

    async fn go(
        &self,
        store: &DurableCompactionStore,
        up: &dyn CompactionBlobUploader,
        rq: &CompactionRunRequest<'_>,
        retry: bool,
    ) -> Result<CompactionRunOutcome, CompactionError> {
        if retry {
            execute_shard_compaction_with_retry(store, up, &self.blob, &self.views, &self.budget, rq, self.dl).await
        } else {
            execute_shard_compaction(store, up, &self.blob, &self.views, &self.budget, rq, self.dl).await
        }
    }
}

fn unwrap_pub(out: CompactionRunOutcome) -> Result<Box<PublishedCompaction>> {
    match out {
        CompactionRunOutcome::Published(p) => Ok(p),
        CompactionRunOutcome::NoWorkDue => anyhow::bail!("expected Published"),
    }
}

#[tokio::test]
async fn sha1_and_sha256_no_delete_equivalence_and_retention_pin() -> Result<()> {
    let (h, _vr_dir) = Harness::open()?;
    for (fmt, fmt_name) in [(ReadAccelObjectFormat::Sha1, "sha1"), (ReadAccelObjectFormat::Sha256, "sha256")] {
        let repo_dir = TempDir::new()?;
        let repo = seed_repo(repo_dir.path(), fmt, 4, 1)?;
        let store = DurableCompactionStore::in_memory();
        h.seed(&store, &repo, fmt_name, 1)?;
        let reg = PackRetentionRegistry::new();
        let mut entries = Vec::with_capacity(repo.packs.len());
        for p in &repo.packs {
            entries.push(PackDigestEntry::from_locators(
                &p.pack_stem,
                &p.pack_locator.to_locator()?,
                &p.idx_locator.to_locator()?,
            ));
        }
        let reader_guard = reg.pin_pack_entries(&entries)?;
        let mut rq = h.mk_req(&repo, CompactionFaultHook::None);
        rq.retention_registry = Some(&reg);
        let res = unwrap_pub(h.go(&store, &TestS3Uploader::default(), &rq, false).await?)?;
        let a = &res.receipt.accounting;
        assert!(res.proof.fsck_verified && res.proof.clone_verified && res.proof.delta_bases_verified);
        assert_eq!((res.proof.total_object_count, res.proof.retention_roots_verified), (repo.oid_count, 1));
        assert!(a.delete_disabled && !a.claims_physical_savings && a.physical_bytes_deleted == 0);
        assert_eq!(a.total_physical_blob_bytes, a.serving_pack_bytes + a.retained_old_pack_bytes);

        let snap = store.load_snapshot(repo.tenant, repo.repo, repo.history).await?;
        assert_eq!((snap.serving_packs.len(), snap.retained_old_packs.len()), (1, 4));
        for old in &snap.retained_old_packs {
            let loc = old.pack_locator.to_locator()?;
            assert!(LoopbackS3::shared().has_key(&loc) && reg.is_pack_pinned(&loc));
            assert!(matches!(h.blob.delete(&loc, h.dl).await, Err(BlobError::DeleteDisabled)));
            h.blob.verify(&loc, h.dl).await?;
        }
        drop(reader_guard);
    }
    Ok(())
}

#[tokio::test]
async fn crash_recovery_lease_fence_concurrent_push_dropped_ack_and_corrupt_readback() -> Result<()> {
    let (h, _vr_dir) = Harness::open()?;
    let tmp = TempDir::new()?;
    let mut repo = seed_repo(tmp.path(), ReadAccelObjectFormat::Sha1, 2, 1)?;
    let store = DurableCompactionStore::open_with_journal(tmp.path().join("journal.json"))?;
    h.seed(&store, &repo, "sha1", 1)?;

    let rq_none = h.mk_req(&repo, CompactionFaultHook::None);
    assert!(matches!(
        h.go(&store, &TestS3Uploader { corrupt: true }, &rq_none, false).await,
        Err(CompactionError::Blob(_) | CompactionError::EquivalenceFailed(_))
    ));
    let up = TestS3Uploader::default();
    for hook in [CompactionFaultHook::CrashBeforeUpload, CompactionFaultHook::CrashAfterUploadBeforePublish] {
        let mut rq = h.mk_req(&repo, hook);
        rq.op_id_override = Some(Uuid::new_v4());
        assert!(h.go(&store, &up, &rq, false).await.is_err());
    }
    let store = store.reload_after_crash()?;
    assert_eq!(store.load_snapshot(repo.tenant, repo.repo, repo.history).await?.membership_generation, 1);

    let lose = CompactionFaultHook::LoseLeaseBeforePublish { usurper_owner: "usurper".into() };
    assert!(matches!(h.go(&store, &up, &h.mk_req(&repo, lose), false).await, Err(CompactionError::LeaseLost(_))));

    let concurrent_pack = push_extra_pack(&mut repo, "concurrent-push", 1, 2)?;
    let mut rq = h.mk_req(
        &repo,
        CompactionFaultHook::ConcurrentPushBeforePublish(Box::new(ConcurrentPushFault {
            pack: concurrent_pack.clone(),
            updated_refs: repo.refs.clone(),
        })),
    );
    (rq.owner_id, rq.now_ms) = ("usurper", 2_500);
    let retried = unwrap_pub(h.go(&store, &up, &rq, true).await?)?;
    assert_eq!((retried.attempts, store.metrics_counts().0), (2, 1));
    let snap = store.load_snapshot(repo.tenant, repo.repo, repo.history).await?;
    assert!(snap.serving_packs.iter().any(|p| p.pack_id == concurrent_pack.pack_id));

    let p_extra = push_extra_pack(&mut repo, "ack-drop-pack", 1, snap.membership_generation + 1)?;
    store.append_concurrent_pack(repo.tenant, repo.repo, repo.history, p_extra, repo.refs.clone(), 4_000, &h.policy)?;
    let op_drop = Uuid::new_v4();
    let mut rq_drop = h.mk_req(&repo, CompactionFaultHook::DropPublishAck);
    (rq_drop.owner_id, rq_drop.now_ms, rq_drop.op_id_override) = ("usurper", 5_000, Some(op_drop));
    assert!(h.go(&store, &up, &rq_drop, false).await.is_err());
    let reloaded = store.reload_after_crash()?;
    let gen_after = reloaded.load_snapshot(repo.tenant, repo.repo, repo.history).await?.membership_generation;
    let mut rq_replay = h.mk_req(&repo, CompactionFaultHook::None);
    rq_replay.op_id_override = Some(op_drop);
    let replayed = unwrap_pub(h.go(&reloaded, &up, &rq_replay, false).await?)?;
    assert_eq!(replayed.receipt.new_membership_generation, gen_after);
    assert!(replayed.proof.fsck_verified && !replayed.proof.oid_set_digest.is_empty());
    Ok(())
}

#[tokio::test]
async fn sharding_isolated_serving_quota_and_concurrent_ingest() -> Result<()> {
    let (h, _vr_dir) = Harness::open()?;
    let serving_git_sem = Arc::new(Semaphore::new(2));
    let _held = serving_git_sem.acquire_many(2).await?;

    let repo_dir = TempDir::new()?;
    let mut repo = seed_repo(repo_dir.path(), ReadAccelObjectFormat::Sha1, 4, 2)?;
    let store = DurableCompactionStore::in_memory();
    h.seed(&store, &repo, "sha1", 2)?;
    for i in 0..4 {
        let extra = push_extra_pack(&mut repo, &format!("stream-{i}"), 2, (i + 2) as u64)?;
        let ts = 2_000 + i as u64 * 100;
        store.append_concurrent_pack(repo.tenant, repo.repo, repo.history, extra, repo.refs.clone(), ts, &h.policy)?;
    }
    store.seal_aged_segments(repo.tenant, repo.repo, repo.history, 100_000, &h.policy)?;

    let router = CompactionShardRouter::new(2)?;
    let mut handles = Vec::new();
    for worker_idx in 0..2 {
        let shards = router.worker_shards(worker_idx, 2)?;
        let (hh, st, rp) = (h.clone(), store.clone(), repo.clone());
        handles.push(tokio::spawn(async move {
            let up = TestS3Uploader::default();
            let mut merged = 0usize;
            for shard_id in shards {
                let mut rq = hh.mk_req(&rp, CompactionFaultHook::None);
                (rq.shard_id, rq.owner_id, rq.now_ms) = (shard_id, "worker", 100_000);
                if matches!(hh.go(&st, &up, &rq, true).await?, CompactionRunOutcome::Published(_)) {
                    merged += 1;
                }
            }
            Ok::<_, CompactionError>(merged)
        }));
    }
    let mut total_merged = 0usize;
    for handle in handles {
        total_merged += handle.await??;
    }
    assert!(total_merged >= 1 && serving_git_sem.available_permits() == 0 && h.budget.metrics().active_jobs == 0);
    Ok(())
}
