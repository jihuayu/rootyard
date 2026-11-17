//! OpenDAL S3 + stock Git (SHA-1 & SHA-256) + 2-process failover tests for Issue #163.

use std::{
    collections::BTreeMap,
    io::BufRead,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Result, ensure};
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use bytes::Bytes;
use rootyard::{
    blob_store::{BlobBackendIdentity, BlobLocator, config::BlobProfile, opendal::BlobStore},
    cache_wake::replica_cache::{lease_pin::AuthTask, *},
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

#[derive(Default)]
struct S3State {
    objects: Mutex<BTreeMap<String, (Option<Uuid>, Vec<u8>)>>,
    tenant_gets: Mutex<BTreeMap<Uuid, (u64, u64)>>,
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
            let (st, l) = (Arc::new(S3State::default()), std::net::TcpListener::bind("127.0.0.1:0").unwrap());
            l.set_nonblocking(true).unwrap();
            let port = l.local_addr().unwrap().port();
            let (tx, rx) = std::sync::mpsc::sync_channel(1);
            let srv = Arc::clone(&st);
            std::thread::spawn(move || {
                tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap().block_on(
                    async move {
                        let _ = tx.send(());
                        let _ = axum::serve(
                            tokio::net::TcpListener::from_std(l).unwrap(),
                            Router::new().fallback(handle_s3).with_state(srv),
                        )
                        .await;
                    },
                );
            });
            rx.recv().unwrap();
            Self { endpoint: format!("http://127.0.0.1:{port}"), state: st }
        })
    }
    fn open_store(&self) -> Result<BlobStore> {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        set_blob_env(&self.endpoint);
        Ok(BlobStore::open(BlobProfile::from_env()?)?)
    }
    fn put_raw(&self, loc: &BlobLocator, data: Vec<u8>) {
        let key = format!("replica-test-bucket/replica-cache-it/{}", loc.path());
        self.state.objects.lock().unwrap().insert(key, (Some(loc.tenant_id()), data));
    }
    fn gets_for(&self, tenant_id: Uuid) -> (u64, u64) {
        self.state.tenant_gets.lock().unwrap().get(&tenant_id).copied().unwrap_or((0, 0))
    }
}

fn set_blob_env(ep: &str) {
    let pairs = "DRIVER=opendal,SERVICE=s3,BUCKET=replica-test-bucket,REGION=us-east-1,ROOT=replica-cache-it,ACCESS_KEY_ID=test-ak,SECRET_ACCESS_KEY=test-sk,ENCRYPTION_MODE=provider-managed,RETRY_MAX_TIMES=0,MAX_OBJECT_BYTES=8388608";
    // SAFETY: callers hold ENV_LOCK or own a dedicated worker subprocess.
    unsafe {
        for kv in pairs.split(',') {
            let (k, v) = kv.split_once('=').unwrap();
            std::env::set_var(format!("ROOTYARD_BLOB_{k}"), v);
        }
        std::env::set_var("ROOTYARD_BLOB_ENDPOINT", ep);
        std::env::remove_var("ROOTYARD_BLOB_KEYRING_DIR");
    }
}

async fn handle_s3(State(st): State<Arc<S3State>>, method: Method, uri: Uri, body: Bytes) -> Response {
    let key = uri.path().trim_start_matches('/').to_owned();
    if !key.contains('/') {
        return Response::new(Body::from("<ListBucketResult/>"));
    }
    match method {
        Method::PUT => {
            let tag = format!("\"{}\"", &hex::encode(Sha256::digest(&body))[..32]);
            st.objects.lock().unwrap().insert(key, (None, body.to_vec()));
            ([(header::ETAG, tag), (header::CONTENT_LENGTH, "0".into())], Body::empty()).into_response()
        }
        Method::HEAD | Method::GET => match st.objects.lock().unwrap().get(&key).cloned() {
            Some((owner, d)) => {
                if method == Method::GET
                    && let Some(tid) = owner
                {
                    let mut g = st.tenant_gets.lock().unwrap();
                    let entry = g.entry(tid).or_default();
                    entry.0 += 1;
                    entry.1 += d.len() as u64;
                }
                let tag = format!("\"{}\"", &hex::encode(Sha256::digest(&d))[..32]);
                let len = if method == Method::HEAD { "0".into() } else { d.len().to_string() };
                (
                    [(header::ETAG, tag), (header::CONTENT_LENGTH, len)],
                    if method == Method::HEAD { Body::empty() } else { Body::from(d) },
                )
                    .into_response()
            }
            None => (StatusCode::NOT_FOUND, [(header::CONTENT_LENGTH, "0")], Body::empty()).into_response(),
        },
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

fn git_ok(repo: &Path, args: &[&str]) -> Result<String> {
    let out = Command::new("git")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "user.name=ry",
            "-c",
            "user.email=ry@e.com",
            "--no-replace-objects",
            "-C",
        ])
        .arg(repo)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()?;
    ensure!(out.status.success(), "git {:?} failed: {}", args, String::from_utf8_lossy(&out.stderr));
    Ok(String::from_utf8(out.stdout)?.trim().to_owned())
}

fn seed_repo(fmt: ReplicaObjectFormat) -> Result<(TempDir, [Uuid; 4], PackObjectSpec, String)> {
    let (dir, tid, rid) = (TempDir::new()?, Uuid::new_v4(), Uuid::new_v4());
    let root = dir.path();
    git_ok(root, &["init", fmt.git_init_flag(), "--initial-branch=main"])?;
    std::fs::write(root.join("app.txt"), b"v1\n")?;
    git_ok(root, &["add", "."])?;
    git_ok(root, &["commit", "-m", "v1"])?;
    let tip = git_ok(root, &["rev-parse", "HEAD"])?;
    git_ok(root, &["repack", "-ad", "--no-write-bitmap-index"])?;
    let pdir = root.join(".git/objects/pack");
    let stem = std::fs::read_dir(&pdir)?
        .filter_map(|e| e.ok()?.file_name().to_str()?.strip_suffix(".pack").map(str::to_owned))
        .next()
        .unwrap();
    let mut put = |ext: &str| -> Result<BlobLocator> {
        let b = std::fs::read(pdir.join(format!("{stem}.{ext}")))?;
        let loc =
            BlobLocator::new(tid, rid, 1, Uuid::new_v4(), "packs", &hex::encode(Sha256::digest(&b)), b.len() as u64)?;
        LoopbackS3::shared().put_raw(&loc, b);
        Ok(loc)
    };
    Ok((
        dir,
        [tid, rid, Uuid::new_v4(), Uuid::new_v4()],
        PackObjectSpec::provider_managed(stem, put("pack")?, put("idx")?),
        tip,
    ))
}

fn mk_snap(
    ids: [Uuid; 4],
    fmt: ReplicaObjectFormat,
    p: &PackObjectSpec,
    tip: &str,
    pins: &DurablePinRegistry,
) -> AuthoritativeSnapshot {
    AuthoritativeSnapshot {
        tenant_id: ids[0],
        repo_id: ids[1],
        history_id: ids[2],
        cluster_incarnation: ids[3],
        object_format: fmt,
        authority_epoch: 1,
        gate_revision: 5,
        version_check: VersionCheckVerdict::Changed,
        head_ref: "refs/heads/main".into(),
        refs: vec![ReplicaRefSpec::new("refs/heads/main", tip)],
        packs: vec![p.clone()],
        durable_pin: pins.acquire(ids[0], ids[1], 5),
    }
}

struct TestAuth(DurablePinRegistry, AuthoritativeSnapshot, AtomicBool);
impl LiveAuthorizer for TestAuth {
    fn authorize_and_check_version<'a>(
        &'a self,
        req: &'a ReplicaReadRequest,
    ) -> AuthTask<'a, Result<AuthoritativeSnapshot, ReplicaCacheError>> {
        Box::pin(async move {
            if !self.2.load(Ordering::SeqCst) {
                return Err(ReplicaCacheError::Unauthorized("denied"));
            }
            if self.1.tenant_id != req.tenant_id || self.1.repo_id != req.repo_id {
                return Err(ReplicaCacheError::Unauthorized("cross-tenant"));
            }
            let mut s = self.1.clone();
            s.durable_pin = self.0.acquire(req.tenant_id, req.repo_id, s.gate_revision);
            Ok(s)
        })
    }
}

fn read_req(t: Uuid, r: Uuid) -> ReplicaReadRequest {
    ReplicaReadRequest {
        tenant_id: t,
        repo_id: r,
        actor_id: "alice".into(),
        operation: ReplicaOperation::GitUploadPack,
        expected_backend_identity: None,
        session_lower_bound: None,
        known_membership_digest: None,
    }
}

fn verify_clone(src: &str, tip: &str) -> Result<()> {
    let d = TempDir::new()?;
    let target = d.path().join("cloned");
    git_ok(d.path(), &["clone", src, target.to_str().unwrap()])?;
    git_ok(&target, &["fsck", "--full", "--strict"])?;
    ensure!(git_ok(&target, &["rev-parse", "HEAD"])? == tip);
    Ok(())
}

#[tokio::test]
async fn s3_opendal_cold_warm_auth_pin_singleflight_and_corrupt_rebuild() -> Result<()> {
    let (s3, pins, dir) = (LoopbackS3::shared(), DurablePinRegistry::new(), TempDir::new()?);
    let (_d, ids, pack, tip) = seed_repo(ReplicaObjectFormat::Sha1)?;
    let limits = ReplicaCacheLimits { max_waiters_per_key: 3, max_total_waiters: 3, ..ReplicaCacheLimits::default() };
    let node = Arc::new(ReplicaCacheNode::open("n-s3", &dir.path().join("replica"), s3.open_store()?, None, limits)?);
    let auth = Arc::new(TestAuth(
        pins.clone(),
        mk_snap(ids, ReplicaObjectFormat::Sha1, &pack, &tip, &pins),
        AtomicBool::new(true),
    ));
    let (g0, b0) = s3.gets_for(ids[0]);

    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..7 {
        let (n, a, req) = (Arc::clone(&node), Arc::clone(&auth), read_req(ids[0], ids[1]));
        tasks.spawn(async move { n.serve_view(&req, a.as_ref(), Instant::now() + Duration::from_secs(20)).await });
    }
    let mut ok_cnt = 0usize;
    while let Some(res) = tasks.join_next().await {
        ok_cnt += usize::from(res.unwrap().is_ok());
    }
    let (g1, b1) = s3.gets_for(ids[0]);
    assert!((4..7).contains(&ok_cnt) && g1 - g0 == 2 && b1 > b0);
    let (req, dl) = (read_req(ids[0], ids[1]), Instant::now() + Duration::from_secs(20));
    let guard = node.serve_view(&req, auth.as_ref(), dl).await?;
    assert!(guard.source() == ReplicaServeSource::ViewCacheHit && s3.gets_for(ids[0]).0 == g0 + 2);
    let (pin_id, view_path) = (guard.durable_pin().pin_id(), guard.repo_path()?.to_path_buf());

    auth.2.store(false, Ordering::SeqCst);
    assert!(matches!(node.serve_view(&req, auth.as_ref(), dl).await, Err(ReplicaCacheError::Unauthorized(_))));
    auth.2.store(true, Ordering::SeqCst);
    node.clear_cache();
    assert!(view_path.is_dir() && pins.is_pin_active(pin_id));
    drop(guard);
    assert!(!view_path.exists() && !pins.is_pin_active(pin_id));

    let g2 = node.serve_view(&req, auth.as_ref(), dl).await?;
    let pack_file = std::fs::read_dir(g2.repo_path()?.join("objects/pack"))?.next().unwrap()?.path();
    drop(g2);
    std::fs::set_permissions(&pack_file, std::fs::Permissions::from_mode(0o600))?;
    std::fs::write(&pack_file, b"tampered")?;
    let rebuilt = node.serve_view(&req, auth.as_ref(), dl).await?;
    assert!(node.stats().corrupt_rebuilds >= 1);
    verify_clone(rebuilt.repo_path()?.to_str().unwrap(), &tip)
}

type WorkerTuple =
    (String, String, String, [Uuid; 4], ReplicaObjectFormat, String, String, (String, u64, Uuid), (String, u64, Uuid));
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = (self.0.kill(), self.0.wait());
    }
}

struct HttpBackend(String, String, BlobBackendIdentity, reqwest::Client);
struct RemoteSlot(ReplicaViewKey, PathBuf);
impl ActiveViewSlot for RemoteSlot {
    fn view_key(&self) -> &ReplicaViewKey {
        &self.0
    }
    fn repo_path(&self) -> Result<&Path, ReplicaCacheError> {
        Ok(&self.1)
    }
    fn ensure_live(&self) -> Result<(), ReplicaCacheError> {
        Ok(())
    }
    fn release_reader(&self) {}
}
impl ReplicaBackend for HttpBackend {
    fn node_id(&self) -> &str {
        &self.0
    }
    fn is_accepting_traffic(&self) -> bool {
        true
    }
    fn serve_replica_view<'a>(
        &'a self,
        req: &'a ReplicaReadRequest,
        authorizer: &'a dyn LiveAuthorizer,
        _dl: Instant,
    ) -> AuthTask<'a, Result<ReplicaViewGuard, ReplicaCacheError>> {
        Box::pin(async move {
            let auth = authorizer.authorize_and_check_version(req).await?;
            let resp = self
                .3
                .get(format!("{}/git/repo.git/info/refs?service=git-upload-pack", self.1))
                .send()
                .await
                .map_err(|e| ReplicaCacheError::ReplicaUnhealthy(e.to_string()))?;
            if !resp.status().is_success() {
                return Err(ReplicaCacheError::ReplicaUnhealthy(format!("http {}", resp.status())));
            }
            Ok(ReplicaViewGuard::new(
                self.0.clone(),
                Arc::new(RemoteSlot(auth.build_view_key(&self.2)?, PathBuf::from(&self.1))),
                auth.durable_pin,
                ReplicaServeSource::ColdBlobMaterialized,
                Default::default(),
                false,
            ))
        })
    }
}

fn spawn_worker(
    id: &str,
    dir: &Path,
    ids: [Uuid; 4],
    fmt: ReplicaObjectFormat,
    p: &PackObjectSpec,
    tip: &str,
    ep: &str,
) -> Result<(ChildGuard, String)> {
    let cfg: WorkerTuple = (
        id.into(),
        dir.to_str().unwrap().into(),
        ep.into(),
        ids,
        fmt,
        tip.into(),
        p.pack_stem.clone(),
        (p.pack_locator.sha256().into(), p.pack_locator.length(), p.pack_locator.attempt_id()),
        (p.idx_locator.sha256().into(), p.idx_locator.length(), p.idx_locator.attempt_id()),
    );
    let mut child = Command::new(std::env::current_exe()?)
        .args(["--exact", "replica_worker_subprocess_hook", "--nocapture"])
        .env("ROOTYARD_REPLICA_WORKER_JSON", serde_json::to_string(&cfg)?)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let (mut line, mut r) = (String::new(), std::io::BufReader::new(child.stdout.take().unwrap()));
    while r.read_line(&mut line)? > 0 {
        if let Some(url) = line.trim().strip_prefix("READY ") {
            return Ok((ChildGuard(child), url.to_owned()));
        }
        line.clear();
    }
    anyhow::bail!("worker exited before READY");
}

#[tokio::test]
async fn two_process_hot_kill_cold_rebuild_sha1_and_sha256() -> Result<()> {
    let (s3, pins) = (LoopbackS3::shared(), DurablePinRegistry::new());
    let bid = s3.open_store()?.backend_identity().clone();
    for fmt in [ReplicaObjectFormat::Sha1, ReplicaObjectFormat::Sha256] {
        let (_d, ids, pack, tip) = seed_repo(fmt)?;
        let (d1, d2) = (TempDir::new()?, TempDir::new()?);
        let (w1, u1) = spawn_worker("proc-1", d1.path(), ids, fmt, &pack, &tip, &s3.endpoint)?;
        let (w2, u2) = spawn_worker("proc-2", d2.path(), ids, fmt, &pack, &tip, &s3.endpoint)?;
        let cl = reqwest::Client::new();
        let b1 = Arc::new(HttpBackend("proc-1".into(), u1.clone(), bid.clone(), cl.clone()));
        let b2 = Arc::new(HttpBackend("proc-2".into(), u2.clone(), bid.clone(), cl));
        let sched =
            ReplicaScheduler::new(vec![b1, b2], TenantFairShareConfig::default(), None, "it", Duration::from_secs(10))?;
        let auth = TestAuth(pins.clone(), mk_snap(ids, fmt, &pack, &tip, &pins), AtomicBool::new(true));
        let (req, g0) = (read_req(ids[0], ids[1]), s3.gets_for(ids[0]).0);
        let out1 = sched.route_and_serve(&req, &auth, Instant::now() + Duration::from_secs(20)).await?;
        let (hot_url, cold_id, cold_url) =
            if out1.routed_node_id == "proc-1" { (u1, "proc-2", u2) } else { (u2, "proc-1", u1) };
        verify_clone(&format!("{hot_url}/git/repo.git"), &tip)?;
        assert_eq!(s3.gets_for(ids[0]).0 - g0, 2);
        let kill_dir = if out1.routed_node_id == "proc-1" {
            drop(w1);
            d1.path()
        } else {
            drop(w2);
            d2.path()
        };
        let _ = std::fs::remove_dir_all(kill_dir);
        let out2 = sched.route_and_serve(&req, &auth, Instant::now() + Duration::from_secs(20)).await?;
        let g2 = s3.gets_for(ids[0]).0;
        assert!(out2.failover_used && out2.attempts == 2 && out2.routed_node_id == cold_id && g2 - g0 == 4);
        verify_clone(&format!("{cold_url}/git/repo.git"), &tip)?;
    }
    Ok(())
}

type WState = Arc<(ReplicaCacheNode, DurablePinRegistry, AuthoritativeSnapshot)>;

#[tokio::test]
async fn replica_worker_subprocess_hook() -> Result<()> {
    let Ok(raw) = std::env::var("ROOTYARD_REPLICA_WORKER_JSON") else {
        return Ok(());
    };
    let (id, dir, ep, ids, fmt, tip, stem, pk, ix): WorkerTuple = serde_json::from_str(&raw)?;
    set_blob_env(&ep);
    let node = ReplicaCacheNode::open(
        id,
        &PathBuf::from(&dir).join("replica"),
        BlobStore::open(BlobProfile::from_env()?)?,
        None,
        ReplicaCacheLimits::default(),
    )?;
    let pins = DurablePinRegistry::new();
    let pack = PackObjectSpec::provider_managed(
        stem,
        BlobLocator::new(ids[0], ids[1], 1, pk.2, "packs", &pk.0, pk.1)?,
        BlobLocator::new(ids[0], ids[1], 1, ix.2, "packs", &ix.0, ix.1)?,
    );
    let snap = mk_snap(ids, fmt, &pack, &tip, &pins);
    let app = Router::new()
        .route("/git/repo.git/info/refs", get(w_refs))
        .route("/git/repo.git/git-upload-pack", post(w_pack))
        .with_state(Arc::new((node, pins, snap)));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    println!("READY http://127.0.0.1:{}", listener.local_addr()?.port());
    tokio::select! { _ = axum::serve(listener, app) => {} _ = tokio::time::sleep(Duration::from_secs(30)) => {} }
    Ok(())
}

async fn w_serve(st: &WState) -> Result<ReplicaViewGuard, StatusCode> {
    let auth = TestAuth(st.1.clone(), st.2.clone(), AtomicBool::new(true));
    st.0.serve_view(&read_req(st.2.tenant_id, st.2.repo_id), &auth, Instant::now() + Duration::from_secs(20))
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}
async fn w_refs(State(st): State<WState>, headers: HeaderMap) -> Response {
    let Ok(g) = w_serve(&st).await else { return StatusCode::SERVICE_UNAVAILABLE.into_response() };
    let mut body = b"001e# service=git-upload-pack\n0000".to_vec();
    body.extend_from_slice(&run_upload_pack(g.repo_path().unwrap(), &headers, None).await);
    ([("content-type", "application/x-git-upload-pack-advertisement")], body).into_response()
}
async fn w_pack(State(st): State<WState>, headers: HeaderMap, body: Bytes) -> Response {
    let Ok(g) = w_serve(&st).await else { return StatusCode::SERVICE_UNAVAILABLE.into_response() };
    (
        [("content-type", "application/x-git-upload-pack-result")],
        run_upload_pack(g.repo_path().unwrap(), &headers, Some(body)).await,
    )
        .into_response()
}
async fn run_upload_pack(repo: &Path, headers: &HeaderMap, stdin_bytes: Option<Bytes>) -> Vec<u8> {
    let mut cmd = tokio::process::Command::new("git");
    cmd.args(["upload-pack", "--stateless-rpc"])
        .args(if stdin_bytes.is_none() { vec!["--advertise-refs"] } else { vec![] })
        .arg(repo)
        .stdout(Stdio::piped())
        .stdin(if stdin_bytes.is_some() { Stdio::piped() } else { Stdio::null() });
    if let Some(p) = headers.get("git-protocol").and_then(|v| v.to_str().ok()) {
        cmd.env("GIT_PROTOCOL", p);
    }
    let mut child = cmd.spawn().unwrap();
    if let Some(bytes) = stdin_bytes
        && let Some(mut stdin) = child.stdin.take()
    {
        let _ = stdin.write_all(&bytes).await;
        let _ = stdin.shutdown().await;
    }
    child.wait_with_output().await.unwrap().stdout
}
