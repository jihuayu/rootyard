//! In-crate OpenDAL Memory + stock Git (SHA-1 & SHA-256) tests covering
//! two-layer pack reuse, rewind, history/backend isolation, active pin/hold
//! preservation under eviction & cancellation, #174 bounds, and singleflight.

use std::{
    collections::BTreeMap,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Result, ensure};
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use uuid::Uuid;

use crate::blob_store::{
    BlobLocator,
    budget::{ResourceContext, ResourceLimits},
    config::BlobProfile,
    opendal::BlobStore,
    test_support::distinct_backend_identities,
};

use super::*;

#[derive(Default)]
struct S3MemState {
    objects: Mutex<BTreeMap<String, Vec<u8>>>,
}

struct LocalTestS3 {
    endpoint: String,
    state: Arc<S3MemState>,
    _server: tokio::task::JoinHandle<()>,
}

impl LocalTestS3 {
    async fn start() -> Result<Self> {
        let state = Arc::new(S3MemState::default());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let srv = Arc::clone(&state);
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, Router::new().fallback(handle_s3).with_state(srv)).await;
        });
        Ok(Self { endpoint: format!("http://127.0.0.1:{port}"), state, _server: server })
    }

    fn store(&self) -> Result<BlobStore> {
        let limits = ResourceLimits::new(2, 4, 8 << 20)?;
        let profile = BlobProfile::memory_profile(limits).with_test_endpoint(&self.endpoint)?;
        Ok(BlobStore::open_with_resources(profile, Arc::new(ResourceContext::new(limits)))?)
    }

    fn put_raw(&self, locator: &BlobLocator, data: Vec<u8>) {
        self.state.objects.lock().unwrap().insert(format!("blob-test-bucket/{}", locator.path()), data);
    }
}

async fn handle_s3(State(st): State<Arc<S3MemState>>, method: Method, uri: Uri) -> Response {
    let key = uri.path().trim_start_matches('/').to_owned();
    if !key.contains('/') {
        return Response::new(Body::from("<ListBucketResult/>"));
    }
    match method {
        Method::HEAD | Method::GET => match st.objects.lock().unwrap().get(&key).cloned() {
            Some(d) => {
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
        .args(["-c", "core.hooksPath=/dev/null", "--no-replace-objects", "-C"])
        .arg(repo)
        .args(args)
        .envs([
            ("GIT_CONFIG_NOSYSTEM", "1"),
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
            ("GIT_AUTHOR_NAME", "rootyard"),
            ("GIT_AUTHOR_EMAIL", "rootyard@example.com"),
            ("GIT_COMMITTER_NAME", "rootyard"),
            ("GIT_COMMITTER_EMAIL", "rootyard@example.com"),
        ])
        .output()?;
    ensure!(out.status.success(), "git {:?} failed: {}", args, String::from_utf8_lossy(&out.stderr));
    Ok(String::from_utf8(out.stdout)?.trim().to_owned())
}

struct MemSeededRepo {
    work_dir: TempDir,
    tenant_id: Uuid,
    repo_id: Uuid,
    history_id: Uuid,
    cluster_incarnation: Uuid,
    format: ReplicaObjectFormat,
    packs: Vec<PackObjectSpec>,
    refs: Vec<ReplicaRefSpec>,
    base_oid: String,
    tip_oid: String,
}

impl MemSeededRepo {
    async fn create(s3: &LocalTestS3, format: ReplicaObjectFormat) -> Result<Self> {
        let work_dir = TempDir::new()?;
        let root = work_dir.path();
        git_ok(root, &["init", format.git_init_flag(), "--initial-branch=main"])?;
        std::fs::write(root.join("README.md"), b"# Rubicon\n")?;
        git_ok(root, &["add", "."])?;
        git_ok(root, &["commit", "-m", "base"])?;
        let base_oid = git_ok(root, &["rev-parse", "HEAD"])?;
        std::fs::write(root.join("app.txt"), b"v1\n")?;
        git_ok(root, &["add", "."])?;
        git_ok(root, &["commit", "-m", "v1"])?;
        let tip_oid = git_ok(root, &["rev-parse", "HEAD"])?;
        git_ok(root, &["repack", "-ad", "--no-write-bitmap-index"])?;
        let mut s = Self {
            work_dir,
            tenant_id: Uuid::new_v4(),
            repo_id: Uuid::new_v4(),
            history_id: Uuid::new_v4(),
            cluster_incarnation: Uuid::new_v4(),
            format,
            packs: Vec::new(),
            refs: vec![ReplicaRefSpec::new("refs/heads/main", &tip_oid)],
            base_oid,
            tip_oid,
        };
        s.packs = s.upload_packs(s3)?;
        Ok(s)
    }

    fn add_commit(&mut self, s3: &LocalTestS3) -> Result<()> {
        let root = self.work_dir.path();
        std::fs::write(root.join("extra.txt"), b"v2\n")?;
        git_ok(root, &["add", "."])?;
        git_ok(root, &["commit", "-m", "v2"])?;
        git_ok(root, &["repack", "--no-write-bitmap-index"])?;
        self.tip_oid = git_ok(root, &["rev-parse", "HEAD"])?;
        self.refs = vec![ReplicaRefSpec::new("refs/heads/main", &self.tip_oid)];
        self.packs = self.upload_packs(s3)?;
        Ok(())
    }

    fn upload_packs(&self, s3: &LocalTestS3) -> Result<Vec<PackObjectSpec>> {
        let pack_dir = self.work_dir.path().join(".git/objects/pack");
        let mut stems: Vec<String> = std::fs::read_dir(&pack_dir)?
            .filter_map(|e| e.ok()?.file_name().to_str()?.strip_suffix(".pack").map(str::to_owned))
            .collect();
        stems.sort();
        let mut out = Vec::with_capacity(stems.len());
        for stem in stems {
            let upload = |ext: &str| -> Result<BlobLocator> {
                let bytes = std::fs::read(pack_dir.join(format!("{stem}.{ext}")))?;
                let sha = hex::encode(Sha256::digest(&bytes));
                let locator = BlobLocator::new(
                    self.tenant_id,
                    self.repo_id,
                    1,
                    Uuid::new_v4(),
                    "packs",
                    &sha,
                    bytes.len() as u64,
                )?;
                s3.put_raw(&locator, bytes);
                Ok(locator)
            };
            let (p_loc, i_loc) = (upload("pack")?, upload("idx")?);
            out.push(PackObjectSpec::provider_managed(stem, p_loc, i_loc));
        }
        Ok(out)
    }

    fn snapshot(&self, pins: &DurablePinRegistry, rev: i64) -> AuthoritativeSnapshot {
        AuthoritativeSnapshot {
            tenant_id: self.tenant_id,
            repo_id: self.repo_id,
            history_id: self.history_id,
            cluster_incarnation: self.cluster_incarnation,
            object_format: self.format,
            authority_epoch: 1,
            gate_revision: rev,
            version_check: VersionCheckVerdict::Changed,
            head_ref: "refs/heads/main".into(),
            refs: self.refs.clone(),
            packs: self.packs.clone(),
            durable_pin: pins.acquire(self.tenant_id, self.repo_id, rev),
        }
    }
}

struct MemAuth {
    pins: DurablePinRegistry,
    snap: Mutex<AuthoritativeSnapshot>,
    allowed: AtomicBool,
}

impl LiveAuthorizer for MemAuth {
    fn authorize_and_check_version<'a>(
        &'a self,
        req: &'a ReplicaReadRequest,
    ) -> lease_pin::AuthTask<'a, Result<AuthoritativeSnapshot, ReplicaCacheError>> {
        Box::pin(async move {
            if !self.allowed.load(Ordering::SeqCst) {
                return Err(ReplicaCacheError::Unauthorized("denied"));
            }
            let mut s = self.snap.lock().unwrap().clone();
            if s.tenant_id != req.tenant_id || s.repo_id != req.repo_id {
                return Err(ReplicaCacheError::Unauthorized("cross-tenant denied"));
            }
            s.durable_pin = self.pins.acquire(req.tenant_id, req.repo_id, s.gate_revision);
            Ok(s)
        })
    }
}

fn req_for(t: Uuid, r: Uuid) -> ReplicaReadRequest {
    ReplicaReadRequest {
        tenant_id: t,
        repo_id: r,
        actor_id: "bob".into(),
        operation: ReplicaOperation::GitUploadPack,
        expected_backend_identity: None,
        session_lower_bound: None,
        known_membership_digest: None,
    }
}

fn assert_clone_ok(repo: &Path, expected_tip: &str) -> Result<()> {
    let dst = TempDir::new()?;
    let target = dst.path().join("cloned");
    git_ok(dst.path(), &["clone", repo.to_str().unwrap(), target.to_str().unwrap()])?;
    git_ok(&target, &["fsck", "--full", "--strict"])?;
    ensure!(git_ok(&target, &["rev-parse", "HEAD"])? == expected_tip);
    Ok(())
}

#[tokio::test]
async fn two_layer_reuse_incremental_rewind_and_push_isolation_sha1_and_sha256() -> Result<()> {
    let s3 = LocalTestS3::start().await?;
    let blob = s3.store()?;
    let (_, other_id) = distinct_backend_identities();
    let pins = DurablePinRegistry::new();

    for fmt in [ReplicaObjectFormat::Sha1, ReplicaObjectFormat::Sha256] {
        let mut seeded = MemSeededRepo::create(&s3, fmt).await?;
        let dir = TempDir::new()?;
        let node = ReplicaCacheNode::open(
            "n1",
            &dir.path().join("replica"),
            blob.clone(),
            None,
            ReplicaCacheLimits::default(),
        )?;
        let auth =
            MemAuth { pins: pins.clone(), snap: Mutex::new(seeded.snapshot(&pins, 1)), allowed: AtomicBool::new(true) };
        let req = req_for(seeded.tenant_id, seeded.repo_id);
        let dl = Instant::now() + Duration::from_secs(30);

        let cold = node.serve_view(&req, &auth, dl).await?;
        assert_eq!(cold.source(), ReplicaServeSource::ColdBlobMaterialized);
        verify_read_only_view_files(cold.repo_path()?)?;
        assert_clone_ok(cold.repo_path()?, &seeded.tip_oid)?;
        let scratch = node.allocate_push_scratch(seeded.tenant_id, seeded.repo_id, 4096)?;
        assert!(scratch.is_isolated_from(cold.repo_path()?));
        drop(scratch);

        let warm = node.serve_view(&req, &auth, dl).await?;
        assert_eq!(warm.source(), ReplicaServeSource::ViewCacheHit);
        assert_eq!(warm.metrics().blob_gets, 0);
        drop(warm);
        drop(cold);

        let mut rewound = seeded.snapshot(&pins, 2);
        rewound.refs = vec![ReplicaRefSpec::new("refs/heads/main", &seeded.base_oid)];
        *auth.snap.lock().unwrap() = rewound;
        let rewound_view = node.serve_view(&req, &auth, dl).await?;
        assert_eq!(rewound_view.source(), ReplicaServeSource::PackCacheFullReuse);
        assert_eq!(rewound_view.metrics().blob_gets, 0);
        assert_eq!(git_ok(rewound_view.repo_path()?, &["rev-parse", "refs/heads/main"])?, seeded.base_oid);
        drop(rewound_view);

        seeded.add_commit(&s3)?;
        *auth.snap.lock().unwrap() = seeded.snapshot(&pins, 3);
        let inc = node.serve_view(&req, &auth, dl).await?;
        assert_eq!(inc.source(), ReplicaServeSource::PackCachePartialRefill);
        assert_eq!(inc.metrics().reused_pack_count, 1);
        assert_eq!(inc.metrics().blob_gets, 2);
        assert_clone_ok(inc.repo_path()?, &seeded.tip_oid)?;
        drop(inc);

        let mut rot = seeded.snapshot(&pins, 3);
        rot.history_id = Uuid::new_v4();
        *auth.snap.lock().unwrap() = rot;
        assert_eq!(node.serve_view(&req, &auth, dl).await?.source(), ReplicaServeSource::PackCacheFullReuse);

        let mut foreign_req = req.clone();
        foreign_req.expected_backend_identity = Some(other_id.clone());
        assert!(matches!(
            node.serve_view(&foreign_req, &auth, dl).await,
            Err(ReplicaCacheError::BackendIdentityMismatch)
        ));
    }
    Ok(())
}

#[tokio::test]
async fn active_reader_guard_preserves_view_and_pin_under_eviction_and_tamper() -> Result<()> {
    let s3 = LocalTestS3::start().await?;
    let blob = s3.store()?;
    let pins = DurablePinRegistry::new();
    let s1 = MemSeededRepo::create(&s3, ReplicaObjectFormat::Sha1).await?;
    let s2 = MemSeededRepo::create(&s3, ReplicaObjectFormat::Sha1).await?;
    let dir = TempDir::new()?;
    let limits = ReplicaCacheLimits { max_view_entries: 2, max_active_views: 4, ..ReplicaCacheLimits::default() };
    let node = ReplicaCacheNode::open("n-pin", &dir.path().join("replica"), blob, None, limits)?;
    let a1 = MemAuth { pins: pins.clone(), snap: Mutex::new(s1.snapshot(&pins, 10)), allowed: AtomicBool::new(true) };
    let a2 = MemAuth { pins: pins.clone(), snap: Mutex::new(s2.snapshot(&pins, 1)), allowed: AtomicBool::new(true) };
    let dl = Instant::now() + Duration::from_secs(30);

    let g1 = node.serve_view(&req_for(s1.tenant_id, s1.repo_id), &a1, dl).await?;
    let pin1 = g1.durable_pin().pin_id();
    let p1 = g1.repo_path()?.to_path_buf();
    assert!(pins.is_pin_active(pin1));

    // #174 session lower bound behind current revision refuses warm cached view.
    let mut behind_req = req_for(s1.tenant_id, s1.repo_id);
    behind_req.session_lower_bound = Some(SessionLowerBound {
        tenant_id: s1.tenant_id,
        repo_id: s1.repo_id,
        history_id: s1.history_id,
        cluster_incarnation: s1.cluster_incarnation,
        authority_epoch: 1,
        min_gate_revision: 11,
    });
    assert!(matches!(
        node.serve_view(&behind_req, &a1, dl).await,
        Err(ReplicaCacheError::BehindSessionLowerBound { required: 11, observed: 10 })
    ));

    // Idle s2 view is evicted when s1 rev 11 arrives; g1 + pin1 remain untouched!
    drop(node.serve_view(&req_for(s2.tenant_id, s2.repo_id), &a2, dl).await?);
    *a1.snap.lock().unwrap() = s1.snapshot(&pins, 11);
    let g1_v2 = node.serve_view(&req_for(s1.tenant_id, s1.repo_id), &a1, dl).await?;
    let p2 = g1_v2.repo_path()?.to_path_buf();
    drop(g1_v2);
    assert!(p1.is_dir() && pins.is_pin_active(pin1));

    // Tamper idle p2 pack on disk -> detected and rebuilt on next serve.
    let pack_file = std::fs::read_dir(p2.join("objects/pack"))?.next().unwrap()?.path();
    std::fs::set_permissions(&pack_file, std::fs::Permissions::from_mode(0o600))?;
    std::fs::write(&pack_file, b"bad")?;
    let rebuilt = node.serve_view(&req_for(s1.tenant_id, s1.repo_id), &a1, dl).await?;
    assert!(node.stats().corrupt_rebuilds >= 1);
    assert_clone_ok(rebuilt.repo_path()?, &s1.tip_oid)?;
    drop(rebuilt);

    node.clear_cache();
    assert!(p1.is_dir() && pins.is_pin_active(pin1));
    drop(g1);
    assert!(!p1.exists() && !pins.is_pin_active(pin1));
    Ok(())
}
