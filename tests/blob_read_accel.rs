//! Real OpenDAL S3 + stock Git parity, fault-injection, and retention tests for Issue #165.

use std::{
    collections::BTreeMap,
    fs::Permissions,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::Command,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
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
    config::BlobProfile,
    disposable_view::DisposableViewRoot,
    opendal::BlobStore,
    read_accel::{
        AuthoritativePackSource, AuthoritativeRef, BuildReadAccelRequest, BuiltReadAccelBundle, ENABLE_BY_DEFAULT,
        ManifestFetchRef, MaterializeViewRequest, MaterializedAccelView, PackRetentionRegistry, ReadAccelArtifactKind,
        ReadAccelConfig, ReadAccelFallbackReason, ReadAccelObjectFormat, ReadAccelSidecarStatus,
        build_and_upload_sidecars, materialize_git_view_with_read_accel, verify_and_recover_view_sidecars,
    },
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use uuid::Uuid;

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
        format!("read-accel-test-bucket/read-accel-it/{}", locator.path())
    }

    fn open_store(&self) -> Result<BlobStore> {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let vars = [
            ("ROOTYARD_BLOB_DRIVER", Some("opendal")),
            ("ROOTYARD_BLOB_SERVICE", Some("s3")),
            ("ROOTYARD_BLOB_BUCKET", Some("read-accel-test-bucket")),
            ("ROOTYARD_BLOB_REGION", Some("us-east-1")),
            ("ROOTYARD_BLOB_ROOT", Some("read-accel-it")),
            ("ROOTYARD_BLOB_ENDPOINT", Some(self.endpoint.as_str())),
            ("ROOTYARD_BLOB_ACCESS_KEY_ID", Some("test-ak")),
            ("ROOTYARD_BLOB_SECRET_ACCESS_KEY", Some("test-sk")),
            ("ROOTYARD_BLOB_ENCRYPTION_MODE", Some("provider-managed")),
            ("ROOTYARD_BLOB_RETRY_MAX_TIMES", Some("0")),
            ("ROOTYARD_BLOB_MAX_OBJECT_BYTES", Some("8388608")),
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

    fn put_raw(&self, locator: &BlobLocator, data: Vec<u8>) {
        self.state.objects.lock().unwrap().insert(Self::key(locator), data);
    }

    fn mutate_object(&self, locator: &BlobLocator, truncate_to: Option<usize>) {
        let mut objs = self.state.objects.lock().unwrap();
        let key = Self::key(locator);
        match truncate_to {
            Some(0) => drop(objs.remove(&key)),
            Some(len) => {
                if let Some(bytes) = objs.get_mut(&key) {
                    bytes.truncate(len);
                }
            }
            None => {
                if let Some(bytes) = objs.get_mut(&key)
                    && !bytes.is_empty()
                {
                    let mid = bytes.len() / 2;
                    bytes[mid] ^= 0xff;
                }
            }
        }
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

fn git_cmd(repo: &Path, args: &[&str]) -> Result<std::process::Output> {
    Ok(Command::new("git")
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
        .output()?)
}

fn git_ok(repo: &Path, args: &[&str]) -> Result<String> {
    let out = git_cmd(repo, args)?;
    ensure!(out.status.success(), "git {:?} failed: {}", args, String::from_utf8_lossy(&out.stderr));
    Ok(String::from_utf8(out.stdout)?.trim().to_owned())
}

fn commit_files(root: &Path, prefix: &str, count: usize) -> Result<()> {
    for i in 0..count {
        std::fs::write(root.join(format!("{prefix}-{i}.txt")), format!("{prefix}-{i}\n"))?;
        for args in [&["add", "."][..], &["commit", "-m", &format!("{prefix} {i}")]] {
            git_ok(root, args)?;
        }
    }
    Ok(())
}

struct SampleRepoPacks {
    work_dir: TempDir,
    tenant_id: Uuid,
    repo_id: Uuid,
    history_id: Uuid,
    format: ReadAccelObjectFormat,
    packs: Vec<AuthoritativePackSource>,
    refs: Vec<AuthoritativeRef>,
    base_commit: String,
}

impl SampleRepoPacks {
    fn seed(format: ReadAccelObjectFormat, multi_pack: bool) -> Result<Self> {
        let work_dir = TempDir::new()?;
        let root = work_dir.path();
        git_ok(root, &["init", format.git_init_flag(), "--initial-branch=main"])?;
        commit_files(root, "base", 4)?;
        let base_commit = git_ok(root, &["rev-parse", "HEAD"])?;
        git_ok(root, &["checkout", "-b", "feature"])?;
        commit_files(root, "feat", 3)?;
        git_ok(root, &["checkout", "main"])?;
        commit_files(root, "main", 1)?;
        let main_tip = git_ok(root, &["rev-parse", "HEAD"])?;
        git_ok(root, &["repack", "-ad", "--no-write-bitmap-index"])?;
        if multi_pack {
            git_ok(root, &["checkout", "feature"])?;
            commit_files(root, "extra", 1)?;
            git_ok(root, &["repack", "--no-write-bitmap-index"])?;
        }
        let feature_tip = git_ok(root, &["rev-parse", "refs/heads/feature"])?;
        let tenant_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let mut sample = Self {
            work_dir,
            tenant_id,
            repo_id,
            history_id: Uuid::new_v4(),
            format,
            packs: Vec::new(),
            refs: vec![
                AuthoritativeRef::new("refs/heads/main", main_tip),
                AuthoritativeRef::new("refs/heads/feature", feature_tip),
            ],
            base_commit,
        };
        sample.packs = sample.collect_and_upload_packs()?;
        Ok(sample)
    }

    fn collect_and_upload_packs(&self) -> Result<Vec<AuthoritativePackSource>> {
        let pack_dir = self.work_dir.path().join(".git/objects/pack");
        let mut stems: Vec<_> = std::fs::read_dir(&pack_dir)?
            .filter_map(|e| e.ok()?.file_name().to_str()?.strip_suffix(".pack").map(str::to_owned))
            .collect();
        stems.sort();
        ensure!(!stems.is_empty());
        let s3 = LoopbackS3::shared();
        let mut packs = Vec::new();
        for stem in stems {
            let mk = |ext: &str| -> Result<BlobLocator> {
                let bytes = std::fs::read(pack_dir.join(format!("{stem}.{ext}")))?;
                let loc = BlobLocator::new(
                    self.tenant_id,
                    self.repo_id,
                    1,
                    Uuid::new_v4(),
                    "packs",
                    &hex::encode(Sha256::digest(&bytes)),
                    bytes.len() as u64,
                )?;
                s3.put_raw(&loc, bytes);
                Ok(loc)
            };
            packs.push(AuthoritativePackSource::provider_managed(stem.clone(), mk("pack")?, mk("idx")?));
        }
        Ok(packs)
    }

    async fn open_with_packs(
        &self,
        ctx: &TestCtx,
        gen_num: u64,
        packs: &[AuthoritativePackSource],
        refs: &[AuthoritativeRef],
        bundle_on: (Option<&BuiltReadAccelBundle>, bool),
        registry: Option<PackRetentionRegistry>,
    ) -> Result<MaterializedAccelView> {
        let (bundle, enabled) = bundle_on;
        let manifest_ref = bundle
            .map(|b| ManifestFetchRef { locator: b.manifest_locator.clone(), envelope: b.manifest_envelope.clone() });
        let config = if enabled { ReadAccelConfig::enabled_default() } else { ReadAccelConfig::default() };
        let req = MaterializeViewRequest {
            tenant_id: self.tenant_id,
            repo_id: self.repo_id,
            history_id: self.history_id,
            object_format: self.format,
            expected_membership_generation: gen_num,
            authoritative_packs: packs.to_vec(),
            refs: refs.to_vec(),
            manifest_ref,
            config,
            retention_registry: registry,
            key_provider: None,
        };
        Ok(materialize_git_view_with_read_accel(&ctx.store, &ctx.vr, &req, ctx.dl).await?)
    }

    async fn build(
        &self,
        ctx: &TestCtx,
        gen_num: u64,
        blob_gen: i64,
        packs: &[AuthoritativePackSource],
        reg: Option<PackRetentionRegistry>,
    ) -> Result<BuiltReadAccelBundle> {
        let req = BuildReadAccelRequest {
            tenant_id: self.tenant_id,
            repo_id: self.repo_id,
            history_id: self.history_id,
            object_format: self.format,
            membership_generation: gen_num,
            blob_generation: blob_gen,
            config: ReadAccelConfig::enabled_default(),
            packs: packs.to_vec(),
            refs: self.refs.clone(),
            retention_registry: reg,
            key_provider: None,
        };
        Ok(build_and_upload_sidecars(&ctx.store, &ctx.vr, &req, ctx.dl).await?)
    }

    async fn open(
        &self,
        ctx: &TestCtx,
        gen_n: u64,
        b: Option<&BuiltReadAccelBundle>,
        on: bool,
    ) -> Result<MaterializedAccelView> {
        self.open_with_packs(ctx, gen_n, &self.packs, &self.refs, (b, on), None).await
    }
}

struct TestCtx {
    store: BlobStore,
    vr: DisposableViewRoot,
    _dir: TempDir,
    dl: Instant,
}

fn test_ctx() -> Result<TestCtx> {
    let _dir = TempDir::new()?;
    let vr = DisposableViewRoot::open(&_dir.path().join("views"), 8, 64 << 20, Duration::from_secs(120))?;
    Ok(TestCtx { store: LoopbackS3::shared().open_store()?, vr, _dir, dl: Instant::now() + Duration::from_secs(60) })
}

fn assert_git_parity(expected_repo: &Path, candidate_repo: &Path, sample: &SampleRepoPacks) -> Result<()> {
    let (main_tip, feature_tip) = (&sample.refs[0].oid, &sample.refs[1].oid);
    for args in [&["rev-list", "--all"][..], &["rev-list", "--count", "--all"], &["merge-base", main_tip, feature_tip]]
    {
        ensure!(git_ok(expected_repo, args)? == git_ok(candidate_repo, args)?, "mismatch on {:?}", args);
    }
    for (anc, tip, want) in [(&sample.base_commit, main_tip, 0), (feature_tip, main_tip, 1)] {
        ensure!(git_cmd(expected_repo, &["merge-base", "--is-ancestor", anc, tip])?.status.code() == Some(want));
        ensure!(git_cmd(candidate_repo, &["merge-base", "--is-ancestor", anc, tip])?.status.code() == Some(want));
    }
    let objs = |repo: &Path| -> Result<Vec<String>> {
        let mut v: Vec<_> =
            git_ok(repo, &["cat-file", "--batch-check", "--batch-all-objects"])?.lines().map(str::to_owned).collect();
        v.sort();
        Ok(v)
    };
    ensure!(objs(expected_repo)? == objs(candidate_repo)?, "cat-file object inventory mismatch");
    Ok(())
}

#[tokio::test]
async fn sha1_and_sha256_parity_and_default_disabled_behavior() -> Result<()> {
    ensure!(!ENABLE_BY_DEFAULT && !ReadAccelConfig::default().enabled);
    let ctx = test_ctx()?;
    for format in [ReadAccelObjectFormat::Sha1, ReadAccelObjectFormat::Sha256] {
        let sample = SampleRepoPacks::seed(format, false)?;
        let disabled_view = sample.open(&ctx, 1, None, false).await?;
        ensure!(
            *disabled_view.status() == ReadAccelSidecarStatus::Disabled
                && disabled_view.metrics().sidecar_get_attempts == 0
        );
        let bundle = sample.build(&ctx, 1, 1, &sample.packs, None).await?;
        ensure!(bundle.manifest.artifacts.len() == 3);
        let enabled_view = sample.open(&ctx, 1, Some(&bundle), true).await?;
        ensure!(
            *enabled_view.status() == ReadAccelSidecarStatus::Applied && enabled_view.metrics().sidecars_applied == 3
        );
        let enabled_path = enabled_view.repo_path()?;
        git_ok(enabled_path, &["multi-pack-index", "verify"])?;
        git_ok(enabled_path, &["commit-graph", "verify"])?;
        ensure!(
            git_ok(enabled_path, &["rev-list", "--count", "--use-bitmap-index", "--all"])?
                == git_ok(disabled_view.repo_path()?, &["rev-list", "--count", "--all"])?
        );
        assert_git_parity(disabled_view.repo_path()?, enabled_path, &sample)?;
    }
    Ok(())
}

#[tokio::test]
async fn fault_injection_drift_missing_corrupt_and_local_cache_recovery() -> Result<()> {
    use ReadAccelFallbackReason::{
        MembershipGenerationDrift, PackSetDigestDrift, SidecarArtifactCorrupt, SidecarArtifactMissing,
    };
    use ReadAccelSidecarStatus::FallbackToAuthoritativePackOnly as Fallback;
    let s3 = LoopbackS3::shared();
    let ctx = test_ctx().context("phase: test context")?;
    let sample = SampleRepoPacks::seed(ReadAccelObjectFormat::Sha1, true).context("phase: seed sample")?;
    let baseline = sample.open(&ctx, 1, None, false).await.context("phase: baseline open")?;
    let bundle = sample.build(&ctx, 1, 1, &sample.packs, None).await.context("phase: baseline build")?;

    // 1. Membership drift & pack-set drift fail closed before sidecar GETs.
    let drift_view = sample.open(&ctx, 2, Some(&bundle), true).await.context("phase: membership drift open")?;
    ensure!(matches!(drift_view.status(), Fallback(MembershipGenerationDrift { expected: 2, manifest: 1 })));
    ensure!(drift_view.metrics().sidecar_get_attempts == 1);
    assert_git_parity(
        baseline.repo_path().context("phase: membership drift parity")?,
        drift_view.repo_path().context("phase: membership drift parity")?,
        &sample,
    )
    .context("phase: membership drift parity")?;
    let subset_view = sample
        .open_with_packs(&ctx, 1, &sample.packs[..1], &[], (Some(&bundle), true), None)
        .await
        .context("phase: pack subset open")?;
    ensure!(matches!(subset_view.status(), Fallback(PackSetDigestDrift)));

    // 2. Local cache tamper scrubs sidecars cleanly; cleared-cache rebuild restores Applied view.
    let cached_view = sample.open(&ctx, 1, Some(&bundle), true).await.context("phase: cached open")?;
    ensure!(
        *cached_view.status() == ReadAccelSidecarStatus::Applied,
        "phase: cached open expected applied, got {}",
        finite_status_label(cached_view.status())
    );
    let bm_path = cached_view
        .repo_path()
        .context("phase: cached bitmap path")?
        .join(&bundle.manifest.artifact(ReadAccelArtifactKind::Bitmap).unwrap().relative_path);
    let bm_meta = std::fs::metadata(&bm_path).context("phase: cached bitmap stat")?;
    ensure!(bm_meta.is_file(), "phase: cached bitmap stat expected regular file");
    ensure!(bm_meta.len() > 8, "phase: cached bitmap stat too small for byte-8 tamper");
    std::fs::set_permissions(&bm_path, Permissions::from_mode(0o644)).context("phase: cached bitmap chmod")?;
    let mut raw = std::fs::read(&bm_path).context("phase: cached bitmap read")?;
    ensure!(raw.len() > 8, "phase: cached bitmap tamper too small for byte-8 tamper");
    raw[8] ^= 0xff;
    std::fs::write(&bm_path, raw).context("phase: cached bitmap tamper write")?;
    let recovered_path = cached_view.repo_path().context("phase: cached bitmap recover")?;
    let (status, removed) = verify_and_recover_view_sidecars(recovered_path, Some(&bundle.manifest), ctx.dl)
        .await
        .context("phase: cached bitmap recover")?;
    ensure!(
        matches!(status, Fallback(SidecarArtifactCorrupt { kind: ReadAccelArtifactKind::Bitmap, .. }))
            && removed.len() == 3
            && !recovered_path.join("objects/pack/multi-pack-index").exists()
    );
    assert_git_parity(baseline.repo_path().context("phase: cached recovered parity")?, recovered_path, &sample)
        .context("phase: cached recovered parity")?;
    cached_view.reap();
    let rebuilt = sample.open(&ctx, 1, Some(&bundle), true).await.context("phase: reaped rebuild open")?;
    ensure!(*rebuilt.status() == ReadAccelSidecarStatus::Applied);
    rebuilt.reap();

    // 3. Bit-flipped MIDX, truncated CommitGraph, and deleted Bitmap Blob all quarantine & fall back cleanly.
    let bundle2 =
        sample.build(&ctx, 1, 2, &sample.packs, None).await.context("phase: remote-fault build commit-graph+bitmap")?;
    for (kind, target_bundle, op, want_missing, require_midx_quarantine) in [
        (ReadAccelArtifactKind::Midx, &bundle, None, false, false),
        (ReadAccelArtifactKind::CommitGraph, &bundle2, Some(12), false, true),
        (ReadAccelArtifactKind::Bitmap, &bundle2, Some(0), true, true),
    ] {
        let (mutate_phase, open_phase, quarantine_phase, parity_phase) = match kind {
            ReadAccelArtifactKind::Midx => (
                "phase: remote-fault midx mutate",
                "phase: remote-fault midx open",
                "phase: remote-fault midx quarantine",
                "phase: remote-fault midx parity",
            ),
            ReadAccelArtifactKind::CommitGraph => (
                "phase: remote-fault commit-graph mutate",
                "phase: remote-fault commit-graph open",
                "phase: remote-fault commit-graph quarantine",
                "phase: remote-fault commit-graph parity",
            ),
            ReadAccelArtifactKind::Bitmap => (
                "phase: remote-fault bitmap mutate",
                "phase: remote-fault bitmap open",
                "phase: remote-fault bitmap quarantine",
                "phase: remote-fault bitmap parity",
            ),
        };
        s3.mutate_object(
            &target_bundle.manifest.artifact(kind).unwrap().locator.to_locator().context(mutate_phase)?,
            op,
        );
        let view = sample.open(&ctx, 1, Some(target_bundle), true).await.context(open_phase)?;
        ensure!(
            match (view.status(), want_missing) {
                (Fallback(SidecarArtifactMissing(k)), true) => *k == kind,
                (Fallback(SidecarArtifactCorrupt { kind: k, .. }), false) => *k == kind,
                _ => false,
            },
            "unexpected fallback status: {}",
            finite_status_label(view.status())
        );
        if require_midx_quarantine {
            ensure!(view.metrics().quarantined_sidecar_paths.iter().any(|p| p == "objects/pack/multi-pack-index"));
            ensure!(!view.repo_path().context(quarantine_phase)?.join("objects/pack/multi-pack-index").exists());
        }
        assert_git_parity(
            baseline.repo_path().context(parity_phase)?,
            view.repo_path().context(parity_phase)?,
            &sample,
        )
        .context(parity_phase)?;
    }
    Ok(())
}

fn finite_status_label(status: &ReadAccelSidecarStatus) -> &'static str {
    match status {
        ReadAccelSidecarStatus::Disabled => "disabled",
        ReadAccelSidecarStatus::Applied => "applied",
        ReadAccelSidecarStatus::FallbackToAuthoritativePackOnly(reason) => match reason {
            ReadAccelFallbackReason::NoManifestConfigured => "fallback/no-manifest",
            ReadAccelFallbackReason::ManifestFetchFailed(_) => "fallback/manifest-fetch-failed",
            ReadAccelFallbackReason::ManifestInvalid(_) => "fallback/manifest-invalid",
            ReadAccelFallbackReason::TenantRepoHistoryMismatch => "fallback/tenant-repo-history-mismatch",
            ReadAccelFallbackReason::ObjectFormatMismatch => "fallback/object-format-mismatch",
            ReadAccelFallbackReason::MembershipGenerationDrift { .. } => "fallback/membership-generation-drift",
            ReadAccelFallbackReason::PackSetDigestDrift => "fallback/pack-set-digest-drift",
            ReadAccelFallbackReason::SidecarArtifactMissing(_) => "fallback/sidecar-artifact-missing",
            ReadAccelFallbackReason::SidecarArtifactCorrupt { .. } => "fallback/sidecar-artifact-corrupt",
            ReadAccelFallbackReason::GitSidecarVerificationFailed { .. } => "fallback/git-sidecar-verification-failed",
        },
    }
}

#[tokio::test]
async fn retention_pin_protects_packs_until_release_and_compaction_rebuild() -> Result<()> {
    let ctx = test_ctx()?;
    let sample = SampleRepoPacks::seed(ReadAccelObjectFormat::Sha1, true)?;
    ensure!(sample.packs.len() >= 2);
    let registry = PackRetentionRegistry::new();
    let gen1 = sample.build(&ctx, 1, 1, &sample.packs, Some(registry.clone())).await?;
    let active_view = sample
        .open_with_packs(&ctx, 1, &sample.packs, &sample.refs, (Some(&gen1), true), Some(registry.clone()))
        .await?;
    ensure!(
        registry.is_pack_pinned(&sample.packs[0].pack_locator) && registry.is_pack_pinned(&sample.packs[0].idx_locator)
    );
    let baseline = sample.open(&ctx, 1, None, false).await?;
    active_view.reap();
    ensure!(!registry.is_pack_pinned(&sample.packs[0].pack_locator) && registry.pinned_locator_count() == 0);

    git_ok(sample.work_dir.path(), &["repack", "-ad", "--no-write-bitmap-index"])?;
    let compacted_packs = sample.collect_and_upload_packs()?;
    ensure!(compacted_packs.len() == 1);
    let gen2 = sample.build(&ctx, 2, 2, &compacted_packs, Some(registry)).await?;
    let gen2_view = sample.open_with_packs(&ctx, 2, &compacted_packs, &sample.refs, (Some(&gen2), true), None).await?;
    ensure!(*gen2_view.status() == ReadAccelSidecarStatus::Applied);
    git_ok(gen2_view.repo_path()?, &["multi-pack-index", "verify"])?;
    assert_git_parity(baseline.repo_path()?, gen2_view.repo_path()?, &sample)?;
    Ok(())
}
