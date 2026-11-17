//! Real OpenDAL S3 + stock Git (`sha1` & `sha256`) integration and adversarial
//! tests for Issue #181 Merkle directory manifest, convergence, and sync.

use std::{
    collections::BTreeMap,
    fs,
    future::Future,
    os::unix::ffi::OsStringExt,
    os::unix::fs::{PermissionsExt, symlink},
    path::Path,
    pin::Pin,
    process::Command,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

use anyhow::{Result, ensure};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::State,
    http::{Method, StatusCode, Uri, header},
    response::Response,
};
use opendal::{Operator, services::S3};
use rootyard::blob_store::{config::BlobProfile, opendal::BlobStore};
use rootyard::workspace_lab::merkle_sync::{
    self as ms, authz::WorkspaceAuthorizer as _, backup_restore::RestoreBackupParams,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use uuid::Uuid;

type ObjMap = Arc<Mutex<BTreeMap<String, Vec<u8>>>>;

struct LoopbackS3 {
    endpoint: String,
    objects: ObjMap,
}
struct OpenDalDriver {
    op: Operator,
}

static SHARED_S3: OnceLock<LoopbackS3> = OnceLock::new();
static ENV_LOCK: Mutex<()> = Mutex::new(());

impl LoopbackS3 {
    fn shared() -> &'static Self {
        SHARED_S3.get_or_init(|| {
            let objects: ObjMap = Arc::default();
            let (srv, l) = (Arc::clone(&objects), std::net::TcpListener::bind("127.0.0.1:0").unwrap());
            l.set_nonblocking(true).unwrap();
            let (port, (tx, rx)) = (l.local_addr().unwrap().port(), std::sync::mpsc::sync_channel(1));
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
                rt.block_on(async move {
                    let l = tokio::net::TcpListener::from_std(l).unwrap();
                    let _ = tx.send(());
                    let _ = axum::serve(l, Router::new().fallback(handle_s3).with_state(srv)).await;
                });
            });
            rx.recv().unwrap();
            Self { endpoint: format!("http://127.0.0.1:{port}"), objects }
        })
    }

    fn open_store(&self, root: &str) -> Result<BlobStore> {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let fixed = "DRIVER=opendal SERVICE=s3 BUCKET=merkle-test-bucket REGION=us-east-1 ACCESS_KEY_ID=test-ak SECRET_ACCESS_KEY=test-sk ENCRYPTION_MODE=provider-managed RETRY_MAX_TIMES=0 MAX_OBJECT_BYTES=8388608";
        let mut pairs: Vec<(String, Option<String>)> = fixed
            .split(' ')
            .map(|kv| {
                let (k, v) = kv.split_once('=').unwrap();
                (format!("ROOTYARD_BLOB_{k}"), Some(v.into()))
            })
            .collect();
        pairs.extend([
            ("ROOTYARD_BLOB_ROOT".into(), Some(root.into())),
            ("ROOTYARD_BLOB_ENDPOINT".into(), Some(self.endpoint.clone())),
            ("ROOTYARD_BLOB_KEYRING_DIR".into(), None),
        ]);
        let saved: Vec<_> = pairs.iter().map(|(k, _)| (k.clone(), std::env::var_os(k))).collect();
        for (k, v) in &pairs {
            unsafe { if let Some(val) = v { std::env::set_var(k, val) } else { std::env::remove_var(k) } }
        }
        let res = BlobStore::open(BlobProfile::from_env()?);
        for (k, old) in saved {
            unsafe { if let Some(val) = old { std::env::set_var(k, val) } else { std::env::remove_var(k) } }
        }
        Ok(res?)
    }

    fn driver(&self, root: &str) -> OpenDalDriver {
        let b = S3::default()
            .bucket("merkle-test-bucket")
            .root(root)
            .region("us-east-1")
            .endpoint(&self.endpoint)
            .disable_config_load()
            .disable_ec2_metadata()
            .access_key_id("test-ak")
            .secret_access_key("test-sk");
        OpenDalDriver { op: Operator::new(b).unwrap().finish() }
    }

    fn key(root: &str, path: &str) -> String {
        format!("merkle-test-bucket/{root}/{path}")
    }
}

async fn handle_s3(State(objs): State<ObjMap>, method: Method, uri: Uri, body: Bytes) -> Response {
    let (key, etag) = (uri.path().trim_start_matches('/').to_owned(), |d: &[u8]| {
        format!("\"{}\"", &hex::encode(Sha256::digest(d))[..32])
    });
    let reply = |code: StatusCode, t: Option<String>, len: usize, b: Body| {
        let mut r = Response::builder().status(code).header(header::CONTENT_LENGTH, len.to_string());
        if let Some(v) = t {
            r = r.header(header::ETAG, v);
        }
        r.body(b).unwrap()
    };
    match method {
        Method::PUT => {
            let t = etag(&body);
            objs.lock().unwrap().insert(key, body.to_vec());
            reply(StatusCode::OK, Some(t), 0, Body::empty())
        }
        Method::HEAD | Method::GET => match objs.lock().unwrap().get(&key).cloned() {
            Some(d) => reply(
                StatusCode::OK,
                Some(etag(&d)),
                d.len(),
                if method == Method::HEAD { Body::empty() } else { Body::from(d) },
            ),
            None => reply(StatusCode::NOT_FOUND, None, 0, Body::empty()),
        },
        _ => reply(StatusCode::METHOD_NOT_ALLOWED, None, 0, Body::empty()),
    }
}

impl ms::BlobUploadDriver for OpenDalDriver {
    fn upload_verified<'a>(
        &'a self,
        store: &'a BlobStore,
        tenant_id: Uuid,
        authority_id: Uuid,
        generation: i64,
        namespace: &'a str,
        sha256: &'a str,
        length: u64,
        source_path: &'a Path,
        deadline: Instant,
    ) -> Pin<Box<dyn Future<Output = Result<rootyard::blob_store::BlobReceipt, ms::MerkleSyncError>> + Send + 'a>> {
        Box::pin(async move {
            let intent = store.new_upload(tenant_id, authority_id, generation, namespace, sha256, length)?;
            let data = fs::read(source_path)?;
            if data.len() as u64 != length || hex::encode(Sha256::digest(&data)) != sha256 {
                return Err(ms::MerkleSyncError::IntegrityMismatch("source mismatch".into()));
            }
            self.op.write(&intent.locator().path(), data).await.map_err(|e| ms::MerkleSyncError::Io(e.to_string()))?;
            Ok(store.verify(intent.locator(), deadline).await?)
        })
    }
}

fn git_ok(repo: &Path, args: &[&str]) -> Result<String> {
    let out = Command::new("git")
        .args(["-c", "core.hooksPath=/dev/null", "--no-replace-objects", "-C"])
        .arg(repo)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "r")
        .env("GIT_AUTHOR_EMAIL", "r@e")
        .env("GIT_COMMITTER_NAME", "r")
        .env("GIT_COMMITTER_EMAIL", "r@e")
        .output()?;
    ensure!(out.status.success(), "git {:?} failed: {}", args, String::from_utf8_lossy(&out.stderr));
    Ok(String::from_utf8(out.stdout)?.trim().to_owned())
}

fn seed_git_repo(repo: &Path, fmt: &str, files: &[(&str, &[u8])]) -> Result<()> {
    fs::create_dir_all(repo)?;
    git_ok(repo, &["init", &format!("--object-format={fmt}"), "--initial-branch=main"])?;
    for &(rel, body) in files {
        let p = repo.join(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(p, body)?;
    }
    git_ok(repo, &["add", "--all"])?;
    git_ok(repo, &["commit", "-m", "seed"])?;
    Ok(())
}

struct SyncEnv {
    root_prefix: String,
    store: BlobStore,
    driver: OpenDalDriver,
    ledger: ms::MerkleCheckpointLedger,
    holds: ms::PinHoldRegistry,
    fences: ms::HistoryFenceRegistry,
    auth: ms::LiveWorkspaceAuthRegistry,
    dir: TempDir,
}

impl SyncEnv {
    fn new(tag: &str) -> Result<Self> {
        let (s3, root_prefix, fences, dir) = (
            LoopbackS3::shared(),
            format!("{tag}-{}", Uuid::new_v4().simple()),
            ms::HistoryFenceRegistry::new(),
            TempDir::new()?,
        );
        Ok(Self {
            store: s3.open_store(&root_prefix)?,
            driver: s3.driver(&root_prefix),
            ledger: ms::MerkleCheckpointLedger::new(),
            holds: ms::PinHoldRegistry::new(),
            auth: ms::LiveWorkspaceAuthRegistry::new(fences.clone()),
            fences,
            root_prefix,
            dir,
        })
    }

    fn grant_ctx(&self) -> Result<ms::AccessContext> {
        let (t, r, h, u, ws) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        self.fences.register_active(t, r, h)?;
        self.auth.grant_user(t, r, u, true, true);
        Ok(ms::AccessContext {
            tenant_id: t,
            repo_id: r,
            user_id: u,
            history_id: h,
            workspace_id: ws,
            lease_epoch: 1,
            request_id: Uuid::new_v4(),
        })
    }

    async fn up(
        &self,
        ctx: &ms::AccessContext,
        repo: &Path,
        pol: ms::EmptyDirPolicy,
        prev: Option<&ms::MerkleStateManifest>,
    ) -> Result<(ms::ScanResult, ms::SyncUploadReport)> {
        self.up_opts(ctx, repo, pol, prev, ms::DirtyScope::FullRescan, None).await
    }

    async fn up_abort(&self, ctx: &ms::AccessContext, repo: &Path, pol: ms::EmptyDirPolicy) -> Result<()> {
        let _ = self
            .up_opts(ctx, repo, pol, None, ms::DirtyScope::FullRescan, Some(ms::UploadFailpoint::BeforeAtomicCommit))
            .await?;
        Ok(())
    }

    async fn up_opts(
        &self,
        ctx: &ms::AccessContext,
        repo: &Path,
        pol: ms::EmptyDirPolicy,
        prev: Option<&ms::MerkleStateManifest>,
        dirty_scope: ms::DirtyScope,
        fp: Option<ms::UploadFailpoint>,
    ) -> Result<(ms::ScanResult, ms::SyncUploadReport)> {
        let (gs, ig, bundle) =
            ms::read_git_state_and_bundle(repo, ms::UntrackedPolicy::IncludeNonIgnored, pol, true, true)?;
        let scan = ms::MerkleWorkspaceScanner::scan(ms::ScanRequest {
            repo_root: repo,
            workspace_id: ctx.workspace_id,
            checkpoint_id: Uuid::new_v4(),
            tenant_id: ctx.tenant_id,
            repo_id: ctx.repo_id,
            history_id: ctx.history_id,
            parent_checkpoint_id: prev.map(|p| p.checkpoint_id),
            chunk_size_bytes: 16 * 1024,
            git_state: &gs,
            ignore: &ig,
            previous: prev,
            dirty_scope,
        })?;
        let (dl, staging) = (Instant::now() + Duration::from_secs(30), self.dir.path().join("staging"));
        let rep = ms::sync_incremental_to_blob(ms::UploadParams {
            ctx,
            authorizer: &self.auth,
            store: &self.store,
            driver: &self.driver,
            ledger: &self.ledger,
            holds: &self.holds,
            repo_root: repo,
            scan: &scan,
            git_bundle: &bundle,
            staging_dir: &staging,
            generation: 1,
            deadline: dl,
            failpoint: fp,
        })
        .await?;
        Ok((scan, rep))
    }

    async fn restore(
        &self,
        ctx: &ms::AccessContext,
        cp_id: Uuid,
        target: &Path,
        agent: &str,
    ) -> Result<ms::RestoreReport, ms::MerkleSyncError> {
        let (dl, staging) = (Instant::now() + Duration::from_secs(30), self.dir.path().join("staging"));
        ms::restore_or_fork_from_blob(ms::RestoreRequest {
            ctx,
            authorizer: &self.auth,
            store: &self.store,
            ledger: &self.ledger,
            holds: &self.holds,
            checkpoint_id: cp_id,
            target_empty_dir: target,
            new_workspace_id: Uuid::new_v4(),
            agent_id: agent,
            staging_parent: &staging,
            deadline: dl,
        })
        .await
    }
}

#[tokio::test]
async fn sha256_watcher_converge_incremental_sync_and_cross_node_restore() -> Result<()> {
    let h = SyncEnv::new("merkle-sha256")?;
    let ctx = h.grant_ctx()?;
    let repo = h.dir.path().join("src256");
    seed_git_repo(&repo, "sha256", &[(".gitignore", b"*.log\n"), ("a/keep.txt", b"keep\n"), ("b/mut.txt", b"v1\n")])?;
    let (base, _) = h.up(&ctx, &repo, ms::EmptyDirPolicy::RetainNonIgnoredEmptyDirs, None).await?;

    let non_utf = std::ffi::OsString::from_vec(b"raw-\xff\xfe.bin".to_vec());
    fs::write(repo.join(&non_utf), b"nonutf-bytes\n")?;
    fs::write(repo.join("b/mut.txt"), b"v2-converged\n")?;
    fs::write(repo.join("skip.log"), b"ignored\n")?;
    fs::create_dir_all(repo.join("retained_dir"))?;
    let mut co = ms::WatcherCoalescer::new();
    co.ingest(ms::WatcherBatch {
        seq_start: 1,
        seq_end: 2,
        events: vec![
            ms::WatcherEvent::Modify(b"b/mut.txt".to_vec()),
            ms::WatcherEvent::Create(b"retained_dir".to_vec()),
            ms::WatcherEvent::Create(non_utf.clone().into_vec()),
        ],
    });
    let (dirty, stats) = co.into_dirty_scope();
    let (scan, _) = h
        .up_opts(&ctx, &repo, ms::EmptyDirPolicy::RetainNonIgnoredEmptyDirs, Some(&base.manifest), dirty, None)
        .await?;
    ensure!(!stats.used_full_rescan && scan.metrics.reused_nodes > 0 && scan.metrics.retained_empty_dirs == 1);
    fs::remove_dir_all(&repo)?;

    let restored = h.dir.path().join("dst256");
    let rep = h.restore(&ctx, scan.manifest.checkpoint_id, &restored, "node-sha256").await?;
    ensure!(
        rep.merkle_root_digest == scan.manifest.merkle_root_digest
            && fs::read(restored.join(&non_utf))? == b"nonutf-bytes\n"
    );
    ensure!(restored.join("retained_dir").is_dir() && !restored.join("skip.log").exists());
    git_ok(&restored, &["fsck", "--full", "--strict"])?;
    Ok(())
}

#[tokio::test]
async fn blob_first_incremental_sync_crash_tamper_and_cross_node_restore_fork() -> Result<()> {
    let h = SyncEnv::new("merkle-sync")?;
    let ctx1 = h.grant_ctx()?;
    let src_repo = h.dir.path().join("node-a");
    let mut big_buf = vec![b'A'; 40 * 1024];
    big_buf[20 * 1024] = b'Z';
    seed_git_repo(&src_repo, "sha1", &[("pkg/big.bin", &big_buf), ("pkg/run.sh", b"#!/bin/sh\necho hi\n")])?;
    fs::set_permissions(src_repo.join("pkg/run.sh"), fs::Permissions::from_mode(0o755))?;
    symlink("run.sh", src_repo.join("pkg/cur.sh"))?;
    git_ok(&src_repo, &["add", "--all"])?;
    git_ok(&src_repo, &["commit", "-m", "init2"])?;
    fs::write(src_repo.join("pkg/run.sh"), b"#!/bin/sh\necho staged\n")?;
    git_ok(&src_repo, &["add", "pkg/run.sh"])?;
    fs::write(src_repo.join("pkg/run.sh"), b"#!/bin/sh\necho worktree\n")?;
    fs::create_dir_all(src_repo.join("empty_keep"))?;

    let (s1, up1) = h.up(&ctx1, &src_repo, ms::EmptyDirPolicy::RetainEmptyDirs, None).await?;
    ensure!(up1.closure_verified && up1.uploaded_chunks >= 3);

    big_buf[5] = b'X';
    fs::write(src_repo.join("pkg/big.bin"), &big_buf)?;
    let (s2, up2) = h.up(&ctx1, &src_repo, ms::EmptyDirPolicy::RetainEmptyDirs, Some(&s1.manifest)).await?;
    ensure!(up2.uploaded_chunks == 1 && up2.reused_chunks >= 2 && up2.reused_bytes > 0);
    let committed_before = h.ledger.committed_locator_paths().len();
    let err = h.up_abort(&ctx1, &src_repo, ms::EmptyDirPolicy::RetainEmptyDirs).await;
    ensure!(err.is_err() && h.ledger.committed_locator_paths().len() == committed_before);
    let cp2 = s2.manifest.checkpoint_id;

    fs::remove_dir_all(&src_repo)?;
    let (s3, m_key) =
        (LoopbackS3::shared(), LoopbackS3::key(&h.root_prefix, &up2.manifest_locator.to_locator()?.path()));
    let saved_m = s3.objects.lock().unwrap().remove(&m_key).unwrap();
    let restore_fail = h.dir.path().join("node-b-fail");
    ensure!(h.restore(&ctx1, cp2, &restore_fail, "b").await.is_err() && !restore_fail.exists());

    s3.objects.lock().unwrap().insert(m_key.clone(), {
        let mut t = saved_m.clone();
        t[0] ^= 0xff;
        t
    });
    ensure!(h.restore(&ctx1, cp2, &restore_fail, "b").await.is_err());
    s3.objects.lock().unwrap().insert(m_key, saved_m);

    for (agent, sub) in [("node-b", "restored-b"), ("node-c-fork", "forked-c")] {
        let target = h.dir.path().join(sub);
        let rep = h.restore(&ctx1, cp2, &target, agent).await?;
        ensure!(
            rep.merkle_root_digest == s2.manifest.merkle_root_digest
                && rep.restored_empty_dirs == 1
                && rep.restored_symlinks == 1
        );
        git_ok(&target, &["fsck", "--full", "--strict"])?;
        ensure!(fs::read(target.join("pkg/big.bin"))? == big_buf && target.join("empty_keep").is_dir());
    }
    Ok(())
}

#[tokio::test]
async fn authz_tenant_isolation_history_fence_pins_gc_and_backup_restore() -> Result<()> {
    let h = SyncEnv::new("merkle-sec")?;
    let (ctx_a, ctx_b) = (h.grant_ctx()?, h.grant_ctx()?);
    let (repo_a, repo_b) = (h.dir.path().join("repo-a"), h.dir.path().join("repo-b"));
    seed_git_repo(&repo_a, "sha1", &[("shared.txt", b"identical-secret-payload\n")])?;
    seed_git_repo(&repo_b, "sha1", &[("shared.txt", b"identical-secret-payload\n")])?;
    let (sa, up_a) = h.up(&ctx_a, &repo_a, ms::EmptyDirPolicy::IgnoreEmptyDirs, None).await?;
    let (_, up_b) = h.up(&ctx_b, &repo_b, ms::EmptyDirPolicy::IgnoreEmptyDirs, None).await?;
    let cp_a = sa.manifest.checkpoint_id;
    ensure!(
        up_b.reused_chunks == 0
            && up_b.uploaded_chunks > 0
            && h.restore(&ctx_b, cp_a, &h.dir.path().join("x-tenant"), "b").await.is_err()
    );

    let (dl, staging) = (Instant::now() + Duration::from_secs(30), h.dir.path().join("staging"));
    let (backup, backup_hold) = ms::backup_restore::export_checkpoint_backup(
        &ctx_a, &h.auth, &h.store, &h.ledger, &h.holds, cp_a, &staging, dl,
    )
    .await?;
    let _ = h.up_abort(&ctx_a, &repo_a, ms::EmptyDirPolicy::IgnoreEmptyDirs).await;
    let gc = h.holds.plan_gc_sweep(&h.ledger.all_issued_locators(), &h.ledger.committed_locator_paths());
    ensure!(
        gc.protected_locators.contains(&up_a.manifest_locator.to_locator()?.path())
            && !gc.gc_eligible_orphan_locators.is_empty()
    );

    h.auth.revoke_user(ctx_a.tenant_id, ctx_a.repo_id, ctx_a.user_id);
    ensure!(h.auth.authorize(&ctx_a, ms::WorkspaceAuthAction::Read).is_err());
    h.auth.grant_user(ctx_a.tenant_id, ctx_a.repo_id, ctx_a.user_id, true, true);

    let h_a2 = Uuid::new_v4();
    h.fences.advance_fence(ctx_a.tenant_id, ctx_a.repo_id, h_a2)?;
    ensure!(h.restore(&ctx_a, cp_a, &h.dir.path().join("fenced"), "a").await.is_err());

    let ctx_a2 = ms::AccessContext { history_id: h_a2, ..ctx_a };
    let (t_ledger, t_holds) = (ms::MerkleCheckpointLedger::new(), ms::PinHoldRegistry::new());
    let b_rep = ms::backup_restore::restore_checkpoint_backup(RestoreBackupParams {
        target_ctx: &ctx_a2,
        authorizer: &h.auth,
        target_store: &h.store,
        driver: &h.driver,
        target_ledger: &t_ledger,
        target_holds: &t_holds,
        bundle: &backup,
        target_empty_dir: &h.dir.path().join("restored-backup"),
        new_workspace_id: Uuid::new_v4(),
        agent_id: "backup-restorer",
        staging_parent: &staging,
        generation: 2,
        deadline: dl,
    })
    .await?;
    ensure!(b_rep.restore_report.merkle_root_digest == backup.merkle_root_digest);
    git_ok(&h.dir.path().join("restored-backup"), &["fsck", "--full", "--strict"])?;
    let _ = h.holds.release_hold(backup_hold);
    Ok(())
}
