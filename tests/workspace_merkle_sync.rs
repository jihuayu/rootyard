//! Real OpenDAL S3 + stock Git (`sha1` & `sha256`) integration and adversarial
//! tests for Issue #181 Merkle directory manifest, convergence, and sync.

use std::{
    collections::BTreeMap,
    fs,
    os::unix::ffi::OsStringExt,
    os::unix::fs::{PermissionsExt, symlink},
    path::Path,
    process::Command,
    sync::{Arc, Mutex},
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
use ms::authz::{TenantRepoScopeKey, WorkspaceAuthorizer as _};
use ms::backup_restore::{
    BackupRestoreReport as BkRep, MerkleBackupBundle as Bundle, RestoreBackupParams, compute_bundle_digest,
    export_checkpoint_backup as exp_bk, restore_checkpoint_backup,
};
use ms::git_compare::GitBundleSnapshot as Gbs;
use ms::{
    AccessContext as Ctx, DirtyScope, EmptyDirPolicy, MerkleCheckpointLedger as Ledger,
    MerkleStateManifest as Manifest, MerkleSyncError, PinHoldRegistry as Holds, RestoreReport as RestRep, ScanResult,
    SyncUploadReport as UpRep, UploadFailpoint, WatcherEvent as WE,
};
use opendal::{Operator, services::S3};
use rootyard::blob_store::{config::BlobProfile, opendal::BlobStore};
use rootyard::workspace_lab::merkle_sync::{self as ms};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use uuid::Uuid;

type ObjMap = Arc<Mutex<BTreeMap<String, Vec<u8>>>>;
type R<T> = Result<T, MerkleSyncError>;

struct LoopbackS3 {
    endpoint: String,
    objects: ObjMap,
}
struct OpenDalDriver {
    op: Operator,
}

static ENV_LOCK: Mutex<()> = Mutex::new(());

impl LoopbackS3 {
    fn start() -> Self {
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
    }

    fn open_store(&self, root: &str) -> Result<BlobStore> {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let fixed = format!(
            "DRIVER=opendal SERVICE=s3 BUCKET=merkle-test-bucket REGION=us-east-1 ACCESS_KEY_ID=test-ak SECRET_ACCESS_KEY=test-sk ENCRYPTION_MODE=provider-managed RETRY_MAX_TIMES=3 MAX_OBJECT_BYTES=8388608 ROOT={root} ENDPOINT={}",
            self.endpoint
        );
        let mut saved = vec![("ROOTYARD_BLOB_KEYRING_DIR".into(), std::env::var_os("ROOTYARD_BLOB_KEYRING_DIR"))];
        unsafe { std::env::remove_var("ROOTYARD_BLOB_KEYRING_DIR") };
        for kv in fixed.split(' ') {
            let (k, v) = kv.split_once('=').unwrap();
            let fk = format!("ROOTYARD_BLOB_{k}");
            saved.push((fk.clone(), std::env::var_os(&fk)));
            unsafe { std::env::set_var(&fk, v) };
        }
        let res = BlobStore::open(BlobProfile::from_env()?);
        for (k, old) in saved {
            unsafe { if let Some(val) = old { std::env::set_var(k, val) } else { std::env::remove_var(k) } }
        }
        Ok(res?)
    }

    fn driver(&self, root: &str) -> OpenDalDriver {
        let b = S3::default().bucket("merkle-test-bucket").root(root).region("us-east-1").endpoint(&self.endpoint);
        let b = b.disable_config_load().disable_ec2_metadata().access_key_id("test-ak").secret_access_key("test-sk");
        OpenDalDriver { op: Operator::new(b).unwrap().finish() }
    }

    fn key(root: &str, path: &str) -> String {
        format!("merkle-test-bucket/{root}/{path}")
    }
}

async fn handle_s3(State(objs): State<ObjMap>, method: Method, uri: Uri, body: Bytes) -> Response {
    let key = uri.path().trim_start_matches('/').to_owned();
    let etag = |d: &[u8]| format!("\"{}\"", &hex::encode(Sha256::digest(d))[..32]);
    let reply = |code: StatusCode, t: Option<String>, len: usize, b: Body| {
        let r =
            Response::builder().status(code).header(header::CONTENT_LENGTH, len).header(header::CONNECTION, "close");
        t.into_iter().fold(r, |acc, v| acc.header(header::ETAG, v)).body(b).unwrap()
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
    fn upload_verified<'a>(&'a self, a: ms::UploadVerifiedArgs<'a>) -> ms::UploadVerifyFuture<'a> {
        Box::pin(async move {
            let i = a.store.new_upload(a.tenant_id, a.authority_id, a.generation, a.namespace, a.sha256, a.length)?;
            let data = fs::read(a.source_path)?;
            let ok = data.len() as u64 == a.length && hex::encode(Sha256::digest(&data)) == a.sha256;
            ok.then_some(()).ok_or_else(|| ms::MerkleSyncError::IntegrityMismatch("source mismatch".into()))?;
            self.op.write(&i.locator().path(), data).await.map_err(|e| ms::MerkleSyncError::Io(e.to_string()))?;
            Ok(a.store.verify(i.locator(), a.deadline).await?)
        })
    }
}

fn git_ok(repo: &Path, args: &[&str]) -> Result<String> {
    let mut cmd = Command::new("git");
    cmd.args(["-c", "core.hooksPath=/dev/null", "--no-replace-objects", "-C"]).arg(repo).args(args).envs([
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ("GIT_AUTHOR_NAME", "r"),
        ("GIT_AUTHOR_EMAIL", "r@e"),
        ("GIT_COMMITTER_NAME", "r"),
        ("GIT_COMMITTER_EMAIL", "r@e"),
    ]);
    let out = cmd.output()?;
    ensure!(out.status.success(), "git {:?} failed: {}", args, String::from_utf8_lossy(&out.stderr));
    Ok(String::from_utf8(out.stdout)?.trim().to_owned())
}

fn seed_git_repo(repo: &Path, fmt: &str, files: &[(&str, &[u8])]) -> Result<()> {
    fs::create_dir_all(repo)?;
    git_ok(repo, &["init", &format!("--object-format={fmt}"), "--initial-branch=main"])?;
    for &(rel, body) in files {
        let p = repo.join(rel);
        p.parent().map(fs::create_dir_all).transpose()?;
        fs::write(p, body)?;
    }
    git_ok(repo, &["add", "--all"])?;
    git_ok(repo, &["commit", "-m", "seed"])?;
    Ok(())
}

struct SyncEnv {
    s3: LoopbackS3,
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
        let (s3, root_prefix, fences) =
            (LoopbackS3::start(), format!("{tag}-{}", Uuid::new_v4().simple()), ms::HistoryFenceRegistry::new());
        let (store, driver, ledger, holds, auth) = (
            s3.open_store(&root_prefix)?,
            s3.driver(&root_prefix),
            ms::MerkleCheckpointLedger::new(),
            ms::PinHoldRegistry::new(),
            ms::LiveWorkspaceAuthRegistry::new(fences.clone()),
        );
        Ok(Self { s3, root_prefix, store, driver, ledger, holds, fences, auth, dir: TempDir::new()? })
    }

    fn dl_stage(&self) -> (Instant, std::path::PathBuf) {
        (Instant::now() + Duration::from_secs(30), self.dir.path().join("staging"))
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
        ctx: &Ctx,
        repo: &Path,
        p: EmptyDirPolicy,
        prev: Option<&Manifest>,
    ) -> Result<(ScanResult, UpRep)> {
        let sb = self.scan_only(ctx, repo, p, prev, DirtyScope::FullRescan)?;
        let up = self.upload_scan(ctx, repo, &sb, &self.ledger, None).await?;
        Ok((sb.0, up))
    }

    fn scan_only(
        &self,
        ctx: &Ctx,
        repo: &Path,
        p: EmptyDirPolicy,
        prev: Option<&Manifest>,
        ds: DirtyScope,
    ) -> Result<(ScanResult, Gbs)> {
        let (gs, ig, bundle) =
            ms::read_git_state_and_bundle(repo, ms::UntrackedPolicy::IncludeNonIgnored, p, true, true)?;
        let scan = ms::MerkleWorkspaceScanner::scan(ms::ScanRequest {
            repo_root: repo,
            workspace_id: ctx.workspace_id,
            checkpoint_id: Uuid::new_v4(),
            tenant_id: ctx.tenant_id,
            repo_id: ctx.repo_id,
            history_id: ctx.history_id,
            parent_checkpoint_id: prev.map(|m| m.checkpoint_id),
            chunk_size_bytes: 16 * 1024,
            git_state: &gs,
            ignore: &ig,
            previous: prev,
            dirty_scope: ds,
        })?;
        Ok((scan, bundle))
    }

    async fn upload_scan(
        &self,
        ctx: &Ctx,
        repo: &Path,
        sb: &(ScanResult, Gbs),
        ledger: &Ledger,
        fp: Option<UploadFailpoint>,
    ) -> R<UpRep> {
        let (deadline, staging_dir) = self.dl_stage();
        ms::sync_incremental_to_blob(ms::UploadParams {
            ctx,
            authorizer: &self.auth,
            store: &self.store,
            driver: &self.driver,
            ledger,
            holds: &self.holds,
            repo_root: repo,
            scan: &sb.0,
            git_bundle: &sb.1,
            staging_dir: &staging_dir,
            generation: 1,
            deadline,
            failpoint: fp,
        })
        .await
    }

    async fn restore(&self, ctx: &Ctx, cp: Uuid, target: &Path, agent: &str) -> R<RestRep> {
        let (deadline, staging_parent) = self.dl_stage();
        ms::restore_or_fork_from_blob(ms::RestoreRequest {
            ctx,
            authorizer: &self.auth,
            store: &self.store,
            ledger: &self.ledger,
            holds: &self.holds,
            checkpoint_id: cp,
            target_empty_dir: target,
            new_workspace_id: Uuid::new_v4(),
            agent_id: agent,
            staging_parent: &staging_parent,
            deadline,
        })
        .await
    }

    async fn rest_backup(&self, ctx: &Ctx, lh: (&Ledger, &Holds), b: &Bundle, dst: &Path) -> R<BkRep> {
        let (deadline, staging_parent) = self.dl_stage();
        restore_checkpoint_backup(RestoreBackupParams {
            target_ctx: ctx,
            authorizer: &self.auth,
            target_store: &self.store,
            driver: &self.driver,
            target_ledger: lh.0,
            target_holds: lh.1,
            bundle: b,
            target_empty_dir: dst,
            new_workspace_id: Uuid::new_v4(),
            agent_id: "backup-restorer",
            staging_parent: &staging_parent,
            generation: 2,
            deadline,
        })
        .await
    }
}

#[tokio::test]
async fn sha256_watcher_converge_incremental_sync_and_cross_node_restore() -> Result<()> {
    let h = SyncEnv::new("merkle-sha256")?;
    let (ctx, pol) = (h.grant_ctx()?, EmptyDirPolicy::RetainNonIgnoredEmptyDirs);
    let repo = h.dir.path().join("src256");
    seed_git_repo(&repo, "sha256", &[(".gitignore", b"*.log\n"), ("a/keep.txt", b"keep\n"), ("b/mut.txt", b"v1\n")])?;
    let (base, _) = h.up(&ctx, &repo, pol, None).await?;

    let non_utf = std::ffi::OsString::from_vec(b"raw-\xff\xfe.bin".to_vec());
    fs::write(repo.join(&non_utf), b"nonutf-bytes\n")?;
    fs::write(repo.join("b/mut.txt"), b"v2-converged\n")?;
    fs::write(repo.join("skip.log"), b"ignored\n")?;
    fs::create_dir_all(repo.join("retained_dir"))?;
    let mut co = ms::WatcherCoalescer::new();
    let evs = vec![
        WE::Modify(b"b/mut.txt".into()),
        WE::Create(b"retained_dir".into()),
        WE::Create(non_utf.clone().into_vec()),
    ];
    co.ingest(ms::WatcherBatch { seq_start: 1, seq_end: 2, events: evs });
    let (dirty, stats) = co.into_dirty_scope();
    let sb = h.scan_only(&ctx, &repo, pol, Some(&base.manifest), dirty)?;
    h.upload_scan(&ctx, &repo, &sb, &h.ledger, None).await?;
    ensure!(!stats.used_full_rescan && sb.0.metrics.reused_nodes > 0 && sb.0.metrics.retained_empty_dirs == 1);
    fs::remove_dir_all(&repo)?;

    let restored = h.dir.path().join("dst256");
    let rep = h.restore(&ctx, sb.0.manifest.checkpoint_id, &restored, "node-sha256").await?;
    ensure!(rep.merkle_root_digest == sb.0.manifest.merkle_root_digest);
    ensure!(
        fs::read(restored.join(&non_utf))? == b"nonutf-bytes\n"
            && restored.join("retained_dir").is_dir()
            && !restored.join("skip.log").exists()
    );
    git_ok(&restored, &["fsck", "--full", "--strict"])?;
    Ok(())
}

#[tokio::test]
async fn blob_first_incremental_sync_crash_tamper_and_cross_node_restore_fork() -> Result<()> {
    let h = SyncEnv::new("merkle-sync")?;
    let (ctx1, pol) = (h.grant_ctx()?, EmptyDirPolicy::RetainEmptyDirs);
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

    let (s1, up1) = h.up(&ctx1, &src_repo, pol, None).await?;
    ensure!(up1.closure_verified && up1.uploaded_chunks >= 3);

    big_buf[5] = b'X';
    fs::write(src_repo.join("pkg/big.bin"), &big_buf)?;
    let (s2, up2) = h.up(&ctx1, &src_repo, pol, Some(&s1.manifest)).await?;
    ensure!(up2.uploaded_chunks == 1 && up2.reused_chunks >= 2 && up2.reused_bytes > 0);
    let committed_before = h.ledger.committed_locator_paths().len();
    let ab = h.scan_only(&ctx1, &src_repo, pol, None, DirtyScope::FullRescan)?;
    let err = h.upload_scan(&ctx1, &src_repo, &ab, &h.ledger, Some(UploadFailpoint::BeforeAtomicCommit)).await;
    ensure!(err.is_err() && h.ledger.committed_locator_paths().len() == committed_before);
    let cp2 = s2.manifest.checkpoint_id;

    // Clean reused leaf lacking captured chunk_sources + scoped-cache miss + same-length post-capture edit fails closed.
    let scope_miss = DirtyScope::Subtrees {
        dirty_dirs: [b"empty_keep".to_vec()].into_iter().collect(),
        dirty_paths: Default::default(),
        force_rehash_dirs: Default::default(),
    };
    let sb_reused = h.scan_only(&ctx1, &src_repo, pol, Some(&s2.manifest), scope_miss)?;
    ensure!(sb_reused.0.chunk_sources.is_empty());
    fs::write(src_repo.join("pkg/run.sh"), b"#!/bin/sh\necho tampered\n")?;
    let miss_ledger = Ledger::new();
    let race_err = h.upload_scan(&ctx1, &src_repo, &sb_reused, &miss_ledger, None).await;
    ensure!(
        matches!(race_err, Err(MerkleSyncError::ConcurrentEdit(_))) && miss_ledger.committed_locator_paths().is_empty()
    );

    fs::remove_dir_all(&src_repo)?;
    let m_key = LoopbackS3::key(&h.root_prefix, &up2.manifest_locator.to_locator()?.path());
    let saved_m = h.s3.objects.lock().unwrap().remove(&m_key).unwrap();
    let restore_fail = h.dir.path().join("node-b-fail");
    ensure!(h.restore(&ctx1, cp2, &restore_fail, "b").await.is_err() && !restore_fail.exists());

    let mut tampered = saved_m.clone();
    tampered[0] ^= 0xff;
    h.s3.objects.lock().unwrap().insert(m_key.clone(), tampered);
    ensure!(h.restore(&ctx1, cp2, &restore_fail, "b").await.is_err());
    h.s3.objects.lock().unwrap().insert(m_key, saved_m);

    let blocker = h.dir.path().join("blocker-file");
    fs::write(&blocker, b"x")?;
    let active_before_fail = h.holds.active_hold_count();
    ensure!(h.restore(&ctx1, cp2, &blocker.join("child"), "fail").await.is_err());
    ensure!(h.holds.active_hold_count() == active_before_fail);

    for (agent, sub) in [("node-b", "restored-b"), ("node-c-fork", "forked-c")] {
        let target = h.dir.path().join(sub);
        let rep = h.restore(&ctx1, cp2, &target, agent).await?;
        ensure!(rep.merkle_root_digest == s2.manifest.merkle_root_digest);
        ensure!((rep.restored_empty_dirs, rep.restored_symlinks) == (1, 1));
        git_ok(&target, &["fsck", "--full", "--strict"])?;
        ensure!(fs::read(target.join("pkg/big.bin"))? == big_buf && target.join("empty_keep").is_dir());
    }
    Ok(())
}

#[tokio::test]
async fn authz_tenant_isolation_history_fence_pins_gc_and_backup_restore() -> Result<()> {
    let h = SyncEnv::new("merkle-sec")?;
    let ((ctx_a, ctx_b), pol) = ((h.grant_ctx()?, h.grant_ctx()?), EmptyDirPolicy::IgnoreEmptyDirs);
    let (repo_a, repo_b) = (h.dir.path().join("repo-a"), h.dir.path().join("repo-b"));
    seed_git_repo(&repo_a, "sha1", &[("shared.txt", b"identical-secret-payload\n")])?;
    seed_git_repo(&repo_b, "sha1", &[("shared.txt", b"identical-secret-payload\n")])?;
    let (sa, up_a) = h.up(&ctx_a, &repo_a, pol, None).await?;
    let (_, up_b) = h.up(&ctx_b, &repo_b, pol, None).await?;
    let cp_a = sa.manifest.checkpoint_id;
    ensure!(up_b.reused_chunks == 0 && up_b.uploaded_chunks > 0);
    ensure!(h.restore(&ctx_b, cp_a, &h.dir.path().join("x-tenant"), "b").await.is_err());

    let ((dl, staging), objs) = (h.dl_stage(), &h.s3.objects);
    let exp = || exp_bk(&ctx_a, &h.auth, &h.store, &h.ledger, &h.holds, cp_a, &staging, dl);
    let t_pat = format!("tenants/{}/", ctx_a.tenant_id);
    let ck = objs.lock().unwrap().keys().find(|k| k.contains(&t_pat) && k.contains("merkle-chunk")).unwrap().clone();
    let saved_ck = objs.lock().unwrap().remove(&ck).unwrap();
    let active_before_exp = h.holds.active_hold_count();
    ensure!(exp().await.is_err() && h.holds.active_hold_count() == active_before_exp);
    objs.lock().unwrap().insert(ck, saved_ck);
    let (backup, backup_hold) = exp().await?;
    let ab = h.scan_only(&ctx_a, &repo_a, pol, None, DirtyScope::FullRescan)?;
    let _ = h.upload_scan(&ctx_a, &repo_a, &ab, &h.ledger, Some(UploadFailpoint::BeforeAtomicCommit)).await;
    let gc = h.holds.plan_gc_sweep(&h.ledger.all_issued_locators(), &h.ledger.committed_locator_paths());
    ensure!(gc.protected_locators.contains(&up_a.manifest_locator.to_locator()?.path()));
    ensure!(!gc.gc_eligible_orphan_locators.is_empty());

    h.auth.revoke_user(ctx_a.tenant_id, ctx_a.repo_id, ctx_a.user_id);
    ensure!(h.auth.authorize(&ctx_a, ms::WorkspaceAuthAction::Read).is_err());
    h.auth.grant_user(ctx_a.tenant_id, ctx_a.repo_id, ctx_a.user_id, true, true);

    let (h_a2, h_a3) = (Uuid::new_v4(), Uuid::new_v4());
    h.fences.advance_fence(ctx_a.tenant_id, ctx_a.repo_id, h_a2)?;
    ensure!(h.restore(&ctx_a, cp_a, &h.dir.path().join("fenced"), "a").await.is_err());

    let (ctx_a2, bid) = (Ctx { history_id: h_a2, ..ctx_a }, h.store.backend_identity().as_hex());
    let ck_hex = &backup.artifacts.iter().find(|a| a.kind == "chunk").unwrap().key_digest;
    let sk = |id| TenantRepoScopeKey::new(ctx_a.tenant_id, ctx_a.repo_id, id, bid, ck_hex);
    let (mut b_miss, mut b_bad_k) = (backup.clone(), backup.clone());
    b_miss.artifacts.retain(|a| a.kind != "chunk");
    b_bad_k.artifacts.iter_mut().find(|a| a.kind == "chunk").unwrap().key_digest = format!("{:064x}", 1u8);
    let (f_ledger, f_holds) = (Ledger::new(), Holds::new());
    for mut bad in [b_miss, b_bad_k] {
        bad.bundle_sha256 = compute_bundle_digest(&bad)?;
        ensure!(h.rest_backup(&ctx_a2, (&f_ledger, &f_holds), &bad, &h.dir.path().join("bad-rest")).await.is_err());
        ensure!(f_ledger.committed_locator_paths().is_empty() && f_ledger.lookup_scoped_object(&sk(h_a2)?).is_none());
        ensure!(f_holds.active_hold_count() == 0);
    }

    let ((t_ledger, t_holds), dst_ok) = ((Ledger::new(), Holds::new()), h.dir.path().join("restored-backup"));
    let b_rep = h.rest_backup(&ctx_a2, (&t_ledger, &t_holds), &backup, &dst_ok).await?;
    ensure!(b_rep.restore_report.merkle_root_digest == backup.merkle_root_digest);
    git_ok(&dst_ok, &["fsck", "--full", "--strict"])?;

    // Re-restoring an already-committed checkpoint_id into a new fenced history fails on staging conflict cleanly.
    h.fences.advance_fence(ctx_a.tenant_id, ctx_a.repo_id, h_a3)?;
    let (ctx_a3, holds_before) = (Ctx { history_id: h_a3, ..ctx_a }, t_holds.active_hold_count());
    let p_fail = h.dir.path().join("precommit-fail");
    ensure!(h.rest_backup(&ctx_a3, (&t_ledger, &t_holds), &backup, &p_fail).await.is_err());
    ensure!(t_ledger.lookup_scoped_object(&sk(h_a3)?).is_none() && t_holds.active_hold_count() == holds_before);
    let _ = h.holds.release_hold(backup_hold);
    Ok(())
}
