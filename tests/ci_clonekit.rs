//! Integration tests for Issue #182 CloneKit: SHA-1/256 incremental fetch, Smart HTTP,
//! failed/empty/history builds, revocation/cancellation/GC pins, #36 dependencies, and PG+S3.

use std::fs::{self, Permissions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use anyhow::{Result, ensure};
use axum::body::{Body, Bytes};
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::{Router, response::Response, routing::any};
use deadpool_postgres::{Manager, Pool};
use rootyard::blob_store::{config::BlobProfile, disposable_view::DisposableViewRoot, opendal::BlobStore};
use rootyard::ci_checkouts::clonekit::{
    CloneKitObjectFormat::{Sha1, Sha256 as FmtSha256},
    *,
};
use rootyard::{
    db,
    ref_store::{
        CoreGateInit, GitObjectFormat, IssuerLane, OperationIdentity, OperationState, PgRefStore, PgRefStoreCore,
        RefName, RequestDigest,
        artifact_hold::{ArtifactHoldPurpose, HoldScope},
    },
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const SECRET: [u8; 32] = [0x42u8; 32];
const fn pol(ck: bool, fb: bool) -> CheckoutPolicy {
    CheckoutPolicy { use_clonekit: ck, fallback_to_git_on_unusable_kit: fb, require_full_fsck: true }
}

fn git_binary() -> PathBuf {
    PathBuf::from(std::env::var("ROOTYARD_TEST_GIT").unwrap_or_else(|_| "/usr/bin/git".into()))
}

fn run_git(dir: Option<&Path>, args: &[&str]) -> Result<String> {
    let mut cmd = Command::new(git_binary());
    cmd.env("GIT_TERMINAL_PROMPT", "0");
    if let Some(d) = dir {
        cmd.current_dir(d);
    }
    let out = cmd.args(args).output()?;
    ensure!(out.status.success(), "git {:?} failed: {}", args, String::from_utf8_lossy(&out.stderr));
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

fn init_repo(parent: &Path, name: &str, fmt: CloneKitObjectFormat) -> Result<PathBuf> {
    let dir = parent.join(name);
    fs::create_dir_all(&dir)?;
    for a in [
        &["init", "--quiet", fmt.git_init_flag()][..],
        &["config", "user.name", "ck"],
        &["config", "user.email", "ck@test"],
        &["config", "uploadpack.allowAnySHA1InWant", "true"],
    ] {
        run_git(Some(&dir), a)?;
    }
    Ok(dir)
}

fn add_commit(repo: &Path, file: &str, content: &[u8], msg: &str) -> Result<String> {
    let p = repo.join(file);
    if let Some(d) = p.parent() {
        fs::create_dir_all(d)?;
    }
    fs::write(&p, content)?;
    run_git(Some(repo), &["add", file])?;
    run_git(Some(repo), &["commit", "--quiet", "-m", msg])?;
    run_git(Some(repo), &["rev-parse", "HEAD"])
}

fn payload_bytes(seed: u8, len: usize) -> Vec<u8> {
    let (mut out, mut s) = (Vec::with_capacity(len), [seed; 32]);
    while out.len() < len {
        s = Sha256::digest(s).into();
        out.extend_from_slice(&s);
    }
    out.truncate(len);
    out
}

fn private_vr(td: &TempDir) -> Result<DisposableViewRoot> {
    let root = td.path().join("work");
    fs::create_dir_all(&root)?;
    fs::set_permissions(&root, Permissions::from_mode(0o700))?;
    Ok(DisposableViewRoot::open(&root, 32, 64 << 20, Duration::from_secs(300))?)
}

fn make_grant(
    ids: (Uuid, Uuid, Uuid),
    fmt: CloneKitObjectFormat,
    oid: &str,
    deps: Option<CloneKitDependencyGrants>,
    now: i64,
) -> Result<(SignedCloneKitGrant, GrantVerificationContext)> {
    let (job_id, audience) = (Uuid::new_v4(), Uuid::new_v4());
    let claims = CloneKitGrantClaims {
        schema: 1,
        grant_id: Uuid::new_v4(),
        tenant_id: ids.0,
        repository_id: ids.1,
        owner_id: ids.0,
        history_id: ids.2,
        storage_generation: 1,
        object_format: fmt,
        target_oid: oid.to_owned(),
        job_id,
        audience,
        issued_unix: now - 10,
        not_after_unix: now + 600,
        min_kit_generation: 1,
        allow_git_fallback: true,
        dependencies: deps.unwrap_or_default(),
    };
    let ctx = GrantVerificationContext {
        tenant_id: ids.0,
        repository_id: ids.1,
        history_id: ids.2,
        storage_generation: 1,
        object_format: fmt,
        target_oid: oid.to_owned(),
        job_id,
        audience,
        now_unix: now,
    };
    Ok((sign_grant(claims, &SECRET)?, ctx))
}

fn build_kit(
    ids: (Uuid, Uuid, Uuid),
    fmt: CloneKitObjectFormat,
    kit_gen: u64,
    repo: &Path,
    td: &TempDir,
    store: Option<&CloneKitPublicationStore>,
    fail: Option<BuildFailurePoint>,
) -> Result<BuiltCloneKitArtifacts> {
    let built = build_clonekit_from_git(
        &BuildCloneKitRequest {
            tenant_id: ids.0,
            repository_id: ids.1,
            owner_id: ids.0,
            history_id: ids.2,
            storage_generation: 1,
            object_format: fmt,
            kit_generation: kit_gen,
            branch_ref: "refs/heads/main".into(),
            created_unix: 1_750_000_000,
            expires_unix: 1_750_003_600,
            git_binary: git_binary(),
            source_repo_dir: repo.to_path_buf(),
            staging_root: td.path().join("st"),
            retention_pin_id: Some(Uuid::new_v4()),
            inject_failure: fail,
        },
        None,
    )?;
    if let Some(s) = store {
        publish_clonekit_versioned(s, &built, &git_binary(), None, None)?;
    }
    Ok(built)
}

struct Co<'a> {
    vr: &'a DisposableViewRoot,
    store: Option<&'a CloneKitPublicationStore>,
    ledger: Option<&'a RetentionPinLedger>,
    blob: Option<&'a BlobStore>,
    manifest: Option<&'a CloneKitManifest>,
    lfs: Option<&'a Path>,
    bearer: Option<&'a str>,
}
impl<'a> Co<'a> {
    fn new(vr: &'a DisposableViewRoot) -> Self {
        Self { vr, store: None, ledger: None, blob: None, manifest: None, lfs: None, bearer: None }
    }
    async fn run(
        &self,
        grant: &SignedCloneKitGrant,
        ctx: &GrantVerificationContext,
        auth: &Arc<dyn CloneKitAuthorityOracle>,
        policy: CheckoutPolicy,
        remote: &str,
        cancel: Option<CancellationToken>,
    ) -> std::result::Result<CheckoutOutcome, CloneKitError> {
        let git = git_binary();
        execute_ci_checkout(&CheckoutRequest {
            grant,
            signing_secret: &SECRET,
            expected_context: ctx,
            authority: Arc::clone(auth),
            policy,
            git_binary: &git,
            origin_remote: remote,
            http_bearer: self.bearer,
            view_root: self.vr,
            pub_store: self.store,
            manifest_override: self.manifest,
            blob_store: self.blob,
            pin_ledger: self.ledger,
            lfs_objects_dir: self.lfs,
            destination_root: None,
            cancel,
        })
        .await
    }
}

type HttpSt = (PathBuf, String, PathBuf, Arc<AtomicUsize>);

async fn smart_http(
    State((root, bearer, backend, bytes)): State<HttpSt>,
    method: axum::http::Method,
    OriginalUri(uri): OriginalUri,
    hdrs: HeaderMap,
    body: Bytes,
) -> Response {
    let hstr = |name: header::HeaderName| hdrs.get(name).and_then(|v| v.to_str().ok()).unwrap_or("");
    if hstr(header::AUTHORIZATION) != format!("Bearer {bearer}") {
        return Response::builder().status(StatusCode::UNAUTHORIZED).body(Body::empty()).expect("401");
    }
    let mut cmd = Command::new(&backend);
    cmd.envs([
        ("GIT_PROJECT_ROOT", root.to_str().unwrap_or("")),
        ("GIT_HTTP_EXPORT_ALL", "1"),
        ("PATH_INFO", uri.path()),
        ("QUERY_STRING", uri.query().unwrap_or("")),
        ("REQUEST_METHOD", method.as_str()),
        ("CONTENT_LENGTH", &body.len().to_string()),
        ("CONTENT_TYPE", hstr(header::CONTENT_TYPE)),
        ("HTTP_CONTENT_ENCODING", hstr(header::CONTENT_ENCODING)),
    ]);
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("backend");
    if let Some(mut s) = child.stdin.take() {
        s.write_all(&body).expect("stdin");
    }
    let raw = child.wait_with_output().expect("out").stdout;
    let (i, w) = raw
        .windows(4)
        .position(|x| x == b"\r\n\r\n")
        .map(|i| (i, 4))
        .or_else(|| raw.windows(2).position(|x| x == b"\n\n").map(|i| (i, 2)))
        .unwrap_or((0, 0));
    let (h, b) = (&raw[..i], &raw[i + w..]);
    let (mut code, mut ct) = (200u16, "application/octet-stream".to_owned());
    for (k, v) in String::from_utf8_lossy(h).lines().filter_map(|l| l.split_once(':')) {
        if k.eq_ignore_ascii_case("status") {
            code = v.split_whitespace().next().and_then(|s| s.parse().ok()).unwrap_or(200);
        } else if k.eq_ignore_ascii_case("content-type") {
            ct = v.trim().to_owned();
        }
    }
    bytes.fetch_add(b.len(), Ordering::SeqCst);
    Response::builder()
        .status(StatusCode::from_u16(code).unwrap_or(StatusCode::OK))
        .header(header::CONTENT_TYPE, ct)
        .body(Body::from(b.to_vec()))
        .expect("resp")
}

async fn start_http(root: &Path, bearer: &str) -> Result<(String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>)> {
    let backend = PathBuf::from(run_git(None, &["--exec-path"])?).join("git-http-backend");
    let (bytes, l) = (Arc::new(AtomicUsize::new(0)), TcpListener::bind(("127.0.0.1", 0)).await?);
    let (addr, st) = (l.local_addr()?, (root.to_path_buf(), bearer.into(), backend, Arc::clone(&bytes)));
    let t = tokio::spawn(async move {
        let _ = axum::serve(l, Router::new().route("/{*rest}", any(smart_http)).with_state(st)).await;
    });
    Ok((format!("http://{addr}"), bytes, t))
}

#[tokio::test]
async fn clonekit_sha1_and_sha256_incremental_smart_http_and_anti_stale_tip() -> Result<()> {
    let (td, ledger) = (TempDir::new()?, RetentionPinLedger::new());
    let (vr, store, origins) =
        (private_vr(&td)?, CloneKitPublicationStore::open(&td.path().join("cat"))?, td.path().join("origins"));
    let (http_base, wire_bytes, server) = start_http(&origins, "tok-smart-182").await?;

    for fmt in [Sha1, FmtSha256] {
        let (name, ids) = (format!("repo-{}", fmt.as_str()), (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()));
        let repo = init_repo(&origins, &format!("{name}.git"), fmt)?;
        let c1 = add_commit(&repo, "assets/big.bin", &payload_bytes(1, 192 * 1024), "c1")?;
        build_kit(ids, fmt, 1, &repo, &td, Some(&store), None)?;
        let c2 = add_commit(&repo, "src/delta.txt", b"incremental-v2\n", "c2")?;
        let (grant, ctx) = make_grant(ids, fmt, &c2, None, 1_750_000_000)?;
        let auth: Arc<dyn CloneKitAuthorityOracle> = Arc::new(InMemoryAuthorityOracle::new());
        let remote = format!("{http_base}/{name}.git");
        let co = Co { store: Some(&store), ledger: Some(&ledger), bearer: Some("tok-smart-182"), ..Co::new(&vr) };

        wire_bytes.store(0, Ordering::SeqCst);
        let stock = co.run(&grant, &ctx, &auth, pol(false, true), &remote, None).await?;
        let stock_wire = wire_bytes.load(Ordering::SeqCst);
        ensure!(stock.telemetry.strategy == CheckoutStrategy::StockGitDirect);

        wire_bytes.store(0, Ordering::SeqCst);
        let ck = co.run(&grant, &ctx, &auth, pol(true, true), &remote, None).await?;
        let ck_wire = wire_bytes.load(Ordering::SeqCst);
        ensure!(
            ck.telemetry.strategy == CheckoutStrategy::CloneKitIncremental { kit_generation: 1, base_commit_oid: c1 }
        );
        ensure!(ck_wire * 4 < stock_wire, "expected >=4x wire savings: ck={ck_wire}, stock={stock_wire}");
        ensure!(
            ck.telemetry.verified_target_oid == c2
                && fs::read(ck.workspace_dir.join("src/delta.txt"))? == b"incremental-v2\n"
        );

        let (bad_g, bad_c) = make_grant(ids, fmt, &"f".repeat(fmt.oid_hex_len()), None, 1_750_000_000)?;
        ensure!(matches!(
            co.run(&bad_g, &bad_c, &auth, pol(true, false), &remote, None).await,
            Err(CloneKitError::GitFailed(_))
        ));
    }
    server.abort();
    Ok(())
}

#[tokio::test]
async fn clonekit_failed_build_empty_repo_and_history_rotation_preserve_last_valid() -> Result<()> {
    let (td, ids) = (TempDir::new()?, (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()));
    let (vr, store) = (private_vr(&td)?, CloneKitPublicationStore::open(&td.path().join("cat"))?);
    let empty = init_repo(td.path(), "empty.git", Sha1)?;
    ensure!(build_kit(ids, Sha1, 1, &empty, &td, None, None)?.manifest.status == CloneKitStatus::EmptyRepository);

    let repo = init_repo(td.path(), "active", Sha1)?;
    let c1 = add_commit(&repo, "a.txt", b"v1", "c1")?;
    build_kit(ids, Sha1, 1, &repo, &td, Some(&store), None)?;
    let b2 = build_kit(ids, Sha1, 2, &repo, &td, None, Some(BuildFailurePoint::CorruptStagedPack))?;
    ensure!(
        publish_clonekit_versioned(&store, &b2, &git_binary(), None, None).is_err()
            && store.load_latest(ids.1)?.expect("latest").kit_generation == 1
    );

    let (g_h2, c_h2) = make_grant((ids.0, ids.1, Uuid::new_v4()), Sha1, &c1, None, 1_750_000_000)?;
    let (co, mem): (Co<'_>, Arc<dyn CloneKitAuthorityOracle>) =
        (Co { store: Some(&store), ..Co::new(&vr) }, Arc::new(InMemoryAuthorityOracle::new()));
    let res = co.run(&g_h2, &c_h2, &mem, pol(true, true), repo.to_str().expect("utf8"), None).await?;
    ensure!(
        res.telemetry.strategy == CheckoutStrategy::StockGitFallback { reason: FallbackReason::KitHistoryMismatch }
    );
    Ok(())
}

#[tokio::test]
async fn clonekit_fail_closed_auth_revocation_cancel_gc_pin_and_dependencies() -> Result<()> {
    let (td, ledger) = (TempDir::new()?, RetentionPinLedger::new());
    let (vr, store, repo) =
        (private_vr(&td)?, CloneKitPublicationStore::open(&td.path().join("cat"))?, init_repo(td.path(), "sec", Sha1)?);
    let (lfs_bytes, lfs_dir) = (b"large-binary-lfs-payload", td.path().join("lfs"));
    let lfs_oid = hex::encode(Sha256::digest(lfs_bytes));
    fs::create_dir_all(&lfs_dir)?;
    fs::write(lfs_dir.join(&lfs_oid), lfs_bytes)?;
    let lfs_ptr =
        format!("version https://git-lfs.github.com/spec/v1\noid sha256:{lfs_oid}\nsize {}\n", lfs_bytes.len());
    add_commit(&repo, "media.bin", lfs_ptr.as_bytes(), "c1")?;
    add_commit(&repo, "nested/media.bin", lfs_ptr.as_bytes(), "c1b")?;
    let sub_oid = add_commit(&init_repo(td.path(), "sub", Sha1)?, "s.txt", b"s", "s1")?;
    run_git(Some(&repo), &["update-index", "--add", "--cacheinfo", &format!("160000,{sub_oid},deps/sub")])?;
    run_git(Some(&repo), &["commit", "--quiet", "-m", "c2"])?;
    let target = run_git(Some(&repo), &["rev-parse", "HEAD"])?;

    let ids = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let deps = CloneKitDependencyGrants {
        lfs_objects: ["media.bin", "nested/media.bin"]
            .map(|path| RequiredLfsObject {
                repository_id: ids.1,
                path: path.into(),
                oid: lfs_oid.clone(),
                size: lfs_bytes.len() as u64,
                grant_id: Uuid::new_v4(),
            })
            .to_vec(),
        submodules: vec![RequiredSubmodule {
            path: "deps/sub".into(),
            repository_id: Uuid::new_v4(),
            target_oid: sub_oid,
            object_format: Sha1,
            storage_generation: 1,
            grant_id: Uuid::new_v4(),
        }],
    };
    let (grant, mut ctx) = make_grant(ids, Sha1, &target, Some(deps.clone()), 1_750_000_000)?;
    let oracle = Arc::new(InMemoryAuthorityOracle::new());
    let auth: Arc<dyn CloneKitAuthorityOracle> = oracle.clone();
    let remote = repo.to_str().expect("utf8");
    let co = Co { lfs: Some(&lfs_dir), ..Co::new(&vr) };

    let lfs_missing = CloneKitDependencyGrants { submodules: deps.submodules.clone(), ..Default::default() };
    let (ng, nc) = make_grant(ids, Sha1, &target, Some(lfs_missing), 1_750_000_000)?;
    ensure!(matches!(
        co.run(&ng, &nc, &auth, pol(false, true), remote, None).await,
        Err(CloneKitError::DependencyCheckFailed(_))
    ));
    let ok = co.run(&grant, &ctx, &auth, pol(false, true), remote, None).await?;
    ensure!(
        ok.telemetry.dependency_receipt.verified_lfs_count == 2
            && ok.telemetry.dependency_receipt.verified_submodule_count == 1
    );

    ctx.tenant_id = Uuid::new_v4();
    ensure!(matches!(
        co.run(&grant, &ctx, &auth, pol(false, true), remote, None).await,
        Err(CloneKitError::CrossTenantDenied)
    ));
    ctx.tenant_id = ids.0;
    oracle.revoke_grant(grant.claims.grant_id);
    ensure!(matches!(
        co.run(&grant, &ctx, &auth, pol(false, true), remote, None).await,
        Err(CloneKitError::GrantRevoked(_))
    ));

    let cancel = CancellationToken::new();
    cancel.cancel();
    ensure!(matches!(
        co.run(&ng, &nc, &auth, pol(false, true), remote, Some(cancel)).await,
        Err(CloneKitError::TransferCancelled)
    ));

    for kgen in [1u64, 2u64] {
        build_kit(ids, Sha1, kgen, &repo, &td, Some(&store), None)?;
    }
    let pin = RetentionPinGuard::acquire(&ledger, ids.1, 1)?;
    ensure!(matches!(store.try_gc_generation(ids.1, 1, &ledger), Err(CloneKitError::PinProtectionActive(_))));
    drop(pin);
    ensure!(store.try_gc_generation(ids.1, 1, &ledger)? && store.version_dir(ids.1, 2).exists());
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL (ROOTYARD_TEST_DATABASE_URL) and controlled S3 (ROOTYARD_BLOB_*)"]
async fn pg_and_garage_s3_clonekit_durable_hold_protected_upload_and_revocation() -> Result<()> {
    let url = std::env::var("ROOTYARD_TEST_DATABASE_URL").expect("ROOTYARD_TEST_DATABASE_URL");
    let (admin, schema) = (db::pool(&url)?, format!("clonekit_test_{}", Uuid::new_v4().simple()));
    admin.get().await?.batch_execute(&format!("CREATE SCHEMA {schema}")).await?;
    let mut cfg: tokio_postgres::Config = url.parse()?;
    cfg.options(format!("-c search_path={schema} -c timezone=UTC -c statement_timeout=30000"));
    let pool = Pool::builder(Manager::new(cfg, tokio_postgres::NoTls))
        .runtime(deadpool_postgres::Runtime::Tokio1)
        .max_size(8)
        .build()?;
    let res = async {
        db::migrate(&pool).await?;
        let (blob, td) = (BlobStore::open(BlobProfile::from_env()?)?, TempDir::new()?);
        let (vr, repo) = (private_vr(&td)?, init_repo(td.path(), "pg_repo", Sha1)?);
        let c1 = add_commit(&repo, "big.bin", &payload_bytes(9, 128 * 1024), "c1")?;
        let (ids, token_id) = ((Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()), Uuid::new_v4());
        let client = pool.get().await?;
        let (token_digest, credential_digest): (&[u8], &[u8]) = (&[7u8; 32], &[9u8; 32]);
        client.execute("INSERT INTO users(id,username) VALUES($1,$2)", &[&ids.0, &format!("ck_{}", &ids.0.simple().to_string()[..8])]).await?;
        client.execute("INSERT INTO tokens(id,user_id,digest) VALUES($1,$2,$3)", &[&token_id, &ids.0, &token_digest]).await?;
        client.execute("INSERT INTO repositories(id,owner_id,name,state,object_format,storage_generation) VALUES($1,$2,$3,'ready','sha1',1)", &[&ids.1, &ids.0, &"ckrepo"]).await?;
        drop(client);

        let pg_dl = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut c = pool.get().await?;
        let gate = *PgRefStoreCore.initialize(&mut c, &CoreGateInit::new(ids.1, ids.0, GitObjectFormat::Sha1, ids.2, 1, 1, RefName::branch("refs/heads/main")?)?, pg_dl).await?.digest();
        let op = OperationIdentity::new(ids.1, ids.0, IssuerLane::new("ci-clonekit")?, 1, Uuid::new_v4(), RequestDigest::from_bytes([1u8; 32]))?;
        let tx = c.transaction().await?;
        ensure!(PgRefStore.begin(&tx, &op, pg_dl).await?.record.state() == OperationState::Pending);
        tx.commit().await?;
        drop(c);

        let mut built = build_kit(ids, Sha1, 1, &repo, &td, None, None)?;
        let receipts = publish_clonekit_to_blob_store(&pool, &blob, &BlobHoldPublishContext { scope: HoldScope::new(ids.1, ids.0, ids.0, ArtifactHoldPurpose::RefPublication, GitObjectFormat::Sha1, ids.2, 1, 1)?, operation: op, expected_gate_digest: gate, authority_id: ids.1, authority_generation: 1 }, &mut built, None).await?;
        ensure!(receipts.len() == 2 && built.manifest.pack.as_ref().and_then(|p| p.blob_locator.as_ref()).is_some());

        let c2 = add_commit(&repo, "next.txt", b"delta2\n", "c2")?;
        let now: i64 = pool.get().await?.query_one("SELECT extract(epoch FROM clock_timestamp())::bigint", &[]).await?.get(0);
        let (signed, ctx) = make_grant(ids, Sha1, &c2, None, now)?;
        let plan = serde_json::json!({"version":1,"job_id":ctx.job_id,"owner_id":ids.0,"repository_id":ids.1,"storage_generation":1,"object_format":"sha1","target_oid":c2,"source_receipt_sha256":"a".repeat(64),"mirror_audience":ctx.audience,"expires_unix":signed.claims.not_after_unix});
        pool.get().await?.execute("INSERT INTO ci_checkout_jobs(repository_id,job_id,owner_id,plan,issuer_token_id,credential_digest,expires_unix) VALUES($1,$2,$3,$4,$5,$6,$7)", &[&ids.1, &ctx.job_id, &ids.0, &plan, &token_id, &credential_digest, &signed.claims.not_after_unix]).await?;

        let pg_auth: Arc<dyn CloneKitAuthorityOracle> = Arc::new(PgCheckoutAuthorityOracle::new(pool.clone()));
        let co = Co { manifest: Some(&built.manifest), blob: Some(&blob), ..Co::new(&vr) };
        let outcome = co.run(&signed, &ctx, &pg_auth, pol(true, true), repo.to_str().expect("utf8"), None).await?;
        ensure!(outcome.telemetry.strategy == CheckoutStrategy::CloneKitIncremental { kit_generation: 1, base_commit_oid: c1 });
        ensure!(pool.get().await?.query_one("SELECT count(*) FROM artifact_holds WHERE state = 'active'", &[]).await?.get::<_, i64>(0) == 2);

        pool.get().await?.execute("UPDATE ci_checkout_jobs SET revoked = true WHERE repository_id=$1 AND job_id=$2", &[&ids.1, &ctx.job_id]).await?;
        ensure!(matches!(co.run(&signed, &ctx, &pg_auth, pol(false, true), repo.to_str().expect("utf8"), None).await, Err(CloneKitError::GrantRevoked(_))));
        Ok(())
    }.await;
    pool.close();
    drop(pool);
    admin.get().await?.batch_execute(&format!("DROP SCHEMA {schema} CASCADE")).await?;
    admin.close();
    res
}
