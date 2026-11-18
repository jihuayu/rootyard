//! Isolated PostgreSQL 17 schema + LoopbackS3 OpenDAL `BlobStore` + production
//! `rootyard::blob_git_gateway::router` harness for Issue #185 end-to-end tests.

use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::Path,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use anyhow::{Result, anyhow, ensure};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use deadpool_postgres::{Manager, Pool};
use rootyard::{
    blob_git_gateway::{BlobGitConfig, BlobGitState, router},
    blob_store::{config::BlobProfile, opendal::BlobStore},
    browse::packfile_uri::{FallbackReason, GatewayPackfileOffload, protocol_v2::push_pkt_line},
    db,
    ref_store::{
        GitObjectFormat,
        core::decision_commit::{PgDecisionProtocol, RealmExpectation},
        serving::lookup,
    },
};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::time::Instant;
use uuid::Uuid;

#[derive(Default)]
struct S3MemState {
    objects: Mutex<BTreeMap<String, Vec<u8>>>,
}

pub struct LoopbackS3 {
    endpoint: String,
}

static SHARED_S3: OnceLock<LoopbackS3> = OnceLock::new();
static ENV_LOCK: Mutex<()> = Mutex::new(());

impl LoopbackS3 {
    pub fn shared() -> &'static Self {
        SHARED_S3.get_or_init(|| {
            let st = Arc::new(S3MemState::default());
            let std_l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            std_l.set_nonblocking(true).unwrap();
            let port = std_l.local_addr().unwrap().port();
            let (tx, rx) = std::sync::mpsc::sync_channel(1);
            std::thread::spawn(move || {
                tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap().block_on(
                    async move {
                        let _ = tx.send(());
                        let _ = axum::serve(
                            tokio::net::TcpListener::from_std(std_l).unwrap(),
                            Router::new().fallback(handle_s3).with_state(st),
                        )
                        .await;
                    },
                );
            });
            rx.recv().unwrap();
            Self { endpoint: format!("http://127.0.0.1:{port}") }
        })
    }

    pub fn open_store(&self) -> Result<BlobStore> {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let pairs = "DRIVER=opendal,SERVICE=s3,BUCKET=packfile-uri-bucket,REGION=us-east-1,ROOT=packfile-uri-it,ACCESS_KEY_ID=test-ak,SECRET_ACCESS_KEY=test-sk,ENCRYPTION_MODE=provider-managed,RETRY_MAX_TIMES=3,MAX_OBJECT_BYTES=67108864";
        // SAFETY: serialized under ENV_LOCK inside integration test process.
        unsafe {
            for kv in pairs.split(',') {
                let (k, v) = kv.split_once('=').unwrap();
                std::env::set_var(format!("ROOTYARD_BLOB_{k}"), v);
            }
            std::env::set_var("ROOTYARD_BLOB_ENDPOINT", &self.endpoint);
            std::env::remove_var("ROOTYARD_BLOB_KEYRING_DIR");
        }
        Ok(BlobStore::open(BlobProfile::from_env()?)?)
    }
}

async fn handle_s3(
    State(st): State<Arc<S3MemState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let key = uri.path().trim_start_matches('/').to_owned();
    if !key.contains('/') {
        return ([(header::CONNECTION, "close")], Body::from("<ListBucketResult/>")).into_response();
    }
    match method {
        Method::PUT => {
            let mut guard = st.objects.lock().unwrap_or_else(|p| p.into_inner());
            if headers.get(header::IF_NONE_MATCH).is_some_and(|v| v == "*") && guard.contains_key(&key) {
                return (StatusCode::PRECONDITION_FAILED, [(header::CONNECTION, "close")], Body::empty())
                    .into_response();
            }
            let tag = format!("\"{}\"", &hex::encode(Sha256::digest(&body))[..32]);
            guard.insert(key, body.to_vec());
            (
                [(header::ETAG, tag), (header::CONTENT_LENGTH, "0".into()), (header::CONNECTION, "close".into())],
                Body::empty(),
            )
                .into_response()
        }
        Method::HEAD | Method::GET => {
            let data = st.objects.lock().unwrap_or_else(|p| p.into_inner()).get(&key).cloned();
            let Some(d) = data else {
                return (
                    StatusCode::NOT_FOUND,
                    [(header::CONTENT_LENGTH, "0"), (header::CONNECTION, "close")],
                    Body::empty(),
                )
                    .into_response();
            };
            let tag = format!("\"{}\"", &hex::encode(Sha256::digest(&d))[..32]);
            if method == Method::GET
                && let Some(r_str) = headers.get(header::RANGE).and_then(|v| v.to_str().ok())
                && let Some((s, e)) = r_str.strip_prefix("bytes=").and_then(|x| x.split_once('-'))
                && let Ok(start) = s.parse::<usize>()
                && start < d.len()
            {
                let end = e.parse::<usize>().unwrap_or(d.len() - 1).min(d.len() - 1);
                let slice = d[start..=end].to_vec();
                return (
                    StatusCode::PARTIAL_CONTENT,
                    [
                        (header::ETAG, tag),
                        (header::CONTENT_LENGTH, slice.len().to_string()),
                        (header::CONTENT_RANGE, format!("bytes {start}-{end}/{}", d.len())),
                        (header::CONNECTION, "close".into()),
                    ],
                    Body::from(slice),
                )
                    .into_response();
            }
            (
                [
                    (header::ETAG, tag),
                    (header::CONTENT_LENGTH, d.len().to_string()),
                    (header::CONNECTION, "close".into()),
                ],
                if method == Method::HEAD { Body::empty() } else { Body::from(d) },
            )
                .into_response()
        }
        Method::DELETE => {
            st.objects.lock().unwrap_or_else(|p| p.into_inner()).remove(&key);
            (StatusCode::NO_CONTENT, [(header::CONNECTION, "close")], Body::empty()).into_response()
        }
        _ => (StatusCode::METHOD_NOT_ALLOWED, [(header::CONNECTION, "close")], Body::empty()).into_response(),
    }
}

pub struct IsolatedPgDb {
    admin: Pool,
    pub pool: Pool,
    schema: String,
}

impl IsolatedPgDb {
    pub async fn try_setup() -> Result<Option<Self>> {
        let Some(url) = std::env::var("ROOTYARD_TEST_DATABASE_URL").ok() else {
            ensure!(
                std::env::var("ROOTYARD_REQUIRE_PG_PACKFILE_URI").as_deref() != Ok("1"),
                "ROOTYARD_TEST_DATABASE_URL is required when ROOTYARD_REQUIRE_PG_PACKFILE_URI=1"
            );
            return Ok(None);
        };
        let schema = format!("packfile_uri_{}", Uuid::new_v4().simple());
        let admin = db::pool(&url)?;
        admin
            .get()
            .await?
            .batch_execute(
                "CREATE TABLE IF NOT EXISTS public.cluster_authority (
                    singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
                    incarnation UUID NOT NULL DEFAULT gen_random_uuid(),
                    rotated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
                );
                INSERT INTO public.cluster_authority(singleton) VALUES(true) ON CONFLICT DO NOTHING;",
            )
            .await?;
        admin.get().await?.batch_execute(&format!("CREATE SCHEMA IF NOT EXISTS {schema}")).await?;
        let mut cfg: tokio_postgres::Config = url.parse()?;
        cfg.options(format!(
            "{} -c search_path={schema} -c timezone=UTC -c statement_timeout=30000 -c lock_timeout=15000",
            cfg.get_options().unwrap_or("")
        ));
        let pool = Pool::builder(Manager::new(cfg, tokio_postgres::NoTls))
            .runtime(deadpool_postgres::Runtime::Tokio1)
            .max_size(12)
            .build()?;
        db::migrate(&pool).await?;
        Ok(Some(Self { admin, pool, schema }))
    }

    pub async fn finish(self, outcome: Result<()>) -> Result<()> {
        let teardown = async {
            let client = self.admin.get().await?;
            client.batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema)).await?;
            Ok::<(), anyhow::Error>(())
        };
        match outcome {
            Ok(()) => teardown.await,
            Err(err) => {
                let _ = teardown.await;
                Err(err)
            }
        }
    }
}

pub struct TestActor {
    pub identity: db::Identity,
    pub token: String,
    pub username: String,
}

pub async fn issue_owner_actor(pool: &Pool) -> Result<TestActor> {
    let username = format!("pfowner{}", &Uuid::new_v4().simple().to_string()[..10]);
    let val = db::issue_token(pool, &username, true, false).await?;
    let token = val["token"].as_str().ok_or_else(|| anyhow!("missing token"))?.to_owned();
    let mut headers = HeaderMap::new();
    headers.insert(header::AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {token}"))?);
    let identity = rootyard::auth::authenticate(pool, &headers).await.map_err(|e| anyhow!("auth failed: {}", e.1))?;
    Ok(TestActor { identity, token, username })
}

pub async fn spawn_gateway(
    pool: Pool,
    store: BlobStore,
    git_binary: &Path,
    scratch_root: &Path,
    offload: Option<Arc<GatewayPackfileOffload>>,
) -> Result<(SocketAddr, Arc<BlobGitState>, tokio::task::JoinHandle<()>)> {
    std::fs::create_dir_all(scratch_root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(scratch_root, std::fs::Permissions::from_mode(0o700))?;
    }
    let mut state = BlobGitState::new(BlobGitConfig {
        pool,
        store,
        git_binary: git_binary.to_path_buf(),
        scratch_root: scratch_root.to_path_buf(),
        max_concurrent_requests: 8,
        max_request_bytes: 16 * 1024 * 1024,
        max_response_bytes: 64 * 1024 * 1024,
        max_inflight_bytes: 64 * 1024 * 1024,
        operation_deadline: Duration::from_secs(60),
        native_limits: Default::default(),
    })?;
    if let Some(off) = offload {
        state = state.with_packfile_offload(off);
    }
    let state = Arc::new(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let app = router(Arc::clone(&state));
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((addr, state, task))
}

pub async fn create_and_provision_repo(
    gw_addr: SocketAddr,
    pool: &Pool,
    state: &BlobGitState,
    owner: &TestActor,
    name: &str,
    fmt: GitObjectFormat,
) -> Result<Uuid> {
    let resp = reqwest::Client::new()
        .post(format!("http://{gw_addr}/api/repos"))
        .bearer_auth(&owner.token)
        .json(&json!({ "name": name, "object_format": fmt.as_str() }))
        .send()
        .await?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await?;
    ensure!(status.is_success(), "POST /api/repos failed ({status}): {body}");
    let dl = Instant::now() + Duration::from_secs(30);
    let serving = lookup(pool, &owner.identity, &owner.username, name, true, state.store().backend_identity(), dl)
        .await
        .map_err(|e| anyhow!("lookup failed: {}", e.1))?;
    let gate = serving.gate;
    let exp = RealmExpectation::new(
        gate.repository_id(),
        gate.tenant_id(),
        gate.object_format(),
        gate.history_incarnation(),
        gate.authority_epoch(),
        gate.group_epoch(),
    )?;
    let mut client = pool.get().await?;
    PgDecisionProtocol.provision(&mut client, &exp, dl).await?;
    Ok(gate.repository_id())
}

pub struct SecurityGateCheckCtx<'a> {
    pub tmp_dir: &'a Path,
    pub pusher_dir: &'a Path,
    pub fmt_str: &'a str,
    pub off_addr: SocketAddr,
    pub off_url: &'a str,
    pub owner_user: &'a str,
    pub repo_name: &'a str,
    pub basic_hdr: &'a str,
    pub ca_cfg: &'a str,
    pub proxy_cfg: &'a str,
    pub non_tip_c1: &'a str,
    pub tip_c3: &'a str,
    pub side_payload: &'a [u8],
    pub offload: &'a GatewayPackfileOffload,
}

/// Synchronous stock `git` runner signature passed into security gate checks.
pub type GitRunnerFn = fn(&[&str], Option<&Path>, Option<&[u8]>) -> Result<Vec<u8>>;

/// Exercises unadvertised `want` rejection, unsupported/unknown v2 arg native fallback,
/// and whole-pack closure isolation on multi-ref shared packs over production `blob_git_gateway`.
pub async fn verify_production_gateway_security_gates(
    ctx: &SecurityGateCheckCtx<'_>,
    git_fn: GitRunnerFn,
) -> Result<String> {
    let http = reqwest::Client::new();
    let up_url = format!("http://{}/git/{}/{}.git/git-upload-pack", ctx.off_addr, ctx.owner_user, ctx.repo_name);
    let served_before = ctx.offload.pack_server().served_requests.load(std::sync::atomic::Ordering::SeqCst);

    // A. Unadvertised `want` (ancestor `non_tip_c1`, not an advertised ref tip) -> UnadvertisedWant.
    let mut unadv_wire = Vec::new();
    push_pkt_line(&mut unadv_wire, b"command=fetch\n")?;
    unadv_wire.extend_from_slice(b"0001");
    push_pkt_line(&mut unadv_wire, b"packfile-uris https\n")?;
    push_pkt_line(&mut unadv_wire, format!("want {}\n", ctx.non_tip_c1).as_bytes())?;
    push_pkt_line(&mut unadv_wire, b"done\n")?;
    unadv_wire.extend_from_slice(b"0000");
    let unadv_resp = http
        .post(&up_url)
        .header("Authorization", ctx.basic_hdr)
        .header("Content-Type", "application/x-git-upload-pack-request")
        .header("Git-Protocol", "version=2")
        .body(unadv_wire)
        .send()
        .await?
        .bytes()
        .await?;
    ensure!(ctx.offload.last_fallback_reason() == Some(FallbackReason::UnadvertisedWant));
    ensure!(!String::from_utf8_lossy(&unadv_resp).contains("packfile-uris"));

    // B. Stock `git clone --depth 1` (`deepen 1`) + unknown v2 arg -> UnsupportedFetchArgs native fallback.
    let shallow_dir = ctx.tmp_dir.join(format!("clone_shallow_{}", ctx.fmt_str));
    git_fn(
        &[
            "-c",
            "protocol.version=2",
            "-c",
            "fetch.uriprotocols=https",
            "-c",
            ctx.ca_cfg,
            "-c",
            ctx.proxy_cfg,
            "clone",
            "--depth",
            "1",
            "--branch",
            "main",
            ctx.off_url,
            shallow_dir.to_str().unwrap(),
        ],
        Some(ctx.tmp_dir),
        None,
    )?;
    git_fn(&["fsck", "--full", "--strict"], Some(&shallow_dir), None)?;
    let cnt = String::from_utf8(git_fn(&["rev-list", "--count", "HEAD"], Some(&shallow_dir), None)?)?;
    ensure!(cnt.trim() == "1", "shallow fallback clone expected depth 1, got {}", cnt.trim());
    ensure!(ctx.offload.last_fallback_reason() == Some(FallbackReason::UnsupportedFetchArgs));

    let mut unk_wire = Vec::new();
    push_pkt_line(&mut unk_wire, b"command=fetch\n")?;
    unk_wire.extend_from_slice(b"0001");
    push_pkt_line(&mut unk_wire, b"packfile-uris https\n")?;
    push_pkt_line(&mut unk_wire, b"unknown-v2-arg value\n")?;
    push_pkt_line(&mut unk_wire, format!("want {}\n", ctx.tip_c3).as_bytes())?;
    push_pkt_line(&mut unk_wire, b"done\n")?;
    unk_wire.extend_from_slice(b"0000");
    let unk_resp = http
        .post(&up_url)
        .header("Authorization", ctx.basic_hdr)
        .header("Content-Type", "application/x-git-upload-pack-request")
        .header("Git-Protocol", "version=2")
        .body(unk_wire)
        .send()
        .await?
        .bytes()
        .await?;
    ensure!(!String::from_utf8_lossy(&unk_resp).contains("packfile-uris"));
    ensure!(ctx.offload.pack_server().served_requests.load(std::sync::atomic::Ordering::SeqCst) == served_before);

    // C. Atomic multi-ref push creates ONE shared `.pack` containing both `main` and `side-branch`;
    //    `--single-branch --branch main` must NEVER offload that mixed `.pack` or leak `side_secret.bin`!
    std::fs::write(ctx.pusher_dir.join("main_c4.txt"), b"main branch commit 4\n")?;
    git_fn(&["add", "main_c4.txt"], Some(ctx.pusher_dir), None)?;
    git_fn(&["commit", "-m", "main c4"], Some(ctx.pusher_dir), None)?;
    let main_c4 = String::from_utf8(git_fn(&["rev-parse", "HEAD"], Some(ctx.pusher_dir), None)?)?.trim().to_owned();

    git_fn(&["checkout", "--orphan", "side-branch"], Some(ctx.pusher_dir), None)?;
    git_fn(&["rm", "-rf", "."], Some(ctx.pusher_dir), None)?;
    std::fs::write(ctx.pusher_dir.join("side_secret.bin"), ctx.side_payload)?;
    git_fn(&["add", "side_secret.bin"], Some(ctx.pusher_dir), None)?;
    git_fn(&["commit", "-m", "side secret"], Some(ctx.pusher_dir), None)?;
    let side_tip = String::from_utf8(git_fn(&["rev-parse", "HEAD"], Some(ctx.pusher_dir), None)?)?.trim().to_owned();
    let side_blob = String::from_utf8(git_fn(&["rev-parse", "HEAD:side_secret.bin"], Some(ctx.pusher_dir), None)?)?
        .trim()
        .to_owned();

    git_fn(
        &["push", ctx.off_url, &format!("{main_c4}:refs/heads/main"), &format!("{side_tip}:refs/heads/side-branch")],
        Some(ctx.pusher_dir),
        None,
    )?;

    let mut inc_mixed = Vec::new();
    push_pkt_line(&mut inc_mixed, b"command=fetch\n")?;
    inc_mixed.extend_from_slice(b"0001");
    push_pkt_line(&mut inc_mixed, b"packfile-uris https\n")?;
    push_pkt_line(&mut inc_mixed, format!("want {main_c4}\n").as_bytes())?;
    push_pkt_line(&mut inc_mixed, format!("have {}\n", ctx.tip_c3).as_bytes())?;
    push_pkt_line(&mut inc_mixed, b"done\n")?;
    inc_mixed.extend_from_slice(b"0000");
    let mixed_resp = http
        .post(&up_url)
        .header("Authorization", ctx.basic_hdr)
        .header("Content-Type", "application/x-git-upload-pack-request")
        .header("Git-Protocol", "version=2")
        .body(inc_mixed)
        .send()
        .await?
        .bytes()
        .await?;
    ensure!(ctx.offload.last_fallback_reason() == Some(FallbackReason::PackContainsUnauthorizedObjects));
    ensure!(!String::from_utf8_lossy(&mixed_resp).contains("packfile-uris"));

    let single_main = ctx.tmp_dir.join(format!("clone_single_main_{}", ctx.fmt_str));
    git_fn(
        &[
            "-c",
            "protocol.version=2",
            "-c",
            "fetch.uriprotocols=https",
            "-c",
            ctx.ca_cfg,
            "-c",
            ctx.proxy_cfg,
            "clone",
            "--single-branch",
            "--branch",
            "main",
            ctx.off_url,
            single_main.to_str().unwrap(),
        ],
        Some(ctx.tmp_dir),
        None,
    )?;
    git_fn(&["fsck", "--full", "--strict"], Some(&single_main), None)?;
    ensure!(single_main.join("main_c4.txt").is_file());
    ensure!(
        git_fn(&["cat-file", "-e", &side_blob], Some(&single_main), None).is_err(),
        "mixed pack leaked unrequested side-branch blob {side_blob} into main single-branch clone"
    );
    Ok(main_c4)
}
