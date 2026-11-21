//! PG17 schema, actor provisioning, and production `rootyard::lfs::routes()` (`AppState`)
//! server harness (`Refs #145`).

pub mod adversarial;
pub mod adversarial_cancel;
pub mod adversarial_default_ops;
pub mod adversarial_org_restart;
pub mod git_smart_http;
pub mod lease_state_regressions;
pub mod multi_instance_auth_boundary;
pub mod s3_loopback;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use deadpool_postgres::{Manager, Pool};
use rootyard::{
    AppState,
    config::Config,
    db, dispatch,
    lfs::blob_proof_publication::{LfsBlobRuntimeGate, init_lfs_blob_proof_tables, set_runtime_gate_override},
    metrics,
    storage::Storage,
};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use uuid::Uuid;

pub use s3_loopback::{LoopbackS3, RealHookInput, run_real_validate_hook};

#[derive(Clone, Debug)]
pub struct TestActor {
    pub user_id: Uuid,
    pub token_id: Uuid,
    pub username: String,
    pub token: String,
}

pub async fn issue_actor(pool: &Pool, username: &str) -> Result<TestActor> {
    let val = db::issue_token(pool, username, true, false).await?;
    Ok(TestActor {
        user_id: serde_json::from_value(val["user_id"].clone())?,
        token_id: serde_json::from_value(val["token_id"].clone())?,
        username: username.to_owned(),
        token: val["token"].as_str().context("token string")?.to_owned(),
    })
}

fn find_git_binary() -> PathBuf {
    for cand in ["/usr/bin/git", "/usr/local/bin/git", "/bin/git"] {
        let p = PathBuf::from(cand);
        if p.exists() {
            return p;
        }
    }
    PathBuf::from("git")
}

static ACTIVE_SERVERS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

pub struct RunningProdLfsServer {
    pub base_url: String,
    pub state: Arc<AppState>,
    _data_dir: TempDir,
    handle: JoinHandle<()>,
}

impl Drop for RunningProdLfsServer {
    fn drop(&mut self) {
        self.handle.abort();
        if ACTIVE_SERVERS.fetch_sub(1, std::sync::atomic::Ordering::SeqCst) == 1 {
            set_runtime_gate_override(None);
        }
    }
}

impl RunningProdLfsServer {
    pub async fn start(gate: LfsBlobRuntimeGate, pool: Pool, db_url: &str) -> Result<Self> {
        Self::start_in_dir(gate, pool, db_url, TempDir::new()?).await
    }

    pub async fn start_in_dir(gate: LfsBlobRuntimeGate, pool: Pool, db_url: &str, data_dir: TempDir) -> Result<Self> {
        set_runtime_gate_override(Some(gate));
        let config = Config {
            database_url: db_url.to_owned(),
            data_dir: data_dir.path().join("data"),
            bind: "127.0.0.1:0".parse()?,
            git: find_git_binary(),
            max_request_bytes: 32 * 1024 * 1024,
            max_output_bytes: 32 * 1024 * 1024,
            max_concurrent_git: 8,
            git_timeout: Duration::from_secs(20),
            git_memory_bytes: 256 * 1024 * 1024,
            max_repo_bytes: 256 * 1024 * 1024,
            max_pending_deliveries: 100,
            outbox_worker: false,
            metrics_bind: None,
        };
        let storage = Storage::open(&config)?;
        let state = Arc::new(AppState {
            mirror_primary: None,
            dispatch: dispatch::Signals::default(),
            config,
            pool,
            storage,
            hooks: None,
            transfer_metrics: Arc::new(metrics::TransferCounters::default()),
            git_slots: Arc::new(Semaphore::new(8)),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let base_url = format!("http://127.0.0.1:{port}");
        let app = git_smart_http::production_s4_test_router(Arc::clone(&state));
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        ACTIVE_SERVERS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(Self { base_url, state, _data_dir: data_dir, handle })
    }

    pub fn git_url_for(&self, actor: &TestActor, owner: &str, repo: &str) -> String {
        format!("{}/{owner}/{repo}.git", self.base_url).replacen(
            "http://",
            &format!("http://{}:{}@", actor.username, actor.token),
            1,
        )
    }

    pub async fn create_repo(
        &self,
        actor: &TestActor,
        owner: Option<&str>,
        name: &str,
        fmt: &str,
    ) -> Result<(Uuid, Uuid)> {
        let mut payload = json!({ "name": name, "object_format": fmt });
        if let Some(o) = owner {
            payload["owner"] = json!(o);
        }
        let res = reqwest::Client::new()
            .post(format!("{}/api/repos", self.base_url))
            .bearer_auth(&actor.token)
            .json(&payload)
            .send()
            .await?;
        let status = res.status();
        let body: Value = res.json().await?;
        ensure!(status.is_success(), "POST /api/repos failed ({status}): {body}");
        ensure!(body["state"] == "ready", "repo must be ready: {body}");
        let repo_id: Uuid = serde_json::from_value(body["id"].clone())?;
        let owner_id: Uuid = self
            .state
            .pool
            .get()
            .await?
            .query_one("SELECT owner_id FROM repositories WHERE id = $1", &[&repo_id])
            .await?
            .get(0);
        Ok((repo_id, owner_id))
    }

    pub async fn create_org(&self, actor: &TestActor, slug: &str) -> Result<Uuid> {
        let res = reqwest::Client::new()
            .post(format!("{}/api/orgs", self.base_url))
            .bearer_auth(&actor.token)
            .json(&json!({ "slug": slug }))
            .send()
            .await?;
        let status = res.status();
        let body: Value = res.json().await?;
        ensure!(status.is_success(), "POST /api/orgs failed ({status}): {body}");
        Ok(serde_json::from_value(body["id"].clone())?)
    }

    pub async fn put_org_member(&self, admin: &TestActor, slug: &str, username: &str, role: &str) -> Result<()> {
        let res = reqwest::Client::new()
            .put(format!("{}/api/orgs/{slug}/members/{username}", self.base_url))
            .bearer_auth(&admin.token)
            .json(&json!({ "role": role }))
            .send()
            .await?;
        ensure!(res.status().is_success(), "PUT org member failed: {}", res.status());
        Ok(())
    }

    pub async fn put_collaborator(
        &self,
        admin: &TestActor,
        owner: &str,
        repo: &str,
        username: &str,
        role: &str,
    ) -> Result<()> {
        let res = reqwest::Client::new()
            .put(format!("{}/api/repos/{owner}/{repo}/collaborators/{username}", self.base_url))
            .bearer_auth(&admin.token)
            .json(&json!({ "role": role }))
            .send()
            .await?;
        ensure!(res.status().is_success(), "PUT collaborator failed: {}", res.status());
        Ok(())
    }
}

pub fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let target = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&entry.path(), &target)?;
        } else if ty.is_file() {
            std::fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

pub async fn run_with_migrated_pg_schema<F, Fut>(f: F) -> Result<()>
where
    F: FnOnce(Pool, String) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let url = std::env::var("ROOTYARD_TEST_DATABASE_URL")
        .context("ROOTYARD_TEST_DATABASE_URL must be set for ignored PG17 tests")?;
    let admin = db::pool(&url)?;
    let schema = format!("lfs145_test_{}", Uuid::new_v4().simple());
    admin.get().await?.batch_execute(&format!("CREATE SCHEMA {schema}")).await?;
    let mut parsed_url = reqwest::Url::parse(&url)?;
    parsed_url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let schema_url = parsed_url.to_string();

    let mut cfg: tokio_postgres::Config = url.parse()?;
    cfg.options(format!("-c search_path={schema} -c timezone=UTC -c statement_timeout=30000 -c lock_timeout=15000"));
    let pool = Pool::builder(Manager::new(cfg, tokio_postgres::NoTls))
        .runtime(deadpool_postgres::Runtime::Tokio1)
        .max_size(24)
        .build()?;
    let res = async {
        db::migrate(&pool).await?;
        init_lfs_blob_proof_tables(&pool).await?;
        f(pool.clone(), schema_url).await
    }
    .await;
    set_runtime_gate_override(None);
    pool.close();
    drop(pool);
    let teardown = admin.get().await?.batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE")).await;
    admin.close();
    res?;
    teardown?;
    Ok(())
}

pub fn init_git_lfs_home(home: &Path) -> Result<()> {
    std::fs::create_dir_all(home)?;
    let out = Command::new("git")
        .args(["lfs", "install", "--skip-repo"])
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .context("git lfs must be installed on PATH")?;
    ensure!(out.status.success(), "git lfs install failed: {}", String::from_utf8_lossy(&out.stderr));
    for (k, v) in [("user.name", "Rootyard LFS Test"), ("user.email", "lfs@rootyard.test"), ("protocol.version", "2")] {
        let cfg = Command::new("git")
            .args(["config", "--global", k, v])
            .env("HOME", home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()?;
        ensure!(cfg.status.success(), "git config {k} failed");
    }
    Ok(())
}

pub fn run_git_raw(cwd: &Path, home: &Path, args: &[&str]) -> Result<Output> {
    let cwd_buf = cwd.to_path_buf();
    let home_buf = home.to_path_buf();
    let owned_args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let res = Command::new("git")
            .args(["-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"])
            .args(&owned_args)
            .current_dir(&cwd_buf)
            .env("HOME", &home_buf)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_ASKPASS", "/bin/false")
            .output();
        let _ = tx.send(res);
    });
    tokio::task::block_in_place(|| {
        rx.recv_timeout(Duration::from_secs(45))
            .map_err(|_| anyhow::anyhow!("git {args:?} timed out after 45s"))?
            .map_err(Into::into)
    })
}

pub fn run_git_ok(cwd: &Path, home: &Path, args: &[&str]) -> Result<String> {
    let out = run_git_raw(cwd, home, args)?;
    if !out.status.success() {
        bail!(
            "git {:?} failed (code {:?}):\nstdout: {}\nstderr: {}",
            args,
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}
