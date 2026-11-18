//! Real PG17 + in-process S3 + native Git harness for the S4 acceptance suite.
//!
//! Each case owns one fresh PostgreSQL schema and one fresh in-memory S3
//! endpoint. A process-global async lock serializes the `ROOTYARD_BLOB_*` and
//! `ROOTYARD_CI_MIRROR_AUDIENCE` environment because the production Blob/CI
//! code reads it by name. Nothing here invokes `cargo` or builds a binary.
#[path = "git.rs"]
pub mod git;
#[path = "s3.rs"]
mod s3;

pub use git::Git;
use s3::LoopbackS3;

use anyhow::{Context, Result, anyhow, ensure};
use deadpool_postgres::{Manager, Pool};
use rootyard::{
    AppState,
    blob_git_gateway::{BlobGitConfig, BlobGitState, router as blob_router},
    blob_store::{config::BlobProfile, opendal::BlobStore},
    config::Config,
    db, dispatch, metrics,
    ref_store::{
        core::decision_commit::{PgDecisionProtocol, RealmExpectation},
        serving::lookup,
    },
    storage::Storage,
};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::{Mutex, MutexGuard},
    task::JoinHandle,
};
use uuid::Uuid;

pub const AUDIENCE: &str = "00000000-0000-4000-8000-000000000147";

static ENV_LOCK: Mutex<()> = Mutex::const_new(());

pub fn deadline() -> tokio::time::Instant {
    tokio::time::Instant::now() + Duration::from_secs(120)
}

struct EnvGuard {
    saved: Vec<(&'static str, Option<String>)>,
}

impl EnvGuard {
    fn set(pairs: &[(&'static str, String)]) -> Self {
        let mut saved = Vec::with_capacity(pairs.len());
        for (key, next) in pairs {
            saved.push((*key, std::env::var(key).ok()));
            unsafe { std::env::set_var(key, next) };
        }
        Self { saved }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (key, previous) in self.saved.drain(..).rev() {
            match previous {
                Some(value) => unsafe { std::env::set_var(key, value) },
                None => unsafe { std::env::remove_var(key) },
            }
        }
    }
}

pub struct Actor {
    pub identity: db::Identity,
    pub token: String,
    pub username: String,
}

pub struct Cluster {
    pub owner: Actor,
    pub main: String,
    pub blob: String,
    pub pool: Pool,
    pub scratch: PathBuf,
    pub git: Git,
    servers: Vec<JoinHandle<()>>,
    s3_delay: Arc<AtomicU64>,
    _s3: LoopbackS3,
    admin: Pool,
    schema: String,
    _env: EnvGuard,
    _lock: MutexGuard<'static, ()>,
}

pub struct Repository {
    pub id: Uuid,
    pub name: String,
    pub generation: i64,
    pub object_format: String,
}

impl Cluster {
    pub async fn setup() -> Result<Self> {
        let lock = ENV_LOCK.lock().await;
        let s3 = LoopbackS3::start().await?;
        let scratch = std::env::temp_dir().join(format!("rootyard-s4-{}", Uuid::new_v4().simple()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&scratch)?;
        }
        #[cfg(not(unix))]
        std::fs::create_dir_all(&scratch)?;
        std::fs::create_dir_all(scratch.join("blob"))?;
        std::fs::create_dir_all(scratch.join("data"))?;
        let run = Uuid::new_v4().simple().to_string();
        let env = EnvGuard::set(&[
            ("ROOTYARD_BLOB_DRIVER", "opendal".to_owned()),
            ("ROOTYARD_BLOB_SERVICE", "s3".to_owned()),
            ("ROOTYARD_BLOB_BUCKET", "s4-view-bucket".to_owned()),
            ("ROOTYARD_BLOB_REGION", "us-east-1".to_owned()),
            ("ROOTYARD_BLOB_ROOT", format!("s4-view/{run}")),
            ("ROOTYARD_BLOB_ENDPOINT", s3.endpoint.clone()),
            ("ROOTYARD_BLOB_ACCESS_KEY_ID", "test-ak".to_owned()),
            ("ROOTYARD_BLOB_SECRET_ACCESS_KEY", "test-sk".to_owned()),
            ("ROOTYARD_BLOB_ENCRYPTION_MODE", "provider-managed".to_owned()),
            ("ROOTYARD_BLOB_MAX_OBJECT_BYTES", "33554432".to_owned()),
            ("ROOTYARD_BLOB_RETRY_MAX_TIMES", "3".to_owned()),
            ("ROOTYARD_CI_MIRROR_AUDIENCE", AUDIENCE.to_owned()),
        ]);
        let base_url =
            std::env::var("ROOTYARD_TEST_DATABASE_URL").context("ROOTYARD_TEST_DATABASE_URL must be set")?;
        let schema = format!("s4_view_{}", Uuid::new_v4().simple());
        let admin = rootyard::db::pool(&base_url)?;
        db::migrate(&admin).await?;
        admin
            .get()
            .await?
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .context("create the run schema")?;
        let pool = schema_pool(&base_url, &schema)?;
        db::migrate(&pool).await?;
        let owner = issue_actor(&pool).await?;
        let git = Git::new()?;
        let binary = git.binary().to_path_buf();
        let profile = BlobProfile::from_env().map_err(|_| anyhow!("ROOTYARD_BLOB_* profile rejected"))?;
        let store = BlobStore::open(profile).map_err(|_| anyhow!("Blob store rejected"))?;
        let blob_state = Arc::new(
            BlobGitState::new(BlobGitConfig {
                pool: pool.clone(),
                store,
                git_binary: binary.clone(),
                scratch_root: scratch.join("blob"),
                max_concurrent_requests: 4,
                max_request_bytes: 16 * 1024 * 1024,
                max_response_bytes: 64 * 1024 * 1024,
                max_inflight_bytes: 64 * 1024 * 1024,
                operation_deadline: Duration::from_secs(120),
                native_limits: Default::default(),
            })
            .map_err(|_| anyhow!("Blob gateway configuration rejected"))?,
        );
        let config = Config {
            database_url: base_url,
            data_dir: scratch.join("data"),
            bind: "127.0.0.1:0".parse()?,
            git: binary,
            max_request_bytes: 64 * 1024 * 1024,
            max_output_bytes: 64 * 1024 * 1024,
            max_concurrent_git: 4,
            git_timeout: Duration::from_secs(120),
            git_memory_bytes: 1024 * 1024 * 1024,
            max_repo_bytes: 128 * 1024 * 1024,
            max_pending_deliveries: 1000,
            outbox_worker: false,
            metrics_bind: None,
        };
        let storage = Storage::open(&config)?;
        let state = Arc::new(AppState {
            mirror_primary: None,
            dispatch: dispatch::Signals::default(),
            config,
            pool: pool.clone(),
            storage,
            hooks: None,
            transfer_metrics: Arc::new(metrics::TransferCounters::default()),
            git_slots: Arc::new(tokio::sync::Semaphore::new(8)),
        });
        let blob_listener = TcpListener::bind("127.0.0.1:0").await?;
        let blob = format!("http://{}", blob_listener.local_addr()?);
        let blob_task = tokio::spawn(async move {
            let _ = axum::serve(blob_listener, blob_router(blob_state)).await;
        });
        let main_listener = TcpListener::bind("127.0.0.1:0").await?;
        let main = format!("http://{}", main_listener.local_addr()?);
        let main_router = rootyard::router(state);
        let main_task = tokio::spawn(async move {
            let _ = axum::serve(main_listener, main_router).await;
        });
        Ok(Self {
            owner,
            main,
            blob,
            pool,
            scratch,
            git,
            servers: vec![blob_task, main_task],
            s3_delay: s3.get_delay_ms.clone(),
            _s3: s3,
            admin,
            schema,
            _env: env,
            _lock: lock,
        })
    }

    pub fn set_s3_get_delay_ms(&self, delay_ms: u64) {
        self.s3_delay.store(delay_ms, Ordering::Release);
    }

    pub async fn create_repository(&self, name: &str, format: &str) -> Result<Repository> {
        let body: Value = self
            .post_json(
                &format!("{}/api/repos", self.blob),
                &self.owner.token,
                json!({"name": name, "object_format": format}),
            )
            .await?;
        let id = Uuid::parse_str(body["id"].as_str().ok_or_else(|| anyhow!("create response has no id"))?)?;
        let profile = BlobProfile::from_env().map_err(|_| anyhow!("profile rejected"))?;
        let store = BlobStore::open(profile).map_err(|_| anyhow!("store rejected"))?;
        let serving =
            lookup(&self.pool, &self.owner.identity, &self.owner.username, name, true, store.backend_identity(), deadline())
                .await
                .map_err(|error| anyhow!("serving lookup: {}", error.1))?;
        let gate = serving.gate;
        let expectation = RealmExpectation::new(
            gate.repository_id(),
            gate.tenant_id(),
            gate.object_format(),
            gate.history_incarnation(),
            gate.authority_epoch(),
            gate.group_epoch(),
        )?;
        let mut client = self.pool.get().await?;
        PgDecisionProtocol
            .provision(&mut client, &expectation, deadline())
            .await
            .map_err(|_| anyhow!("decision realm provisioning refused"))?;
        drop(client);
        let generation: i64 =
            self.pool.get().await?.query_one("SELECT storage_generation FROM repositories WHERE id=$1", &[&id]).await?.get(0);
        Ok(Repository { id, name: name.to_owned(), generation, object_format: format.to_owned() })
    }

    fn source_url(&self, repo: &Repository) -> String {
        format!(
            "http://{}:{}@{}/git/{}/{}.git",
            self.owner.username,
            self.owner.token,
            self.blob.trim_start_matches("http://"),
            self.owner.username,
            repo.name
        )
    }

    pub async fn push_initial(&self, repo: &Repository, files: &[(&str, &str)]) -> Result<String> {
        let work = self.scratch.join(format!("push-{}", Uuid::new_v4().simple()));
        std::fs::create_dir_all(&work)?;
        if repo.object_format == "sha256" {
            self.git.init_remote(&work, &self.source_url(repo), "repo").await?;
        } else {
            self.git.clone(&work, &self.source_url(repo), "repo").await?;
        }
        let checkout = work.join("repo");
        let mut head = String::new();
        for (file, content) in files {
            head = self.git.commit(&checkout, file, content, "fixture").await?;
        }
        self.git.ok(&checkout, &["push", "origin", "HEAD:refs/heads/main"]).await?;
        Ok(head)
    }

    pub async fn force_push(&self, repo: &Repository, file: &str, content: &str) -> Result<String> {
        let work = self.scratch.join(format!("force-{}", Uuid::new_v4().simple()));
        std::fs::create_dir_all(&work)?;
        self.git.clone_any(&work, &self.source_url(repo), "repo", &repo.object_format).await?;
        let checkout = work.join("repo");
        let head = self.git.commit(&checkout, file, content, "rewrite").await?;
        self.git.ok(&checkout, &["push", "--force", "origin", "HEAD:refs/heads/main"]).await?;
        Ok(head)
    }

    pub async fn clone_source(&self, repo: &Repository) -> Result<std::path::PathBuf> {
        let work = self.scratch.join(format!("source-{}", Uuid::new_v4().simple()));
        std::fs::create_dir_all(&work)?;
        self.git.clone_any(&work, &self.source_url(repo), "repo", &repo.object_format).await?;
        Ok(work.join("repo"))
    }

    pub async fn ci_clone(&self, repo: &Repository, target: &str, token: &str) -> Result<String> {
        let work = self.scratch.join(format!("ci-{}", Uuid::new_v4().simple()));
        std::fs::create_dir_all(&work)?;
        let url = format!(
            "http://{}:{}@{}/ci/{}/git/{}/{}.git",
            self.owner.username,
            token,
            self.main.trim_start_matches("http://"),
            target,
            self.owner.username,
            repo.name
        );
        self.git.clone_any(&work, &url, "ci", &repo.object_format).await?;
        self.git.text(&work.join("ci"), &["rev-parse", "HEAD"]).await
    }

    pub async fn clone_view(&self, view: &str, format: &str) -> Result<PathBuf> {
        let work = self.scratch.join(format!("view-http-{}", Uuid::new_v4().simple()));
        std::fs::create_dir_all(&work)?;
        let url = format!(
            "http://{}:{}@{}/git/views/{view}.git",
            self.owner.username,
            self.owner.token,
            self.main.trim_start_matches("http://"),
        );
        self.git.clone_any(&work, &url, "proj", format).await?;
        Ok(work.join("proj"))
    }

    pub async fn pin(&self, repo: &Repository, job_id: Uuid, target: &str) -> Result<Value> {
        self.post_json(
            &format!("{}/api/repos/{}/{}/ci-pins", self.main, self.owner.username, repo.name),
            &self.owner.token,
            json!({"job_id": job_id, "target_oid": target, "storage_generation": repo.generation}),
        )
        .await
    }

    pub async fn checkout(&self, repo: &Repository, job_id: Uuid, target: &str) -> Result<String> {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs() as i64;
        let body: Value = self
            .post_json(
                &format!("{}/api/repos/{}/{}/ci-checkouts", self.main, self.owner.username, repo.name),
                &self.owner.token,
                json!({
                    "job_id": job_id,
                    "target_oid": target,
                    "storage_generation": repo.generation,
                    "mirror_audience": AUDIENCE,
                    "expires_unix": now + 600,
                }),
            )
            .await?;
        body["token"].as_str().map(str::to_owned).ok_or_else(|| anyhow!("checkout response has no token"))
    }

    pub async fn namespace(&self, repo: &Repository, base: &str, path: &str) -> Result<String> {
        let body: Value = self
            .post_json(
                &format!("{}/api/namespaces", self.main),
                &self.owner.token,
                json!({
                    "name": format!("ns-{}", Uuid::new_v4().simple()),
                    "mounts": [{
                        "path": path,
                        "owner": self.owner.username,
                        "repository": repo.name,
                        "base_oid": base,
                    }],
                }),
            )
            .await?;
        body["id"].as_str().map(str::to_owned).ok_or_else(|| anyhow!("namespace has no id"))
    }

    pub async fn view(&self, namespace: &str, mount_path: &str, subdir: &str) -> Result<String> {
        let body: Value = self
            .post_json(
                &format!("{}/api/namespaces/{namespace}/views", self.main),
                &self.owner.token,
                json!({"mount_path": mount_path, "subdir": subdir}),
            )
            .await?;
        body["id"].as_str().map(str::to_owned).ok_or_else(|| anyhow!("view has no id"))
    }

    pub async fn get_bundle(&self, view: &str) -> Result<Vec<u8>> {
        let response = reqwest::Client::new()
            .get(format!("{}/api/views/{view}/bundle", self.main))
            .bearer_auth(&self.owner.token)
            .send()
            .await?;
        ensure!(response.status().is_success(), "bundle returned {}", response.status());
        Ok(response.bytes().await?.to_vec())
    }

    pub async fn reverse(&self, view: &str, bundle: &[u8], source_ref: &str) -> Result<Value> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        self.post_json(
            &format!("{}/api/views/{view}/changesets", self.main),
            &self.owner.token,
            json!({
                "bundle_base64": STANDARD.encode(bundle),
                "bundle_ref": "refs/heads/projected",
                "source_ref": source_ref,
                "message": "reverse fixture merge",
            }),
        )
        .await
    }

    pub async fn post_json(&self, url: &str, token: &str, body: Value) -> Result<Value> {
        let response = reqwest::Client::new().post(url).bearer_auth(token).json(&body).send().await?;
        let status = response.status();
        let value: Value = response.json().await.unwrap_or(Value::Null);
        ensure!(status.is_success(), "POST {url} returned {status}: {value}");
        Ok(value)
    }

    pub async fn finish(mut self, outcome: Result<()>) -> Result<()> {
        for server in self.servers.drain(..) {
            server.abort();
            let _ = server.await;
        }
        let cleanup = async {
            let client = self.admin.get().await?;
            client.batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema)).await?;
            Ok::<(), anyhow::Error>(())
        }
        .await;
        let _ = std::fs::remove_dir_all(&self.scratch);
        match (outcome, cleanup) {
            (Err(error), _) => Err(error),
            (Ok(()), Err(error)) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        }
    }
}

/// Deterministic printable bytes that Git's deflate cannot compress, so the
/// retained pack is large enough to arrive in many 16 KiB transport chunks.
pub fn incompressible(len: usize) -> String {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let mut text = String::with_capacity(len + len / 32 + 1);
    while text.len() < len {
        for _ in 0..32 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            text.push(char::from(b'!' + ((state >> 33) as u8 % 94)));
        }
        text.push('\n');
    }
    text
}

/// POST a JSON body and keep only the status, for assertions about refusals.
pub async fn post_status(url: &str, token: &str, body: Value) -> Result<reqwest::StatusCode> {
    let response = reqwest::Client::new().post(url).bearer_auth(token).json(&body).send().await?;
    Ok(response.status())
}

async fn issue_actor(pool: &Pool) -> Result<Actor> {
    let username = format!("s4{}", &Uuid::new_v4().simple().to_string()[..12]);
    let value = db::issue_token(pool, &username, true, false)
        .await
        .map_err(|error| anyhow!("issue token: {error}"))?;
    let token = value["token"].as_str().ok_or_else(|| anyhow!("no token secret"))?.to_owned();
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        format!("Bearer {token}").parse().map_err(|_| anyhow!("token header"))?,
    );
    let identity = rootyard::auth::authenticate(pool, &headers)
        .await
        .map_err(|error| anyhow!("authenticate: {}", error.1))?;
    Ok(Actor { identity, token, username })
}

fn schema_pool(url: &str, schema: &str) -> Result<Pool> {
    let mut config: tokio_postgres::Config = url.parse()?;
    config.options(format!("-c search_path={schema} -c timezone=UTC -c statement_timeout=30000"));
    Ok(Pool::builder(Manager::new(config, tokio_postgres::NoTls))
        .runtime(deadpool_postgres::Runtime::Tokio1)
        .max_size(16)
        .build()?)
}
