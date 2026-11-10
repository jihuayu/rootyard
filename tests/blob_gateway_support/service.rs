//! The real, already built `rootyard serve-blob` binary, launched exactly as
//! the `standalone` entrypoint configures itself.
//!
//! The fixture never builds, patches or replaces the binary. It passes the
//! operator's real environment through only after a start-up preflight, and it
//! pins the run-owned coordinates so this suite can never collide with another
//! run:
//!
//! * `DATABASE_URL` is the operator's URL with one random `search_path`
//!   ([`Db::database_url`]); the service holds its lifecycle barrier inside this
//!   database and resolves every table to the schema this process migrated;
//! * `ROOTYARD_BLOB_ROOT` is this run's random relative remote prefix. It is a
//!   bucket prefix, never a local directory: an absolute path such as a scratch
//!   directory joined with `blob-root` is refused by `validate_root` before the
//!   service starts;
//! * the service migrates itself (`ROOTYARD_SCHEMA_MODE=auto`). The fixture
//!   migrated the run schema first, so the service's own `db::migrate` is the
//!   production start-up path on an already-current schema.
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use serde_json::{Value, json};
use tokio::process::Command;

use super::{
    actor::Actor,
    blob,
    db::{Db, deadline},
    preflight::preflight,
};

/// Start the already built production binary.
pub struct Service {
    child: tokio::process::Child,
    pub address: SocketAddr,
    _scratch: tempfile::TempDir,
}

impl Service {
    pub async fn launch(binary: &Path) -> Result<Self> {
        Self::launch_with(binary, &[]).await
    }

    /// Same launch with extra environment entries (tests only). They are set
    /// first; the fixed run-owned coordinates always win. The scratch directory
    /// carries the run-only `git126-` prefix, so any compute view the service
    /// leaves behind is visibly owned by this suite.
    pub async fn launch_with(binary: &Path, extra: &[(&str, &str)]) -> Result<Self> {
        preflight(binary)?;
        let schema_mode = schema_mode();
        ensure!(
            extra.iter().all(|(name, _)| *name != "ROOTYARD_SCHEMA_MODE"),
            "the run chooses ROOTYARD_SCHEMA_MODE once for every service; no per-service override"
        );
        let database_url = std::env::var("ROOTYARD_TEST_DATABASE_URL")
            .context("ROOTYARD_TEST_DATABASE_URL must be set for the blob_git_gateway suite")?;
        let scratch = tempfile::Builder::new().prefix("git126-").tempdir()?;
        let scratch_path = scratch.path().to_path_buf();
        // The service refuses a scratch directory another uid can read, and the
        // runtime HOME must exist already (it does not create it).
        private_directory(&scratch_path)?;
        let log = std::fs::File::create(scratch_path.join("service.log"))?;
        let runtime_home = scratch_path.join("runtime-home");
        private_directory(&runtime_home)?;
        // Reserve an ephemeral loopback port, then hand it to the service. The
        // service's readiness probe must reach the service itself.
        let reserved = std::net::TcpListener::bind(("127.0.0.1", 0))?;
        let address = reserved.local_addr()?;
        drop(reserved);
        let (root_name, root) = blob::root_environment()?;
        let mut command = Command::new(binary);
        command.arg("serve-blob").env_clear();
        for (name, value) in extra {
            command.env(name, value);
        }
        let mut child = command
            .env("DATABASE_URL", &database_url)
            .env("ROOTYARD_BIND", address.to_string())
            .env("ROOTYARD_GIT", git_binary())
            .env("ROOTYARD_SCRATCH_DIR", &scratch_path)
            .env("ROOTYARD_DATA_DIR", &runtime_home)
            .env(root_name, root)
            .env("ROOTYARD_SCHEMA_MODE", schema_mode)
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &runtime_home)
            .env("TMPDIR", &runtime_home)
            .env("ROOTYARD_MAX_CONCURRENT_GIT", "8")
            .current_dir(&scratch_path)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .kill_on_drop(true)
            .spawn()
            .context("could not start the rootyard serve-blob binary")?;
        let client = reqwest::Client::builder().timeout(Duration::from_secs(2)).no_proxy().build()?;
        for _ in 0..600 {
            if let Some(status) = child.try_wait()? {
                let log = std::fs::read_to_string(scratch_path.join("service.log")).unwrap_or_default();
                bail!("serve-blob exited during startup ({status}): {}", startup_lines(&log));
            }
            if let Ok(response) = client.get(format!("http://{address}/health/ready")).send().await
                && response.status().is_success()
            {
                return Ok(Self { child, address, _scratch: scratch });
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let log = std::fs::read_to_string(scratch_path.join("service.log")).unwrap_or_default();
        let _ = child.start_kill();
        bail!("serve-blob did not become ready on its loopback port in time: {}", startup_lines(&log));
    }

    /// Create one real repository through the create API and return its id.
    pub async fn create_repository(&self, owner: &Actor, name: &str) -> Result<uuid::Uuid> {
        let response = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .no_proxy()
            .build()?
            .post(format!("http://{}/api/repos", self.address))
            .bearer_auth(&owner.token)
            .json(&json!({"name": name, "object_format": "sha1"}))
            .send()
            .await?;
        let status = response.status();
        ensure!(status.is_success(), "create API refused a repository with {status}");
        let body: Value = response.json().await?;
        let owner_slug = body["owner"].as_str().unwrap_or_default();
        ensure!(
            owner_slug == owner.username && body["name"].as_str() == Some(name),
            "create API returned another identity"
        );
        Ok(uuid::Uuid::parse_str(body["id"].as_str().unwrap_or_default())?)
    }

    /// Provision the migration-144 decision realm once, so the push cases
    /// exercise ref decisions and not realm provisioning. A refusal is an error:
    /// a push cannot succeed without the realm.
    pub async fn provision_decision_realm(&self, db: &Db, owner: &Actor, name: &str) -> Result<()> {
        use rootyard::ref_store::core::decision_commit::{PgDecisionProtocol, RealmExpectation};
        let backend = self.backend_identity()?;
        let serving = rootyard::ref_store::serving::lookup(
            &db.pool,
            &owner.identity,
            &owner.username,
            name,
            true,
            &backend,
            deadline(),
        )
        .await
        .map_err(|error| anyhow!("serving lookup refused the created repository: {}", error.1))?;
        let gate = serving.gate;
        let expectation = RealmExpectation::new(
            gate.repository_id(),
            gate.tenant_id(),
            gate.object_format(),
            gate.history_incarnation(),
            gate.authority_epoch(),
            gate.group_epoch(),
        )?;
        #[allow(unused_mut)]
        let mut client = db.pool.get().await?;
        PgDecisionProtocol
            .provision(&mut client, &expectation, deadline())
            .await
            .map_err(|error| anyhow!("decision realm provisioning refused: {error}"))?;
        Ok(())
    }

    /// Identity of the Blob backend this service opened (same operator profile,
    /// same run-owned prefix).
    pub fn backend_identity(&self) -> Result<rootyard::blob_store::BlobBackendIdentity> {
        blob::open_store().map(|store| store.backend_identity().clone())
    }

    /// One typed HTTP GET from the service (not through the proxy).
    pub async fn get(&self, token: Option<&str>, path: &str) -> Result<(u16, Value)> {
        let mut request = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .no_proxy()
            .build()?
            .get(format!("http://{}{path}", self.address));
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        let response = request.send().await?;
        let status = response.status().as_u16();
        let body = response.json().await.unwrap_or(Value::Null);
        Ok((status, body))
    }

    /// Stop the service and prove it exited. Its temp scratch goes with it.
    #[allow(dead_code)]
    pub async fn stop(mut self) -> Result<()> {
        self.child.start_kill()?;
        tokio::time::timeout(Duration::from_secs(30), self.child.wait())
            .await
            .map_err(|_| anyhow!("serve-blob did not exit after SIGKILL"))??;
        Ok(())
    }
}

/// The schema mode every service of this run uses. `auto` is the default; an
/// operator that runs PostgreSQL with an external migrator sets `external` for
/// the whole run, and every service then verifies instead of migrating.
fn schema_mode() -> &'static str {
    match std::env::var("ROOTYARD_SCHEMA_MODE").as_deref() {
        Ok("external") => "external",
        _ => "auto",
    }
}

fn git_binary() -> PathBuf {
    PathBuf::from(std::env::var("ROOTYARD_TEST_GIT").unwrap_or_else(|_| "/usr/bin/git".to_owned()))
}

fn private_directory(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn startup_lines(log: &str) -> String {
    let lines = log.lines().filter(|line| !line.trim().is_empty()).take(8).collect::<Vec<_>>();
    if lines.is_empty() { "<no output>".to_owned() } else { lines.join(" | ") }
}
