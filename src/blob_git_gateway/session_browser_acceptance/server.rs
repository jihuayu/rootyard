//! The real standalone child: private run root, keyring files, scrubbed
//! environment, bounded readiness probe and bounded SIGTERM drain.
use std::{
    os::unix::{
        fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
        process::ExitStatusExt,
    },
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, ensure};
use tokio::{process::Child, time::Instant};
use zeroize::Zeroizing;

use super::support::db::Db;

/// Bound on the child's readiness probe.
const READY_SECONDS: u64 = 120;
/// Bound on the graceful SIGTERM drain.
const STOP_SECONDS: u64 = 120;

/// One unique mode-`0700` root removed on drop; its files are mode `0600`.
pub(super) struct RunRoot {
    root: tempfile::TempDir,
}

impl RunRoot {
    pub(super) fn create() -> Result<Self> {
        let root = tempfile::Builder::new()
            .prefix("rootyard-session-browser-")
            .tempdir_in(std::env::temp_dir())
            .context("private browser acceptance root")?;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
        Ok(Self { root })
    }

    pub(super) fn root_path(&self) -> &Path {
        self.root.path()
    }

    pub(super) fn path(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }

    pub(super) fn private_dir(&self, name: &str) -> Result<PathBuf> {
        let path = self.path(name);
        std::fs::DirBuilder::new().mode(0o700).create(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        Ok(path)
    }

    /// Create one empty mode-`0600` file and return its path.
    pub(super) fn private_file(&self, name: &str) -> Result<PathBuf> {
        let path = self.path(name);
        write_private(&path, b"")?;
        Ok(path)
    }
}

/// Write one new mode-`0600` file. Its bytes are caller-owned; nothing is
/// logged.
pub(super) fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// A required environment variable that must name an absolute executable.
pub(super) fn required_binary(name: &str) -> Result<PathBuf> {
    let path = std::env::var_os(name).map(PathBuf::from).ok_or_else(|| anyhow!("{name} must be set for this case"))?;
    ensure!(path.is_absolute(), "{name} must be an absolute path");
    require_executable(&path, name)
}

/// A path that must be an existing executable file.
pub(super) fn require_executable(path: &Path, name: &str) -> Result<PathBuf> {
    let metadata = std::fs::metadata(path).map_err(|_| anyhow!("{name} must name an existing executable"))?;
    ensure!(metadata.is_file() && metadata.permissions().mode() & 0o111 != 0, "{name} must be an executable file");
    Ok(path.to_path_buf())
}

// ---------------------------------------------------------------------------
// The real standalone child.
// ---------------------------------------------------------------------------

pub(super) struct Server {
    child: Child,
    address: std::net::SocketAddr,
}

impl Server {
    pub(super) fn spawn(db: &Db, cli: &Path, git: &super::Git, scratch: &Path, run: &RunRoot) -> Result<Self> {
        let port = free_port()?;
        let address = format!("127.0.0.1:{port}").parse()?;
        // Carries the fixture password; it lives only in this owner and is
        // never printed.
        let database_url = Zeroizing::new(db.service_url()?);
        let log = run.private_file("server.log")?;
        let stdout = std::fs::OpenOptions::new().append(true).open(&log)?;
        let stderr = stdout.try_clone()?;
        let mut command = tokio::process::Command::new(cli);
        command
            .arg("serve-blob")
            .env_clear()
            .env("DATABASE_URL", database_url.as_str())
            .env("ROOTYARD_BIND", format!("127.0.0.1:{port}"))
            .env("ROOTYARD_GIT", git.binary())
            .env("ROOTYARD_SCRATCH_DIR", scratch)
            .env("ROOTYARD_SESSION_KEYRING", run.path("session-keyring"))
            .env("HOME", std::env::var_os("HOME").unwrap_or_else(|| "/tmp".into()))
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C");
        for (name, value) in std::env::vars_os() {
            if is_service_setting(&name.to_string_lossy()) {
                command.env(&name, value);
            }
        }
        // Both streams are append handles on the one private log file, so the
        // child never writes to a pipe whose reader is gone.
        command.stdin(Stdio::null()).stdout(Stdio::from(stdout)).stderr(Stdio::from(stderr)).kill_on_drop(true);
        let child = command.spawn().context("the standalone CLI child could not be started")?;
        drop(database_url);
        Ok(Self { child, address })
    }

    pub(super) fn address(&self) -> std::net::SocketAddr {
        self.address
    }

    fn exited(&mut self) -> Result<Option<std::process::ExitStatus>> {
        self.child.try_wait().context("the CLI child state could not be read")
    }

    /// SIGTERM, then a bounded wait on success and failure paths alike.
    pub(super) async fn stop(mut self) -> Result<()> {
        if self.child.try_wait()?.is_some() {
            return Ok(());
        }
        let pid = self.child.id().context("the CLI child has no process id")?;
        // SAFETY: `kill` is signal-safe; its result is checked below.
        let sent = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
        ensure!(sent == 0, "SIGTERM could not be sent to the CLI child");
        match tokio::time::timeout(Duration::from_secs(STOP_SECONDS), self.child.wait()).await {
            Ok(status) => {
                let status = status?;
                ensure!(
                    status.code() == Some(0),
                    "the CLI child did not exit cleanly after SIGTERM (signal {:?}); see its private log",
                    status.signal()
                );
                Ok(())
            }
            Err(_) => {
                self.child.start_kill()?;
                let _ = self.child.wait().await;
                Err(anyhow!("the CLI child did not stop within its bounded drain; see its private log"))
            }
        }
    }
}

/// Only the configured reachability settings of the owned services are passed
/// on. `ROOTYARD_DATA_DIR` and everything else in the parent environment stay
/// out, so no other data tree or default is ever consulted.
fn is_service_setting(name: &str) -> bool {
    name.starts_with("ROOTYARD_BLOB_")
        || matches!(
            name,
            "PGHOST"
                | "PGHOSTADDR"
                | "PGPORT"
                | "PGUSER"
                | "PGPASSWORD"
                | "PGDATABASE"
                | "PGSSLMODE"
                | "PGSSLROOTCERT"
                | "PGSSLCERT"
                | "PGSSLKEY"
                | "PGSCHEMA"
                | "PGAPPNAME"
        )
}

fn free_port() -> Result<u16> {
    Ok(std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

/// Poll the real readiness route under one deadline; an early child exit ends
/// the wait at once. The private log path is reported, never its content.
pub(super) async fn wait_ready(server: &mut Server, run: &RunRoot) -> Result<std::net::SocketAddr> {
    let address = server.address();
    let client = super::http_client()?;
    let until = Instant::now() + Duration::from_secs(READY_SECONDS);
    let mut last = 0_u16;
    loop {
        if let Some(status) = server.exited()? {
            return Err(anyhow!(
                "the standalone CLI child exited before readiness (code {:?}, signal {:?}); its private log is kept in {}",
                status.code(),
                status.signal(),
                run.root_path().display()
            ));
        }
        if Instant::now() >= until {
            return Err(anyhow!("service readiness deadline exceeded (last status {last}); see the private log"));
        }
        last = match tokio::time::timeout(
            Duration::from_secs(5),
            client.get(format!("http://{address}/health/ready")).send(),
        )
        .await
        {
            Ok(Ok(response)) => response.status().as_u16(),
            Ok(Err(_)) | Err(_) => 0,
        };
        if last == 200 {
            return Ok(address);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
