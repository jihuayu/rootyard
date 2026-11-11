//! Native Git fixture runner. Every command uses a cleared environment, an
//! owned HOME/template, no hooks, no replacement objects and a bounded timeout.
//! The fixture creates and validates only real Git objects.
use anyhow::{Context, Result, anyhow, ensure};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

const GIT_SECONDS: u64 = 120;

pub struct Git {
    binary: PathBuf,
}

pub struct Output {
    pub success: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Git {
    pub fn new() -> Result<Self> {
        let path = PathBuf::from(std::env::var("ROOTYARD_TEST_GIT").unwrap_or_else(|_| "/usr/bin/git".into()));
        ensure!(path.is_absolute() && path.is_file(), "ROOTYARD_TEST_GIT must be an absolute existing git binary");
        Ok(Self { binary: path })
    }

    pub fn binary(&self) -> &Path {
        &self.binary
    }

    /// Run one fixture command in `cwd`. A non-zero exit is returned, not
    /// wrapped: CAS-refusal cases need the real stderr.
    pub async fn run(&self, cwd: &Path, args: &[&str]) -> Result<Output> {
        let home = tempfile::tempdir()?;
        let template = home.path().join("template");
        std::fs::create_dir_all(&template)?;
        let mut command = tokio::process::Command::new(&self.binary);
        command
            .current_dir(cwd)
            .env_clear()
            .env("HOME", home.path())
            .env("XDG_CONFIG_HOME", home.path())
            .env("PATH", "/usr/bin:/bin")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_ATTR_NOSYSTEM", "1")
            .env("GIT_TEMPLATE_DIR", &template)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("LC_ALL", "C")
            .env("GIT_AUTHOR_NAME", "Rootyard Gateway Fixture")
            .env("GIT_AUTHOR_EMAIL", "gateway@rootyard.invalid")
            .env("GIT_COMMITTER_NAME", "Rootyard Gateway Fixture")
            .env("GIT_COMMITTER_EMAIL", "gateway@rootyard.invalid")
            .arg("-c")
            .arg("core.hooksPath=/dev/null")
            .arg("-c")
            .arg("gc.auto=0")
            .arg("--no-replace-objects")
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let output = tokio::time::timeout(Duration::from_secs(GIT_SECONDS), command.output())
            .await
            .map_err(|_| anyhow!("fixture git command timed out"))??;
        drop(home);
        Ok(Output { success: output.status.success(), stdout: output.stdout, stderr: output.stderr })
    }

    pub async fn ok(&self, cwd: &Path, args: &[&str]) -> Result<Vec<u8>> {
        let output = self.run(cwd, args).await?;
        ensure!(
            output.success,
            "fixture git `{}` failed: {}",
            args.first().copied().unwrap_or("<none>"),
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Ok(output.stdout)
    }

    pub async fn text(&self, cwd: &Path, args: &[&str]) -> Result<String> {
        Ok(std::str::from_utf8(&self.ok(cwd, args).await?)?.trim().to_owned())
    }

    /// Clone over real Smart HTTP with Basic credentials in the URL.
    pub async fn clone(&self, cwd: &Path, url: &str, destination: &str) -> Result<Output> {
        self.run(cwd, &["clone", "--no-hardlinks", url, destination]).await
    }

    /// Commit deterministic fixture bytes in an existing work tree.
    pub async fn commit(&self, repo: &Path, file: &str, content: &str, message: &str) -> Result<String> {
        std::fs::write(repo.join(file), content).with_context(|| format!("write fixture file {file}"))?;
        self.ok(repo, &["add", file]).await?;
        self.ok(repo, &["commit", "--quiet", "-m", message]).await?;
        self.text(repo, &["rev-parse", "HEAD"]).await
    }
}

/// Percent-free credentials: the production token is `ryt_` plus hex and the
/// fixture username is lowercase ASCII, so URL encoding is unnecessary.
///
/// The path is the serving gateway's real Smart HTTP route (`/git/...`, see
/// `blob_git_gateway::router` and the API `clone_path`), which also requires
/// the `.git` suffix on the repository name.
pub fn clone_url(address: std::net::SocketAddr, owner: &str, name: &str, username: &str, token: &str) -> String {
    // Smart HTTP route of the directly mounted `blob_git_gateway::router`
    // (no prefix proxy), so the path is `/git/{owner}/{name}/...`; the clone
    // URL names the same route and keeps the required `.git` suffix.
    format!("http://{username}:{token}@{address}/git/{owner}/{name}.git")
}

/// Wait until the gateway scratch root has no request directories left. The
/// durable ACK lives in PostgreSQL/Blob, so an empty scratch root is the proof
/// that no temporary compute view is required for later reads.
pub async fn assert_no_compute_views(root: &Path) -> Result<()> {
    for _ in 0..40 {
        let mut entries = std::fs::read_dir(root)?.filter_map(|entry| entry.ok());
        if entries.next().is_none() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(anyhow!("temporary Git compute views were not removed"))
}
