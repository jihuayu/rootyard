//! Native Git runner for the S4 acceptance harness.
use anyhow::{Result, anyhow, ensure};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

pub struct Git {
    binary: PathBuf,
}

impl Git {
    pub fn new() -> Result<Self> {
        let binary = PathBuf::from(std::env::var("ROOTYARD_TEST_GIT").unwrap_or_else(|_| "/usr/bin/git".into()));
        ensure!(binary.is_absolute() && binary.is_file(), "ROOTYARD_TEST_GIT must be an absolute git binary");
        Ok(Self { binary })
    }

    pub fn binary(&self) -> &Path {
        &self.binary
    }

    pub async fn run(&self, cwd: &Path, args: &[&str]) -> Result<(bool, Vec<u8>, Vec<u8>)> {
        let mut command = tokio::process::Command::new(&self.binary);
        command
            .current_dir(cwd)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_AUTHOR_NAME", "Rootyard S4 Fixture")
            .env("GIT_AUTHOR_EMAIL", "s4@rootyard.invalid")
            .env("GIT_COMMITTER_NAME", "Rootyard S4 Fixture")
            .env("GIT_COMMITTER_EMAIL", "s4@rootyard.invalid")
            .arg("-c")
            .arg("core.hooksPath=/dev/null")
            .arg("-c")
            .arg("http.postBuffer=16777216")
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let output = tokio::time::timeout(Duration::from_secs(120), command.output())
            .await
            .map_err(|_| anyhow!("fixture git timed out"))??;
        Ok((output.status.success(), output.stdout, output.stderr))
    }

    pub async fn ok(&self, cwd: &Path, args: &[&str]) -> Result<Vec<u8>> {
        let (success, stdout, stderr) = self.run(cwd, args).await?;
        ensure!(
            success,
            "git {:?} failed: {}",
            args.first().copied().unwrap_or(""),
            String::from_utf8_lossy(&stderr).trim()
        );
        Ok(stdout)
    }

    pub async fn text(&self, cwd: &Path, args: &[&str]) -> Result<String> {
        Ok(std::str::from_utf8(&self.ok(cwd, args).await?)?.trim().to_owned())
    }

    pub async fn commit(&self, repo: &Path, file: &str, content: &str, message: &str) -> Result<String> {
        let path = repo.join(file);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, content)?;
        self.ok(repo, &["add", file]).await?;
        self.ok(repo, &["commit", "--quiet", "-m", message]).await?;
        self.text(repo, &["rev-parse", "HEAD"]).await
    }

    pub async fn clone(&self, cwd: &Path, url: &str, name: &str) -> Result<()> {
        self.ok(cwd, &["clone", "--no-local", "--no-hardlinks", "--no-tags", url, name]).await?;
        Ok(())
    }

    pub async fn init_remote(&self, cwd: &Path, url: &str, name: &str) -> Result<()> {
        self.ok(cwd, &["init", "--quiet", "--object-format=sha256", name]).await?;
        self.ok(&cwd.join(name), &["remote", "add", "origin", url]).await?;
        Ok(())
    }

    pub async fn clone_any(&self, cwd: &Path, url: &str, name: &str, format: &str) -> Result<()> {
        if format != "sha256" {
            return self.clone(cwd, url, name).await;
        }
        self.ok(cwd, &["init", "--quiet", "--object-format=sha256", name]).await?;
        let repo = cwd.join(name);
        self.ok(&repo, &["remote", "add", "origin", url]).await?;
        self.ok(&repo, &["fetch", "--quiet", "origin"]).await?;
        self.ok(&repo, &["checkout", "--quiet", "-B", "main", "FETCH_HEAD"]).await?;
        Ok(())
    }
}
