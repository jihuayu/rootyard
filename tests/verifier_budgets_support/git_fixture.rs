//! Stock Git bare-repository fixture and incompressible pack generator.

use anyhow::{Result, anyhow, ensure};
use rootyard::ref_store::GitObjectFormat;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

const GIT_SECONDS: u64 = 60;

pub(super) struct GitRepo {
    _root: tempfile::TempDir,
    bare: PathBuf,
    home: PathBuf,
    template: PathBuf,
    git: PathBuf,
}

impl GitRepo {
    pub(super) async fn new(git: PathBuf, format: GitObjectFormat) -> Result<Self> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        let template = root.path().join("template");
        std::fs::create_dir_all(&home)?;
        std::fs::create_dir_all(&template)?;
        let repo = Self { bare: root.path().join("fixture.git"), home, template, git, _root: root };
        let fmt = format!("--object-format={}", format.as_str());
        let tmpl = format!("--template={}", repo.template.display());
        repo.run(&["init", "--bare", "--quiet", &fmt, &tmpl], None).await?;
        Ok(repo)
    }

    async fn run(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<Vec<u8>> {
        let with_repo = self.bare.is_dir();
        let mut command = tokio::process::Command::new(&self.git);
        command
            .current_dir(self._root.path())
            .env_clear()
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_ATTR_NOSYSTEM", "1")
            .env("GIT_TEMPLATE_DIR", &self.template)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("LC_ALL", "C")
            .env("GIT_AUTHOR_NAME", "Rootyard Verifier Bench")
            .env("GIT_AUTHOR_EMAIL", "bench@rootyard.invalid")
            .env("GIT_COMMITTER_NAME", "Rootyard Verifier Bench")
            .env("GIT_COMMITTER_EMAIL", "bench@rootyard.invalid")
            .arg("-c")
            .arg("core.hooksPath=/dev/null")
            .arg("-c")
            .arg("gc.auto=0")
            .arg("--no-replace-objects")
            .args(args)
            .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if with_repo {
            command.env("GIT_DIR", &self.bare);
        }
        let mut child = command.spawn()?;
        if let Some(bytes) = stdin {
            let mut pipe = child.stdin.take().ok_or_else(|| anyhow!("git stdin missing"))?;
            pipe.write_all(bytes).await?;
            drop(pipe);
        }
        let out = tokio::time::timeout(Duration::from_secs(GIT_SECONDS), child.wait_with_output()).await??;
        ensure!(out.status.success(), "git `{:?}` failed: {}", args.first(), String::from_utf8_lossy(&out.stderr));
        Ok(out.stdout)
    }

    pub(super) async fn build_pack(&self, name: &str, content: &[u8]) -> Result<(String, PathBuf, PathBuf)> {
        let blob =
            String::from_utf8(self.run(&["hash-object", "-w", "--stdin"], Some(content)).await?)?.trim().to_owned();
        let entry = format!("100644 blob {blob}\tpayload.bin\n");
        let tree = String::from_utf8(self.run(&["mktree"], Some(entry.as_bytes())).await?)?.trim().to_owned();
        let commit =
            String::from_utf8(self.run(&["commit-tree", &tree, "-m", "fixture"], None).await?)?.trim().to_owned();
        self.run(&["update-ref", "refs/heads/main", &commit], None).await?;
        let pack_bytes = self.run(&["pack-objects", "--stdout", "--all"], None).await?;
        let dir = self._root.path().join("artifacts");
        std::fs::create_dir_all(&dir)?;
        let pack = dir.join(format!("{name}.pack"));
        std::fs::write(&pack, &pack_bytes)?;
        self.run(&["index-pack", &pack.to_string_lossy()], None).await?;
        let idx = dir.join(format!("{name}.idx"));
        Ok((commit, pack, idx))
    }
}

pub(super) fn incompressible_payload(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}
