//! Real Git fixture and an independent stock-Git validator for materialized
//! root bytes. Nothing here fabricates a Git object: the fixture creates real
//! objects with the configured trusted binary, and validation uses a fresh
//! repository containing only the bytes returned by the root view.
use anyhow::{Result, anyhow, ensure};
use rootyard::ref_store::GitObjectFormat;
use rootyard::ref_store::core::pack_commit::{PackArtifactRole, RegisteredPack};
use rootyard::ref_store::core::retention_root::RootReadView;
use sha2::{Digest, Sha256};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::time::Instant;
use uuid::Uuid;

const GIT_SECONDS: u64 = 60;

pub fn git_binary() -> Result<PathBuf> {
    let path = PathBuf::from(std::env::var("ROOTYARD_TEST_GIT").unwrap_or_else(|_| "/usr/bin/git".into()));
    ensure!(path.is_absolute() && path.is_file(), "ROOTYARD_TEST_GIT must be an absolute existing git binary");
    Ok(path)
}

pub struct PairFiles {
    pub pack: PathBuf,
    pub idx: PathBuf,
}

impl PairFiles {
    fn new(pack: PathBuf, idx: PathBuf) -> Result<Self> {
        ensure!(pack.is_file() && idx.is_file(), "fixture pack/idx file is missing");
        Ok(Self { pack, idx })
    }
}

pub fn digest_file(path: &Path) -> Result<(String, u64)> {
    let bytes = std::fs::read(path)?;
    Ok((hex::encode(Sha256::digest(&bytes)), bytes.len() as u64))
}

/// Owned fixture Git: cleared environment, known author, bounded timeout and
/// synthetic bytes only.
pub struct GitRepo {
    _root: tempfile::TempDir,
    bare: PathBuf,
    home: PathBuf,
    template: PathBuf,
    pub git: PathBuf,
}

impl GitRepo {
    pub async fn new(git: PathBuf, format: GitObjectFormat) -> Result<Self> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        let template = root.path().join("template");
        std::fs::create_dir_all(&home)?;
        std::fs::create_dir_all(&template)?;
        let repo = Self { bare: root.path().join("fixture.git"), home, template, git, _root: root };
        let object_format = format!("--object-format={}", format.as_str());
        let template_arg = format!("--template={}", repo.template.display());
        let bare_arg = repo.bare.to_str().ok_or_else(|| anyhow!("fixture bare path is not UTF-8"))?.to_owned();
        repo.run(
            &["init", "--bare", "--quiet", object_format.as_str(), template_arg.as_str(), bare_arg.as_str()],
            None,
        )
        .await?;
        ensure!(repo.bare.is_dir(), "fixture git did not initialize its explicit bare directory");
        Ok(repo)
    }

    pub async fn run(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<Vec<u8>> {
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
            .env("GIT_TEMPLATE_DIR", &self.template)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("LC_ALL", "C")
            .env("GIT_AUTHOR_NAME", "Rootyard Fixture")
            .env("GIT_AUTHOR_EMAIL", "fixture@rootyard.invalid")
            .env("GIT_COMMITTER_NAME", "Rootyard Fixture")
            .env("GIT_COMMITTER_EMAIL", "fixture@rootyard.invalid")
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
            let mut pipe = child.stdin.take().ok_or_else(|| anyhow!("fixture git stdin is not piped"))?;
            pipe.write_all(bytes).await?;
            drop(pipe);
        }
        let output = tokio::time::timeout(Duration::from_secs(GIT_SECONDS), child.wait_with_output())
            .await
            .map_err(|_| anyhow!("fixture git timed out"))??;
        ensure!(
            output.status.success(),
            "fixture git `{}` failed: {}",
            args.first().copied().unwrap_or("<none>"),
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Ok(output.stdout)
    }

    pub fn text(bytes: &[u8]) -> Result<String> {
        Ok(std::str::from_utf8(bytes)?.trim().to_owned())
    }

    pub async fn add_blob(&self, bytes: &[u8]) -> Result<String> {
        Self::text(&self.run(&["hash-object", "-w", "--stdin"], Some(bytes)).await?)
    }

    pub async fn build_commit(&self, file: &str, content: &[u8], message: &str) -> Result<String> {
        let blob = self.add_blob(content).await?;
        let entry = format!("100644 blob {blob}\t{file}\n");
        let tree = Self::text(&self.run(&["mktree"], Some(entry.as_bytes())).await?)?;
        Self::text(&self.run(&["commit-tree", &tree, "-m", message], None).await?)
    }

    pub async fn update_ref(&self, name: &str, oid: &str) -> Result<()> {
        self.run(&["update-ref", name, oid], None).await?;
        Ok(())
    }

    fn artifacts_dir(&self) -> Result<PathBuf> {
        let dir = self.bare.parent().ok_or_else(|| anyhow!("fixture repo has no parent"))?.join("artifacts");
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    pub async fn pack_all(&self, name: &str) -> Result<PairFiles> {
        let bytes = self.run(&["pack-objects", "--stdout", "--all"], None).await?;
        ensure!(bytes.starts_with(b"PACK"), "git pack-objects did not produce a pack stream");
        let pack = self.artifacts_dir()?.join(format!("{name}.pack"));
        std::fs::write(&pack, &bytes)?;
        let pack_arg = pack.to_str().ok_or_else(|| anyhow!("fixture pack path is not UTF-8"))?.to_owned();
        self.run(&["index-pack", pack_arg.as_str()], None).await?;
        PairFiles::new(pack, self.artifacts_dir()?.join(format!("{name}.idx")))
    }

    pub async fn cat_file(&self, oid: &str) -> Result<String> {
        let bytes = self.run(&["cat-file", "-p", oid], None).await?;
        ensure!(!bytes.is_empty(), "stock Git read an empty object body");
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    pub async fn rev_parse(&self, revision: &str) -> Result<String> {
        Self::text(&self.run(&["rev-parse", revision], None).await?)
    }

    pub async fn object_type(&self, oid: &str) -> Result<String> {
        Self::text(&self.run(&["cat-file", "-t", oid], None).await?)
    }
}

pub fn assert_pack_identity(expected: &RegisteredPack, actual: &RegisteredPack) -> Result<()> {
    ensure!(expected.pack_id() == actual.pack_id(), "pack id differs");
    ensure!(expected.registration_id() == actual.registration_id(), "registration id differs");
    ensure!(
        expected.artifact_set_digest().as_hex() == actual.artifact_set_digest().as_hex(),
        "artifact-set digest differs"
    );
    ensure!(expected.joined_revision() == actual.joined_revision(), "joined revision differs");
    for role in [PackArtifactRole::Pack, PackArtifactRole::Idx] {
        let (e, a) = (expected.artifact(role), actual.artifact(role));
        ensure!(e.slot() == a.slot() && e.hold_id() == a.hold_id(), "artifact slot/hold differs");
        ensure!(
            e.provider() == a.provider() && e.backend_identity() == a.backend_identity(),
            "artifact backend differs"
        );
        ensure!(
            e.verified_sha256() == a.verified_sha256() && e.verified_length() == a.verified_length(),
            "verified digest differs"
        );
        let (el, al) = (e.locator(), a.locator());
        ensure!(
            el.tenant_id() == al.tenant_id()
                && el.authority_id() == al.authority_id()
                && el.authority_generation() == al.authority_generation()
                && el.attempt_id() == al.attempt_id()
                && el.namespace() == al.namespace()
                && el.sha256() == al.sha256()
                && el.length() == al.length(),
            "physical locator differs"
        );
    }
    Ok(())
}

/// Materialize exactly the view's pack/idx bytes into a fresh bare repository
/// and let stock Git validate the pack, its object closure and the captured
/// refs. This is independent of the root adapter's own native verification.
pub async fn stock_git_accepts_view(view: &RootReadView, corpus: &GitRepo, deadline: Instant) -> Result<()> {
    ensure!(!view.packs().is_empty(), "root view has no packs");
    let stock = GitRepo::stock_repo(corpus.git.clone(), view.object_format()).await?;
    for pack in view.packs() {
        let bytes = view
            .pack_bytes(pack.pack_id(), deadline)
            .await
            .map_err(|error| anyhow!("root pack read refused: {error}"))?;
        let idx = view
            .idx_bytes(pack.pack_id(), deadline)
            .await
            .map_err(|error| anyhow!("root idx read refused: {error}"))?;
        ensure!(
            bytes.len() as u64 == pack.artifact(PackArtifactRole::Pack).verified_length()
                && hex::encode(Sha256::digest(&bytes))
                    == pack.artifact(PackArtifactRole::Pack).verified_sha256().as_str(),
            "root pack bytes differ from the retained locator"
        );
        ensure!(
            idx.len() as u64 == pack.artifact(PackArtifactRole::Idx).verified_length()
                && hex::encode(Sha256::digest(&idx)) == pack.artifact(PackArtifactRole::Idx).verified_sha256().as_str(),
            "root idx bytes differ from the retained locator"
        );
        let dir = stock.bare_objects_pack()?;
        std::fs::write(dir.join(format!("pack-{}.pack", pack.pack_id())), &bytes)?;
        std::fs::write(dir.join(format!("pack-{}.idx", pack.pack_id())), &idx)?;
    }
    for reference in view.refs() {
        stock.update_ref(reference.name(), reference.oid_hex()).await?;
    }
    if let Some(head) = view.head_oid_hex() {
        ensure!(
            view.refs().iter().any(|reference| reference.name() == view.head_ref() && reference.oid_hex() == head),
            "captured HEAD is not one of the captured refs"
        );
        let kind = GitRepo::text(&stock.run(&["cat-file", "-t", head], None).await?)?;
        ensure!(kind == "commit", "captured HEAD is not a commit object");
        stock.cat_file(head).await?;
    }
    stock.run(&["fsck", "--full", "--strict", "--no-progress"], None).await?;
    Ok(())
}

impl GitRepo {
    async fn stock_repo(git: PathBuf, format: GitObjectFormat) -> Result<Self> {
        let stock = GitRepo::new(git, format).await?;
        let head = "refs/heads/main";
        stock.bare_objects_pack()?;
        let _ = stock.run(&["symbolic-ref", "HEAD", head], None).await;
        Ok(stock)
    }

    fn bare_objects_pack(&self) -> Result<PathBuf> {
        let dir = self.bare.join("objects").join("pack");
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    pub async fn read_object(&self, oid: &str) -> Result<String> {
        self.cat_file(oid).await
    }

    pub fn id() -> Uuid {
        Uuid::new_v4()
    }
}

/// Git wrapper used solely to pause the first real native invocation. It always
/// `exec`s the configured trusted binary, so all evidence remains real Git.
pub struct GitGate {
    dir: tempfile::TempDir,
}

impl GitGate {
    pub fn new(real_git: &Path) -> Result<Self> {
        ensure!(real_git.is_absolute(), "trusted git must be an absolute path");
        let dir = tempfile::tempdir()?;
        let script = dir.path().join("git-gate");
        let body = format!(
            "#!/bin/sh\n\
             set -eu\n\
             if [ ! -e '{mark}' ]; then\n\
             \x20 : > '{ready}'\n\
             \x20 S=/bin/sleep\n\
             \x20 [ -x \"$S\" ] || S=/usr/bin/sleep\n\
             \x20 while [ ! -e '{release}' ]; do \"$S\" 0.02 || :; done\n\
             \x20 : > '{mark}'\n\
             fi\n\
             exec '{real}' \"$@\"\n",
            mark = dir.path().join("gated").display(),
            ready = dir.path().join("ready").display(),
            release = dir.path().join("release").display(),
            real = real_git.display(),
        );
        std::fs::write(&script, body)?;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700))?;
        Ok(Self { dir })
    }

    pub fn binary(&self) -> PathBuf {
        self.dir.path().join("git-gate")
    }

    pub async fn wait_ready(&self) -> Result<()> {
        let ready = self.dir.path().join("ready");
        tokio::time::timeout(Duration::from_secs(20), async {
            while !ready.exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .map_err(|_| anyhow!("root materialization never reached its first real native Git step"))?;
        Ok(())
    }

    pub fn release(&self) -> Result<()> {
        std::fs::write(self.dir.path().join("release"), b"go")?;
        Ok(())
    }
}

pub struct GateRelease<'a>(pub &'a GitGate);

impl Drop for GateRelease<'_> {
    fn drop(&mut self) {
        let _ = self.0.release();
    }
}
