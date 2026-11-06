//! Native Git helpers and authoritative-ref parsing for storage transitions.
use super::MAX_REFS;
use crate::{AppState, git_http};
use anyhow::{Result, ensure};
use std::{
    collections::BTreeMap,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{process::Command, time::Instant};

fn reserved(name: &str) -> bool {
    name.starts_with("refs/rootyard-") || name.starts_with("refs/replace/") || name.starts_with("refs/pull/")
}

/// Only branch and tag refs are part of the authority snapshot. Native journal
/// and internal roots remain local to the GitFS volume and are never exported.
pub(super) fn exported(name: &str) -> bool {
    (name.starts_with("refs/heads/") || name.starts_with("refs/tags/"))
        && crate::journal::valid_ref(name)
        && !reserved(name)
}

pub(super) fn parse_refs(bytes: &[u8], object_format: &str) -> Result<BTreeMap<String, String>> {
    ensure!(bytes.len() <= 8 * 1024 * 1024, "ref listing exceeds bound");
    let text = std::str::from_utf8(bytes)?;
    ensure!(text.is_empty() || text.ends_with('\n'), "truncated ref listing");
    let length = if object_format == "sha256" { 64 } else { 40 };
    let zero = "0".repeat(length);
    let mut refs = BTreeMap::new();
    for line in text.lines() {
        ensure!(refs.len() < MAX_REFS, "too many refs");
        let (name, oid) = line.split_once(' ').ok_or_else(|| anyhow::anyhow!("invalid ref listing"))?;
        ensure!(name.starts_with("refs/") && name.len() <= 1024, "invalid ref identity");
        ensure!(!reserved(name), "reserved ref cannot be exported");
        ensure!(oid.len() == length && oid.bytes().all(|b| b.is_ascii_hexdigit()) && oid != zero, "invalid ref oid");
        ensure!(refs.insert(name.to_owned(), oid.to_owned()).is_none(), "duplicate ref");
    }
    Ok(refs)
}

pub(super) fn valid_head(head_ref: &str) -> bool {
    head_ref.starts_with("refs/heads/") && crate::journal::valid_ref(head_ref)
}

/// Compute the minimal mutations needed to make the GitFS authority refs match
/// the Pando snapshot. Internal refs outside refs/heads and refs/tags are left
/// untouched so native journal state is not destroyed by a rollback.
pub(super) fn plan_ref_mutations(
    current: &BTreeMap<String, String>,
    desired: &BTreeMap<String, String>,
) -> (Vec<(String, String)>, Vec<String>) {
    let mut updates = Vec::new();
    for (name, oid) in desired {
        if current.get(name) != Some(oid) {
            updates.push((name.clone(), oid.clone()));
        }
    }
    let deletes = current.keys().filter(|name| exported(name) && !desired.contains_key(*name)).cloned().collect();
    (updates, deletes)
}

pub(super) async fn git(state: &AppState, dir: &Path, args: &[&str], deadline: Instant) -> Result<Vec<u8>> {
    let mut cmd = Command::new(&state.config.git);
    cmd.env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .arg("--git-dir")
        .arg(dir)
        .args(args)
        .stdin(Stdio::null());
    let timeout = deadline.saturating_duration_since(Instant::now()).min(Duration::from_secs(120));
    ensure!(!timeout.is_zero(), "storage transition deadline elapsed");
    git_http::collect_git_output(cmd, 8 * 1024 * 1024, timeout).await
}

pub(super) async fn index_pack(state: &AppState, dir: &Path, pack: &Path, deadline: Instant) -> Result<()> {
    let file = std::fs::File::open(pack)?;
    let mut cmd = Command::new(&state.config.git);
    cmd.env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .arg("--git-dir")
        .arg(dir)
        .args(["index-pack", "--stdin"]);
    let timeout = deadline.saturating_duration_since(Instant::now()).min(Duration::from_secs(120));
    ensure!(!timeout.is_zero(), "storage transition deadline elapsed");
    git_http::collect_git_output_input(cmd, 8 * 1024 * 1024, timeout, Stdio::from(file)).await?;
    Ok(())
}

async fn object_count(state: &AppState, dir: &Path, deadline: Instant) -> Result<u64> {
    let output = git(state, dir, &["cat-file", "--batch-all-objects", "--batch-check=%(objectname)"], deadline).await?;
    Ok(output.split(|b| *b == b'\n').filter(|line| !line.is_empty()).count() as u64)
}

pub(super) fn work_dir(state: &AppState) -> Result<PathBuf> {
    let root = state.storage.root.join("pando-transition");
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&root)?;
    let meta = std::fs::symlink_metadata(&root)?;
    ensure!(
        meta.is_dir()
            && !meta.file_type().is_symlink()
            && std::os::unix::fs::MetadataExt::uid(&meta) == unsafe { libc::geteuid() },
        "transition scratch root is not privately owned"
    );
    let path = root.join(format!(".transition-{}", uuid::Uuid::new_v4()));
    std::fs::DirBuilder::new().mode(0o700).create(&path)?;
    Ok(path)
}

pub(super) struct WorkDir(pub(super) PathBuf);
impl Drop for WorkDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Verify that a pack set covers every desired ref and that the advertised
/// HEAD is reachable from the same object closure. Returns the object count.
pub(super) async fn verify_closure(
    state: &AppState,
    object_format: &str,
    packs: &[PathBuf],
    refs: &BTreeMap<String, String>,
    head_ref: &str,
    deadline: Instant,
) -> Result<u64> {
    ensure!(!refs.is_empty() && refs.len() <= MAX_REFS, "transition snapshot has no refs");
    ensure!(valid_head(head_ref), "transition snapshot HEAD is invalid");
    let work = WorkDir(work_dir(state)?);
    let view = work.0.join("verify.git");
    let format_arg = format!("--object-format={object_format}");
    let mut init = Command::new(&state.config.git);
    init.env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args(["init", "--bare", &format_arg])
        .arg(&view)
        .stdin(Stdio::null());
    let timeout = deadline.saturating_duration_since(Instant::now()).min(Duration::from_secs(120));
    ensure!(!timeout.is_zero(), "storage transition deadline elapsed");
    git_http::collect_git_output(init, 4096, timeout).await?;
    for pack in packs {
        index_pack(state, &view, pack, deadline).await?;
    }
    for (name, oid) in refs {
        git(state, &view, &["update-ref", "--no-deref", name, oid], deadline).await?;
    }
    git(state, &view, &["symbolic-ref", "HEAD", head_ref], deadline).await?;
    git(state, &view, &["fsck", "--full", "--strict"], deadline).await?;
    let observed = parse_refs(
        &git(state, &view, &["for-each-ref", "--format=%(refname) %(objectname)"], deadline).await?,
        object_format,
    )?;
    ensure!(&observed == refs, "transition ref parity mismatch");
    let head_oid = git(state, &view, &["rev-parse", "--verify", &format!("{head_ref}^{{commit}}")], deadline).await?;
    ensure!(!head_oid.is_empty(), "transition HEAD does not resolve");
    object_count(state, &view, deadline).await
}
