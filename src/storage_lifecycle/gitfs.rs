//! Bounded GitFS maintenance. No command prunes or replaces reader-visible packs.
use super::models::Policy;
use crate::{AppState, lfs::storage::repo_lfs_dir};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::{
    os::unix::fs::MetadataExt,
    path::Path,
    process::Stdio,
    time::{Duration, SystemTime},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

fn command(state: &AppState, repo: Uuid, args: &[&str]) -> Result<Command> {
    let path = state.storage.verify_path(repo)?;
    let mut cmd = state.storage.git(&state.config);
    cmd.arg("--git-dir")
        .arg(path)
        .args(args)
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_CONFIG_COUNT", "2")
        .env("GIT_CONFIG_KEY_0", "core.hooksPath")
        .env("GIT_CONFIG_VALUE_0", "/dev/null")
        .env("GIT_CONFIG_KEY_1", "gc.auto")
        .env("GIT_CONFIG_VALUE_1", "0")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let parent = std::process::id() as libc::pid_t;
    unsafe {
        cmd.pre_exec(move || {
            if libc::setpgid(0, 0) != 0 || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() != parent {
                libc::_exit(125);
            }
            Ok(())
        });
    }
    Ok(cmd)
}

pub async fn run_git(
    state: &AppState,
    repo: Uuid,
    args: &[&str],
    cancel: &CancellationToken,
    limit: usize,
) -> Result<String> {
    let mut cmd = command(state, repo, args)?;
    cmd.stdout(Stdio::piped());
    let mut child = cmd.spawn().context("spawn Git maintenance")?;
    let stdout = child.stdout.take().context("Git stdout unavailable")?;
    let timeout = tokio::time::sleep(state.config.git_timeout);
    tokio::pin!(timeout);
    let mut bytes = Vec::new();
    let mut limited_stdout = stdout.take((limit + 1) as u64);
    let read = limited_stdout.read_to_end(&mut bytes);
    tokio::pin!(read);
    let result = tokio::select! {
        result = &mut read => result.map(|_| ()),
        _ = cancel.cancelled() => { crate::git_http::kill_group_child(&mut child).await?; bail!("maintenance lease lost"); },
        _ = &mut timeout => { crate::git_http::kill_group_child(&mut child).await?; bail!("Git maintenance timed out"); },
    };
    if let Err(error) = result {
        crate::git_http::kill_group_child(&mut child).await?;
        return Err(error.into());
    }
    if bytes.len() > limit {
        crate::git_http::kill_group_child(&mut child).await?;
        bail!("Git maintenance output exceeded limit");
    }
    let status = tokio::select! {
        result = crate::git_http::finish_group_child(&mut child) => result?,
        _ = cancel.cancelled() => { crate::git_http::kill_group_child(&mut child).await?; bail!("maintenance lease lost"); },
        _ = &mut timeout => { crate::git_http::kill_group_child(&mut child).await?; bail!("Git maintenance timed out"); },
    };
    if !status.success() {
        bail!("Git maintenance exited unsuccessfully");
    }
    Ok(String::from_utf8(bytes)?)
}

/// Run a native Git command with a bounded stdin payload. The child owns a new
/// process group and is SIGKILLed as a group on cancellation or timeout.
pub async fn run_git_with_input(
    state: &AppState,
    repo: Uuid,
    args: &[&str],
    input: &[u8],
    cancel: &CancellationToken,
    limit: usize,
) -> Result<String> {
    let mut cmd = command(state, repo, args)?;
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
    let mut child = cmd.spawn().context("spawn Git maintenance input")?;
    let mut stdin = child.stdin.take().context("Git stdin unavailable")?;
    let stdout = child.stdout.take().context("Git stdout unavailable")?;
    let timeout = tokio::time::sleep(state.config.git_timeout);
    tokio::pin!(timeout);
    let io = async {
        stdin.write_all(input).await?;
        stdin.shutdown().await?;
        drop(stdin);
        let mut bytes = Vec::new();
        let mut limited = stdout.take((limit + 1) as u64);
        limited.read_to_end(&mut bytes).await?;
        Ok::<Vec<u8>, std::io::Error>(bytes)
    };
    tokio::pin!(io);
    let bytes = tokio::select! {
        result = &mut io => result?,
        _ = cancel.cancelled() => {
            crate::git_http::kill_group_child(&mut child).await?;
            bail!("maintenance lease lost");
        },
        _ = &mut timeout => {
            crate::git_http::kill_group_child(&mut child).await?;
            bail!("Git maintenance timed out");
        },
    };
    if bytes.len() > limit {
        crate::git_http::kill_group_child(&mut child).await?;
        bail!("Git maintenance output exceeded limit");
    }
    let status = tokio::select! {
        result = crate::git_http::finish_group_child(&mut child) => result?,
        _ = cancel.cancelled() => {
            crate::git_http::kill_group_child(&mut child).await?;
            bail!("maintenance lease lost");
        },
        _ = &mut timeout => {
            crate::git_http::kill_group_child(&mut child).await?;
            bail!("Git maintenance timed out");
        },
    };
    if !status.success() {
        bail!("Git maintenance exited unsuccessfully");
    }
    Ok(String::from_utf8(bytes)?)
}

/// Batch object existence. Missing OIDs are reported as absent; a malformed
/// response fails closed so it can never be mistaken for successful deletion.
pub async fn existing_oids(
    state: &AppState,
    repo: Uuid,
    oids: &[String],
    cancel: &CancellationToken,
) -> Result<std::collections::BTreeSet<String>> {
    if oids.is_empty() {
        return Ok(std::collections::BTreeSet::new());
    }
    let mut input = String::new();
    for oid in oids {
        if !matches!(oid.len(), 40 | 64) || !oid.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            bail!("invalid object ID for existence check");
        }
        input.push_str(oid);
        input.push('\n');
    }
    let raw = run_git_with_input(
        state,
        repo,
        &["cat-file", "--batch-check=%(objectname) %(objecttype)"],
        input.as_bytes(),
        cancel,
        8 * 1024 * 1024,
    )
    .await?;
    let mut existing = std::collections::BTreeSet::new();
    for line in raw.lines() {
        let mut fields = line.split_ascii_whitespace();
        let oid = fields.next().context("missing object check identity")?;
        let kind = fields.next().context("missing object check type")?;
        if fields.next().is_some() {
            bail!("invalid object existence response");
        }
        if kind != "missing" {
            existing.insert(oid.to_owned());
        }
    }
    Ok(existing)
}

#[derive(Default, Debug)]
pub struct Counts {
    pub loose: i64,
    pub packs: i64,
    pub loose_kib: u64,
    pub pack_kib: u64,
}
pub async fn count(state: &AppState, repo: Uuid, cancel: &CancellationToken) -> Result<Counts> {
    let output = run_git(state, repo, &["count-objects", "-v"], cancel, 4096).await?;
    let mut counts = Counts::default();
    let mut size_loose_seen = false;
    let mut size_pack_seen = false;
    for line in output.lines() {
        if let Some(v) = line.strip_prefix("count: ") {
            counts.loose = v.parse()?;
        }
        if let Some(v) = line.strip_prefix("packs: ") {
            counts.packs = v.parse()?;
        }
        if let Some(v) = line.strip_prefix("size: ") {
            counts.loose_kib = v.parse()?;
            size_loose_seen = true;
        }
        if let Some(v) = line.strip_prefix("size-pack: ") {
            counts.pack_kib = v.parse()?;
            size_pack_seen = true;
        }
    }
    if !size_pack_seen || !size_loose_seen {
        bail!("Git object size unavailable for maintenance preflight");
    }
    Ok(counts)
}

/// Distinguish a missing object (Git exit 1) from a failed inspection. The
/// latter must never be interpreted as successful collection after a crash.
pub async fn object_exists(state: &AppState, repo: Uuid, oid: &str, cancel: &CancellationToken) -> Result<bool> {
    let mut cmd = command(state, repo, &["cat-file", "-e", oid])?;
    cmd.stdout(Stdio::null());
    let mut child = cmd.spawn().context("spawn Git object existence check")?;
    let timeout = tokio::time::sleep(state.config.git_timeout);
    tokio::pin!(timeout);
    let status = tokio::select! {
        result=crate::git_http::finish_group_child(&mut child) => result?,
        _=cancel.cancelled() => {
            crate::git_http::kill_group_child(&mut child).await?;
            bail!("maintenance lease lost during object check");
        },
        _=&mut timeout => {
            crate::git_http::kill_group_child(&mut child).await?;
            bail!("Git object check timed out");
        },
    };
    if status.success() {
        Ok(true)
    } else if status.code() == Some(1) {
        Ok(false)
    } else {
        bail!("Git object check failed")
    }
}

fn clean_staging(dir: &Path, age: Duration, cancel: &CancellationToken) -> Result<u64> {
    if !dir.exists() {
        return Ok(0);
    }
    let root = std::fs::symlink_metadata(dir)?;
    if !root.is_dir() || root.file_type().is_symlink() {
        bail!("unsafe LFS staging directory");
    }
    let mut deleted = 0;
    for entry in std::fs::read_dir(dir)?.take(4096) {
        if cancel.is_cancelled() {
            bail!("maintenance lease lost");
        }
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.strip_prefix(".tmp-").is_some_and(|tail| Uuid::parse_str(tail).is_ok()) {
            continue;
        }
        let meta = std::fs::symlink_metadata(entry.path())?;
        if !meta.file_type().is_file() || meta.nlink() != 1 {
            continue;
        }
        if SystemTime::now().duration_since(meta.modified()?).unwrap_or_default() < age {
            continue;
        }
        std::fs::remove_file(entry.path())?;
        deleted += 1;
    }
    Ok(deleted)
}

pub async fn execute(
    state: &AppState,
    repo: Uuid,
    kind: &str,
    policy: &Policy,
    cancel: &CancellationToken,
) -> Result<Value> {
    match kind {
        "gitfs_repack" => {
            // No `-d` or prune: current readers and pinned snapshots retain old packs.
            run_git(state, repo, &["repack", "-a", "--no-write-bitmap-index"], cancel, 1024).await?;
            Ok(json!({"repacked":true,"pruned":false}))
        }
        "gitfs_cache_hydrate" => {
            run_git(state, repo, &["commit-graph", "write", "--reachable"], cancel, 1024).await?;
            Ok(json!({"commit_graph":"written"}))
        }
        "gitfs_stage_cleanup" => {
            let dir = repo_lfs_dir(&state.storage.root, repo);
            let age = Duration::from_secs(policy.stage_age_seconds as u64);
            let cancel = cancel.clone();
            let deleted = tokio::task::spawn_blocking(move || clean_staging(&dir, age, &cancel)).await??;
            Ok(json!({"staging_files_deleted":deleted}))
        }
        "gitfs_cache_evict" => {
            let info = state.storage.verify_path(repo)?.join("objects/info");
            crate::journal::safe_path(&info)?;
            let graph = info.join("commit-graph");
            match std::fs::symlink_metadata(&graph) {
                Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() && meta.nlink() == 1 => {
                    if meta.modified()?.elapsed().unwrap_or_default().as_secs() >= policy.cache_max_age_seconds as u64 {
                        std::fs::remove_file(graph)?;
                        Ok(json!({"commit_graph":"evicted"}))
                    } else {
                        Ok(json!({"commit_graph":"retained_new"}))
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(json!({"commit_graph":"absent"})),
                _ => bail!("unsafe commit-graph cache path"),
            }
        }
        "gitfs_tombstone_delete" => {
            bail!("destructive cleanup requires complete reader lease coverage")
        }
        _ => bail!("unknown storage maintenance job kind"),
    }
}
