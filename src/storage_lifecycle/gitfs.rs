//! Bounded GitFS maintenance. No command prunes or replaces reader-visible packs.
use super::models::Policy;
use crate::{AppState, lfs::storage::repo_lfs_dir};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::{os::unix::fs::MetadataExt, path::Path, process::Stdio, time::{Duration, SystemTime}};
use tokio::{io::AsyncReadExt, process::Command};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

fn command(state: &AppState, repo: Uuid, args: &[&str]) -> Result<Command> {
    let path = state.storage.verify_path(repo)?;
    let mut cmd = state.storage.git(&state.config);
    cmd.arg("--git-dir").arg(path).args(args)
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_CONFIG_COUNT", "2")
        .env("GIT_CONFIG_KEY_0", "core.hooksPath")
        .env("GIT_CONFIG_VALUE_0", "/dev/null")
        .env("GIT_CONFIG_KEY_1", "gc.auto")
        .env("GIT_CONFIG_VALUE_1", "0")
        .stdin(Stdio::null()).stderr(Stdio::null())
        .kill_on_drop(true);
    let parent = std::process::id() as libc::pid_t;
    unsafe {
        cmd.pre_exec(move || {
            if libc::setpgid(0, 0) != 0 || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() != parent { libc::_exit(125); }
            Ok(())
        });
    }
    Ok(cmd)
}

fn terminate_group(pid: Option<u32>) {
    if let Some(pid) = pid { unsafe { libc::kill(-(pid as libc::pid_t), libc::SIGKILL); } }
}

pub async fn run_git(state: &AppState, repo: Uuid, args: &[&str], cancel: &CancellationToken, limit: usize) -> Result<String> {
    let mut cmd = command(state, repo, args)?;
    cmd.stdout(Stdio::piped());
    let mut child = cmd.spawn().context("spawn Git maintenance")?;
    let pid = child.id();
    let stdout = child.stdout.take().context("Git stdout unavailable")?;
    let timeout = tokio::time::sleep(state.config.git_timeout);
    tokio::pin!(timeout);
    let mut bytes = Vec::new();
    let mut limited_stdout=stdout.take((limit + 1) as u64);
    let read = limited_stdout.read_to_end(&mut bytes);
    tokio::pin!(read);
    let result = tokio::select! {
        result = &mut read => result.map(|_| ()),
        _ = cancel.cancelled() => { terminate_group(pid); let _=child.wait().await; bail!("maintenance lease lost"); },
        _ = &mut timeout => { terminate_group(pid); let _=child.wait().await; bail!("Git maintenance timed out"); },
    };
    result?;
    if bytes.len() > limit { terminate_group(pid); let _=child.wait().await; bail!("Git maintenance output exceeded limit"); }
    let status = tokio::select! {
        result = child.wait() => result?,
        _ = cancel.cancelled() => { terminate_group(pid); let _=child.wait().await; bail!("maintenance lease lost"); },
        _ = &mut timeout => { terminate_group(pid); let _=child.wait().await; bail!("Git maintenance timed out"); },
    };
    if !status.success() { bail!("Git maintenance exited unsuccessfully"); }
    Ok(String::from_utf8(bytes)?)
}

#[derive(Default, Debug)]
pub struct Counts { pub loose: i64, pub packs: i64 }
pub async fn count(state: &AppState, repo: Uuid, cancel: &CancellationToken) -> Result<Counts> {
    let output = run_git(state, repo, &["count-objects", "-v"], cancel, 4096).await?;
    let mut counts = Counts::default();
    for line in output.lines() {
        if let Some(v) = line.strip_prefix("count: ") { counts.loose = v.parse()?; }
        if let Some(v) = line.strip_prefix("packs: ") { counts.packs = v.parse()?; }
    }
    Ok(counts)
}

fn clean_staging(dir: &Path, age: Duration, cancel: &CancellationToken) -> Result<u64> {
    if !dir.exists() { return Ok(0); }
    let root=std::fs::symlink_metadata(dir)?;
    if !root.is_dir() || root.file_type().is_symlink() { bail!("unsafe LFS staging directory"); }
    let mut deleted=0;
    for entry in std::fs::read_dir(dir)?.take(4096) {
        if cancel.is_cancelled() { bail!("maintenance lease lost"); }
        let entry=entry?;
        let name=entry.file_name();
        let Some(name)=name.to_str() else { continue };
        if !name.strip_prefix(".tmp-").is_some_and(|tail| Uuid::parse_str(tail).is_ok()) { continue; }
        let meta=std::fs::symlink_metadata(entry.path())?;
        if !meta.file_type().is_file() || meta.nlink()!=1 { continue; }
        if SystemTime::now().duration_since(meta.modified()?).unwrap_or_default() < age { continue; }
        std::fs::remove_file(entry.path())?;
        deleted+=1;
    }
    Ok(deleted)
}

pub async fn execute(state: &AppState, repo: Uuid, kind: &str, policy: &Policy, cancel: &CancellationToken) -> Result<Value> {
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
            let dir=repo_lfs_dir(&state.storage.root, repo);
            let age=Duration::from_secs(policy.stage_age_seconds as u64);
            let cancel=cancel.clone();
            let deleted=tokio::task::spawn_blocking(move || clean_staging(&dir,age,&cancel)).await??;
            Ok(json!({"staging_files_deleted":deleted}))
        }
        "gitfs_cache_evict" => {
            let info=state.storage.verify_path(repo)?.join("objects/info");
            crate::journal::safe_path(&info)?;
            let graph=info.join("commit-graph");
            match std::fs::symlink_metadata(&graph) {
                Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() && meta.nlink()==1 => {
                    if meta.modified()?.elapsed().unwrap_or_default().as_secs()>=policy.cache_max_age_seconds as u64 {
                        std::fs::remove_file(graph)?;
                        Ok(json!({"commit_graph":"evicted"}))
                    } else { Ok(json!({"commit_graph":"retained_new"})) }
                }
                Err(error) if error.kind()==std::io::ErrorKind::NotFound => Ok(json!({"commit_graph":"absent"})),
                _ => bail!("unsafe commit-graph cache path"),
            }
        }
        "gitfs_tombstone_delete" => bail!("destructive cleanup requires complete reader lease coverage"),
        _ => bail!("unknown storage maintenance job kind"),
    }
}
