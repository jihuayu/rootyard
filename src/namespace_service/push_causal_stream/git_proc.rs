//! Bounded stock-Git subprocess executor, rlimits, and batch object inspectors (#183).

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use std::process::Stdio;
use std::time::Instant;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

use crate::ref_store::core::types::GitObjectFormat;

use super::types::{GitSubprocessLimits, PushCausalError, STREAM_CHUNK_BYTES};

#[cfg(unix)]
const NULL_GIT_CONFIG: &str = "/dev/null";
#[cfg(not(unix))]
const NULL_GIT_CONFIG: &str = "NUL";

pub(super) struct ObjectMeta {
    pub(super) kind: String,
    pub(super) size: u64,
}

pub(super) enum GitStdin<'a> {
    Null,
    Bytes(&'a [u8]),
    File(&'a Path),
}

pub(super) async fn init_isolated_bare_repo(
    view_dir: &Path,
    format: GitObjectFormat,
    proc_limits: &GitSubprocessLimits,
    deadline: Instant,
) -> Result<(), PushCausalError> {
    init_isolated_bare_repo_bin(Path::new("git"), view_dir, format, proc_limits, deadline).await
}

pub(super) async fn init_isolated_bare_repo_bin(
    git_bin: &Path,
    view_dir: &Path,
    format: GitObjectFormat,
    proc_limits: &GitSubprocessLimits,
    deadline: Instant,
) -> Result<(), PushCausalError> {
    let fmt_flag = format!("--object-format={}", format.as_str());
    let dir_str = view_dir.to_str().ok_or_else(|| PushCausalError::Io("non-utf8 view dir".into()))?;
    run_git_bin(git_bin, view_dir, &["init", "--bare", &fmt_flag, dir_str], GitStdin::Null, proc_limits, deadline)
        .await?;
    Ok(())
}

pub(super) async fn list_idx_oids(
    view_dir: &Path,
    idx_path: &Path,
    proc_limits: &GitSubprocessLimits,
    deadline: Instant,
) -> Result<Vec<String>, PushCausalError> {
    list_idx_oids_bin(Path::new("git"), view_dir, idx_path, proc_limits, deadline).await
}

pub(super) async fn list_idx_oids_bin(
    git_bin: &Path,
    view_dir: &Path,
    idx_path: &Path,
    proc_limits: &GitSubprocessLimits,
    deadline: Instant,
) -> Result<Vec<String>, PushCausalError> {
    let idx_bytes = fs::read(idx_path).map_err(|e| PushCausalError::Io(e.to_string()))?;
    let out =
        run_git_bin(git_bin, view_dir, &["show-index"], GitStdin::Bytes(&idx_bytes), proc_limits, deadline).await?;
    let text = String::from_utf8(out).map_err(|e| PushCausalError::CorruptPack(e.to_string()))?;
    let mut oids = Vec::new();
    for line in text.lines() {
        if let Some(oid) = line.split_whitespace().nth(1) {
            oids.push(oid.to_owned());
        }
    }
    Ok(oids)
}

pub(super) async fn batch_check_objects(
    view_dir: &Path,
    oids: &[String],
    proc_limits: &GitSubprocessLimits,
    deadline: Instant,
) -> Result<BTreeMap<String, ObjectMeta>, PushCausalError> {
    let mut stdin = String::new();
    for oid in oids {
        stdin.push_str(oid);
        stdin.push('\n');
    }
    let out = run_git(
        view_dir,
        &["cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
        GitStdin::Bytes(stdin.as_bytes()),
        proc_limits,
        deadline,
    )
    .await?;
    let text = String::from_utf8(out).map_err(|e| PushCausalError::CorruptPack(e.to_string()))?;
    let mut map = BTreeMap::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() == 3 && !line.ends_with("missing") {
            let size = parts[2].parse::<u64>().unwrap_or(0);
            map.insert(parts[0].to_owned(), ObjectMeta { kind: parts[1].to_owned(), size });
        }
    }
    Ok(map)
}

pub(super) async fn check_is_ancestor(
    view_dir: &Path,
    old_oid: &str,
    new_oid: &str,
    proc_limits: &GitSubprocessLimits,
    deadline: Instant,
) -> Result<bool, PushCausalError> {
    match run_git(view_dir, &["merge-base", "--is-ancestor", old_oid, new_oid], GitStdin::Null, proc_limits, deadline)
        .await
    {
        Ok(_) => Ok(true),
        Err(PushCausalError::CorruptPack(_)) => Ok(false),
        Err(other) => Err(other),
    }
}

pub(super) fn sha256_and_len_sync(path: &Path) -> Result<(String, u64), PushCausalError> {
    let mut file = File::open(path).map_err(|e| PushCausalError::Io(e.to_string()))?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buf = [0u8; STREAM_CHUNK_BYTES];
    loop {
        let n = file.read(&mut buf).map_err(|e| PushCausalError::Io(e.to_string()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total = total.saturating_add(n as u64);
    }
    Ok((hex::encode(hasher.finalize()), total))
}

pub(super) fn verify_file_sha256_len(
    path: &Path,
    expected_sha256: &str,
    expected_len: u64,
) -> Result<(), PushCausalError> {
    let (actual_sha, actual_len) = sha256_and_len_sync(path)?;
    if actual_len != expected_len || actual_sha != expected_sha256 {
        return Err(PushCausalError::UnauthorizedBaseDependency(
            "base artifact failed SHA-256 or length verification".into(),
        ));
    }
    Ok(())
}

pub(super) async fn run_git(
    repo_dir: &Path,
    args: &[&str],
    stdin_mode: GitStdin<'_>,
    limits: &GitSubprocessLimits,
    deadline: Instant,
) -> Result<Vec<u8>, PushCausalError> {
    run_git_bin(Path::new("git"), repo_dir, args, stdin_mode, limits, deadline).await
}

pub(super) async fn run_git_bin(
    git_bin: &Path,
    repo_dir: &Path,
    args: &[&str],
    stdin_mode: GitStdin<'_>,
    limits: &GitSubprocessLimits,
    deadline: Instant,
) -> Result<Vec<u8>, PushCausalError> {
    let timeout = deadline.checked_duration_since(Instant::now()).ok_or(PushCausalError::DeadlineExceeded)?;
    let mut cmd = Command::new(git_bin);
    let stdin_stdio = match stdin_mode {
        GitStdin::Null => Stdio::null(),
        GitStdin::Bytes(_) => Stdio::piped(),
        GitStdin::File(path) => Stdio::from(File::open(path).map_err(|e| PushCausalError::Io(e.to_string()))?),
    };
    cmd.args(["-c", "core.hooksPath=/dev/null", "-c", "gc.auto=0", "--no-replace-objects"]);
    if args.first().copied() != Some("init") {
        cmd.arg("-C").arg(repo_dir);
    }
    cmd.args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", NULL_GIT_CONFIG)
        .env("GIT_CONFIG_SYSTEM", NULL_GIT_CONFIG)
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(stdin_stdio)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    {
        let proc_limits = *limits;
        // SAFETY: `pre_exec` invokes only async-signal-safe `setpgid`/`getrlimit`/`setrlimit`.
        unsafe {
            cmd.pre_exec(move || apply_unix_rlimits(proc_limits));
        }
    }
    let mut child = cmd.spawn().map_err(|e| PushCausalError::Io(e.to_string()))?;
    let stdin_task = match stdin_mode {
        GitStdin::Bytes(bytes) => {
            let data = bytes.to_vec();
            child.stdin.take().map(|mut pipe| {
                tokio::spawn(async move {
                    let _ = pipe.write_all(&data).await;
                    let _ = pipe.shutdown().await;
                })
            })
        }
        _ => None,
    };
    let stdout = child.stdout.take().ok_or_else(|| PushCausalError::Io("missing stdout".into()))?;
    let stderr = child.stderr.take().ok_or_else(|| PushCausalError::Io("missing stderr".into()))?;
    let work = async {
        let (out, err) = tokio::try_join!(
            read_pipe_bounded(stdout, limits.max_pipe_bytes),
            read_pipe_bounded(stderr, limits.max_pipe_bytes)
        )?;
        let status = child.wait().await.map_err(|e| PushCausalError::Io(e.to_string()))?;
        Ok::<_, PushCausalError>((status, out, err))
    };
    let (status, out, err) =
        tokio::time::timeout(timeout, work).await.map_err(|_| PushCausalError::DeadlineExceeded)??;
    if let Some(t) = stdin_task {
        let _ = t.await;
    }
    if !status.success() {
        return Err(PushCausalError::CorruptPack(String::from_utf8_lossy(&err).trim().to_owned()));
    }
    Ok(out)
}

async fn read_pipe_bounded<R: AsyncRead + Unpin>(reader: R, limit: usize) -> Result<Vec<u8>, PushCausalError> {
    let mut out = Vec::new();
    let mut limited = reader.take(limit.saturating_add(1) as u64);
    limited.read_to_end(&mut out).await.map_err(|e| PushCausalError::Io(e.to_string()))?;
    if out.len() > limit {
        return Err(PushCausalError::LimitExceeded("git child output exceeded pipe bound"));
    }
    Ok(out)
}

#[cfg(unix)]
fn apply_unix_rlimits(limits: GitSubprocessLimits) -> std::io::Result<()> {
    // SAFETY: calls async-signal-safe POSIX `setpgid` between fork and exec.
    if unsafe { libc::setpgid(0, 0) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    for (resource, raw_limit) in [
        (libc::RLIMIT_AS, limits.address_space_bytes),
        (libc::RLIMIT_CPU, limits.cpu_seconds),
        (libc::RLIMIT_FSIZE, limits.file_size_bytes),
        (libc::RLIMIT_NOFILE, limits.max_open_files),
        (libc::RLIMIT_CORE, 0),
    ] {
        let mut cur = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        // SAFETY: `cur` points to an initialized POD `rlimit`.
        if unsafe { libc::getrlimit(resource, &mut cur) } == -1 {
            return Err(std::io::Error::last_os_error());
        }
        let target = raw_limit.min(cur.rlim_max);
        let value = libc::rlimit { rlim_cur: target, rlim_max: target };
        // SAFETY: `value` clamps resource limit within kernel bounds.
        if unsafe { libc::setrlimit(resource, &value) } == -1 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}
