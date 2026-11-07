//! Bound newly reachable Git objects and reject pointers whose promised LFS bytes
//! cannot be downloaded from this repository's tenant.
use crate::{
    AppState, Error,
    journal::RefChange,
    lfs::{models, storage},
};
use axum::http::StatusCode;
use deadpool_postgres::Transaction;
use std::{path::Path, process::Stdio, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_postgres::GenericClient;
use uuid::Uuid;

const MAX_OBJECTS: usize = 20_000;
const MAX_SMALL_BLOBS: usize = 4_096;
const MAX_LIST_BYTES: usize = 8 * 1024 * 1024;
const MAX_POINTER_BYTES: usize = 1024;

/// The canonical Git LFS v1 pointer version line. Installed clients accept a
/// CRLF terminator here (`git lfs pointer --check` exits 0 while `--strict`
/// rejects it), so this gate must recognize it too; otherwise a CRLF pointer to
/// missing or wrong-size bytes would be treated as ordinary content and skip
/// verification.
const POINTER_VERSION_LINE: &[u8] = b"version https://git-lfs.github.com/spec/v1";

fn starts_lfs_pointer(bytes: &[u8]) -> bool {
    let Some(rest) = bytes.strip_prefix(POINTER_VERSION_LINE) else {
        return false;
    };
    rest.starts_with(b"\n") || rest.starts_with(b"\r\n")
}

/// Bounded CRLF -> LF normalization so the canonical v1 parser sees the same
/// field lines regardless of the writer's line ending style. Only applied to
/// blobs already recognized as pointer-shaped, so ordinary text is untouched.
fn normalize_pointer_line_endings(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\r' && bytes.get(index + 1) == Some(&b'\n') {
            out.push(b'\n');
            index += 2;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    out
}

pub(crate) async fn git_input(
    git_dir: &Path,
    git_bin: &Path,
    timeout: Duration,
    args: &[&str],
    input: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut cmd = tokio::process::Command::new(git_bin);
    cmd.env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("LC_ALL", "C")
        .env("GIT_TERMINAL_PROMPT", "0");
    // Git receive-pack places incoming objects in a quarantine directory
    // until the pre-receive hook accepts the update. Forward only these two
    // Git-managed paths; the rest of the hook environment remains cleared.
    for name in ["GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES"] {
        if let Some(value) = std::env::var_os(name) {
            cmd.env(name, value);
        }
    }
    cmd.arg("-c")
        .arg("core.hooksPath=/dev/null")
        .arg("--no-replace-objects")
        .arg("--git-dir")
        .arg(git_dir)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = cmd.spawn().map_err(Error::internal)?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| Error::internal("Git stdin missing"))?;
    let input = input.to_vec();
    let mut writer = tokio::spawn(async move { stdin.write_all(&input).await });
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::internal("Git stdout missing"))?;
    let result = tokio::time::timeout(timeout, async {
        let mut out = Vec::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = stdout.read(&mut buf).await.map_err(Error::internal)?;
            if n == 0 {
                break;
            }
            if out.len().saturating_add(n) > MAX_LIST_BYTES {
                return Err(Error(
                    StatusCode::CONFLICT,
                    "LFS pointer inspection exceeded output limit",
                ));
            }
            out.extend_from_slice(&buf[..n]);
        }
        (&mut writer)
            .await
            .map_err(Error::internal)?
            .map_err(Error::internal)?;
        let status = child.wait().await.map_err(Error::internal)?;
        if !status.success() {
            return Err(Error(
                StatusCode::CONFLICT,
                "LFS pointer Git command failed",
            ));
        }
        Ok(out)
    })
    .await;
    match result {
        Ok(Ok(out)) => Ok(out),
        Ok(Err(err)) => {
            writer.abort();
            let _ = child.start_kill();
            let _ = child.wait().await;
            Err(err)
        }
        Err(_) => {
            writer.abort();
            let _ = child.start_kill();
            let _ = child.wait().await;
            Err(Error::timeout())
        }
    }
}

pub async fn validate_new_refs(
    state: &Arc<AppState>,
    tx: &Transaction<'_>,
    repo_id: Uuid,
    tenant_id: Uuid,
    changes: &[RefChange],
) -> Result<(), Error> {
    let git_dir = state
        .storage
        .verify_path(repo_id)
        .map_err(Error::internal)?;
    validate_new_refs_with_client(
        &**tx,
        &git_dir,
        &state.storage.root,
        &state.config.git,
        state.config.git_timeout,
        repo_id,
        tenant_id,
        changes,
    )
    .await
}

/// Callable by the synchronous Git pre-receive hook before any ref moves.
pub async fn validate_new_refs_with_client<C: GenericClient + Sync>(
    client: &C,
    git_dir: &Path,
    data_root: &Path,
    git_bin: &Path,
    timeout: Duration,
    repo_id: Uuid,
    tenant_id: Uuid,
    changes: &[RefChange],
) -> Result<(), Error> {
    let deadline = tokio::time::Instant::now() + timeout;
    let remaining = || deadline.saturating_duration_since(tokio::time::Instant::now());
    let max_lfs_bytes = std::env::var("ROOTYARD_LFS_POINTER_VERIFY_BYTES")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(512 * 1024 * 1024)
        .min(8 * 1024 * 1024 * 1024);
    let mut inspected_lfs_bytes = 0u64;
    let mut inspected_lfs_oids = std::collections::BTreeSet::new();
    let format = git_input(
        git_dir,
        git_bin,
        remaining(),
        &["rev-parse", "--show-object-format"],
        &[],
    )
    .await?;
    let oid_len = if format.starts_with(b"sha256") {
        64
    } else if format.starts_with(b"sha1") {
        40
    } else {
        return Err(Error(StatusCode::CONFLICT, "unsupported Git object format"));
    };
    let valid_git_oid = |oid: &str| {
        oid.len() == oid_len
            && oid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    let mut objects = std::collections::BTreeSet::new();
    for change in changes {
        if !valid_git_oid(&change.old_oid) || !valid_git_oid(&change.new_oid) {
            return Err(Error(StatusCode::CONFLICT, "Git object ID format mismatch"));
        }
        if change.new_oid.bytes().all(|b| b == b'0') {
            continue;
        }
        let old = format!("^{}", change.old_oid);
        let mut args = vec!["rev-list", "--objects", &change.new_oid];
        if change.old_oid.bytes().any(|b| b != b'0') {
            args.push(&old);
        } else {
            args.extend(["--not", "--all"]);
        }
        let raw = git_input(git_dir, git_bin, remaining(), &args, &[]).await?;
        let list = std::str::from_utf8(&raw).map_err(Error::internal)?;
        for line in list.lines() {
            let oid = line.split_once(' ').map_or(line, |(oid, _)| oid);
            if !valid_git_oid(oid) {
                return Err(Error(
                    StatusCode::CONFLICT,
                    "invalid Git object during LFS inspection",
                ));
            }
            objects.insert(oid.to_owned());
            if objects.len() > MAX_OBJECTS {
                return Err(Error(
                    StatusCode::CONFLICT,
                    "LFS pointer inspection exceeded object limit",
                ));
            }
        }
    }
    if objects.is_empty() {
        return Ok(());
    }
    let input = objects
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let meta = git_input(
        git_dir,
        git_bin,
        remaining(),
        &[
            "cat-file",
            "--batch-check=%(objectname) %(objecttype) %(objectsize)",
        ],
        input.as_bytes(),
    )
    .await?;
    let mut small = Vec::new();
    for line in std::str::from_utf8(&meta).map_err(Error::internal)?.lines() {
        let mut fields = line.split_whitespace();
        let (Some(oid), Some(kind), Some(size)) = (fields.next(), fields.next(), fields.next())
        else {
            return Err(Error(StatusCode::CONFLICT, "invalid Git object metadata"));
        };
        let size: usize = size
            .parse()
            .map_err(|_| Error(StatusCode::CONFLICT, "invalid Git object size"))?;
        if kind == "blob" && size <= MAX_POINTER_BYTES {
            small.push(oid.to_owned());
            if small.len() > MAX_SMALL_BLOBS {
                return Err(Error(
                    StatusCode::CONFLICT,
                    "LFS pointer inspection exceeded blob limit",
                ));
            }
        }
    }
    if small.is_empty() {
        return Ok(());
    }
    let input = small.join("\n") + "\n";
    let payload = git_input(
        git_dir,
        git_bin,
        remaining(),
        &["cat-file", "--batch"],
        input.as_bytes(),
    )
    .await?;
    let mut cursor = 0usize;
    for _ in &small {
        let end = payload[cursor..]
            .iter()
            .position(|b| *b == b'\n')
            .map(|n| cursor + n)
            .ok_or(Error(StatusCode::CONFLICT, "invalid Git blob batch"))?;
        let header = std::str::from_utf8(&payload[cursor..end]).map_err(Error::internal)?;
        let mut fields = header.split_whitespace();
        let _oid = fields.next();
        let kind = fields.next();
        let size: usize = fields
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or(Error(StatusCode::CONFLICT, "invalid Git blob batch"))?;
        if kind != Some("blob") || size > MAX_POINTER_BYTES {
            return Err(Error(StatusCode::CONFLICT, "invalid Git blob batch"));
        }
        cursor = end + 1;
        let end = cursor
            .checked_add(size)
            .filter(|end| *end < payload.len())
            .ok_or(Error(StatusCode::CONFLICT, "truncated Git blob batch"))?;
        let bytes = &payload[cursor..end];
        cursor = end + 1;
        if !starts_lfs_pointer(bytes) {
            continue;
        }
        let normalized = normalize_pointer_line_endings(bytes);
        let spec = models::parse_pointer(&normalized)
            .ok_or(Error(StatusCode::CONFLICT, "invalid LFS pointer"))?;
        if !inspected_lfs_oids.insert(spec.oid.clone()) {
            continue;
        }
        inspected_lfs_bytes = inspected_lfs_bytes
            .checked_add(spec.size as u64)
            .ok_or(Error(
                StatusCode::CONFLICT,
                "LFS pointer inspection byte limit exceeded",
            ))?;
        if inspected_lfs_bytes > max_lfs_bytes {
            return Err(Error(
                StatusCode::CONFLICT,
                "LFS pointer inspection byte limit exceeded",
            ));
        }
        let row = tokio::time::timeout_at(deadline,client.query_opt("SELECT size FROM lfs_objects WHERE tenant_id=$1 AND repository_id=$2 AND oid=$3 AND state='ready'",
            &[&tenant_id, &repo_id, &spec.oid])).await.map_err(|_|Error::timeout())?.map_err(Error::internal)?
            .ok_or(Error(StatusCode::CONFLICT, "LFS pointer references an unavailable object"))?;
        let size: i64 = row.get(0);
        if size != spec.size
            || !storage::ensure_readable(
                data_root,
                repo_id,
                tenant_id,
                &spec.oid,
                size as u64,
                deadline,
            )
            .await
            .map_err(Error::internal)?
        {
            return Err(Error(
                StatusCode::CONFLICT,
                "LFS pointer object size or digest mismatch",
            ));
        }
    }
    Ok(())
}
