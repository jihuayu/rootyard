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

/// Canonical Git LFS v1 version line emitted by current clients.
const POINTER_VERSION_LINE: &str = "version https://git-lfs.github.com/spec/v1";
/// Legacy version lines still accepted by the installed client
/// (`git lfs pointer --check` exit 0): hawser (https only) and git-media v/2
/// (http only). Scheme-swapped variants are rejected by the client and stay
/// ordinary content here.
const POINTER_LEGACY_HAWSER: &str = "version https://hawser.github.com/spec/v1";
const POINTER_LEGACY_MEDIA: &str = "version http://git-media.io/v/2";

/// Rewrites a recognized pointer blob into the canonical v1 byte form the
/// bounded parser expects. Recognized, client-compatible shapes:
/// * leading Unicode whitespace trimmed like Go `bytes.TrimSpace` (space,
///   tab, LF, CR, VT, FF, NBSP, ...); a leading BOM is not trimmed;
/// * first line exactly the canonical v1, legacy hawser https v1, or legacy
///   git-media http v/2 version line (no trailing space or tab);
/// * LF or CRLF line terminators, optional final newline;
/// * the legacy version line is mapped to canonical before parsing.
/// Anything else (trailing space/tab on the version line, reordered fields, or
/// unsupported legacy schemes such as http git-lfs, https media or http
/// hawser) is not pointer-shaped and remains ordinary content, matching the
/// client's own pointer recognition.
fn canonical_pointer_bytes(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.len() > MAX_POINTER_BYTES {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?.trim_start();
    let line_end = text.find('\n').unwrap_or(text.len());
    let mut header = &text[..line_end];
    if let Some(stripped) = header.strip_suffix('\r') {
        header = stripped;
    }
    if header != POINTER_VERSION_LINE
        && header != POINTER_LEGACY_HAWSER
        && header != POINTER_LEGACY_MEDIA
    {
        return None;
    }
    let remainder = &text[line_end..];
    let mut out = Vec::with_capacity(POINTER_VERSION_LINE.len() + remainder.len());
    out.extend_from_slice(POINTER_VERSION_LINE.as_bytes());
    let rest = remainder.as_bytes();
    let mut index = 0;
    while index < rest.len() {
        if rest[index] == b'\r' && rest.get(index + 1) == Some(&b'\n') {
            out.push(b'\n');
            index += 2;
        } else {
            out.push(rest[index]);
            index += 1;
        }
    }
    Some(out)
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
    // Key inspection by the promised (oid, size) pair, not oid alone: a batch
    // may contain a valid pointer and a wrong-size pointer to the same object.
    // De-duplicating by oid before the size check would validate the first
    // promise and silently skip the second; distinct sizes must each be
    // checked, while identical oid+size pairs still collapse.
    let mut inspected_lfs_promises = std::collections::BTreeSet::new();
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
        let Some(normalized) = canonical_pointer_bytes(bytes) else {
            continue;
        };
        let spec = models::parse_pointer(&normalized)
            .ok_or(Error(StatusCode::CONFLICT, "invalid LFS pointer"))?;
        if !inspected_lfs_promises.insert((spec.oid.clone(), spec.size)) {
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
