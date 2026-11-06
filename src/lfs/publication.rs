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
use tokio::io::AsyncWriteExt;
use tokio_postgres::GenericClient;
use uuid::Uuid;

const MAX_OBJECTS: usize = 20_000;
const MAX_SMALL_BLOBS: usize = 4_096;
const MAX_LIST_BYTES: usize = 8 * 1024 * 1024;
const MAX_POINTER_BYTES: usize = 1024;

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
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input).await.map_err(Error::internal)?;
    }
    let output = tokio::time::timeout(timeout, child.wait_with_output())
        .await
        .map_err(|_| Error::timeout())?
        .map_err(Error::internal)?;
    if !output.status.success() || output.stdout.len() > MAX_LIST_BYTES {
        return Err(Error(
            StatusCode::CONFLICT,
            "LFS pointer inspection failed or exceeded limit",
        ));
    }
    Ok(output.stdout)
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
    let mut objects = std::collections::BTreeSet::new();
    for change in changes {
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
        let raw = git_input(git_dir, git_bin, timeout, &args, &[]).await?;
        let list = std::str::from_utf8(&raw).map_err(Error::internal)?;
        for line in list.lines() {
            let oid = line.split_once(' ').map_or(line, |(oid, _)| oid);
            if !crate::pulls::models::valid_oid(oid) {
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
        timeout,
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
        timeout,
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
        if !bytes.starts_with(b"version https://git-lfs.github.com/spec/v1\n") {
            continue;
        }
        let spec = models::parse_pointer(bytes)
            .ok_or(Error(StatusCode::CONFLICT, "invalid LFS pointer"))?;
        let row = client.query_opt("SELECT size FROM lfs_objects WHERE tenant_id=$1 AND repository_id=$2 AND oid=$3 AND state='ready'",
            &[&tenant_id, &repo_id, &spec.oid]).await.map_err(Error::internal)?
            .ok_or(Error(StatusCode::CONFLICT, "LFS pointer references an unavailable object"))?;
        let size: i64 = row.get(0);
        if size != spec.size
            || !storage::verify_object_integrity(data_root, repo_id, &spec.oid, size as u64)
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
