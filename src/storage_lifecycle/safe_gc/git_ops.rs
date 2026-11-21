//! Stock-Git & real BlobStore read-back verification helpers (#122).

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Instant,
};

use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};

use crate::blob_store::{BlobLocator, disposable_view::TempViewLease, opendal::BlobStore};

use super::{SafeGcError, model::SafeGcObjectFormat};

const IO_CHUNK_BYTES: usize = 64 * 1024;
#[cfg(unix)]
const NULL_GIT_CONFIG: &str = "/dev/null";
#[cfg(not(unix))]
const NULL_GIT_CONFIG: &str = "NUL";

pub(super) fn format_arg(fmt: SafeGcObjectFormat) -> &'static str {
    fmt.as_str()
}

pub async fn run_git_isolated(
    repo_dir: Option<&Path>,
    args: &[&str],
    stdin_bytes: Option<&[u8]>,
    deadline: Instant,
) -> Result<Vec<u8>, SafeGcError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(SafeGcError::Io("git deadline exceeded".into()));
    }
    let mut cmd = Command::new("git");
    cmd.args([
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "gc.auto=0",
        "-c",
        "gc.autoDetach=false",
        "-c",
        "maintenance.auto=0",
        "-c",
        "maintenance.autoDetach=false",
        "--no-replace-objects",
    ]);
    if let Some(dir) = repo_dir {
        cmd.arg("-C").arg(dir);
    }
    cmd.args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", NULL_GIT_CONFIG)
        .env("GIT_CONFIG_SYSTEM", NULL_GIT_CONFIG)
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(if stdin_bytes.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = cmd.spawn().map_err(|e| SafeGcError::Io(e.to_string()))?;
    let stdin_handle = stdin_bytes.map(|bytes| {
        let payload = bytes.to_vec();
        let stdin = child.stdin.take();
        tokio::spawn(async move {
            if let Some(mut pipe) = stdin {
                pipe.write_all(&payload).await.map_err(|e| SafeGcError::Io(e.to_string()))?;
                pipe.shutdown().await.map_err(|e| SafeGcError::Io(e.to_string()))?;
            }
            Ok::<(), SafeGcError>(())
        })
    });
    let output = tokio::time::timeout(remaining, child.wait_with_output())
        .await
        .map_err(|_| SafeGcError::Io("git command timed out".into()))?
        .map_err(|e| SafeGcError::Io(e.to_string()))?;
    if let Some(handle) = stdin_handle {
        handle.await.map_err(|e| SafeGcError::Io(e.to_string()))??;
    }
    if !output.status.success() {
        return Err(SafeGcError::CompactionVerificationFailed(
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ));
    }
    Ok(output.stdout)
}

pub async fn sha256_file_and_len(path: &Path) -> Result<(String, u64), SafeGcError> {
    let mut file = tokio::fs::File::open(path).await.map_err(|e| SafeGcError::Io(e.to_string()))?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buf = vec![0_u8; IO_CHUNK_BYTES];
    loop {
        let n = file.read(&mut buf).await.map_err(|e| SafeGcError::Io(e.to_string()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total = total.saturating_add(n as u64);
    }
    Ok((hex::encode(hasher.finalize()), total))
}

pub async fn locate_single_pack_pair(pack_dir: &Path) -> Result<(PathBuf, PathBuf), SafeGcError> {
    let mut rd = tokio::fs::read_dir(pack_dir).await.map_err(|e| SafeGcError::Io(e.to_string()))?;
    let (mut pack_path, mut idx_path) = (None, None);
    while let Some(entry) = rd.next_entry().await.map_err(|e| SafeGcError::Io(e.to_string()))? {
        let name = entry.file_name();
        let text = name.to_string_lossy();
        if text.ends_with(".pack") {
            pack_path = Some(entry.path());
        } else if text.ends_with(".idx") {
            idx_path = Some(entry.path());
        }
    }
    match (pack_path, idx_path) {
        (Some(p), Some(i)) => Ok((p, i)),
        _ => Err(SafeGcError::CompactionVerificationFailed("expected single replacement .pack/.idx pair".into())),
    }
}

pub async fn download_and_verify_pair(
    store: &BlobStore,
    pack_loc: &BlobLocator,
    idx_loc: &BlobLocator,
    dest_dir: &Path,
    view_owner: Arc<TempViewLease>,
    deadline: Instant,
) -> Result<(PathBuf, PathBuf), SafeGcError> {
    let pack_out = dest_dir.join("pack-readback.pack");
    let idx_out = dest_dir.join("pack-readback.idx");
    store.get_to_file_with_owner(pack_loc, &pack_out, deadline, Arc::clone(&view_owner)).await?;
    store.get_to_file_with_owner(idx_loc, &idx_out, deadline, view_owner).await?;
    Ok((pack_out, idx_out))
}

async fn write_refs_to_repo(
    repo: &Path,
    refs: &[(String, String)],
    extra_roots: &[String],
    deadline: Instant,
) -> Result<(), SafeGcError> {
    let mut ref_script = String::new();
    for (name, oid) in refs {
        ref_script.push_str(&format!("create {name} {oid}\n"));
    }
    for (i, oid) in extra_roots.iter().enumerate() {
        ref_script.push_str(&format!("create refs/keep/safe-gc-pin-{i} {oid}\n"));
    }
    if !ref_script.is_empty() {
        run_git_isolated(Some(repo), &["update-ref", "--stdin"], Some(ref_script.as_bytes()), deadline).await?;
    }
    Ok(())
}

async fn list_idx_oids(
    repo: &Path,
    idx_path: &Path,
    object_format: SafeGcObjectFormat,
    deadline: Instant,
) -> Result<BTreeSet<String>, SafeGcError> {
    let idx_bytes = tokio::fs::read(idx_path).await.map_err(|e| SafeGcError::Io(e.to_string()))?;
    let flag = format!("--object-format={}", format_arg(object_format));
    let out = run_git_isolated(Some(repo), &["show-index", &flag], Some(&idx_bytes), deadline).await?;
    let mut set = BTreeSet::new();
    for line in String::from_utf8_lossy(&out).lines() {
        if let Some(oid) = line.split_whitespace().nth(1) {
            set.insert(oid.to_owned());
        }
    }
    Ok(set)
}

pub async fn build_self_contained_pack_from_sources(
    work_repo: &Path,
    selected_pairs: &[(PathBuf, PathBuf)],
    unselected_pairs: &[(PathBuf, PathBuf)],
    closure_roots: (&[(String, String)], &[String]),
    out_stage_prefix: &Path,
    object_format: SafeGcObjectFormat,
    deadline: Instant,
) -> Result<(PathBuf, PathBuf, Vec<String>), SafeGcError> {
    let (refs, extra_roots) = closure_roots;
    let _ = run_git_isolated(
        None,
        &["init", "--bare", "--object-format", format_arg(object_format), work_repo.to_str().unwrap_or("")],
        None,
        deadline,
    )
    .await?;
    let pack_dir = work_repo.join("objects").join("pack");
    tokio::fs::create_dir_all(&pack_dir).await.map_err(|e| SafeGcError::Io(e.to_string()))?;
    let mut selected_oids = BTreeSet::new();
    for (idx, (pk, ix)) in selected_pairs.iter().enumerate() {
        let stem = format!("sel-{idx}");
        tokio::fs::copy(pk, pack_dir.join(format!("{stem}.pack"))).await.map_err(|e| SafeGcError::Io(e.to_string()))?;
        let dst_ix = pack_dir.join(format!("{stem}.idx"));
        tokio::fs::copy(ix, &dst_ix).await.map_err(|e| SafeGcError::Io(e.to_string()))?;
        selected_oids.extend(list_idx_oids(work_repo, &dst_ix, object_format, deadline).await?);
    }
    for (idx, (pk, ix)) in unselected_pairs.iter().enumerate() {
        let stem = format!("keep-{idx}");
        tokio::fs::copy(pk, pack_dir.join(format!("{stem}.pack"))).await.map_err(|e| SafeGcError::Io(e.to_string()))?;
        tokio::fs::copy(ix, pack_dir.join(format!("{stem}.idx"))).await.map_err(|e| SafeGcError::Io(e.to_string()))?;
    }
    write_refs_to_repo(work_repo, refs, extra_roots, deadline).await?;
    run_git_isolated(Some(work_repo), &["fsck", "--full", "--strict"], None, deadline).await?;
    let rev_raw = run_git_isolated(Some(work_repo), &["rev-list", "--objects", "--all"], None, deadline).await?;
    let mut oids = BTreeSet::new();
    let mut pack_input = String::new();
    for line in String::from_utf8_lossy(&rev_raw).lines() {
        if let Some(oid) = line.split_whitespace().next().filter(|s| !s.is_empty())
            && (unselected_pairs.is_empty() || selected_oids.contains(oid))
            && oids.insert(oid.to_owned())
        {
            pack_input.push_str(oid);
            pack_input.push('\n');
        }
    }
    if oids.is_empty() {
        return Err(SafeGcError::CompactionVerificationFailed(
            "no reachable objects to compact in selected set".into(),
        ));
    }
    if let Some(parent) = out_stage_prefix.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|e| SafeGcError::Io(e.to_string()))?;
    }
    let prefix_str = out_stage_prefix.to_str().ok_or_else(|| SafeGcError::Io("non-utf8 stage path".into()))?;
    run_git_isolated(Some(work_repo), &["pack-objects", "-q", prefix_str], Some(pack_input.as_bytes()), deadline)
        .await?;
    let (new_pack, new_idx) = locate_single_pack_pair(out_stage_prefix.parent().unwrap_or(work_repo)).await?;
    Ok((new_pack, new_idx, oids.into_iter().collect()))
}

pub async fn verify_readback_pack_closure(
    verify_repo: &Path,
    pair: (&Path, &Path),
    unselected_pairs: &[(PathBuf, PathBuf)],
    closure_roots: (&[(String, String)], &[String]),
    expected_oids: &[String],
    object_format: SafeGcObjectFormat,
    deadline: Instant,
) -> Result<(), SafeGcError> {
    let (pack_path, idx_path) = pair;
    let (refs, extra_roots) = closure_roots;
    let _ = run_git_isolated(
        None,
        &["init", "--bare", "--object-format", format_arg(object_format), verify_repo.to_str().unwrap_or("")],
        None,
        deadline,
    )
    .await?;
    let pack_dir = verify_repo.join("objects").join("pack");
    tokio::fs::create_dir_all(&pack_dir).await.map_err(|e| SafeGcError::Io(e.to_string()))?;
    let dst_idx = pack_dir.join("verified.idx");
    let dst_pack = pack_dir.join("verified.pack");
    tokio::fs::copy(pack_path, &dst_pack).await.map_err(|e| SafeGcError::Io(e.to_string()))?;
    tokio::fs::copy(idx_path, &dst_idx).await.map_err(|e| SafeGcError::Io(e.to_string()))?;
    // Verify replacement pack is self-contained (zero thin/unresolved deltas) BEFORE staging unselected packs.
    run_git_isolated(Some(verify_repo), &["verify-pack", "-v", dst_idx.to_str().unwrap_or("")], None, deadline).await?;
    let idx_oids = list_idx_oids(verify_repo, &dst_idx, object_format, deadline).await?;
    for oid in expected_oids {
        if !idx_oids.contains(oid) {
            return Err(SafeGcError::CompactionVerificationFailed(format!("readback pack missing object {oid}")));
        }
    }
    for (idx, (pk, ix)) in unselected_pairs.iter().enumerate() {
        let stem = format!("keep-{idx}");
        tokio::fs::copy(pk, pack_dir.join(format!("{stem}.pack"))).await.map_err(|e| SafeGcError::Io(e.to_string()))?;
        tokio::fs::copy(ix, pack_dir.join(format!("{stem}.idx"))).await.map_err(|e| SafeGcError::Io(e.to_string()))?;
    }
    write_refs_to_repo(verify_repo, refs, extra_roots, deadline).await?;
    run_git_isolated(Some(verify_repo), &["fsck", "--full", "--strict"], None, deadline).await?;
    Ok(())
}
