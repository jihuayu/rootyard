//! Bounded stock-Git and BlobStore readback/verification helpers (#162).

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};

use crate::blob_store::{BlobLocator, opendal::BlobStore, read_accel::ReadAccelObjectFormat};

use super::{
    CompactionError,
    sharding::{CompactionPackEntry, CompactionRef},
};

const IO_CHUNK_BYTES: usize = 64 * 1024;
#[cfg(unix)]
const NULL_GIT_CONFIG: &str = "/dev/null";
#[cfg(not(unix))]
const NULL_GIT_CONFIG: &str = "NUL";

pub(super) fn parse_object_format(raw: &str) -> Result<ReadAccelObjectFormat, CompactionError> {
    match raw {
        "sha1" => Ok(ReadAccelObjectFormat::Sha1),
        "sha256" => Ok(ReadAccelObjectFormat::Sha256),
        other => Err(CompactionError::InvalidInput(format!("unsupported object_format `{other}`"))),
    }
}

pub(super) fn format_label(fmt: ReadAccelObjectFormat) -> &'static str {
    match fmt {
        ReadAccelObjectFormat::Sha1 => "sha1",
        ReadAccelObjectFormat::Sha256 => "sha256",
    }
}

pub(super) async fn run_compaction_git(
    repo_dir: Option<&Path>,
    args: &[&str],
    stdin_bytes: Option<&[u8]>,
    deadline: Instant,
) -> Result<Vec<u8>, CompactionError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(CompactionError::DeadlineExceeded);
    }
    let mut cmd = Command::new("git");
    cmd.args(["-c", "core.hooksPath=/dev/null", "--no-replace-objects"]);
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
    let mut child = cmd.spawn().map_err(|e| CompactionError::Io(e.to_string()))?;
    let stdin_handle = stdin_bytes.map(|bytes| {
        let payload = bytes.to_vec();
        let stdin = child.stdin.take();
        tokio::spawn(async move {
            if let Some(mut pipe) = stdin {
                pipe.write_all(&payload).await.map_err(|e| CompactionError::Io(e.to_string()))?;
                pipe.shutdown().await.map_err(|e| CompactionError::Io(e.to_string()))?;
            }
            Ok::<(), CompactionError>(())
        })
    });
    let wait_timeout = remaining.min(Duration::from_secs(120));
    let out = tokio::time::timeout(wait_timeout, child.wait_with_output())
        .await
        .map_err(|_| CompactionError::DeadlineExceeded)?
        .map_err(|e| CompactionError::Io(e.to_string()))?;
    if let Some(handle) = stdin_handle {
        let _ = handle.await;
    }
    if !out.status.success() {
        let cmd_name = args.first().copied().unwrap_or("git").to_owned();
        return Err(CompactionError::GitCommandFailed {
            command: cmd_name,
            detail: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
        });
    }
    Ok(out.stdout)
}

pub(super) async fn sha256_file_and_len(path: &Path) -> Result<(String, u64), CompactionError> {
    let mut file = tokio::fs::File::open(path).await.map_err(|e| CompactionError::Io(e.to_string()))?;
    let mut hasher = Sha256::new();
    let (mut total, mut buf) = (0u64, vec![0u8; IO_CHUNK_BYTES]);
    loop {
        let n = file.read(&mut buf).await.map_err(|e| CompactionError::Io(e.to_string()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total = total.saturating_add(n as u64);
    }
    Ok((hex::encode(hasher.finalize()), total))
}

async fn download_verified_to_path(
    store: &BlobStore,
    locator: &BlobLocator,
    expected_sha: &str,
    expected_len: u64,
    dest: &Path,
    deadline: Instant,
) -> Result<u64, CompactionError> {
    store.get_to_file(locator, dest, deadline).await?;
    let (actual_sha, actual_len) = sha256_file_and_len(dest).await?;
    if actual_sha != expected_sha || actual_len != expected_len || actual_sha != locator.sha256() {
        return Err(CompactionError::EquivalenceFailed(format!(
            "authoritative Blob `{}` digest/length mismatch",
            locator.path()
        )));
    }
    Ok(actual_len)
}

pub(super) async fn verify_and_readback_pair(
    store: &BlobStore,
    p_loc: &BlobLocator,
    p_sha: &str,
    p_len: u64,
    i_loc: &BlobLocator,
    i_sha: &str,
    i_len: u64,
    staging_dir: &Path,
    deadline: Instant,
) -> Result<(), CompactionError> {
    let p_receipt = store.verify(p_loc, deadline).await?;
    let i_receipt = store.verify(i_loc, deadline).await?;
    if p_receipt.verified_sha256() != p_sha
        || p_receipt.verified_length() != p_len
        || i_receipt.verified_sha256() != i_sha
        || i_receipt.verified_length() != i_len
    {
        return Err(CompactionError::EquivalenceFailed("uploaded pack/idx receipt verification mismatch".into()));
    }
    let (rb_p, rb_i) = (staging_dir.join("rb-candidate.pack"), staging_dir.join("rb-candidate.idx"));
    download_verified_to_path(store, p_loc, p_sha, p_len, &rb_p, deadline).await?;
    download_verified_to_path(store, i_loc, i_sha, i_len, &rb_i, deadline).await?;
    let _ = tokio::fs::remove_file(&rb_p).await;
    let _ = tokio::fs::remove_file(&rb_i).await;
    Ok(())
}

pub(super) fn hash_string_lines(lines: &[String]) -> String {
    let mut h = Sha256::new();
    h.update((lines.len() as u64).to_be_bytes());
    for line in lines {
        h.update((line.len() as u64).to_be_bytes());
        h.update(line.as_bytes());
    }
    hex::encode(h.finalize())
}

async fn init_bare_repo(repo_dir: &Path, fmt: ReadAccelObjectFormat, deadline: Instant) -> Result<(), CompactionError> {
    let dir_str = repo_dir.to_str().ok_or_else(|| CompactionError::InvalidInput("non-utf8 repo dir".into()))?;
    run_compaction_git(None, &["init", "--bare", "--quiet", fmt.git_init_flag(), dir_str], None, deadline).await?;
    Ok(())
}

pub(super) async fn populate_bare_with_entries(
    store: &BlobStore,
    repo_dir: &Path,
    fmt: ReadAccelObjectFormat,
    packs: &[CompactionPackEntry],
    verify_each: bool,
    deadline: Instant,
) -> Result<(), CompactionError> {
    init_bare_repo(repo_dir, fmt, deadline).await?;
    let pack_dir = repo_dir.join("objects/pack");
    for entry in packs {
        let p_loc = entry.pack_locator.to_locator()?;
        let i_loc = entry.idx_locator.to_locator()?;
        download_verified_to_path(
            store,
            &p_loc,
            &entry.pack_sha256,
            entry.pack_bytes,
            &pack_dir.join(format!("{}.pack", entry.pack_stem)),
            deadline,
        )
        .await?;
        download_verified_to_path(
            store,
            &i_loc,
            &entry.idx_sha256,
            entry.idx_bytes,
            &pack_dir.join(format!("{}.idx", entry.pack_stem)),
            deadline,
        )
        .await?;
        if verify_each {
            let idx_arg = format!("objects/pack/{}.idx", entry.pack_stem);
            run_compaction_git(Some(repo_dir), &["verify-pack", "-v", &idx_arg], None, deadline).await?;
        }
    }
    Ok(())
}

/// Verify a candidate `.pack`/`.idx` pair in isolation so no external delta bases are required.
pub(super) async fn verify_pack_self_contained(
    fmt: ReadAccelObjectFormat,
    pack_path: &Path,
    idx_path: &Path,
    isolated_dir: &Path,
    deadline: Instant,
) -> Result<(usize, usize), CompactionError> {
    init_bare_repo(isolated_dir, fmt, deadline).await?;
    let pack_dir = isolated_dir.join("objects/pack");
    tokio::fs::copy(pack_path, pack_dir.join("candidate.pack"))
        .await
        .map_err(|e| CompactionError::Io(e.to_string()))?;
    tokio::fs::copy(idx_path, pack_dir.join("candidate.idx")).await.map_err(|e| CompactionError::Io(e.to_string()))?;
    let raw =
        run_compaction_git(Some(isolated_dir), &["verify-pack", "-v", "objects/pack/candidate.idx"], None, deadline)
            .await?;
    let text = String::from_utf8(raw).map_err(|e| CompactionError::EquivalenceFailed(e.to_string()))?;
    let oid_len = fmt.oid_hex_len();
    let mut pack_oids = BTreeSet::new();
    let mut delta_bases = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(oid) = fields.next() else { continue };
        let Some(kind) = fields.next() else { continue };
        if oid.len() == oid_len && matches!(kind, "commit" | "tree" | "blob" | "tag") {
            pack_oids.insert(oid.to_owned());
            let _size = fields.next();
            let _pack_size = fields.next();
            let _offset = fields.next();
            if fields.next().is_some()
                && let Some(base) = fields.next()
            {
                delta_bases.push(base.to_owned());
            }
        }
    }
    if pack_oids.is_empty() {
        return Err(CompactionError::EquivalenceFailed("compacted candidate pack contains zero objects".into()));
    }
    for base in &delta_bases {
        if !pack_oids.contains(base) {
            return Err(CompactionError::EquivalenceFailed(format!(
                "compacted candidate pack references missing external delta base `{base}`"
            )));
        }
    }
    run_compaction_git(Some(isolated_dir), &["fsck", "--full", "--strict"], None, deadline).await?;
    Ok((pack_oids.len(), delta_bases.len()))
}

pub(super) async fn install_refs_verify_and_measure(
    repo_dir: &Path,
    refs: &[CompactionRef],
    roots: &[String],
    deadline: Instant,
) -> Result<(Vec<String>, String), CompactionError> {
    if !refs.is_empty() {
        let mut updates = String::new();
        for r in refs {
            updates.push_str(&format!("update {} {}\n", r.name, r.oid));
        }
        run_compaction_git(Some(repo_dir), &["update-ref", "--stdin"], Some(updates.as_bytes()), deadline).await?;
        let head_branch = refs
            .iter()
            .find(|r| r.name == "refs/heads/main")
            .or_else(|| refs.iter().find(|r| r.name.starts_with("refs/heads/")));
        if let Some(branch) = head_branch {
            run_compaction_git(Some(repo_dir), &["symbolic-ref", "HEAD", &branch.name], None, deadline).await?;
        }
    }
    for oid in roots {
        let spec = format!("{oid}^{{object}}");
        run_compaction_git(Some(repo_dir), &["cat-file", "-e", &spec], None, deadline).await?;
    }
    run_compaction_git(Some(repo_dir), &["fsck", "--full", "--strict"], None, deadline).await?;
    let all_raw =
        run_compaction_git(Some(repo_dir), &["cat-file", "--batch-check", "--batch-all-objects"], None, deadline)
            .await?;
    let mut lines: Vec<String> = String::from_utf8(all_raw)
        .map_err(|e| CompactionError::EquivalenceFailed(e.to_string()))?
        .lines()
        .map(str::to_owned)
        .collect();
    lines.sort();
    let closure = if refs.is_empty() && roots.is_empty() {
        hash_string_lines(&lines)
    } else {
        let mut rev_args = vec!["rev-list", "--objects"];
        if !refs.is_empty() {
            rev_args.push("--all");
        }
        for oid in roots {
            rev_args.push(oid.as_str());
        }
        let rev_raw = run_compaction_git(Some(repo_dir), &rev_args, None, deadline).await?;
        let mut rev_lines: Vec<String> = String::from_utf8(rev_raw)
            .map_err(|e| CompactionError::EquivalenceFailed(e.to_string()))?
            .lines()
            .map(str::to_owned)
            .collect();
        rev_lines.sort();
        hash_string_lines(&rev_lines)
    };
    Ok((lines, closure))
}

pub(super) async fn collect_object_ids(repo_dir: &Path, deadline: Instant) -> Result<(String, usize), CompactionError> {
    let raw = run_compaction_git(Some(repo_dir), &["cat-file", "--batch-check", "--batch-all-objects"], None, deadline)
        .await?;
    let text = String::from_utf8(raw).map_err(|e| CompactionError::EquivalenceFailed(e.to_string()))?;
    let mut oids = BTreeSet::new();
    for line in text.lines() {
        if let Some(oid) = line.split_whitespace().next() {
            oids.insert(oid.to_owned());
        }
    }
    if oids.is_empty() {
        return Err(CompactionError::EquivalenceFailed("input shard closure contains zero objects".into()));
    }
    let mut stdin = String::with_capacity(oids.len() * 65);
    for oid in &oids {
        stdin.push_str(oid);
        stdin.push('\n');
    }
    Ok((stdin, oids.len()))
}

pub(super) fn locate_single_pack_pair(dir: &Path) -> Result<(PathBuf, PathBuf), CompactionError> {
    let mut packs = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|e| CompactionError::Io(e.to_string()))? {
        let path = entry.map_err(|e| CompactionError::Io(e.to_string()))?.path();
        if path.extension().is_some_and(|ext| ext == "pack") {
            packs.push(path);
        }
    }
    if packs.len() != 1 {
        return Err(CompactionError::EquivalenceFailed(format!("expected 1 compacted pack, found {}", packs.len())));
    }
    let pack = packs.remove(0);
    let idx = pack.with_extension("idx");
    if !idx.is_file() {
        return Err(CompactionError::EquivalenceFailed("compacted .idx missing".into()));
    }
    Ok((pack, idx))
}
