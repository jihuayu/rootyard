//! Bounded reverse-import Git helpers sharing the S4 process-group runner.
use super::s4_git_proc::{
    GitStdin, META_OUTPUT_CAP, ReverseGitObjectType, ReverseGitProbeObject, ReverseGitProbeResult, ReverseGitStage,
    base_command, classify_batch_check_line, emit_probe, git_bytes, run_git_bounded,
};
use crate::Error;
use axum::http::StatusCode;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path as FsPath, PathBuf},
};
use tokio::time::Instant;

const REVERSE_OUTPUT_CAP: usize = 16 * 1024 * 1024;
const MAX_CANDIDATE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_PACK_BYTES: usize = 32 * 1024 * 1024;

pub(crate) struct GitInputSpec<'a> {
    pub repo: &'a FsPath,
    pub args: &'a [&'a str],
    pub input: &'a [u8],
    pub actor: Option<&'a str>,
    pub max_out: usize,
    pub stage: ReverseGitStage,
}

pub(crate) async fn git_input(
    git_bin: &FsPath,
    spec: GitInputSpec<'_>,
    deadline: Instant,
) -> Result<Vec<u8>, Error> {
    let mut cmd = base_command(git_bin);
    cmd.args(["-c", "core.hooksPath=/dev/null", "--no-replace-objects", "-C"])
        .arg(spec.repo)
        .args(spec.args);
    if let Some(actor) = spec.actor {
        let email = format!("{actor}@users.rootyard.invalid");
        cmd.env("GIT_AUTHOR_NAME", actor)
            .env("GIT_COMMITTER_NAME", actor)
            .env("GIT_AUTHOR_EMAIL", &email)
            .env("GIT_COMMITTER_EMAIL", email);
    }
    run_git_bounded(
        cmd,
        GitStdin::Bytes(spec.input),
        spec.max_out,
        deadline,
        Error(StatusCode::CONFLICT, "Git View reverse mapping conflict"),
        Some(spec.stage),
    )
    .await
}

pub(crate) async fn new_pack(
    git_bin: &FsPath,
    root: &FsPath,
    source: &FsPath,
    new_oid: &str,
    base_oid: &str,
    deadline: Instant,
) -> Result<(PathBuf, PathBuf), Error> {
    let objects = git_bytes(
        git_bin,
        source,
        &["rev-list", "--objects", new_oid, "--not", base_oid],
        deadline,
        "Git View reverse mapping conflict",
        Some(ReverseGitStage::PackWriteIndex),
    )
    .await?;
    let pack = git_input(
        git_bin,
        GitInputSpec {
            repo: source,
            args: &["pack-objects", "--stdout"],
            input: &objects,
            actor: None,
            max_out: MAX_PACK_BYTES + 1,
            stage: ReverseGitStage::PackWriteIndex,
        },
        deadline,
    )
    .await?;
    if pack.is_empty() || pack.len() > MAX_PACK_BYTES {
        return Err(Error(StatusCode::PAYLOAD_TOO_LARGE, "proposal pack exceeds 32 MiB"));
    }
    let pack_path = root.join("new.pack");
    let idx_path = root.join("new.idx");
    fs::write(&pack_path, pack).map_err(Error::internal)?;
    let idx_text = idx_path.to_str().ok_or_else(Error::bad_request)?;
    let pack_text = pack_path.to_str().ok_or_else(Error::bad_request)?;
    git_bytes(
        git_bin,
        source,
        &["index-pack", "-o", idx_text, pack_text],
        deadline,
        "Git View reverse mapping conflict",
        Some(ReverseGitStage::PackWriteIndex),
    )
    .await?;
    Ok((pack_path, idx_path))
}

pub(crate) async fn verify_candidate_budget(
    git_bin: &FsPath,
    repo: &FsPath,
    candidate: &str,
    base: &str,
    deadline: Instant,
) -> Result<u64, Error> {
    let exclude = format!("^{base}");
    let mut cmd = base_command(git_bin);
    cmd.args(["-c", "core.hooksPath=/dev/null", "--no-replace-objects", "-C"])
        .arg(repo)
        .args(["rev-list", "--objects", candidate])
        .arg(exclude);
    let raw = run_git_bounded(
        cmd,
        GitStdin::Null,
        REVERSE_OUTPUT_CAP,
        deadline,
        Error(StatusCode::CONFLICT, "Git View reverse mapping conflict"),
        Some(ReverseGitStage::AncestryIntegrity),
    )
    .await?;
    let mut input = Vec::new();
    let mut count = 0usize;
    for row in raw.split(|byte| *byte == b'\n').filter(|row| !row.is_empty()) {
        let oid = row.split(|byte| *byte == b' ').next().unwrap_or_default();
        if oid.len() != 40 && oid.len() != 64 {
            return Err(Error::bad_request());
        }
        input.extend_from_slice(oid);
        input.push(b'\n');
        count += 1;
        if count > 100_000 {
            return Err(Error(StatusCode::PAYLOAD_TOO_LARGE, "proposal has too many Git objects"));
        }
    }
    let sizes = git_input(
        git_bin,
        GitInputSpec {
            repo,
            args: &["cat-file", "--batch-check=%(objectsize)"],
            input: &input,
            actor: None,
            max_out: REVERSE_OUTPUT_CAP,
            stage: ReverseGitStage::AncestryIntegrity,
        },
        deadline,
    )
    .await?;
    let mut total = 0u64;
    for size in sizes.split(|byte| *byte == b'\n').filter(|line| !line.is_empty()) {
        let size = std::str::from_utf8(size).map_err(Error::internal)?;
        total = total
            .checked_add(size.parse::<u64>().map_err(Error::internal)?)
            .ok_or_else(Error::bad_request)?;
        if total > MAX_CANDIDATE_BYTES {
            return Err(Error(StatusCode::PAYLOAD_TOO_LARGE, "proposal objects exceed 256 MiB"));
        }
    }
    Ok(total)
}

fn parse_tree(raw: &[u8]) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, Error> {
    let mut entries = BTreeMap::new();
    for record in raw.split(|byte| *byte == 0).filter(|record| !record.is_empty()) {
        let Some(tab) = record.iter().position(|byte| *byte == b'\t') else {
            return Err(Error::internal("invalid Git tree record"));
        };
        entries.insert(record[tab + 1..].to_vec(), record.to_vec());
    }
    Ok(entries)
}

fn child_tree(entries: &BTreeMap<Vec<u8>, Vec<u8>>, key: &[u8]) -> Result<Option<String>, Error> {
    let Some(record) = entries.get(key) else { return Ok(None) };
    let head = record.split(|byte| *byte == b'\t').next().unwrap_or_default();
    let text = std::str::from_utf8(head).map_err(Error::internal)?;
    let fields: Vec<&str> = text.split(' ').collect();
    if fields.len() != 3 || fields[1] != "tree" {
        return Err(Error(StatusCode::CONFLICT, "source path is not a tree"));
    }
    Ok(Some(fields[2].to_owned()))
}

fn valid_object_id(oid: &str) -> bool {
    matches!(oid.len(), 40 | 64) && oid.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// True only for the child-status failure that emitted the original marker.
fn is_reverse_child_failure(error: &Error) -> bool {
    error.0 == StatusCode::CONFLICT && error.1 == "Git View reverse mapping conflict"
}

/// Return the one naturally retained root entry and its recorded Git type.
///
/// Only a single sibling is safe to name without app-specific file semantics;
/// zero or several siblings are ambiguous, and a malformed record is an error.
pub(crate) fn retained_root_sibling<'a>(
    entries: &'a BTreeMap<Vec<u8>, Vec<u8>>,
    replaced: &[u8],
) -> Result<Option<(&'a str, ReverseGitObjectType)>, ()> {
    let mut siblings = entries.iter().filter(|(key, _)| key.as_slice() != replaced);
    let Some((_, record)) = siblings.next() else { return Ok(None) };
    if siblings.next().is_some() {
        return Ok(None);
    }
    let Some(head) = record.split(|byte| *byte == b'\t').next() else { return Err(()) };
    let text = std::str::from_utf8(head).map_err(|_| ())?;
    let mut fields = text.split(' ');
    let (Some(_mode), Some(kind), Some(oid)) = (fields.next(), fields.next(), fields.next()) else {
        return Err(());
    };
    if fields.next().is_some() || !valid_object_id(oid) {
        return Err(());
    }
    let kind = ReverseGitObjectType::parse(kind).ok_or(())?;
    Ok(Some((oid, kind)))
}

/// Probe the replacement subtree and one retained root sibling after a failed
/// root `mktree`. This runs only on the existing failure path, in the same
/// disposable source repository, with one read-only bounded `cat-file` command.
async fn probe_failed_root_mktree(
    git_bin: &FsPath,
    repo: &FsPath,
    replacement: &str,
    entries: &BTreeMap<Vec<u8>, Vec<u8>>,
    replaced: &[u8],
    deadline: Instant,
) {
    let mut expected: Vec<(ReverseGitProbeObject, &str, ReverseGitObjectType)> = Vec::with_capacity(2);
    if valid_object_id(replacement) {
        expected.push((ReverseGitProbeObject::ReplacementSubtree, replacement, ReverseGitObjectType::Tree));
    } else {
        emit_probe(ReverseGitProbeObject::ReplacementSubtree, ReverseGitProbeResult::ProbeError, None);
    }
    match retained_root_sibling(entries, replaced) {
        Ok(Some((oid, kind))) if valid_object_id(oid) => {
            expected.push((ReverseGitProbeObject::RetainedRootSibling, oid, kind));
        }
        Ok(Some(_)) | Err(()) => {
            emit_probe(ReverseGitProbeObject::RetainedRootSibling, ReverseGitProbeResult::ProbeError, None);
        }
        Ok(None) => {
            emit_probe(ReverseGitProbeObject::RetainedRootSibling, ReverseGitProbeResult::Unavailable, None);
        }
    }
    if expected.is_empty() {
        return;
    }
    if Instant::now() >= deadline {
        for (object, _, _) in expected {
            emit_probe(object, ReverseGitProbeResult::Unavailable, None);
        }
        return;
    }
    let mut input = Vec::new();
    for (_, oid, _) in &expected {
        input.extend_from_slice(oid.as_bytes());
        input.push(b'\n');
    }
    let mut cmd = base_command(git_bin);
    cmd.args(["-c", "core.hooksPath=/dev/null", "--no-replace-objects", "-C"])
        .arg(repo)
        .args(["cat-file", "--batch-check"]);
    let raw = run_git_bounded(
        cmd,
        GitStdin::Bytes(&input),
        4096,
        deadline,
        Error::internal("reverse root probe failed"),
        None,
    )
    .await;
    let Ok(raw) = raw else {
        for (object, _, _) in expected {
            emit_probe(object, ReverseGitProbeResult::ProbeError, None);
        }
        return;
    };
    let lines: Vec<&str> = raw
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .filter_map(|line| std::str::from_utf8(line).ok())
        .collect();
    for (object, oid, kind) in expected {
        let Some(line) = lines.iter().find(|line| line.split_whitespace().next() == Some(oid)) else {
            emit_probe(object, ReverseGitProbeResult::ProbeError, None);
            continue;
        };
        let (result, object_type) = classify_batch_check_line(line, oid, kind);
        emit_probe(object, result, object_type);
    }
}

async fn mktree(
    git_bin: &FsPath,
    repo: &FsPath,
    entries: &BTreeMap<Vec<u8>, Vec<u8>>,
    deadline: Instant,
) -> Result<String, Error> {
    let mut input = Vec::new();
    for record in entries.values() {
        input.extend_from_slice(record);
        input.push(0);
    }
    let raw = git_input(
        git_bin,
        GitInputSpec {
            repo,
            args: &["mktree", "-z"],
            input: &input,
            actor: None,
            max_out: META_OUTPUT_CAP,
            stage: ReverseGitStage::SubtreeRootRebuild,
        },
        deadline,
    )
    .await?;
    String::from_utf8(raw).map(|text| text.trim().to_owned()).map_err(Error::internal)
}

pub(crate) async fn replace_tree(
    git_bin: &FsPath,
    repo: &FsPath,
    tree: &str,
    parts: &[&str],
    projected: &str,
    deadline: Instant,
    stage: Option<ReverseGitStage>,
) -> Result<String, Error> {
    let mut index = 0usize;
    let mut current = tree.to_owned();
    let mut entries = parse_tree(
        &git_bytes(
            git_bin,
            repo,
            &["ls-tree", "-z", &current],
            deadline,
            "Git View reverse mapping conflict",
            Some(ReverseGitStage::SubtreeRootListing),
        )
        .await?,
    )?;
    let mut frames = Vec::new();
    loop {
        let part = parts.get(index).ok_or_else(Error::bad_request)?;
        let key = part.as_bytes().to_vec();
        if index + 1 == parts.len() {
            entries.insert(key, format!("040000 tree {projected}\t{part}").into_bytes());
            match mktree(git_bin, repo, &entries, deadline).await {
                Ok(tree) => current = tree,
                Err(error) => {
                    // The original child-failure line already carries the
                    // nonzero/signal class; the probe is strictly after it.
                    if parts.len() == 1
                        && stage == Some(ReverseGitStage::SubtreeRootRebuild)
                        && is_reverse_child_failure(&error)
                    {
                        probe_failed_root_mktree(git_bin, repo, projected, &entries, part.as_bytes(), deadline)
                            .await;
                    }
                    return Err(error);
                }
            }
            break;
        }
        let child = match child_tree(&entries, &key)? {
            Some(child) => child,
            None => mktree(git_bin, repo, &BTreeMap::new(), deadline).await?,
        };
        frames.push((entries, key, part.to_string()));
        current = child;
        entries = parse_tree(
            &git_bytes(
                git_bin,
                repo,
                &["ls-tree", "-z", &current],
                deadline,
                "Git View reverse mapping conflict",
                Some(ReverseGitStage::SubtreeRootListing),
            )
            .await?,
        )?;
        index += 1;
    }
    while let Some((mut parent, key, part)) = frames.pop() {
        parent.insert(key, format!("040000 tree {current}\t{part}").into_bytes());
        current = mktree(git_bin, repo, &parent, deadline).await?;
    }
    Ok(current)
}
