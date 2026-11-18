//! Clean-environment stock Git verification (pack/idx, fsck --full, clone) (#153).

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::ref_store::GitObjectFormat;

use super::types::{PairedBackupError, validate_oid_hex};

fn run_git(repo_dir: Option<&Path>, args: &[&str], stdin_bytes: &[u8]) -> Result<String, PairedBackupError> {
    let mut cmd = Command::new("git");
    cmd.args(["-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "--no-replace-objects"]);
    if let Some(dir) = repo_dir {
        cmd.arg("-C").arg(dir);
    }
    cmd.args(args);
    cmd.env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", if cfg!(unix) { "/dev/null" } else { "NUL" })
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_AUTHOR_NAME", "rootyard")
        .env("GIT_AUTHOR_EMAIL", "rootyard@example.invalid")
        .env("GIT_COMMITTER_NAME", "rootyard")
        .env("GIT_COMMITTER_EMAIL", "rootyard@example.invalid")
        .env("LC_ALL", "C");
    let out = if stdin_bytes.is_empty() {
        cmd.output()?
    } else {
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = cmd.spawn()?;
        if let Some(mut sin) = child.stdin.take() {
            sin.write_all(stdin_bytes)?;
        }
        child.wait_with_output()?
    };
    if !out.status.success() {
        return Err(PairedBackupError::GitVerificationFailed(format!(
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// Verify restored packs and refs end-to-end via real `git index-pack`, `git fsck --full`,
/// and real `git clone`, returning the number of verified refs.
pub fn verify_bare_repo_from_blobs(
    work_dir: &Path,
    format: GitObjectFormat,
    refs: &BTreeMap<String, String>,
    pack_pairs: &[(PathBuf, PathBuf)],
    clone_dir: &Path,
) -> Result<usize, PairedBackupError> {
    if refs.is_empty() || pack_pairs.is_empty() {
        return Err(PairedBackupError::GitVerificationFailed("cannot verify empty repository closure".into()));
    }
    let bare = work_dir.join("restored.git");
    fs::create_dir_all(&bare)?;
    let fmt_str = match format {
        GitObjectFormat::Sha1 => "sha1",
        GitObjectFormat::Sha256 => "sha256",
    };
    run_git(Some(&bare), &["init", "--bare", &format!("--object-format={fmt_str}"), "--initial-branch=main"], &[])?;

    let pack_dst_dir = bare.join("objects").join("pack");
    fs::create_dir_all(&pack_dst_dir)?;
    for (idx, (pack_path, idx_path)) in pack_pairs.iter().enumerate() {
        let pack_dst = pack_dst_dir.join(format!("pack-restored-{idx:04}.pack"));
        let idx_dst = pack_dst_dir.join(format!("pack-restored-{idx:04}.idx"));
        fs::copy(pack_path, &pack_dst)?;
        fs::copy(idx_path, &idx_dst)?;
        run_git(Some(&bare), &["index-pack", "--strict", &pack_dst.to_string_lossy()], &[])?;
        run_git(Some(&bare), &["verify-pack", "-v", &idx_dst.to_string_lossy()], &[])?;
    }

    let mut batch = String::new();
    for (ref_name, oid) in refs {
        if !ref_name.starts_with("refs/") || ref_name.contains(['\r', '\n', '\0']) || !validate_oid_hex(format, oid) {
            return Err(PairedBackupError::GitVerificationFailed(format!("invalid ref entry {ref_name}")));
        }
        batch.push_str(&format!("create {ref_name} {oid}\n"));
    }
    run_git(Some(&bare), &["update-ref", "--stdin"], batch.as_bytes())?;
    let head_target = refs
        .get_key_value("refs/heads/main")
        .or_else(|| refs.iter().next())
        .map(|(k, _)| k.as_str())
        .ok_or_else(|| PairedBackupError::GitVerificationFailed("cannot pick HEAD from empty refs".into()))?;
    run_git(Some(&bare), &["symbolic-ref", "HEAD", head_target], &[])?;
    run_git(Some(&bare), &["fsck", "--full", "--strict"], &[])?;

    if clone_dir.exists() {
        fs::remove_dir_all(clone_dir)?;
    }
    run_git(None, &["clone", "--no-hardlinks", &bare.to_string_lossy(), &clone_dir.to_string_lossy()], &[])?;
    run_git(Some(clone_dir), &["fsck", "--full", "--strict"], &[])?;
    let cloned_head = run_git(Some(clone_dir), &["rev-parse", "HEAD"], &[])?;
    let expected_head = refs.get(head_target).ok_or_else(|| {
        PairedBackupError::GitVerificationFailed("expected HEAD target missing from restored refs".into())
    })?;
    if cloned_head != *expected_head {
        return Err(PairedBackupError::GitVerificationFailed(format!(
            "cloned HEAD {cloned_head} differs from expected {expected_head}"
        )));
    }
    Ok(refs.len())
}

/// Helper used by tests/evaluators to build a real stock-Git pack/idx pair and commit OID.
pub fn seed_commit_pack(
    seed_root: &Path,
    format: GitObjectFormat,
    filename: &str,
    content: &[u8],
    parent_commit: Option<&str>,
) -> Result<(String, PathBuf, PathBuf), PairedBackupError> {
    let repo = seed_root.join("repo");
    let fmt_str = match format {
        GitObjectFormat::Sha1 => "sha1",
        GitObjectFormat::Sha256 => "sha256",
    };
    if !repo.join(".git").exists() {
        fs::create_dir_all(&repo)?;
        run_git(Some(&repo), &["init", &format!("--object-format={fmt_str}"), "--initial-branch=main"], &[])?;
    }
    fs::write(repo.join(filename), content)?;
    run_git(Some(&repo), &["add", "."], &[])?;
    run_git(Some(&repo), &["commit", "-m", filename], &[])?;
    let commit = run_git(Some(&repo), &["rev-parse", "HEAD"], &[])?;
    let range = match parent_commit {
        Some(prev) => format!("{prev}..{commit}"),
        None => commit.clone(),
    };
    let rev_list = run_git(Some(&repo), &["rev-list", "--objects", &range], &[])?;
    let oids: String = rev_list.lines().filter_map(|l| l.split(' ').next()).map(|o| format!("{o}\n")).collect();
    let pack_dir = seed_root.join(format!("pack-{}", commit.get(..12).unwrap_or("x")));
    fs::create_dir_all(&pack_dir)?;
    let prefix = pack_dir.join("out").to_string_lossy().into_owned();
    run_git(Some(&repo), &["-c", "pack.writeReverseIndex=false", "pack-objects", "-q", &prefix], oids.as_bytes())?;
    let entries: Vec<PathBuf> = fs::read_dir(&pack_dir)?.filter_map(Result::ok).map(|e| e.path()).collect();
    let pick = |ext: &str| {
        entries
            .iter()
            .find(|p| p.extension() == Some(std::ffi::OsStr::new(ext)))
            .cloned()
            .ok_or_else(|| PairedBackupError::GitVerificationFailed(format!("pack-objects did not produce .{ext}")))
    };
    Ok((commit, pick("pack")?, pick("idx")?))
}
