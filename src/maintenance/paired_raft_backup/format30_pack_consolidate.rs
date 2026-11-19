//! Stock-Git pack consolidation for restored `format 30` repositories whose archived membership
//! exceeds `MAX_BATCH_NEW_PACKS`, including repositories that legitimately hold zero refs (#153).
//!
//! The workspace is private, disposable and never published: restored `.pack`/`.idx` pairs are
//! copied under collision-free stems, every object id is enumerated from the *packs themselves*
//! (not from refs), and one canonical pack is emitted whose object count must match exactly.
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use uuid::Uuid;

use crate::ref_store::GitObjectFormat;

use super::backup::stream_sha256_file;
use super::format30_realm_rehome::RestoredRepoPackFile;
use super::types::PairedBackupError;

/// Owner-scoped temporary workspace removed on drop.
pub(super) struct RebindTempDir(pub(super) PathBuf);

impl RebindTempDir {
    pub(super) fn create() -> Result<Self, PairedBackupError> {
        let path = std::env::temp_dir().join(format!("rootyard-rebind-{}", Uuid::new_v4()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&path)?;
        }
        #[cfg(not(unix))]
        std::fs::create_dir_all(&path)?;
        Ok(Self(path))
    }
}

impl Drop for RebindTempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Pick one object id from a restored pack through its `.idx`, without needing a repository.
/// `--object-format` is mandatory: without it `git show-index` parses a SHA-256 `.idx` as a
/// 20-byte SHA-1 index and reports a truncated object id. `show-index` prints
/// `<byte_offset> <oid_hex> (<crc32>)`, so the object id is the *second* whitespace column.
pub(super) fn pick_any_object_oid_from_pack(
    git: &Path,
    object_format: GitObjectFormat,
    idx_path: &Path,
) -> Result<String, PairedBackupError> {
    let idx = std::fs::File::open(idx_path)?;
    let output = Command::new(git)
        .arg("show-index")
        .arg(format!("--object-format={}", object_format.as_str()))
        .stdin(Stdio::from(idx))
        .output()
        .map_err(PairedBackupError::Io)?;
    if !output.status.success() {
        return Err(PairedBackupError::GitVerificationFailed(format!(
            "git show-index for restore pack consolidation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().nth(1))
        .find(|oid| !oid.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| PairedBackupError::StateMachine("restored pack holds no object id".into()))
}

/// Consolidate every restored pair into one canonical pack built from all packed objects.
pub(super) fn consolidate_packs_with_git(
    git: &Path,
    object_format: GitObjectFormat,
    packs: &[RestoredRepoPackFile],
    root: &Path,
) -> Result<RestoredRepoPackFile, PairedBackupError> {
    let init = Command::new(git)
        .args(["init", "--bare", "--object-format", object_format.as_str()])
        .arg(root)
        .output()
        .map_err(PairedBackupError::Io)?;
    if !init.status.success() {
        return Err(PairedBackupError::GitVerificationFailed(format!(
            "git init for restore pack consolidation failed: {}",
            String::from_utf8_lossy(&init.stderr)
        )));
    }
    let pack_dir = root.join("objects/pack");
    std::fs::create_dir_all(&pack_dir)?;
    for (index, pack) in packs.iter().enumerate() {
        let stem = unique_pack_stem(index, &pack.pack_sha256);
        std::fs::copy(&pack.pack_path, pack_dir.join(format!("{stem}.pack")))?;
        std::fs::copy(&pack.idx_path, pack_dir.join(format!("{stem}.idx")))?;
    }
    let object_ids = list_all_object_ids(git, root)?;
    let expected = object_ids.len();
    // Ephemeral workspace-only tag: the copy is trusted only once Git resolves a packed object
    // through a real ref, and it is deleted again before the workspace is dropped.
    let tag = format!("refs/tags/rootyard-rebind-{}", Uuid::new_v4());
    run_git_dir(git, root, &["update-ref", &tag, &object_ids[0]])?;
    let (pack_path, idx_path) = write_single_pack(git, root, &object_ids)?;
    run_git_dir(git, root, &["update-ref", "-d", &tag])?;
    let counted = count_pack_objects(git, root, &idx_path)?;
    if counted != expected {
        return Err(PairedBackupError::GitVerificationFailed(format!(
            "restore pack consolidation kept {counted} of {expected} objects"
        )));
    }
    let (pack_len, pack_sha256) = stream_sha256_file(&pack_path)?;
    let (idx_len, idx_sha256) = stream_sha256_file(&idx_path)?;
    Ok(RestoredRepoPackFile { pack_path, pack_sha256, pack_len, idx_path, idx_sha256, idx_len })
}

fn unique_pack_stem(index: usize, sha256: &str) -> String {
    format!("pack-{index:06}-{}", sha256.get(..12).unwrap_or(sha256))
}

fn run_git_dir(git: &Path, root: &Path, args: &[&str]) -> Result<std::process::Output, PairedBackupError> {
    let output = Command::new(git).arg("--git-dir").arg(root).args(args).output().map_err(PairedBackupError::Io)?;
    if !output.status.success() {
        return Err(PairedBackupError::GitVerificationFailed(format!(
            "git {} for restore pack consolidation failed: {}",
            args.first().copied().unwrap_or_default(),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(output)
}

fn list_all_object_ids(git: &Path, root: &Path) -> Result<Vec<String>, PairedBackupError> {
    let output = run_git_dir(git, root, &["cat-file", "--batch-all-objects", "--batch-check=%(objectname)"])?;
    let ids: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect();
    if ids.is_empty() {
        return Err(PairedBackupError::StateMachine("restored pack closure holds no object ids".into()));
    }
    Ok(ids)
}

fn write_single_pack(git: &Path, root: &Path, object_ids: &[String]) -> Result<(PathBuf, PathBuf), PairedBackupError> {
    let mut child = Command::new(git)
        .arg("--git-dir")
        .arg(root)
        .args(["pack-objects", "--stdout", "-q"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(PairedBackupError::Io)?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| PairedBackupError::StateMachine("git pack-objects stdin is unavailable".into()))?;
    {
        let mut writer = std::io::BufWriter::new(stdin);
        for oid in object_ids {
            writer.write_all(oid.as_bytes())?;
            writer.write_all(b"\n")?;
        }
        writer.flush()?;
    }
    let output = child.wait_with_output().map_err(PairedBackupError::Io)?;
    if !output.status.success() {
        return Err(PairedBackupError::GitVerificationFailed(format!(
            "git pack-objects for restore pack consolidation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let pack_path = root.join("pack-consolidated.pack");
    std::fs::write(&pack_path, &output.stdout)?;
    let index = Command::new(git)
        .arg("--git-dir")
        .arg(root)
        .arg("index-pack")
        .arg(&pack_path)
        .output()
        .map_err(PairedBackupError::Io)?;
    if !index.status.success() {
        return Err(PairedBackupError::GitVerificationFailed(format!(
            "git index-pack for restore pack consolidation failed: {}",
            String::from_utf8_lossy(&index.stderr)
        )));
    }
    let idx_path = pack_path.with_extension("idx");
    if !idx_path.is_file() {
        return Err(PairedBackupError::StateMachine("consolidated idx is missing".into()));
    }
    Ok((pack_path, idx_path))
}

fn count_pack_objects(git: &Path, root: &Path, idx_path: &Path) -> Result<usize, PairedBackupError> {
    let output = Command::new(git)
        .arg("--git-dir")
        .arg(root)
        .args(["verify-pack", "-v"])
        .arg(idx_path)
        .output()
        .map_err(PairedBackupError::Io)?;
    if !output.status.success() {
        return Err(PairedBackupError::GitVerificationFailed(format!(
            "git verify-pack for restore pack consolidation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| {
            let mut fields = line.split_whitespace();
            let (Some(oid), Some(kind)) = (fields.next(), fields.next()) else {
                return false;
            };
            oid.len() >= 40
                && oid.bytes().all(|b| b.is_ascii_hexdigit())
                && matches!(kind, "commit" | "tree" | "blob" | "tag")
        })
        .count())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_pack(git: &Path, scratch: &Path, target: &Path, content: &[u8]) -> RestoredRepoPackFile {
        let blob = {
            let mut child = Command::new(git)
                .arg("--git-dir")
                .arg(scratch)
                .args(["hash-object", "-w", "--stdin"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .expect("git hash-object");
            child.stdin.take().expect("stdin").write_all(content).expect("write blob");
            let out = child.wait_with_output().expect("hash-object");
            String::from_utf8_lossy(&out.stdout).trim().to_owned()
        };
        let (pack_path, idx_path) = write_single_pack(git, scratch, &[blob]).expect("single pack");
        std::fs::create_dir_all(target).expect("pack dir");
        // Every restored pair carries the same archive-local file name, exactly like a real
        // format 30 archive path `blob/<repo>/<pack_id>/pack.pack` + `idx.idx`.
        let named_pack = target.join("pack.pack");
        let named_idx = target.join("idx.idx");
        std::fs::copy(&pack_path, &named_pack).expect("copy pack");
        std::fs::copy(&idx_path, &named_idx).expect("copy idx");
        let (pack_len, pack_sha256) = stream_sha256_file(&named_pack).expect("pack digest");
        let (idx_len, idx_sha256) = stream_sha256_file(&named_idx).expect("idx digest");
        RestoredRepoPackFile { pack_path: named_pack, pack_sha256, pack_len, idx_path: named_idx, idx_sha256, idx_len }
    }

    #[test]
    fn consolidate_more_than_eight_identical_filename_pairs_preserves_all_objects() {
        let git = PathBuf::from("git");
        if Command::new(&git).arg("--version").output().is_err() {
            return;
        }
        let root = RebindTempDir::create().expect("workspace");
        let scratch = root.0.join("scratch.git");
        Command::new(&git).args(["init", "--bare", "--object-format", "sha256"]).arg(&scratch).output().expect("init");
        let mut pairs = Vec::new();
        for index in 0..9u8 {
            let target = root.0.join(format!("restored-{index}"));
            pairs.push(seed_pack(&git, &scratch, &target, format!("object-{index}\n").as_bytes()));
        }
        let out_dir = root.0.join("consolidated");
        let consolidated = consolidate_packs_with_git(&git, GitObjectFormat::Sha256, &pairs, &out_dir).expect("pack");
        assert_eq!(count_pack_objects(&git, &out_dir, &consolidated.idx_path).expect("count"), 9);
        assert!(consolidated.pack_len > 0 && consolidated.idx_len > 0);
        let oid = pick_any_object_oid_from_pack(&git, GitObjectFormat::Sha256, &consolidated.idx_path).expect("oid");
        assert!(oid.len() == 64 && oid.bytes().all(|b| b.is_ascii_hexdigit()));
    }
}
