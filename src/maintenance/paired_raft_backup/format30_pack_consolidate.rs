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

/// Conservative per-plan ACK budget for rebind ref chunks. It is half of the canonical
/// `MAX_ACK_BODY_BYTES` bound (64 KiB) so pack/scope/digest fields can never overflow one ACK body.
pub(super) const MAX_REBIND_REF_ACK_BYTES: usize = 32 * 1024;

/// Hard per-plan cap on rebind refs. `ensure_pack_terminal_budget` (see
/// `ref_store::core::pack_commit::receipt`) charges every ref name in a `PackCommitPlan` at the
/// worst-case `WORST_CASE_REF_NAME_BYTES = 1024`, so a plan tops out at 51 refs against the 64 KiB
/// `TerminalResult` ceiling. 48 leaves headroom for the pack/scope/digest fields while still
/// letting a `136`-ref repository rebind across three canonical plans.
pub(super) const MAX_REBIND_PLAN_REFS: usize = 48;

/// Split restored refs into non-empty A4 plan chunks bounded by both the per-plan ref count and a
/// conservative ACK-body byte estimate. A ref is always admitted into empty chunks, so even a name
/// longer than the whole budget still makes progress in a chunk of its own.
pub(super) fn chunk_refs_for_plans(
    refs: &[(String, String)],
    max_refs: usize,
    max_ack_budget_bytes: usize,
) -> Vec<Vec<(String, String)>> {
    let cap = max_refs.max(1);
    let mut chunks: Vec<Vec<(String, String)>> = Vec::new();
    let mut used_bytes = 0usize;
    for (name, oid) in refs {
        let cost = name.len().saturating_add(oid.len()).saturating_add(128);
        let start_new = match chunks.last() {
            None => true,
            Some(chunk) => {
                chunk.len() >= cap || (!chunk.is_empty() && used_bytes.saturating_add(cost) > max_ack_budget_bytes)
            }
        };
        if start_new {
            chunks.push(Vec::new());
            used_bytes = 0;
        }
        if let Some(chunk) = chunks.last_mut() {
            chunk.push((name.clone(), oid.clone()));
        }
        used_bytes = used_bytes.saturating_add(cost);
    }
    chunks
}

/// Checked/saturating sum of every restored pack pair's `.pack` + `.idx` bytes.
pub(super) fn total_pack_bytes(packs: &[RestoredRepoPackFile]) -> u64 {
    packs.iter().fold(0u64, |sum, pack| sum.saturating_add(pack.pack_len.saturating_add(pack.idx_len)))
}

/// A rebind plan must consolidate when it exceeds the pack-count *or* the total verifier byte bound.
pub(super) fn needs_consolidation_with_limit(packs: &[RestoredRepoPackFile], max_plan_bytes: u64) -> bool {
    !packs.is_empty()
        && (packs.len() > crate::ref_store::core::pack_commit::MAX_BATCH_NEW_PACKS
            || total_pack_bytes(packs) > max_plan_bytes)
}

/// Choose the pack set for the first rebind plan, consolidating into one canonical pack whenever the
/// archived membership exceeds the pack-count or byte budget. A consolidated closure that still
/// exceeds the verifier byte bound is a typed refusal, never an oversized plan handed to A4.
pub(super) fn select_packs_for_rebind_with_limit(
    git: &Path,
    object_format: GitObjectFormat,
    packs: &[RestoredRepoPackFile],
    max_plan_bytes: u64,
    repo_workspace: Option<&Path>,
) -> Result<Vec<RestoredRepoPackFile>, PairedBackupError> {
    if !needs_consolidation_with_limit(packs, max_plan_bytes) {
        return Ok(packs.to_vec());
    }
    let root = repo_workspace
        .ok_or_else(|| PairedBackupError::StateMachine("restore pack consolidation workspace is missing".into()))?;
    let single = consolidate_packs_with_git(git, object_format, packs, root)?;
    if single.pack_len.saturating_add(single.idx_len) > max_plan_bytes {
        return Err(PairedBackupError::StateMachine(
            "consolidated pack closure exceeds verifier total byte bound".into(),
        ));
    }
    Ok(vec![single])
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
    fn chunk_refs_for_plans_splits_by_count_and_ack_byte_budget() {
        let oid = "a".repeat(64);
        let refs: Vec<(String, String)> =
            (0..135).map(|index| (format!("refs/tags/bulk-{index:03}"), oid.clone())).collect();
        let chunks = chunk_refs_for_plans(&refs, MAX_REBIND_PLAN_REFS, MAX_REBIND_REF_ACK_BYTES);
        assert_eq!(chunks.len(), 3, "135 refs above the 51-ref terminal budget must split into three plans");
        assert_eq!((chunks[0].len(), chunks[1].len(), chunks[2].len()), (48, 48, 39));
        let flattened: Vec<(String, String)> = chunks.iter().flatten().cloned().collect();
        assert_eq!(flattened, refs, "chunking must preserve the exact ref set and order");

        let long_name = "r".repeat(700);
        let long_refs: Vec<(String, String)> =
            (0..45).map(|index| (format!("refs/tags/{long_name}-{index}"), oid.clone())).collect();
        let long_chunks = chunk_refs_for_plans(&long_refs, 128, MAX_REBIND_REF_ACK_BYTES);
        assert!(long_chunks.len() >= 2, "45 long ref names must exceed the 32 KiB ACK budget");
        assert_eq!((long_chunks[0].len(), long_chunks[1].len()), (36, 9));
        for chunk in &long_chunks {
            let footprint: usize = chunk.iter().map(|(name, oid)| name.len() + oid.len() + 128).sum();
            assert!(
                footprint <= MAX_REBIND_REF_ACK_BYTES,
                "every chunk footprint {footprint} must stay within the ACK budget"
            );
        }
        assert_eq!(long_chunks.iter().flatten().count(), long_refs.len());
    }

    #[test]
    fn select_packs_for_rebind_consolidates_when_bytes_exceed_plan_limit() {
        let git = PathBuf::from("git");
        if Command::new(&git).arg("--version").output().is_err() {
            return;
        }
        let root = RebindTempDir::create().expect("workspace");
        let scratch = root.0.join("scratch.git");
        Command::new(&git).args(["init", "--bare", "--object-format", "sha256"]).arg(&scratch).output().expect("init");
        let mut pairs = Vec::new();
        for index in 0..3u8 {
            let target = root.0.join(format!("restored-{index}"));
            pairs.push(seed_pack(&git, &scratch, &target, format!("object-{index}\n").as_bytes()));
        }
        let total = total_pack_bytes(&pairs);
        assert!(pairs.len() <= 8 && total > 0, "three packs alone stay under the pack-count limit");
        let out_dir = root.0.join("selected-consolidated");
        let selected = select_packs_for_rebind_with_limit(
            &git,
            GitObjectFormat::Sha256,
            &pairs,
            total - 1,
            Some(out_dir.as_path()),
        )
        .expect("consolidate on byte overflow");
        assert_eq!(selected.len(), 1, "a byte-overflowing membership must consolidate into one pack");
        assert_eq!(count_pack_objects(&git, &out_dir, &selected[0].idx_path).expect("count"), 3);
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
