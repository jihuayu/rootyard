//! Stock-Git pack consolidation for restored `format 30` repositories above `MAX_BATCH_NEW_PACKS` (#153).
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use uuid::Uuid;

use crate::ref_store::GitObjectFormat;
use crate::ref_store::core::pack_commit::VERIFIER_MAX_OBJECTS;

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
/// `--object-format` is mandatory: `show-index` prints `<offset> <oid_hex> (<crc32>)`.
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

/// Half of the canonical `MAX_ACK_BODY_BYTES` bound (64 KiB), leaving room for pack/scope/digest fields.
pub(super) const MAX_REBIND_REF_ACK_BYTES: usize = 32 * 1024;

/// Hard per-plan cap on rebind refs: `ensure_pack_terminal_budget` charges every ref name at the
/// worst-case `1024` bytes, so a plan tops out at 51 refs against the 64 KiB `TerminalResult`
/// ceiling. 48 leaves headroom while still letting a `136`-ref repository rebind across three plans.
pub(super) const MAX_REBIND_PLAN_REFS: usize = 48;

/// Split restored refs into non-empty A4 plans bounded by ref count and a conservative ACK-byte
/// estimate; a single over-budget ref still makes progress in a chunk of its own.
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

/// Typed failure for a single-pair or consolidated closure above A4's frozen verifier byte budget.
fn exceeds_verifier_budget(bound_bytes: u64) -> PairedBackupError {
    PairedBackupError::RepositoryClosureExceedsVerifierBudget { repository_id: None, bound_bytes }
}

/// Choose the pack set for the first rebind plan, consolidating whenever the archived membership
/// exceeds the pack-count or byte budget; an oversized consolidated closure is a typed refusal.
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
    let single = consolidate_packs_with_git(git, object_format, packs, root, max_plan_bytes)?;
    if single.pack_len.saturating_add(single.idx_len) > max_plan_bytes {
        return Err(exceeds_verifier_budget(max_plan_bytes));
    }
    Ok(vec![single])
}

/// Consolidate every restored pair into one canonical pack built from all packed objects.
pub(super) fn consolidate_packs_with_git(
    git: &Path,
    object_format: GitObjectFormat,
    packs: &[RestoredRepoPackFile],
    root: &Path,
    max_plan_bytes: u64,
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
    // Ephemeral workspace-only tag: the copy is trusted once Git resolves a packed object through a
    // real ref; the tag is deleted again before the workspace is dropped.
    let tag = format!("refs/tags/rootyard-rebind-{}", Uuid::new_v4());
    run_git_dir(git, root, &["update-ref", &tag, &object_ids[0]])?;
    let (pack_path, idx_path) = write_single_pack(git, root, &object_ids, max_plan_bytes)?;
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

fn spawn_piped(
    git: &Path,
    root: &Path,
    args: &[&str],
    idx: Option<&Path>,
    what: &str,
) -> Result<(std::process::Child, std::process::ChildStdout, std::process::ChildStderr), PairedBackupError> {
    let mut cmd = Command::new(git);
    cmd.arg("--git-dir").arg(root).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    if let Some(idx) = idx {
        cmd.arg(idx);
    }
    let mut child = cmd.spawn().map_err(PairedBackupError::Io)?;
    let out =
        child.stdout.take().ok_or_else(|| PairedBackupError::StateMachine(format!("{what} stdout unavailable")))?;
    let err =
        child.stderr.take().ok_or_else(|| PairedBackupError::StateMachine(format!("{what} stderr unavailable")))?;
    Ok((child, out, err))
}

fn drain_stderr(stderr: std::process::ChildStderr) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        let mut err = String::new();
        let _ = BufReader::new(stderr.take(4096)).read_to_string(&mut err);
        err
    })
}

fn reap_checked(
    child: &mut std::process::Child,
    reader: std::thread::JoinHandle<String>,
    what: &str,
) -> Result<(), PairedBackupError> {
    let status = child.wait()?;
    let err = reader.join().unwrap_or_default();
    if !status.success() {
        return Err(PairedBackupError::GitVerificationFailed(format!("{what} failed: {err}")));
    }
    Ok(())
}

fn list_all_object_ids(git: &Path, root: &Path) -> Result<Vec<String>, PairedBackupError> {
    let args = ["cat-file", "--batch-all-objects", "--batch-check=%(objectname)"];
    let (mut child, stdout, stderr) = spawn_piped(git, root, &args, None, "git cat-file")?;
    let reader = drain_stderr(stderr);
    let mut ids = Vec::new();
    for line in BufReader::new(stdout.take((VERIFIER_MAX_OBJECTS + 2) * 68)).lines() {
        let oid = line?.trim().to_owned();
        if !oid.is_empty() {
            ids.push(oid);
        }
        if ids.len() > VERIFIER_MAX_OBJECTS as usize {
            let _ = child.kill();
            let _ = child.wait();
            return Err(PairedBackupError::StateMachine(
                "consolidated pack closure exceeds verifier object count bound".into(),
            ));
        }
    }
    reap_checked(&mut child, reader, "git cat-file for restore pack consolidation")?;
    if ids.is_empty() {
        return Err(PairedBackupError::StateMachine("restored pack closure holds no object ids".into()));
    }
    Ok(ids)
}

fn write_single_pack(
    git: &Path,
    root: &Path,
    object_ids: &[String],
    max_plan_bytes: u64,
) -> Result<(PathBuf, PathBuf), PairedBackupError> {
    let (mut child, mut stdout, stderr) = spawn_piped(git, root, &["pack-objects", "--stdout", "-q"], None, "pack")?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| PairedBackupError::StateMachine("git pack-objects stdin is unavailable".into()))?;
    let pack_path = root.join("pack-consolidated.pack");
    let mut pack_out = std::io::BufWriter::new(std::fs::File::create(&pack_path)?);
    std::thread::scope(|scope| -> Result<(), PairedBackupError> {
        scope.spawn(move || {
            let mut writer = std::io::BufWriter::new(stdin);
            for oid in object_ids {
                if writer.write_all(oid.as_bytes()).and_then(|()| writer.write_all(b"\n")).is_err() {
                    return;
                }
            }
            let _ = writer.flush();
        });
        let reader = drain_stderr(stderr);
        let mut buf = [0u8; 64 * 1024];
        let mut written = 0u64;
        loop {
            let n = stdout.read(&mut buf)?;
            if n == 0 {
                break;
            }
            written = written.saturating_add(n as u64);
            if written > max_plan_bytes {
                let _ = child.kill();
                let _ = child.wait();
                drop(pack_out);
                let _ = std::fs::remove_file(&pack_path);
                return Err(exceeds_verifier_budget(max_plan_bytes));
            }
            pack_out.write_all(&buf[..n])?;
        }
        pack_out.flush()?;
        drop(pack_out);
        reap_checked(&mut child, reader, "git pack-objects for restore pack consolidation")?;
        Ok(())
    })?;
    let mut index_cmd = Command::new(git);
    index_cmd.arg("--git-dir").arg(root).arg("index-pack").arg(&pack_path);
    let index = index_cmd.output().map_err(PairedBackupError::Io)?;
    if !index.status.success() {
        let err = String::from_utf8_lossy(&index.stderr);
        return Err(PairedBackupError::GitVerificationFailed(format!(
            "git index-pack for restore pack consolidation failed: {err}"
        )));
    }
    let idx_path = pack_path.with_extension("idx");
    if !idx_path.is_file() {
        return Err(PairedBackupError::StateMachine("consolidated idx is missing".into()));
    }
    let pack_len = std::fs::metadata(&pack_path)?.len();
    let idx_len = std::fs::metadata(&idx_path)?.len();
    if pack_len.saturating_add(idx_len) > max_plan_bytes {
        let _ = std::fs::remove_file(&pack_path);
        let _ = std::fs::remove_file(&idx_path);
        return Err(exceeds_verifier_budget(max_plan_bytes));
    }
    Ok((pack_path, idx_path))
}

fn count_pack_objects(git: &Path, root: &Path, idx_path: &Path) -> Result<usize, PairedBackupError> {
    let (mut child, stdout, stderr) = spawn_piped(git, root, &["verify-pack", "-v"], Some(idx_path), "verify-pack")?;
    let reader = drain_stderr(stderr);
    let counted = BufReader::new(stdout.take((VERIFIER_MAX_OBJECTS + 32) * 160))
        .lines()
        .map_while(Result::ok)
        .filter(|line| {
            let mut fields = line.split_whitespace();
            let (Some(oid), Some(kind)) = (fields.next(), fields.next()) else {
                return false;
            };
            oid.len() >= 40
                && oid.bytes().all(|b| b.is_ascii_hexdigit())
                && matches!(kind, "commit" | "tree" | "blob" | "tag")
        })
        .count();
    reap_checked(&mut child, reader, "git verify-pack for restore pack consolidation")?;
    Ok(counted)
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
            let mut out = String::new();
            child.stdout.take().expect("stdout").read_to_string(&mut out).expect("hash-object");
            assert!(child.wait().expect("hash-object").success(), "git hash-object failed");
            out.trim().to_owned()
        };
        let (pack_path, idx_path) = write_single_pack(git, scratch, &[blob], u64::MAX).expect("single pack");
        std::fs::create_dir_all(target).expect("pack dir");
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
        let limit = total - 1;
        let selected = select_packs_for_rebind_with_limit(&git, GitObjectFormat::Sha256, &pairs, limit, Some(&out_dir))
            .expect("consolidate on byte overflow");
        assert_eq!(selected.len(), 1, "a byte-overflowing membership must consolidate into one pack");
        assert_eq!(count_pack_objects(&git, &out_dir, &selected[0].idx_path).expect("count"), 3);
    }

    #[test]
    fn consolidate_packs_aborts_when_pack_or_idx_exceeds_byte_bound() {
        let git = PathBuf::from("git");
        if Command::new(&git).arg("--version").output().is_err() {
            return;
        }
        let root = RebindTempDir::create().expect("workspace");
        let scratch = root.0.join("scratch.git");
        Command::new(&git).args(["init", "--bare", "--object-format", "sha256"]).arg(&scratch).output().expect("init");
        let mut pairs = Vec::new();
        for index in 0..2u8 {
            let target = root.0.join(format!("restored-{index}"));
            pairs.push(seed_pack(&git, &scratch, &target, format!("object-{index}\n").as_bytes()));
        }
        let out_a = root.0.join("bounded-pack");
        let packed = select_packs_for_rebind_with_limit(&git, GitObjectFormat::Sha256, &pairs, 16, Some(&out_a));
        assert!(matches!(
            packed,
            Err(PairedBackupError::RepositoryClosureExceedsVerifierBudget { bound_bytes: 16, .. })
        ));
        assert!(!out_a.join("pack-consolidated.pack").exists());
        let measure_dir = root.0.join("measure-consolidated");
        let pack = consolidate_packs_with_git(&git, GitObjectFormat::Sha256, &pairs, &measure_dir, u64::MAX).unwrap();
        let (out_b, limit) = (root.0.join("bounded-idx"), pack.pack_len + 1);
        let r = select_packs_for_rebind_with_limit(&git, GitObjectFormat::Sha256, &pairs, limit, Some(&out_b));
        assert!(matches!(
            r,
            Err(PairedBackupError::RepositoryClosureExceedsVerifierBudget { bound_bytes, .. }) if bound_bytes == limit
        ));
        assert!(!out_b.join("pack-consolidated.pack").exists() && !out_b.join("pack-consolidated.idx").exists());
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
        let pack = consolidate_packs_with_git(&git, GitObjectFormat::Sha256, &pairs, &out_dir, u64::MAX).unwrap();
        assert_eq!(count_pack_objects(&git, &out_dir, &pack.idx_path).expect("count"), 9);
        assert!(pack.pack_len > 0 && pack.idx_len > 0);
        let oid = pick_any_object_oid_from_pack(&git, GitObjectFormat::Sha256, &pack.idx_path).expect("oid");
        assert!(oid.len() == 64 && oid.bytes().all(|b| b.is_ascii_hexdigit()));
    }
}
