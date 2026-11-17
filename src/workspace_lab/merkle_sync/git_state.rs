use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    fs,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

use sha2::{Digest, Sha256};

use super::{
    MAX_MANIFEST_JSON_BYTES, MAX_TREE_ENTRIES, MerkleSyncError,
    git_compare::{GitBundleSnapshot, build_git_bundle_snapshot, collect_git_files, read_regular_bounded},
    manifest::{
        EmptyDirPolicy, GitIndexEntryRecord, GitStateSnapshot, HeadSnapshot, IgnorePolicySpec, MerkleObjectFormat,
        UntrackedPolicy, compute_index_merkle_root, encode_rel_bytes, validate_rel_path_bytes,
    },
};
use crate::workspace_lab::{core, ignore::IgnoreMatcher};

#[derive(Clone, Debug)]
pub struct IgnoreSnapshot {
    pub policy: IgnorePolicySpec,
    pub tracked_paths: BTreeSet<Vec<u8>>,
    pub git_untracked: BTreeSet<Vec<u8>>,
    pub rootyard_matcher: IgnoreMatcher,
}

fn git_exe() -> OsString {
    std::env::var_os("ROOTYARD_WORKSPACE_GIT").unwrap_or_else(|| "git".into())
}

pub(crate) fn run_git_raw(repo: &Path, args: &[&str]) -> Result<Output, MerkleSyncError> {
    Command::new(git_exe())
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            "-c",
            "core.excludesFile=/dev/null",
            "-c",
            "core.attributesFile=/dev/null",
            "-c",
            "core.quotepath=false",
            "-c",
            "gc.auto=0",
            "-c",
            "maintenance.auto=false",
        ])
        .arg("-C")
        .arg(repo)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| MerkleSyncError::GitFailed(format!("spawn git failed: {e}")))
}

pub(crate) fn git_bytes(repo: &Path, args: &[&str]) -> Result<Vec<u8>, MerkleSyncError> {
    let out = run_git_raw(repo, args)?;
    if !out.status.success() {
        return Err(MerkleSyncError::GitFailed(format!("git {} failed", args.first().unwrap_or(&""))));
    }
    Ok(out.stdout)
}

fn git_text(repo: &Path, args: &[&str]) -> Result<String, MerkleSyncError> {
    let bytes = git_bytes(repo, args)?;
    Ok(String::from_utf8(bytes).map_err(|e| MerkleSyncError::GitFailed(e.to_string()))?.trim().to_owned())
}

pub fn validate_git_compat(repo: &Path) -> Result<MerkleObjectFormat, MerkleSyncError> {
    if !fs::symlink_metadata(repo)?.is_dir() {
        return Err(MerkleSyncError::UnsupportedGitState("workspace root must be a real directory".into()));
    }
    let dot_git = repo.join(".git");
    let git_meta = fs::symlink_metadata(&dot_git)
        .map_err(|_| MerkleSyncError::UnsupportedGitState("missing .git directory".into()))?;
    if git_meta.file_type().is_symlink() || git_meta.is_file() || !git_meta.is_dir() {
        return Err(MerkleSyncError::UnsupportedGitState("linked worktree or symlinked .git unsupported".into()));
    }
    for banned in ["worktrees", "modules", "shallow", "objects/info/alternates", "info/grafts", "info/sparse-checkout"]
    {
        if dot_git.join(banned).try_exists()? {
            return Err(MerkleSyncError::UnsupportedGitState(format!("unsupported Git state: {banned}")));
        }
    }
    let mut git_files = Vec::new();
    collect_git_files(&dot_git, Path::new(""), &mut git_files)?;
    for (rel, _) in &git_files {
        if rel.starts_with("hooks") && !rel.as_os_str().as_bytes().ends_with(b".sample") {
            return Err(MerkleSyncError::UnsupportedGitState("custom Git hooks unsupported".into()));
        }
        if rel.file_name().is_some_and(|n| n.as_bytes().starts_with(b"sharedindex.")) {
            return Err(MerkleSyncError::UnsupportedGitState("split index unsupported".into()));
        }
    }
    let cfg = git_bytes(repo, &["config", "--local", "--no-includes", "--null", "--list"])?;
    for rec in cfg.split(|b| *b == 0).filter(|x| !x.is_empty()) {
        let sep =
            rec.iter().position(|b| *b == b'\n').ok_or_else(|| MerkleSyncError::GitFailed("bad config".into()))?;
        let k =
            std::str::from_utf8(&rec[..sep]).map_err(|_| MerkleSyncError::UnsupportedGitState("bad cfg key".into()))?;
        let v = std::str::from_utf8(&rec[sep + 1..])
            .map_err(|_| MerkleSyncError::UnsupportedGitState("bad cfg val".into()))?;
        let ok = match k {
            "core.repositoryformatversion" => v == "0" || v == "1",
            "extensions.objectformat" => v == "sha1" || v == "sha256",
            "core.filemode" | "core.logallrefupdates" => v == "true",
            "core.bare" | "core.ignorecase" | "core.precomposeunicode" => v == "false",
            "core.autocrlf" => ["false", "true", "input"].contains(&v),
            "core.eol" => ["native", "lf", "crlf"].contains(&v),
            "user.name" | "user.email" => !v.contains(['\r', '\n']),
            _ => false,
        };
        if !ok {
            return Err(MerkleSyncError::UnsupportedGitState(format!("unsupported local Git config key: {k}")));
        }
    }
    let fmt = match git_text(repo, &["rev-parse", "--show-object-format"])?.as_str() {
        "sha1" => MerkleObjectFormat::Sha1,
        "sha256" => MerkleObjectFormat::Sha256,
        other => return Err(MerkleSyncError::UnsupportedGitState(format!("unsupported object format: {other}"))),
    };
    if git_text(repo, &["rev-parse", "--is-bare-repository"])? != "false" {
        return Err(MerkleSyncError::UnsupportedGitState("bare repository unsupported".into()));
    }
    if !git_bytes(repo, &["for-each-ref", "--format=%(refname)", "refs/replace/"])?.is_empty() {
        return Err(MerkleSyncError::UnsupportedGitState("replacement refs unsupported".into()));
    }
    let info_attr = dot_git.join("info/attributes");
    if info_attr.try_exists()? {
        let bytes = read_regular_bounded(&info_attr, MAX_MANIFEST_JSON_BYTES)?;
        core::check_gitattributes(&bytes, false).map_err(|e| MerkleSyncError::UnsupportedGitState(e.to_string()))?;
    }
    Ok(fmt)
}

pub(crate) fn parse_index_ita_and_validate(
    repo: &Path,
    fmt: MerkleObjectFormat,
) -> Result<(BTreeSet<Vec<u8>>, String), MerkleSyncError> {
    let index_path = repo.join(".git/index");
    if !index_path.try_exists()? {
        return Ok((BTreeSet::new(), hex::encode(Sha256::digest(b""))));
    }
    let bytes = read_regular_bounded(&index_path, MAX_MANIFEST_JSON_BYTES)?;
    let raw_sha = hex::encode(Sha256::digest(&bytes));
    let oid_len = fmt.oid_byte_len();
    let entry_fixed = 40 + oid_len + 2;
    if bytes.len() < 12 + oid_len || &bytes[..4] != b"DIRC" {
        return Err(MerkleSyncError::UnsupportedGitState("invalid Git index header".into()));
    }
    let version = u32::from_be_bytes(bytes[4..8].try_into().map_err(|_| MerkleSyncError::GitFailed("hdr".into()))?);
    if !matches!(version, 2 | 3) {
        return Err(MerkleSyncError::UnsupportedGitState("only Git index v2/v3 supported".into()));
    }
    let count =
        u32::from_be_bytes(bytes[8..12].try_into().map_err(|_| MerkleSyncError::GitFailed("cnt".into()))?) as usize;
    if count > MAX_TREE_ENTRIES {
        return Err(MerkleSyncError::UnsupportedGitState("index entry count exceeds limit".into()));
    }
    let end = bytes.len() - oid_len;
    let mut cursor = 12usize;
    let mut ita_paths = BTreeSet::new();
    for _ in 0..count {
        let start = cursor;
        if cursor.checked_add(entry_fixed).is_none_or(|n| n > end) {
            return Err(MerkleSyncError::UnsupportedGitState("truncated index entry".into()));
        }
        let mode = u32::from_be_bytes(
            bytes[start + 24..start + 28].try_into().map_err(|_| MerkleSyncError::GitFailed("m".into()))?,
        );
        if (mode & 0o170000) == 0o160000 {
            return Err(MerkleSyncError::UnsupportedGitState("submodules/gitlinks in index unsupported".into()));
        }
        if !matches!(mode & 0o170000, 0o100000 | 0o120000) {
            return Err(MerkleSyncError::UnsupportedGitState("unsupported Git index entry mode".into()));
        }
        let flags = u16::from_be_bytes(
            bytes[start + 40 + oid_len..start + entry_fixed]
                .try_into()
                .map_err(|_| MerkleSyncError::GitFailed("f".into()))?,
        );
        cursor += entry_fixed;
        let mut is_ita = false;
        if flags & 0x4000 != 0 {
            if version != 3 || cursor + 2 > end {
                return Err(MerkleSyncError::UnsupportedGitState("invalid extended index flags".into()));
            }
            let ext = u16::from_be_bytes(
                bytes[cursor..cursor + 2].try_into().map_err(|_| MerkleSyncError::GitFailed("e".into()))?,
            );
            if ext & !0x2000 != 0 {
                return Err(MerkleSyncError::UnsupportedGitState(
                    "skip-worktree or unknown index flags unsupported".into(),
                ));
            }
            is_ita = ext & 0x2000 != 0;
            cursor += 2;
        }
        let nul = bytes[cursor..end]
            .iter()
            .position(|b| *b == 0)
            .ok_or_else(|| MerkleSyncError::UnsupportedGitState("unterminated index path".into()))?;
        let path_bytes = &bytes[cursor..cursor + nul];
        validate_rel_path_bytes(path_bytes)?;
        if is_ita {
            ita_paths.insert(path_bytes.to_vec());
        }
        cursor += nul + 1;
        cursor = start + (cursor - start).div_ceil(8) * 8;
        if cursor > end {
            return Err(MerkleSyncError::UnsupportedGitState("truncated index padding".into()));
        }
    }
    while cursor < end {
        if cursor + 8 > end {
            return Err(MerkleSyncError::UnsupportedGitState("truncated index extension".into()));
        }
        let name = &bytes[cursor..cursor + 4];
        if name != b"TREE" && name != b"REUC" {
            return Err(MerkleSyncError::UnsupportedGitState(
                "unsupported split/sparse/fsmonitor index extension".into(),
            ));
        }
        let ext_len = u32::from_be_bytes(
            bytes[cursor + 4..cursor + 8].try_into().map_err(|_| MerkleSyncError::GitFailed("ex".into()))?,
        ) as usize;
        cursor = cursor
            .checked_add(8 + ext_len)
            .ok_or_else(|| MerkleSyncError::UnsupportedGitState("ext overflow".into()))?;
        if cursor > end {
            return Err(MerkleSyncError::UnsupportedGitState("truncated index extension payload".into()));
        }
    }
    Ok((ita_paths, raw_sha))
}

fn read_optional_head_oid(repo: &Path, name: &str) -> Result<Option<String>, MerkleSyncError> {
    let p = repo.join(".git").join(name);
    if !p.try_exists()? {
        return Ok(None);
    }
    Ok(Some(String::from_utf8_lossy(&read_regular_bounded(&p, 256)?).trim().to_owned()))
}

fn collect_ignore_files_digest(
    repo: &Path,
    use_gitignore: bool,
    use_rootyardignore: bool,
) -> Result<String, MerkleSyncError> {
    let mut files: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    if use_gitignore && repo.join(".git/info/exclude").try_exists()? {
        files.push((
            b".git/info/exclude".to_vec(),
            read_regular_bounded(&repo.join(".git/info/exclude"), MAX_MANIFEST_JSON_BYTES)?,
        ));
    }
    fn walk_ignores(
        root: &Path,
        rel: &Path,
        use_gi: bool,
        use_ri: bool,
        out: &mut Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<(), MerkleSyncError> {
        for child in fs::read_dir(root.join(rel))? {
            let child = child?;
            let name = child.file_name();
            let child_rel = if rel.as_os_str().is_empty() { PathBuf::from(&name) } else { rel.join(&name) };
            let meta = fs::symlink_metadata(child.path())?;
            if meta.is_dir() {
                if name == OsStr::new(".git") {
                    if !rel.as_os_str().is_empty() {
                        return Err(MerkleSyncError::UnsupportedGitState("nested .git directory unsupported".into()));
                    }
                    continue;
                }
                walk_ignores(root, &child_rel, use_gi, use_ri, out)?;
            } else if meta.is_file() {
                let bname = name.as_bytes();
                if (use_gi && bname == b".gitignore") || (use_ri && bname == b".rootyardignore") {
                    out.push((
                        child_rel.as_os_str().as_bytes().to_vec(),
                        read_regular_bounded(&child.path(), MAX_MANIFEST_JSON_BYTES)?,
                    ));
                }
            }
        }
        Ok(())
    }
    walk_ignores(repo, Path::new(""), use_gitignore, use_rootyardignore, &mut files)?;
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let mut hasher = Sha256::new();
    hasher.update(b"rootyard.merkle-sync.v1:ignore-rules\0");
    for (p, body) in files {
        hasher.update(&(p.len() as u64).to_le_bytes());
        hasher.update(&p);
        hasher.update(&(body.len() as u64).to_le_bytes());
        hasher.update(&body);
    }
    Ok(hex::encode(hasher.finalize()))
}

pub fn read_git_state_and_bundle(
    repo: &Path,
    untracked_policy: UntrackedPolicy,
    empty_dir_policy: EmptyDirPolicy,
    use_gitignore: bool,
    use_rootyardignore: bool,
) -> Result<(GitStateSnapshot, IgnoreSnapshot, GitBundleSnapshot), MerkleSyncError> {
    let fmt = validate_git_compat(repo)?;
    let (ita_paths, index_raw_sha256) = parse_index_ita_and_validate(repo, fmt)?;
    let head = if let Ok(commit_oid) = git_text(repo, &["rev-parse", "--verify", "HEAD^{commit}"]) {
        let tree_oid = git_text(repo, &["rev-parse", "--verify", "HEAD^{tree}"])?;
        let sym = run_git_raw(repo, &["symbolic-ref", "-q", "HEAD"])?;
        if sym.status.success() {
            let ref_name =
                String::from_utf8(sym.stdout).map_err(|e| MerkleSyncError::GitFailed(e.to_string()))?.trim().to_owned();
            HeadSnapshot::Attached { ref_name, commit_oid, tree_oid }
        } else {
            HeadSnapshot::Detached { commit_oid, tree_oid }
        }
    } else {
        HeadSnapshot::Unborn { ref_name: git_text(repo, &["symbolic-ref", "HEAD"])? }
    };
    let mut head_paths = BTreeSet::new();
    if !matches!(head, HeadSnapshot::Unborn { .. }) {
        for rec in
            git_bytes(repo, &["ls-tree", "-rz", "--full-tree", "HEAD"])?.split(|b| *b == 0).filter(|x| !x.is_empty())
        {
            if rec.starts_with(b"160000 ") {
                return Err(MerkleSyncError::UnsupportedGitState("gitlinks in HEAD unsupported".into()));
            }
            if let Some(tab) = rec.iter().position(|b| *b == b'\t') {
                head_paths.insert(rec[tab + 1..].to_vec());
            }
        }
    }
    let mut index_entries = Vec::new();
    let mut index_paths = BTreeSet::new();
    for rec in git_bytes(repo, &["ls-files", "--stage", "-z"])?.split(|b| *b == 0).filter(|x| !x.is_empty()) {
        if rec.starts_with(b"160000 ") {
            return Err(MerkleSyncError::UnsupportedGitState("gitlinks in index unsupported".into()));
        }
        let tab =
            rec.iter().position(|b| *b == b'\t').ok_or_else(|| MerkleSyncError::GitFailed("bad stage rec".into()))?;
        let hdr = std::str::from_utf8(&rec[..tab]).map_err(|_| MerkleSyncError::GitFailed("bad stage hdr".into()))?;
        let mut parts = hdr.split_whitespace();
        let mode = u32::from_str_radix(parts.next().ok_or_else(|| MerkleSyncError::GitFailed("m".into()))?, 8)
            .map_err(|_| MerkleSyncError::GitFailed("m".into()))?;
        let oid_s = parts.next().ok_or_else(|| MerkleSyncError::GitFailed("oid".into()))?;
        let stage: u8 = parts
            .next()
            .ok_or_else(|| MerkleSyncError::GitFailed("st".into()))?
            .parse()
            .map_err(|_| MerkleSyncError::GitFailed("st".into()))?;
        let path_raw = &rec[tab + 1..];
        validate_rel_path_bytes(path_raw)?;
        let size = git_text(repo, &["cat-file", "-s", oid_s]).ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
        index_paths.insert(path_raw.to_vec());
        index_entries.push(GitIndexEntryRecord {
            path_base64: encode_rel_bytes(path_raw),
            stage,
            mode,
            git_oid: oid_s.to_owned(),
            size,
            intent_to_add: ita_paths.contains(path_raw),
        });
    }
    index_entries.sort_by(|a, b| (&a.path_base64, a.stage).cmp(&(&b.path_base64, b.stage)));
    let merge_head = read_optional_head_oid(repo, "MERGE_HEAD")?;
    let cherry_pick_head = read_optional_head_oid(repo, "CHERRY_PICK_HEAD")?;
    let rebase_head = read_optional_head_oid(repo, "REBASE_HEAD")?;
    let index_merkle_root = compute_index_merkle_root(
        fmt,
        &index_entries,
        &index_raw_sha256,
        merge_head.as_deref(),
        cherry_pick_head.as_deref(),
        rebase_head.as_deref(),
    );
    let git_state = GitStateSnapshot {
        object_format: fmt,
        head,
        index_entries,
        index_raw_sha256,
        index_merkle_root,
        merge_head,
        cherry_pick_head,
        rebase_head,
    };
    let tracked_paths: BTreeSet<Vec<u8>> = head_paths.union(&index_paths).cloned().collect();
    let mut git_untracked = BTreeSet::new();
    let untracked_args: &[&str] = if use_gitignore {
        &["ls-files", "--others", "--exclude-standard", "-z"]
    } else {
        &["ls-files", "--others", "-z"]
    };
    for rec in git_bytes(repo, untracked_args)?.split(|b| *b == 0).filter(|x| !x.is_empty()) {
        validate_rel_path_bytes(rec)?;
        git_untracked.insert(rec.to_vec());
    }
    let rootyard_matcher = if use_rootyardignore {
        IgnoreMatcher::from_worktree(repo).map_err(|e| MerkleSyncError::Io(e.to_string()))?
    } else {
        IgnoreMatcher::default()
    };
    let ignore_rules_digest = collect_ignore_files_digest(repo, use_gitignore, use_rootyardignore)?;
    let ignore_snapshot = IgnoreSnapshot {
        policy: IgnorePolicySpec {
            untracked_policy,
            empty_dir_policy,
            use_gitignore,
            use_rootyardignore,
            ignore_rules_digest,
        },
        tracked_paths,
        git_untracked,
        rootyard_matcher,
    };
    let bundle = build_git_bundle_snapshot(repo, fmt)?;
    Ok((git_state, ignore_snapshot, bundle))
}
