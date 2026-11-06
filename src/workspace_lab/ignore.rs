use super::core::{MAX_MANIFEST, Store, read_regular, relative_path, walk};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    ffi::OsStr,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathClass {
    ManagedTracked,
    ManagedUntracked,
    Ignored,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceClassification {
    pub head_paths: BTreeSet<PathBuf>,
    pub index_paths: BTreeSet<PathBuf>,
    pub tracked_paths: BTreeSet<PathBuf>,
    pub untracked_paths: BTreeSet<PathBuf>,
    pub managed_paths: BTreeSet<PathBuf>,
    pub ignored_paths: BTreeSet<PathBuf>,
}

#[derive(Clone, Debug)]
struct IgnoreRule {
    base_dir: PathBuf,
    pattern: String,
    negated: bool,
    dir_only: bool,
    anchored: bool,
}

#[derive(Clone, Debug, Default)]
pub struct IgnoreMatcher {
    rules: Vec<IgnoreRule>,
}

impl IgnoreMatcher {
    pub fn from_worktree(repo: &Path) -> Result<Self> {
        let mut ignore_files = Vec::new();
        if repo.join(".rootyardignore").is_file() {
            ignore_files.push(PathBuf::from(".rootyardignore"));
        }
        for (path, meta) in walk(repo)? {
            if path.starts_with(".git") || !meta.is_file() {
                continue;
            }
            if path.file_name() == Some(OsStr::new(".rootyardignore"))
                && path != Path::new(".rootyardignore")
            {
                ignore_files.push(path);
            }
        }
        ignore_files.sort_by_key(|p| (p.components().count(), p.clone()));

        let mut matcher = Self::default();
        for rel_file in ignore_files {
            let base_dir = rel_file.parent().map(Path::to_path_buf).unwrap_or_default();
            let raw = read_regular(&repo.join(&rel_file), MAX_MANIFEST)?;
            let content = String::from_utf8_lossy(&raw);
            matcher.add_patterns(&base_dir, &content);
        }
        Ok(matcher)
    }

    pub fn add_patterns(&mut self, base_dir: &Path, content: &str) {
        for raw_line in content.lines() {
            let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
            if line.is_empty() {
                continue;
            }
            if line.starts_with('#') {
                continue;
            }
            let trimmed = trim_unescaped_trailing_spaces(line);
            if trimmed.is_empty() {
                continue;
            }
            let (negated, rest) = if let Some(stripped) = trimmed.strip_prefix('!') {
                (true, stripped)
            } else if let Some(stripped) = trimmed.strip_prefix(r"\!") {
                (false, stripped)
            } else if let Some(stripped) = trimmed.strip_prefix(r"\#") {
                (false, stripped)
            } else {
                (false, trimmed)
            };
            let (dir_only, rest) = if let Some(stripped) = rest.strip_suffix('/') {
                (true, stripped)
            } else {
                (false, rest)
            };
            if rest.is_empty() {
                continue;
            }
            let (anchored, pattern) = if let Some(stripped) = rest.strip_prefix('/') {
                (true, stripped.to_owned())
            } else {
                (rest.contains('/'), rest.to_owned())
            };
            if pattern.is_empty() {
                continue;
            }
            self.rules.push(IgnoreRule {
                base_dir: base_dir.to_path_buf(),
                pattern,
                negated,
                dir_only,
                anchored,
            });
        }
    }

    fn matches_single(&self, rel_path: &Path, is_dir: bool) -> bool {
        let mut ignored = false;
        for rule in &self.rules {
            if rule.dir_only && !is_dir {
                continue;
            }
            let sub_path = if rule.base_dir.as_os_str().is_empty() {
                rel_path
            } else if let Ok(stripped) = rel_path.strip_prefix(&rule.base_dir) {
                if stripped.as_os_str().is_empty() {
                    continue;
                }
                stripped
            } else {
                continue;
            };
            let rel_str = String::from_utf8_lossy(sub_path.as_os_str().as_bytes());
            let matched = if rule.anchored {
                glob_match_path(&rule.pattern, &rel_str)
            } else {
                let file_name = sub_path
                    .file_name()
                    .map(|n| String::from_utf8_lossy(n.as_bytes()).into_owned())
                    .unwrap_or_default();
                glob_match_segment(&rule.pattern, &file_name)
                    || glob_match_path(&rule.pattern, &rel_str)
            };
            if matched {
                ignored = !rule.negated;
            }
        }
        ignored
    }

    pub fn is_ignored(&self, rel_path: &Path, is_dir: bool) -> bool {
        if self.rules.is_empty() {
            return false;
        }
        let mut anc = PathBuf::new();
        let components: Vec<_> = rel_path.components().collect();
        for comp in components.iter().take(components.len().saturating_sub(1)) {
            anc.push(comp.as_os_str());
            if self.matches_single(&anc, true) {
                return true;
            }
        }
        self.matches_single(rel_path, is_dir)
    }
}

fn trim_unescaped_trailing_spaces(mut s: &str) -> &str {
    while s.ends_with(' ') {
        let before = &s[..s.len() - 1];
        let backslashes = before.chars().rev().take_while(|&c| c == '\\').count();
        if backslashes % 2 == 1 {
            break;
        }
        s = before;
    }
    s
}

fn glob_match_path(pattern: &str, text: &str) -> bool {
    let pat_segs: Vec<&str> = pattern.split('/').collect();
    let txt_segs: Vec<&str> = text.split('/').collect();
    match_segments(&pat_segs, &txt_segs)
}

fn match_segments(pat: &[&str], txt: &[&str]) -> bool {
    if pat.is_empty() {
        return txt.is_empty();
    }
    if pat[0] == "**" {
        if match_segments(&pat[1..], txt) {
            return true;
        }
        if !txt.is_empty() && match_segments(pat, &txt[1..]) {
            return true;
        }
        return false;
    }
    if txt.is_empty() {
        return false;
    }
    glob_match_segment(pat[0], txt[0]) && match_segments(&pat[1..], &txt[1..])
}

fn glob_match_segment(pat: &str, txt: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let t: Vec<char> = txt.chars().collect();
    match_chars(&p, &t)
}

fn match_chars(p: &[char], t: &[char]) -> bool {
    if p.is_empty() {
        return t.is_empty();
    }
    match p[0] {
        '*' => {
            let mut next_p = 1;
            while next_p < p.len() && p[next_p] == '*' {
                next_p += 1;
            }
            if match_chars(&p[next_p..], t) {
                return true;
            }
            if !t.is_empty() && match_chars(p, &t[1..]) {
                return true;
            }
            false
        }
        '?' => !t.is_empty() && match_chars(&p[1..], &t[1..]),
        '\\' if p.len() >= 2 => !t.is_empty() && p[1] == t[0] && match_chars(&p[2..], &t[1..]),
        '[' => {
            if t.is_empty() {
                return false;
            }
            if let Some((matched, consumed)) = match_bracket(&p[1..], t[0]) {
                matched && match_chars(&p[1 + consumed..], &t[1..])
            } else {
                p[0] == t[0] && match_chars(&p[1..], &t[1..])
            }
        }
        ch => !t.is_empty() && ch == t[0] && match_chars(&p[1..], &t[1..]),
    }
}

fn match_bracket(p: &[char], c: char) -> Option<(bool, usize)> {
    if p.is_empty() {
        return None;
    }
    let (negate, mut idx) = if p[0] == '!' || p[0] == '^' {
        (true, 1)
    } else {
        (false, 0)
    };
    let mut found_close = None;
    for (i, character) in p.iter().enumerate().skip(idx) {
        if *character == ']' && i > idx {
            found_close = Some(i);
            break;
        }
    }
    let close_idx = found_close?;
    let mut matched = false;
    while idx < close_idx {
        if idx + 2 < close_idx && p[idx + 1] == '-' {
            if c >= p[idx] && c <= p[idx + 2] {
                matched = true;
            }
            idx += 3;
        } else {
            if c == p[idx] {
                matched = true;
            }
            idx += 1;
        }
    }
    Some((if negate { !matched } else { matched }, close_idx + 1))
}

pub fn classify_workspace(store: &Store, repo: &Path) -> Result<WorkspaceClassification> {
    let mut head_paths = BTreeSet::new();
    for record in store
        .git(repo, &["ls-tree", "-rz", "--full-tree", "HEAD"])?
        .split(|b| *b == 0)
        .filter(|x| !x.is_empty())
    {
        ensure!(
            !record.starts_with(b"160000 "),
            "submodules/gitlinks are unsupported"
        );
        let split = record
            .iter()
            .position(|b| *b == b'\t')
            .context("invalid Git ls-tree record")?;
        head_paths.insert(relative_path(&record[split + 1..])?);
    }

    let mut index_paths = BTreeSet::new();
    for record in store
        .git(repo, &["ls-files", "--stage", "-z"])?
        .split(|b| *b == 0)
        .filter(|x| !x.is_empty())
    {
        ensure!(
            !record.starts_with(b"160000 "),
            "submodules/gitlinks are unsupported"
        );
        let split = record
            .iter()
            .position(|b| *b == b'\t')
            .context("invalid Git ls-files record")?;
        index_paths.insert(relative_path(&record[split + 1..])?);
    }

    let tracked_paths: BTreeSet<PathBuf> = head_paths.union(&index_paths).cloned().collect();

    let mut git_untracked = BTreeSet::new();
    for record in store
        .git(repo, &["ls-files", "--others", "--exclude-standard", "-z"])?
        .split(|b| *b == 0)
        .filter(|x| !x.is_empty())
    {
        git_untracked.insert(relative_path(record)?);
    }

    let rootyard_matcher = IgnoreMatcher::from_worktree(repo)?;
    let mut untracked_paths = BTreeSet::new();
    let mut ignored_paths = BTreeSet::new();

    for (path, _) in walk(repo)? {
        if path.starts_with(".git") {
            continue;
        }
        if tracked_paths.contains(&path) {
            continue;
        }
        if git_untracked.contains(&path) && !rootyard_matcher.is_ignored(&path, false) {
            untracked_paths.insert(path);
        } else {
            ignored_paths.insert(path);
        }
    }

    let managed_paths: BTreeSet<PathBuf> = tracked_paths.union(&untracked_paths).cloned().collect();

    Ok(WorkspaceClassification {
        head_paths,
        index_paths,
        tracked_paths,
        untracked_paths,
        managed_paths,
        ignored_paths,
    })
}

pub fn managed_paths(store: &Store, repo: &Path) -> Result<BTreeSet<PathBuf>> {
    Ok(classify_workspace(store, repo)?.managed_paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rootyardignore_patterns_negation_and_directory_rules() {
        let mut matcher = IgnoreMatcher::default();
        matcher.add_patterns(
            Path::new(""),
            "# comment\n*.tmp\n!keep.tmp\nbuild/\nsecret/data/*.bin\n!secret/data/allow.bin\n",
        );
        assert!(matcher.is_ignored(Path::new("foo.tmp"), false));
        assert!(matcher.is_ignored(Path::new("sub/bar.tmp"), false));
        assert!(!matcher.is_ignored(Path::new("keep.tmp"), false));
        assert!(!matcher.is_ignored(Path::new("sub/keep.tmp"), false));
        assert!(matcher.is_ignored(Path::new("build/output.o"), false));
        assert!(matcher.is_ignored(Path::new("secret/data/x.bin"), false));
        assert!(!matcher.is_ignored(Path::new("secret/data/allow.bin"), false));
    }
}
