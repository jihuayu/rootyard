use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::Path,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    MAX_CHUNK_BYTES, MIN_CHUNK_BYTES, MerkleSyncError,
    git_compare::GitBundleSnapshot,
    git_state::{read_git_state_and_bundle, validate_git_compat},
    manifest::{EmptyDirPolicy, UntrackedPolicy},
    scanner::{DirtyScope, MerkleWorkspaceScanner, ScanRequest, ScanResult},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoalescerStats {
    pub total_events_seen: u64,
    pub duplicate_events_folded: u64,
    pub out_of_order_batches: u64,
    pub overflow_or_drop_escalations: u64,
    pub used_full_rescan: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WatcherEvent {
    Create(Vec<u8>),
    Modify(Vec<u8>),
    Remove(Vec<u8>),
    Rename { from: Vec<u8>, to: Vec<u8> },
    Chmod(Vec<u8>),
    GitAdminChanged(Vec<u8>),
    IgnoreRuleChanged(Vec<u8>),
    Overflow,
    Dropped(u64),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WatcherBatch {
    pub seq_start: u64,
    pub seq_end: u64,
    pub events: Vec<WatcherEvent>,
}

#[derive(Clone, Debug, Default)]
pub struct WatcherCoalescer {
    last_seq: u64,
    saw_overflow_or_drop: bool,
    dirty_paths: BTreeSet<Vec<u8>>,
    dirty_dirs: BTreeSet<Vec<u8>>,
    force_rehash_dirs: BTreeSet<Vec<u8>>,
    total_events_seen: u64,
    duplicate_events_folded: u64,
    out_of_order_batches: u64,
    overflow_or_drop_escalations: u64,
}

impl WatcherCoalescer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn current_seq(&self) -> u64 {
        self.last_seq
    }

    pub fn ingest(&mut self, batch: WatcherBatch) {
        if batch.seq_start > self.last_seq + 1 && self.last_seq > 0 {
            self.saw_overflow_or_drop = true;
            self.overflow_or_drop_escalations += 1;
        }
        if batch.seq_end <= self.last_seq {
            self.out_of_order_batches += 1;
        } else {
            self.last_seq = batch.seq_end;
        }
        for ev in batch.events {
            self.total_events_seen += 1;
            self.record_event(ev);
        }
    }

    fn maybe_mark_ignore_path(&mut self, p: &[u8]) {
        if is_ignore_control_path(p) {
            let norm = p.strip_prefix(b"./").unwrap_or(p);
            let dir = if norm == b".git/info/exclude" { Vec::new() } else { parent_bytes(norm) };
            self.force_rehash_dirs.insert(dir.clone());
            self.dirty_dirs.insert(dir);
        }
    }

    fn record_event(&mut self, ev: WatcherEvent) {
        match ev {
            WatcherEvent::Overflow | WatcherEvent::Dropped(_) => {
                self.saw_overflow_or_drop = true;
                self.overflow_or_drop_escalations += 1;
            }
            WatcherEvent::GitAdminChanged(p) => {
                self.maybe_mark_ignore_path(&p);
                if !is_git_admin_path(&p) {
                    self.mark_path(p);
                }
            }
            WatcherEvent::IgnoreRuleChanged(p) => {
                let norm = p.strip_prefix(b"./").unwrap_or(p.as_slice());
                let dir = if norm == b".git/info/exclude" { Vec::new() } else { parent_bytes(norm) };
                self.force_rehash_dirs.insert(dir.clone());
                self.dirty_dirs.insert(dir);
                if !is_git_admin_path(&p) {
                    self.mark_path(p);
                }
            }
            WatcherEvent::Rename { from, to } => {
                self.maybe_mark_ignore_path(&from);
                self.maybe_mark_ignore_path(&to);
                if !is_git_admin_path(&from) {
                    self.mark_path(from);
                }
                if !is_git_admin_path(&to) {
                    self.mark_path(to);
                }
            }
            WatcherEvent::Create(p) | WatcherEvent::Modify(p) | WatcherEvent::Remove(p) | WatcherEvent::Chmod(p) => {
                self.maybe_mark_ignore_path(&p);
                if !is_git_admin_path(&p) {
                    self.mark_path(p);
                }
            }
        }
    }

    fn mark_path(&mut self, p: Vec<u8>) {
        if p.is_empty() {
            self.dirty_dirs.insert(Vec::new());
            return;
        }
        let parent = parent_bytes(&p);
        self.dirty_dirs.insert(parent);
        if !self.dirty_paths.insert(p) {
            self.duplicate_events_folded += 1;
        }
    }

    pub fn into_dirty_scope(&mut self) -> (DirtyScope, CoalescerStats) {
        let used_full_rescan = self.saw_overflow_or_drop || self.force_rehash_dirs.contains(b"".as_slice());
        let scope = if used_full_rescan {
            DirtyScope::FullRescan
        } else {
            DirtyScope::Subtrees {
                dirty_dirs: std::mem::take(&mut self.dirty_dirs),
                dirty_paths: std::mem::take(&mut self.dirty_paths),
                force_rehash_dirs: std::mem::take(&mut self.force_rehash_dirs),
            }
        };
        let stats = CoalescerStats {
            total_events_seen: self.total_events_seen,
            duplicate_events_folded: self.duplicate_events_folded,
            out_of_order_batches: self.out_of_order_batches,
            overflow_or_drop_escalations: self.overflow_or_drop_escalations,
            used_full_rescan,
        };
        self.saw_overflow_or_drop = false;
        self.dirty_dirs.clear();
        self.dirty_paths.clear();
        self.force_rehash_dirs.clear();
        (scope, stats)
    }
}

fn is_git_admin_path(p: &[u8]) -> bool {
    let norm = p.strip_prefix(b"./").unwrap_or(p);
    norm == b".git" || norm.starts_with(b".git/")
}

fn is_ignore_control_path(p: &[u8]) -> bool {
    let norm = p.strip_prefix(b"./").unwrap_or(p);
    norm == b".gitignore"
        || norm.ends_with(b"/.gitignore")
        || norm == b".rootyardignore"
        || norm.ends_with(b"/.rootyardignore")
        || norm == b".git/info/exclude"
}

fn parent_bytes(path: &[u8]) -> Vec<u8> {
    match path.iter().rposition(|b| *b == b'/') {
        Some(idx) => path[..idx].to_vec(),
        None => Vec::new(),
    }
}

pub trait QuiescenceBarrierProbe {
    fn on_pre_barrier(&mut self, _attempt: u32) -> Result<(), MerkleSyncError> {
        Ok(())
    }

    fn on_post_scan(&mut self, _attempt: u32) -> Result<(), MerkleSyncError> {
        Ok(())
    }

    fn current_watcher_seq(&self) -> u64 {
        0
    }
}

pub struct NoopBarrierProbe;
impl QuiescenceBarrierProbe for NoopBarrierProbe {}

#[derive(Clone)]
pub struct CaptureBarrierRequest<'a> {
    pub repo_root: &'a Path,
    pub workspace_id: Uuid,
    pub checkpoint_id: Uuid,
    pub tenant_id: Uuid,
    pub repo_id: Uuid,
    pub history_id: Uuid,
    pub parent_checkpoint_id: Option<Uuid>,
    pub chunk_size_bytes: u32,
    pub untracked_policy: UntrackedPolicy,
    pub empty_dir_policy: EmptyDirPolicy,
    pub use_gitignore: bool,
    pub use_rootyardignore: bool,
    pub expected_revision: i64,
    pub actual_revision_fn: &'a dyn Fn() -> i64,
    pub expected_lease_epoch: i64,
    pub actual_lease_epoch_fn: &'a dyn Fn() -> i64,
    pub previous: Option<&'a super::manifest::MerkleStateManifest>,
    pub max_attempts: u32,
}

#[derive(Clone, Debug)]
pub enum ConvergeOutcome {
    Converged { scan: Box<ScanResult>, git_bundle: GitBundleSnapshot, attempts: u32, stats: CoalescerStats },
    NotQuiescent { reason: String, attempts: u32 },
    UnsupportedState { reason: String },
}

#[derive(PartialEq, Eq)]
struct WorkspaceStamp {
    head_bytes: Vec<u8>,
    index_sha256: String,
    refs_digest: String,
    stat_digest: String,
    watcher_seq: u64,
    revision: i64,
    lease_epoch: i64,
}

fn capture_stamp(
    repo: &Path,
    watcher_seq: u64,
    revision: i64,
    lease_epoch: i64,
) -> Result<WorkspaceStamp, MerkleSyncError> {
    let _ = validate_git_compat(repo)?;
    let dot_git = repo.join(".git");
    let head_bytes = fs::read(dot_git.join("HEAD"))?;
    let index_sha256 = if dot_git.join("index").try_exists()? {
        hex::encode(Sha256::digest(fs::read(dot_git.join("index"))?))
    } else {
        hex::encode(Sha256::digest(b""))
    };
    let mut ref_entries: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    collect_dir_digests(&dot_git, Path::new("refs"), &mut ref_entries)?;
    if dot_git.join("packed-refs").try_exists()? {
        ref_entries.insert(b"packed-refs".to_vec(), fs::read(dot_git.join("packed-refs"))?);
    }
    let mut ref_hasher = Sha256::new();
    for (k, v) in ref_entries {
        ref_hasher.update((k.len() as u64).to_le_bytes());
        ref_hasher.update(&k);
        ref_hasher.update((v.len() as u64).to_le_bytes());
        ref_hasher.update(&v);
    }
    let mut stat_hasher = Sha256::new();
    hash_worktree_stat_tree(repo, Path::new(""), &mut stat_hasher)?;
    Ok(WorkspaceStamp {
        head_bytes,
        index_sha256,
        refs_digest: hex::encode(ref_hasher.finalize()),
        stat_digest: hex::encode(stat_hasher.finalize()),
        watcher_seq,
        revision,
        lease_epoch,
    })
}

fn collect_dir_digests(base: &Path, rel: &Path, out: &mut BTreeMap<Vec<u8>, Vec<u8>>) -> Result<(), MerkleSyncError> {
    let dir = base.join(rel);
    if !dir.try_exists()? {
        return Ok(());
    }
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let rel_child = rel.join(entry.file_name());
        let meta = fs::symlink_metadata(entry.path())?;
        if meta.is_dir() {
            collect_dir_digests(base, &rel_child, out)?;
        } else if meta.is_file() {
            if rel_child.as_os_str().as_bytes().ends_with(b".lock") {
                return Err(MerkleSyncError::NotQuiescent("active .git lock file".into()));
            }
            out.insert(rel_child.as_os_str().as_bytes().to_vec(), fs::read(entry.path())?);
        }
    }
    Ok(())
}

fn hash_worktree_stat_tree(root: &Path, rel: &Path, hasher: &mut Sha256) -> Result<(), MerkleSyncError> {
    let mut items = Vec::new();
    for entry in fs::read_dir(root.join(rel))? {
        let entry = entry?;
        let name = entry.file_name();
        if name == OsStr::new(".git") {
            if !rel.as_os_str().is_empty() {
                return Err(MerkleSyncError::UnsupportedGitState("nested .git directory unsupported".into()));
            }
            continue;
        }
        items.push((name.as_bytes().to_vec(), entry.path(), rel.join(name)));
    }
    items.sort_by(|a, b| a.0.cmp(&b.0));
    for (name_bytes, full, child_rel) in items {
        let meta = fs::symlink_metadata(&full)?;
        hasher.update((name_bytes.len() as u64).to_le_bytes());
        hasher.update(&name_bytes);
        hasher.update(meta.mode().to_le_bytes());
        hasher.update(meta.len().to_le_bytes());
        hasher.update(meta.ino().to_le_bytes());
        hasher.update(meta.mtime().to_le_bytes());
        hasher.update(meta.mtime_nsec().to_le_bytes());
        hasher.update(meta.ctime().to_le_bytes());
        hasher.update(meta.ctime_nsec().to_le_bytes());
        if meta.is_dir() {
            hasher.update(b"D");
            hash_worktree_stat_tree(root, &child_rel, hasher)?;
        } else if meta.file_type().is_symlink() {
            hasher.update(b"L");
        } else if meta.is_file() {
            hasher.update(b"F");
        } else {
            return Err(MerkleSyncError::UnsupportedGitState("special file unsupported".into()));
        }
    }
    Ok(())
}

pub fn capture_with_quiescence_barrier(
    req: &CaptureBarrierRequest<'_>,
    coalescer: &mut WatcherCoalescer,
    probe: &mut dyn QuiescenceBarrierProbe,
) -> Result<ConvergeOutcome, MerkleSyncError> {
    if req.max_attempts == 0 {
        return Err(MerkleSyncError::InvalidInput("max_attempts must be >= 1".into()));
    }
    if !(MIN_CHUNK_BYTES..=MAX_CHUNK_BYTES).contains(&(req.chunk_size_bytes as usize)) {
        return Err(MerkleSyncError::InvalidInput("chunk_size_bytes out of bounds".into()));
    }
    let mut last_reason = String::new();
    let mut escalate_full = false;
    for attempt in 1..=req.max_attempts {
        probe.on_pre_barrier(attempt)?;
        let pre_rev = (req.actual_revision_fn)();
        let pre_epoch = (req.actual_lease_epoch_fn)();
        if pre_rev != req.expected_revision || pre_epoch != req.expected_lease_epoch {
            return Ok(ConvergeOutcome::NotQuiescent {
                reason: "workspace revision or lease_epoch drifted before capture".into(),
                attempts: attempt,
            });
        }
        let pre_seq = coalescer.current_seq().max(probe.current_watcher_seq());
        macro_rules! barrier_step {
            ($expr:expr) => {
                match $expr {
                    Ok(v) => v,
                    Err(MerkleSyncError::UnsupportedGitState(reason)) => {
                        return Ok(ConvergeOutcome::UnsupportedState { reason });
                    }
                    Err(MerkleSyncError::NotQuiescent(reason)) | Err(MerkleSyncError::ConcurrentEdit(reason)) => {
                        last_reason = reason;
                        escalate_full = true;
                        continue;
                    }
                    Err(err) => return Err(err),
                }
            };
        }
        let pre_stamp = barrier_step!(capture_stamp(req.repo_root, pre_seq, pre_rev, pre_epoch));

        let (mut dirty_scope, mut stats) = coalescer.into_dirty_scope();
        if escalate_full || attempt > 1 {
            dirty_scope = DirtyScope::FullRescan;
            stats.used_full_rescan = true;
        }

        let (git_state, ignore, git_bundle) = barrier_step!(read_git_state_and_bundle(
            req.repo_root,
            req.untracked_policy,
            req.empty_dir_policy,
            req.use_gitignore,
            req.use_rootyardignore,
        ));

        let scan = barrier_step!(MerkleWorkspaceScanner::scan(ScanRequest {
            repo_root: req.repo_root,
            workspace_id: req.workspace_id,
            checkpoint_id: req.checkpoint_id,
            tenant_id: req.tenant_id,
            repo_id: req.repo_id,
            history_id: req.history_id,
            parent_checkpoint_id: req.parent_checkpoint_id,
            chunk_size_bytes: req.chunk_size_bytes,
            git_state: &git_state,
            ignore: &ignore,
            previous: req.previous,
            dirty_scope,
        }));

        probe.on_post_scan(attempt)?;
        let post_rev = (req.actual_revision_fn)();
        let post_epoch = (req.actual_lease_epoch_fn)();
        let post_seq = coalescer.current_seq().max(probe.current_watcher_seq());
        let post_stamp = barrier_step!(capture_stamp(req.repo_root, post_seq, post_rev, post_epoch));

        if pre_stamp != post_stamp {
            last_reason = "workspace mutated during single-barrier capture (mixed-point refused)".into();
            escalate_full = true;
            continue;
        }
        return Ok(ConvergeOutcome::Converged { scan: Box::new(scan), git_bundle, attempts: attempt, stats });
    }
    Ok(ConvergeOutcome::NotQuiescent { reason: last_reason, attempts: req.max_attempts })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converge_rejects_below_min_chunk_size_early() {
        let one = || 1i64;
        let mut co = WatcherCoalescer::new();
        let req = CaptureBarrierRequest {
            repo_root: Path::new("."),
            workspace_id: Uuid::nil(),
            checkpoint_id: Uuid::nil(),
            tenant_id: Uuid::nil(),
            repo_id: Uuid::nil(),
            history_id: Uuid::nil(),
            parent_checkpoint_id: None,
            chunk_size_bytes: 1,
            untracked_policy: UntrackedPolicy::IncludeNonIgnored,
            empty_dir_policy: EmptyDirPolicy::IgnoreEmptyDirs,
            use_gitignore: true,
            use_rootyardignore: true,
            expected_revision: 1,
            actual_revision_fn: &one,
            expected_lease_epoch: 1,
            actual_lease_epoch_fn: &one,
            previous: None,
            max_attempts: 1,
        };
        assert!(matches!(
            capture_with_quiescence_barrier(&req, &mut co, &mut NoopBarrierProbe),
            Err(MerkleSyncError::InvalidInput(_))
        ));
    }
}
