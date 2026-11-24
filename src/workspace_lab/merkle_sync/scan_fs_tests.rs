use std::{
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tempfile::TempDir;
use uuid::Uuid;

use super::*;
use crate::workspace_lab::merkle_sync::{
    converge::{
        CaptureBarrierRequest, ConvergeOutcome, NoopBarrierProbe, QuiescenceBarrierProbe, WatcherBatch,
        WatcherCoalescer, WatcherEvent, capture_with_quiescence_barrier,
    },
    git_state::read_git_state_and_bundle,
    manifest::{EmptyDirPolicy, MerkleStateManifest, UntrackedPolicy},
    scanner::{DirtyScope, MerkleWorkspaceScanner, ScanRequest},
};

fn git_ok(repo: &Path, args: &[&str]) {
    let out = Command::new("git")
        .args(["-c", "core.hooksPath=/dev/null", "--no-replace-objects", "-C"])
        .arg(repo)
        .args(args)
        .envs([
            ("GIT_CONFIG_NOSYSTEM", "1"),
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
            ("GIT_AUTHOR_NAME", "r"),
            ("GIT_AUTHOR_EMAIL", "r@e"),
            ("GIT_COMMITTER_NAME", "r"),
            ("GIT_COMMITTER_EMAIL", "r@e"),
        ])
        .output()
        .expect("run git");
    assert!(out.status.success(), "git {args:?} failed");
}

struct MutatingBarrierProbe {
    repo: PathBuf,
    seq: Arc<AtomicU64>,
    keep_mutating: bool,
}

impl QuiescenceBarrierProbe for MutatingBarrierProbe {
    fn on_post_scan(&mut self, attempt: u32) -> Result<(), MerkleSyncError> {
        if self.keep_mutating || attempt == 1 {
            self.seq.fetch_add(1, Ordering::SeqCst);
            fs::write(self.repo.join("sub_a/edited.txt"), format!("race-{attempt}\n"))?;
        }
        Ok(())
    }
    fn current_watcher_seq(&self) -> u64 {
        self.seq.load(Ordering::SeqCst)
    }
}

#[test]
fn lossy_watcher_convergence_and_quiescence_barrier_races() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let repo = dir.path().join("repo");
    fs::create_dir_all(repo.join("sub_a/nested"))?;
    fs::create_dir_all(repo.join("sub_b/deep"))?;
    fs::write(repo.join("sub_a/edited.txt"), b"init-a\n")?;
    fs::write(repo.join("sub_a/nested/keep.txt"), b"keep\n")?;
    for i in 0..8 {
        fs::write(repo.join(format!("sub_b/deep/b_{i}.txt")), vec![b'B'; 4096])?;
    }
    git_ok(&repo, &["init", "--initial-branch=main"]);
    git_ok(&repo, &["add", "--all"]);
    git_ok(&repo, &["commit", "-m", "seed"]);

    let (t, r, h, ws) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let (gs, ig, _) = read_git_state_and_bundle(
        &repo,
        UntrackedPolicy::IncludeNonIgnored,
        EmptyDirPolicy::IgnoreEmptyDirs,
        true,
        true,
    )?;
    let base = MerkleWorkspaceScanner::scan(ScanRequest {
        repo_root: &repo,
        workspace_id: ws,
        checkpoint_id: Uuid::new_v4(),
        tenant_id: t,
        repo_id: r,
        history_id: h,
        parent_checkpoint_id: None,
        chunk_size_bytes: 16 * 1024,
        git_state: &gs,
        ignore: &ig,
        previous: None,
        dirty_scope: DirtyScope::FullRescan,
    })?;

    fs::write(repo.join("sub_a/edited.txt"), b"v2-a\n")?;
    let mut co = WatcherCoalescer::new();
    co.ingest(WatcherBatch {
        seq_start: 1,
        seq_end: 3,
        events: vec![
            WatcherEvent::Modify(b"sub_a/edited.txt".to_vec()),
            WatcherEvent::Modify(b"sub_a/edited.txt".to_vec()),
        ],
    });
    co.ingest(WatcherBatch {
        seq_start: 1,
        seq_end: 2,
        events: vec![WatcherEvent::Create(b"sub_a/edited.txt".to_vec())],
    });
    let one = || 1i64;
    let run = |c: &mut WatcherCoalescer,
               prev: Option<&MerkleStateManifest>,
               max_a: u32,
               probe: &mut dyn QuiescenceBarrierProbe| {
        capture_with_quiescence_barrier(
            &CaptureBarrierRequest {
                repo_root: &repo,
                workspace_id: ws,
                checkpoint_id: Uuid::new_v4(),
                tenant_id: t,
                repo_id: r,
                history_id: h,
                parent_checkpoint_id: prev.map(|p| p.checkpoint_id),
                chunk_size_bytes: 16 * 1024,
                untracked_policy: UntrackedPolicy::IncludeNonIgnored,
                empty_dir_policy: EmptyDirPolicy::IgnoreEmptyDirs,
                use_gitignore: true,
                use_rootyardignore: true,
                expected_revision: 1,
                actual_revision_fn: &one,
                expected_lease_epoch: 1,
                actual_lease_epoch_fn: &one,
                previous: prev,
                max_attempts: max_a,
            },
            c,
            probe,
        )
    };
    let ConvergeOutcome::Converged { scan: inc, stats, .. } =
        run(&mut co, Some(&base.manifest), 3, &mut NoopBarrierProbe)?
    else {
        panic!("expected incremental convergence");
    };
    assert!(stats.duplicate_events_folded >= 1 && stats.out_of_order_batches == 1 && !stats.used_full_rescan);
    assert!(inc.metrics.reused_nodes > 0 && inc.metrics.hashed_bytes < base.metrics.hashed_bytes);

    let gh = b".github/workflows/check.yml";
    fs::create_dir_all(repo.join(".github/workflows"))?;
    fs::write(repo.join(".github/workflows/check.yml"), b"name: ci-v1\n")?;
    co.ingest(WatcherBatch { seq_start: 4, seq_end: 5, events: vec![WatcherEvent::Create(gh.to_vec())] });
    let ConvergeOutcome::Converged { scan: inc_gh, stats: gh_stats, .. } =
        run(&mut co, Some(&inc.manifest), 3, &mut NoopBarrierProbe)?
    else {
        panic!("expected .github subtree incremental convergence");
    };
    assert!(!gh_stats.used_full_rescan && inc_gh.metrics.reused_nodes > 0);
    assert!(inc_gh.manifest.merkle_root_digest != inc.manifest.merkle_root_digest);
    assert!(inc_gh.manifest.nodes.contains_key(&super::super::manifest::encode_rel_bytes(b".github/workflows")));
    fs::write(repo.join(".github/workflows/check.yml"), b"name: ci-v2\n")?;
    co.ingest(WatcherBatch { seq_start: 5, seq_end: 6, events: vec![WatcherEvent::Modify(gh.to_vec())] });
    let ConvergeOutcome::Converged { scan: inc_gh2, .. } =
        run(&mut co, Some(&inc_gh.manifest), 3, &mut NoopBarrierProbe)?
    else {
        panic!("expected .github modify convergence");
    };
    assert!(inc_gh2.manifest.merkle_root_digest != inc_gh.manifest.merkle_root_digest);

    fs::write(repo.join("sub_b/deep/b_0.txt"), b"changed-during-drop\n")?;
    co.ingest(WatcherBatch { seq_start: 10, seq_end: 11, events: vec![WatcherEvent::Overflow] });
    let mut run_p = |seq, keep, prev, max_a| {
        let mut p =
            MutatingBarrierProbe { repo: repo.clone(), seq: Arc::new(AtomicU64::new(seq)), keep_mutating: keep };
        run(&mut co, prev, max_a, &mut p)
    };
    assert!(matches!(run_p(11, false, Some(&inc_gh2.manifest), 3)?, ConvergeOutcome::Converged { attempts: 2, .. }));
    assert!(matches!(run_p(20, true, None, 2)?, ConvergeOutcome::NotQuiescent { attempts: 2, .. }));

    // An exhausted capture must not discard the only hint for an edit that
    // was never reflected in the last committed manifest.
    let edited = b"edited-before-capture\n";
    fs::write(repo.join("sub_b/deep/b_1.txt"), edited)?;
    let mut interrupted = WatcherCoalescer::new();
    interrupted.ingest(WatcherBatch {
        seq_start: 1,
        seq_end: 1,
        events: vec![WatcherEvent::Modify(b"sub_b/deep/b_1.txt".to_vec())],
    });
    let mut race = MutatingBarrierProbe { repo: repo.clone(), seq: Arc::new(AtomicU64::new(1)), keep_mutating: true };
    assert!(matches!(
        run(&mut interrupted, Some(&inc_gh2.manifest), 1, &mut race)?,
        ConvergeOutcome::NotQuiescent { attempts: 1, .. }
    ));
    let ConvergeOutcome::Converged { scan: recovered, stats, .. } =
        run(&mut interrupted, Some(&inc_gh2.manifest), 1, &mut NoopBarrierProbe)?
    else {
        panic!("expected convergence after the interrupted capture");
    };
    use super::super::manifest::encode_rel_bytes;
    let edited_leaf = recovered.manifest.nodes[&encode_rel_bytes(b"sub_b/deep")]
        .children
        .iter()
        .find(|child| child.name_base64 == encode_rel_bytes(b"b_1.txt"))
        .expect("edited leaf");
    assert_eq!(edited_leaf.content_sha256, Some(hex::encode(Sha256::digest(edited))));
    assert!(stats.used_full_rescan);
    Ok(())
}
