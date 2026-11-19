use super::*;
use std::path::PathBuf;
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(unix)]
#[path = "s4_git_proc_identity_tests.rs"]
mod identity;

const REVERSE_STAGES: [(ReverseGitStage, &str); 10] = [
    (ReverseGitStage::SourceProjection, "source_projection"),
    (ReverseGitStage::ProposalVerifyFetch, "proposal_verify_fetch"),
    (ReverseGitStage::AncestryIntegrity, "ancestry_integrity"),
    (ReverseGitStage::SubtreeExportRefUpdate, "subtree_export_ref_update"),
    (ReverseGitStage::SubtreeSourceFetch, "subtree_source_fetch"),
    (ReverseGitStage::SubtreeSourceTreeResolve, "subtree_source_tree_resolve"),
    (ReverseGitStage::SubtreeRootListing, "subtree_root_listing"),
    (ReverseGitStage::SubtreeRootRebuild, "subtree_root_rebuild"),
    (ReverseGitStage::CommitSynthesize, "commit_synthesize"),
    (ReverseGitStage::PackWriteIndex, "pack_write_index"),
];

const SCRIPT: &str = concat!(
    r#"sh -c 'trap "" TERM; while :; do sleep 1; done' & echo $$ $! > "$1"; "#,
    r#"trap "" TERM; while :; do sleep 1; done"#,
);
#[cfg(unix)]
const FINAL_SCRIPT: &str = r#"exec >/dev/null
sh -c 'trap "" TERM; while :; do sleep 1; done' &
echo $$ $! > "$1"
trap "" TERM
while :; do sleep 1; done"#;

fn try_pids(path: &FsPath) -> Option<(i32, i32)> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut values = text.split_whitespace().filter_map(|value| value.parse::<i32>().ok());
    Some((values.next()?, values.next()?))
}

async fn wait_pids(path: &FsPath) -> (i32, i32) {
    for _ in 0..200 {
        if let Some(pids) = try_pids(path) {
            return pids;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("test Git wrapper did not publish its process group");
}

fn command(pidfile: &FsPath) -> Command {
    let mut cmd = base_command(FsPath::new("/bin/sh"));
    cmd.args(["-c", SCRIPT, "sh", pidfile.to_str().unwrap()]);
    cmd
}

#[cfg(unix)]
fn final_command(pidfile: &FsPath) -> Command {
    let mut cmd = base_command(FsPath::new("/bin/sh"));
    cmd.args(["-c", FINAL_SCRIPT, "sh", pidfile.to_str().unwrap()]);
    cmd
}

#[cfg(unix)]
#[tokio::test]
async fn timeout_kills_process_group_and_reaps_leader() {
    let scratch = ScratchDir::create("rootyard-s4-proc-order").unwrap();
    let root = scratch.root().to_path_buf();
    let pidfile = root.join("timeout.pid");
    let deadline = Instant::now() + Duration::from_millis(700);
    let error = with_scratch(
        vec![scratch.hold()],
        run_git_bounded(command(&pidfile), GitStdin::Null, 1024, deadline, Error::internal("failed"), None),
    )
    .await
    .unwrap_err();
    assert_eq!(error.0, StatusCode::GATEWAY_TIMEOUT);
    let (leader, grandchild) = wait_pids(&pidfile).await;
    assert!(root.exists(), "the scratch directory vanished before the reaped check");
    assert!(!PathBuf::from(format!("/proc/{leader}")).exists());
    assert!(!PathBuf::from(format!("/proc/{grandchild}")).exists());
    drop(scratch);
    assert!(!root.exists());
}

#[cfg(unix)]
#[tokio::test]
async fn cancelled_future_drop_kills_process_group_and_reaps_leader() {
    let scratch = ScratchDir::create("rootyard-s4-proc-order").unwrap();
    let root = scratch.root().to_path_buf();
    let pidfile = root.join("cancel.pid");
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut future = Box::pin(with_scratch(
        vec![scratch.hold()],
        run_git_bounded(command(&pidfile), GitStdin::Null, 1024, deadline, Error::internal("failed"), None),
    ));
    let (leader, grandchild) = loop {
        if let Some((leader_pid, descendant_pid)) = try_pids(&pidfile) {
            break identity::capture_pair(leader_pid, descendant_pid);
        }
        tokio::select! {
            _ = &mut future => panic!("cancelled process unexpectedly finished"),
            _ = tokio::time::sleep(Duration::from_millis(5)) => {}
        }
    };
    drop(future);
    drop(scratch);
    for _ in 0..100 {
        if !root.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(!root.exists(), "the scratch directory outlived the cancelled Git command");
    assert_eq!(leader.state(), identity::ProcState::Gone, "the original direct leader was not reaped");
    let descendant_state = grandchild.state();
    assert!(
        matches!(descendant_state, identity::ProcState::Gone | identity::ProcState::Exited),
        "the original descendant is still live after cancellation: {descendant_state:?}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn closed_stdout_hang_times_out_at_final_wait_and_reaps_before_scratch_drop() {
    let scratch = ScratchDir::create("rootyard-s4-proc-final").unwrap();
    let root = scratch.root().to_path_buf();
    let pidfile = root.join("final.pid");
    let deadline = Instant::now() + Duration::from_millis(250);
    let error = with_scratch(
        vec![scratch.hold()],
        run_git_bounded(final_command(&pidfile), GitStdin::Null, 1024, deadline, Error::internal("failed"), None),
    )
    .await
    .unwrap_err();
    assert_eq!(error.0, StatusCode::GATEWAY_TIMEOUT);
    let (leader, grandchild) = wait_pids(&pidfile).await;
    assert!(root.exists(), "the scratch directory vanished before the final wait was confirmed");
    assert!(!PathBuf::from(format!("/proc/{leader}")).exists());
    for _ in 0..100 {
        if !PathBuf::from(format!("/proc/{grandchild}")).exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(!PathBuf::from(format!("/proc/{grandchild}")).exists());
    drop(scratch);
    assert!(!root.exists());
}

#[cfg(unix)]
#[tokio::test]
async fn expired_timeout_cleanup_hands_scratch_to_reaper_until_group_exits() {
    let scratch = ScratchDir::create("rootyard-s4-proc-handoff").unwrap();
    let root = scratch.root().to_path_buf();
    let pidfile = root.join("handoff.pid");
    let mut guard = with_scratch(vec![scratch.hold()], async {
        let mut cmd = command(&pidfile);
        cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
        ReapOnDropGuard::spawn(cmd).unwrap()
    })
    .await;
    let (leader, grandchild) = wait_pids(&pidfile).await;
    drop(scratch);
    guard.kill_and_reap_bounded(Duration::ZERO).await;
    drop(guard);
    for _ in 0..200 {
        if !root.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(!root.exists(), "the scratch directory outlived the timed-out reaper handoff");
    assert!(!PathBuf::from(format!("/proc/{leader}")).exists());
    assert!(!PathBuf::from(format!("/proc/{grandchild}")).exists());
}

#[cfg(unix)]
#[tokio::test]
async fn spawn_reaper_failure_bounds_caller_and_reaps_without_zombies() {
    let scratch = ScratchDir::create("rootyard-s4-proc-spawn-ok").unwrap();
    let root = scratch.root().to_path_buf();
    let pidfile = root.join("spawn-ok.pid");
    let mut cmd = command(&pidfile);
    cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true).process_group(0);
    let child = cmd.spawn().unwrap();
    let pid = i32::try_from(child.id().unwrap()).unwrap();
    let (leader, grandchild) = wait_pids(&pidfile).await;
    let holds = vec![scratch.hold()];
    drop(scratch);
    let started = std::time::Instant::now();
    spawn_reaper_with(child, pid, holds, |_| Err(io::Error::other("simulated thread limit")));
    assert!(started.elapsed() < Duration::from_millis(200), "spawn failure blocked caller");
    for _ in 0..300 {
        if !root.exists()
            && !PathBuf::from(format!("/proc/{leader}")).exists()
            && !PathBuf::from(format!("/proc/{grandchild}")).exists()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(!PathBuf::from(format!("/proc/{leader}")).exists(), "leader was left as a zombie");
    assert!(!PathBuf::from(format!("/proc/{grandchild}")).exists(), "grandchild survived cleanup");
    assert!(!root.exists(), "confirmed-quiescent scratch was not removed");
}

#[cfg(unix)]
static ALLOW_PROC_PROBE: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
fn proc_is_zombie(pid: i32) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    stat.rsplit_once(") ")
        .and_then(|(_, rest)| rest.split_whitespace().next())
        .is_some_and(|state| state == "Z" || state == "X")
}

#[cfg(unix)]
fn unknown_group(pid: i32) -> io::Result<bool> {
    if ALLOW_PROC_PROBE.load(Ordering::Acquire) {
        crate::git_http::group_quiescent(pid)
    } else {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "simulated procfs error"))
    }
}

#[cfg(unix)]
#[tokio::test]
async fn spawn_reaper_failure_with_unknown_group_preserves_scratch_and_reaps_child() {
    ALLOW_PROC_PROBE.store(false, Ordering::Release);
    let scratch = ScratchDir::create("rootyard-s4-proc-spawn-unk").unwrap();
    let root = scratch.root().to_path_buf();
    let pidfile = root.join("spawn-unk.pid");
    let mut cmd = command(&pidfile);
    cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true).process_group(0);
    let child = cmd.spawn().unwrap();
    let pid = i32::try_from(child.id().unwrap()).unwrap();
    let (leader, grandchild) = wait_pids(&pidfile).await;
    let holds = vec![scratch.hold()];
    drop(scratch);
    let started = std::time::Instant::now();
    crate::ci_pins::s4_git_runner::spawn_reaper_with_probe(
        child,
        pid,
        holds,
        |_| Err(io::Error::other("simulated thread limit")),
        unknown_group,
    );
    for _ in 0..300 {
        if !PathBuf::from(format!("/proc/{grandchild}")).exists() && proc_is_zombie(leader) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let post_budget = Duration::from_millis(400);
    if let Some(remaining) = post_budget.checked_sub(started.elapsed()) {
        tokio::time::sleep(remaining).await;
    }
    assert!(proc_is_zombie(leader), "leader was reaped prematurely on probe error, releasing PGID");
    assert!(!PathBuf::from(format!("/proc/{grandchild}")).exists(), "grandchild survived SIGKILL");
    assert!(root.exists(), "uncertain scratch vanished while group probe errored");
    ALLOW_PROC_PROBE.store(true, Ordering::Release);
    for _ in 0..300 {
        if !PathBuf::from(format!("/proc/{leader}")).exists() && !root.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(!PathBuf::from(format!("/proc/{leader}")).exists(), "leader survived after probe recovery");
    assert!(!root.exists(), "confirmed scratch was not released after probe recovery");
}

#[cfg(unix)]
#[tokio::test]
async fn git_proc_spawn_refuses_to_start_child_when_standby_sweeper_fails() {
    let scratch = ScratchDir::create("rootyard-s4-proc-nostandby").unwrap();
    let marker = scratch.root().join("ran");
    let mut cmd = base_command(FsPath::new("/bin/sh"));
    cmd.args(["-c", "echo spawned > \"$1\"", "sh", marker.to_str().unwrap()]);
    let err = ReapOnDropGuard::spawn_with_warm(cmd, || Err(io::Error::other("simulated standby failure")))
        .err()
        .expect("standby failure must refuse spawn");
    assert_eq!(err.0, StatusCode::SERVICE_UNAVAILABLE);
    assert!(!marker.exists(), "GitView child ran despite standby failure");
}

#[test]
fn reverse_git_diagnostic_labels_are_closed_and_bounded() {
    for (stage, label) in REVERSE_STAGES {
        assert_eq!(stage.as_str(), label);
    }
    let outcomes = [
        (reverse_diag::ReverseGitChildOutcome::NonzeroExit, "nonzero_exit"),
        (reverse_diag::ReverseGitChildOutcome::Signaled, "signaled"),
        (reverse_diag::ReverseGitChildOutcome::Unknown, "unknown"),
    ];
    for (outcome, label) in outcomes {
        assert_eq!(outcome.as_str(), label);
    }
    let mut line = Vec::new();
    reverse_diag::write_failure_line(
        &mut line,
        ReverseGitStage::CommitSynthesize,
        reverse_diag::ReverseGitChildOutcome::Signaled,
    )
    .unwrap();
    assert_eq!(line, b"rootyard: S4 reverse Git child failed stage=commit_synthesize outcome=signaled\n");
}

#[test]
fn reverse_git_diagnostic_write_failure_is_best_effort() {
    struct Failing;
    impl std::io::Write for Failing {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let result = reverse_diag::write_failure_line(
        &mut Failing,
        ReverseGitStage::CommitSynthesize,
        reverse_diag::ReverseGitChildOutcome::NonzeroExit,
    );
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::BrokenPipe);
}

#[cfg(unix)]
#[test]
fn reverse_git_child_outcome_distinguishes_nonzero_signal_and_unknown() {
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(
        reverse_diag::classify(ExitStatus::from_raw(7 << 8)),
        reverse_diag::ReverseGitChildOutcome::NonzeroExit
    );
    assert_eq!(reverse_diag::classify(ExitStatus::from_raw(9)), reverse_diag::ReverseGitChildOutcome::Signaled);
    assert_eq!(reverse_diag::classify(ExitStatus::from_raw(0x7f)), reverse_diag::ReverseGitChildOutcome::Unknown);
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn every_reverse_stage_reaches_closed_runner_diagnostic_and_keeps_public_conflict() {
    for (stage, _) in REVERSE_STAGES {
        let _ = reverse_diag::take_for_test();
        let mut cmd = base_command(FsPath::new("/bin/sh"));
        cmd.args(["-c", "exit 7"]);
        let error = run_git_bounded(
            cmd,
            GitStdin::Null,
            1024,
            Instant::now() + Duration::from_secs(10),
            Error(StatusCode::CONFLICT, "Git View reverse mapping conflict"),
            Some(stage),
        )
        .await
        .unwrap_err();
        assert_eq!(error.0, StatusCode::CONFLICT);
        assert_eq!(error.1, "Git View reverse mapping conflict");
        assert_eq!(
            reverse_diag::take_for_test(),
            vec![(stage, reverse_diag::ReverseGitChildOutcome::NonzeroExit)]
        );
    }
}

#[test]
fn reverse_root_probe_selects_one_retained_sibling_without_guessing_type() {
    use std::collections::BTreeMap;
    let subtree = "1".repeat(40);
    let sibling = "2".repeat(40);
    let mut entries = BTreeMap::new();
    entries.insert(b"dir".to_vec(), format!("040000 tree {subtree}\tdir").into_bytes());
    entries.insert(b"vendor".to_vec(), format!("160000 commit {sibling}\tvendor").into_bytes());
    assert_eq!(
        retained_root_sibling(&entries, b"dir"),
        Ok(Some((sibling.as_str(), ReverseGitObjectType::Commit)))
    );
    entries.insert(b"other".to_vec(), format!("100644 blob {sibling}\tother").into_bytes());
    assert_eq!(retained_root_sibling(&entries, b"dir"), Ok(None));
    let mut malformed = BTreeMap::new();
    malformed.insert(b"dir".to_vec(), format!("040000 tree {subtree}\tdir").into_bytes());
    malformed.insert(b"root.txt".to_vec(), b"100644 blob nope\troot.txt".to_vec());
    assert_eq!(retained_root_sibling(&malformed, b"dir"), Err(()));
}

#[test]
fn reverse_root_probe_output_is_closed_and_separate() {
    let oid = "1".repeat(40);
    let mut line = Vec::new();
    reverse_diag::write_failure_line(
        &mut line,
        ReverseGitStage::SubtreeRootRebuild,
        reverse_diag::ReverseGitChildOutcome::NonzeroExit,
    )
    .unwrap();
    reverse_diag::write_probe_line(
        &mut line,
        reverse_diag::ReverseGitProbeObject::ReplacementSubtree,
        reverse_diag::ReverseGitProbeResult::PresentAndTyped,
        Some(reverse_diag::ReverseGitObjectType::Tree),
    )
    .unwrap();
    assert_eq!(
        line,
        b"rootyard: S4 reverse Git child failed stage=subtree_root_rebuild outcome=nonzero_exit\n\
rootyard: S4 reverse Git child probe object=replacement_subtree result=present_and_typed type=tree\n"
            .to_vec()
    );
    for (result, label) in [
        (ReverseGitProbeResult::PresentAndTyped, "present_and_typed"),
        (ReverseGitProbeResult::Missing, "missing"),
        (ReverseGitProbeResult::ProbeError, "probe_error"),
        (ReverseGitProbeResult::Unavailable, "unavailable"),
    ] {
        assert_eq!(result.as_str(), label);
    }
    for (kind, label) in [
        (ReverseGitObjectType::Blob, "blob"),
        (ReverseGitObjectType::Tree, "tree"),
        (ReverseGitObjectType::Commit, "commit"),
        (ReverseGitObjectType::Tag, "tag"),
    ] {
        assert_eq!(kind.as_str(), label);
    }
    for (object, label) in [
        (ReverseGitProbeObject::ReplacementSubtree, "replacement_subtree"),
        (ReverseGitProbeObject::RetainedRootSibling, "retained_root_sibling"),
    ] {
        assert_eq!(object.as_str(), label);
    }
    assert_eq!(
        classify_batch_check_line(&format!("{oid} tree 12"), &oid, ReverseGitObjectType::Tree),
        (ReverseGitProbeResult::PresentAndTyped, Some(ReverseGitObjectType::Tree))
    );
    assert_eq!(
        classify_batch_check_line(&format!("{oid} missing"), &oid, ReverseGitObjectType::Tree),
        (ReverseGitProbeResult::Missing, None)
    );
    assert_eq!(
        classify_batch_check_line(&format!("{oid} blob 12"), &oid, ReverseGitObjectType::Tree),
        (ReverseGitProbeResult::ProbeError, None)
    );
    assert_eq!(
        classify_batch_check_line(&format!("{oid} tree nope"), &oid, ReverseGitObjectType::Tree),
        (ReverseGitProbeResult::ProbeError, None)
    );
}
