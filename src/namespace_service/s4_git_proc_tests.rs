use super::*;
use std::path::PathBuf;
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, Ordering};

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

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProcStat {
    state: u8,
    group: i32,
    start_time: u64,
}

#[cfg(unix)]
#[derive(Clone, Copy)]
enum Probe {
    Present(ProcStat),
    Missing,
    Invalid,
}

#[cfg(unix)]
fn recognized_state(state: u8) -> bool {
    matches!(state, b'R' | b'S' | b'D' | b'T' | b't' | b'Z' | b'X' | b'I' | b'P' | b'W' | b'K')
}

#[cfg(unix)]
fn live_state(state: u8) -> bool {
    recognized_state(state) && !matches!(state, b'Z' | b'X')
}

#[cfg(unix)]
fn parse_stat(raw: &str, pid: i32) -> Option<ProcStat> {
    // The command name is parenthesized and may itself contain ") ". Split at
    // the final delimiter, then validate the exact PID prefix before fields.
    let (prefix, tail) = raw.rsplit_once(") ")?;
    let expected_pid = pid.to_string();
    if prefix.split_once(" (")?.0 != expected_pid {
        return None;
    }
    let fields: Vec<_> = tail.split_whitespace().collect();
    let state = fields.first()?.as_bytes();
    if fields.len() < 20
        || state.len() != 1
        || !recognized_state(state[0])
        || fields[1..20].iter().any(|field| field.parse::<i128>().is_err())
    {
        return None;
    }
    Some(ProcStat { state: state[0], group: fields[2].parse().ok()?, start_time: fields[19].parse().ok()? })
}

#[cfg(unix)]
fn probe(pid: i32) -> Probe {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(raw) => parse_stat(&raw, pid).map_or(Probe::Invalid, Probe::Present),
        Err(error)
            if error.kind() == io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH) =>
        {
            Probe::Missing
        }
        Err(_) => Probe::Invalid,
    }
}

#[cfg(unix)]
fn live_procfs() -> bool {
    let Some(pid) = i32::try_from(std::process::id()).ok() else {
        return false;
    };
    std::fs::read_to_string("/proc/self/stat")
        .ok()
        .and_then(|raw| parse_stat(&raw, pid))
        .is_some_and(|stat| live_state(stat.state))
}

#[cfg(unix)]
fn classify_grandchild(expected: ProcStat, observed: Probe, procfs_live: bool) -> Result<&'static str, &'static str> {
    match observed {
        Probe::Present(stat) if !recognized_state(stat.state) => Err("inconclusive"),
        Probe::Present(stat) if stat.start_time != expected.start_time => Ok("pid-reused"),
        Probe::Present(stat) if matches!(stat.state, b'Z' | b'X') => Ok("quiescent"),
        Probe::Present(_) => Err("live-same-identity"),
        Probe::Missing if procfs_live => Ok("exited"),
        Probe::Missing | Probe::Invalid => Err("inconclusive"),
    }
}

#[cfg(unix)]
fn fixture_identity(leader: i32, grandchild: i32) -> ProcStat {
    match probe(grandchild) {
        Probe::Present(stat) if stat.group == leader && live_state(stat.state) => stat,
        Probe::Present(_) => panic!("fixture grandchild stat: not-live-or-wrong-group"),
        Probe::Missing => panic!("fixture grandchild stat: missing"),
        Probe::Invalid => panic!("fixture grandchild stat: invalid"),
    }
}

#[cfg(unix)]
#[test]
fn cancelled_descendant_stat_is_strict_and_closed() {
    let raw = format!("4242 (git ) child) S 77 77 {}9000", "0 ".repeat(16));
    let expected = ProcStat { state: b'S', group: 77, start_time: 9_000 };
    assert_eq!(parse_stat(&raw, 4242), Some(expected));
    assert_eq!(parse_stat(&format!("{raw} 0 0 0"), 4242), Some(expected));
    assert!(parse_stat(&raw, 4243).is_none());
    assert!(parse_stat("4242 sh) S 0 1 1", 4242).is_none());
    assert!(parse_stat(&raw.replace("S 77 77", "? 77 77").replace(" 9000", " 9001"), 4242).is_none());
    assert!(parse_stat(&raw.replace(" 9000", " nope"), 4242).is_none());
    assert!(parse_stat(&raw.replace("S 77 77", "S 77 nope"), 4242).is_none());
    assert!(parse_stat("4242 (sh) S 0 77", 4242).is_none());

    let present = |state: u8, group: i32, start_time: u64| {
        Probe::Present(ProcStat { state, group, start_time })
    };
    assert_eq!(classify_grandchild(expected, present(b'R', 77, 9_001), false), Ok("pid-reused"));
    assert_eq!(classify_grandchild(expected, present(b'Z', 456, 9_000), false), Ok("quiescent"));
    assert_eq!(classify_grandchild(expected, present(b'X', 77, 9_000), false), Ok("quiescent"));
    assert_eq!(classify_grandchild(expected, present(b'S', 456, 9_000), false), Err("live-same-identity"));
    assert_eq!(classify_grandchild(expected, present(b'?', 77, 9_001), false), Err("inconclusive"));
    assert_eq!(classify_grandchild(expected, Probe::Missing, true), Ok("exited"));
    assert_eq!(classify_grandchild(expected, Probe::Missing, false), Err("inconclusive"));
    assert_eq!(classify_grandchild(expected, Probe::Invalid, true), Err("inconclusive"));
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
        if let Some(pids) = try_pids(&pidfile) {
            break pids;
        }
        tokio::select! {
            _ = &mut future => panic!("cancelled process unexpectedly finished"),
            _ = tokio::time::sleep(Duration::from_millis(5)) => {}
        }
    };
    // Pin the fixture as a live recognized descendant in the published process
    // group and its start time before cancellation invalidates the PID.
    let identity = fixture_identity(leader, grandchild);
    drop(future);
    drop(scratch);
    for _ in 0..100 {
        if !root.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(!root.exists(), "the scratch directory outlived the cancelled Git command");
    assert!(!PathBuf::from(format!("/proc/{leader}")).exists());
    // The reaped leader cannot reap the orphaned grandchild: namespace init may
    // do so asynchronously. A missing PID is exit proof only when live procfs is
    // independently validated; a same-identity live entry fails even if it
    // moved process groups.
    let observed = probe(grandchild);
    let procfs_live = matches!(observed, Probe::Missing) && live_procfs();
    if let Err(class) = classify_grandchild(identity, observed, procfs_live) {
        panic!("cancelled Git descendant cleanup class: {class} (expected exited, pid-reused or quiescent)");
    }
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
