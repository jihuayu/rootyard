use super::*;
use std::path::PathBuf;
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, Ordering};

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

#[cfg(target_os = "linux")]
const PROC_FIELDS_THROUGH_STARTTIME: usize = 20;

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProcState {
    Gone,
    Exited,
    Live,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct ProcIdentity {
    pid: i32,
    starttime: u64,
}

#[cfg(target_os = "linux")]
impl ProcIdentity {
    fn state(self) -> ProcState {
        assert_procfs_live();
        match read_proc_stat(self.pid) {
            None => ProcState::Gone,
            Some(stat) if stat.starttime != self.starttime => ProcState::Gone,
            Some(stat) => stat.state,
        }
    }
}

#[cfg(target_os = "linux")]
struct ProcStat {
    state: ProcState,
    pgrp: i32,
    starttime: u64,
}

#[cfg(target_os = "linux")]
fn capture_original_pair(leader: i32, descendant: i32) -> (ProcIdentity, ProcIdentity) {
    assert_procfs_live();
    let leader_stat = read_proc_stat(leader)
        .unwrap_or_else(|| panic!("original direct child {leader} is not present in procfs before drop"));
    let descendant_stat = read_proc_stat(descendant)
        .unwrap_or_else(|| panic!("original TERM-resistant descendant {descendant} is not present in procfs before drop"));
    assert_eq!(leader_stat.state, ProcState::Live, "original direct child {leader} is {:?}, not live", leader_stat.state);
    assert_eq!(
        descendant_stat.state,
        ProcState::Live,
        "original TERM-resistant descendant {descendant} is {:?}, not live",
        descendant_stat.state
    );
    assert_eq!(
        leader_stat.pgrp, leader,
        "original direct child {leader} is in process group {}, not its own",
        leader_stat.pgrp
    );
    assert_eq!(
        descendant_stat.pgrp, leader,
        "original TERM-resistant descendant {descendant} is in process group {}, not leader {leader}",
        descendant_stat.pgrp
    );
    (
        ProcIdentity { pid: leader, starttime: leader_stat.starttime },
        ProcIdentity { pid: descendant, starttime: descendant_stat.starttime },
    )
}

#[cfg(target_os = "linux")]
fn assert_original_descendant_not_live(descendant: ProcIdentity) {
    let state = descendant.state();
    assert!(
        matches!(state, ProcState::Gone | ProcState::Exited),
        "original descendant {} (starttime {}) is still live after cancellation: {state:?}",
        descendant.pid,
        descendant.starttime
    );
}

#[cfg(target_os = "linux")]
fn assert_procfs_live() {
    let pid = i32::try_from(std::process::id()).expect("test pid fits i32");
    match read_proc_stat(pid) {
        Some(stat) if stat.state == ProcState::Live => {}
        Some(stat) => panic!("procfs is present but test process {pid} is {:?}", stat.state),
        None => panic!("procfs is not live: /proc/{pid}/stat is absent"),
    }
}

#[cfg(target_os = "linux")]
fn read_proc_stat(pid: i32) -> Option<ProcStat> {
    let path = format!("/proc/{pid}/stat");
    let stat = match std::fs::read_to_string(&path) {
        Ok(stat) => stat,
        Err(error) if error.kind() == io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH) => {
            return None;
        }
        Err(error) => panic!("cannot read {path}: {error}"),
    };
    let (prefix, rest) =
        stat.rsplit_once(") ").unwrap_or_else(|| panic!("truncated {path}: missing command terminator"));
    let (stat_pid, _) = prefix.split_once(" (").unwrap_or_else(|| panic!("malformed {path}: missing `pid (` prefix"));
    let stat_pid = stat_pid.parse::<i32>().unwrap_or_else(|_| panic!("malformed {path}: non-numeric pid"));
    assert_eq!(stat_pid, pid, "{path} describes pid {stat_pid}, not {pid}");
    let fields: Vec<_> = rest.split_whitespace().collect();
    if fields.len() < PROC_FIELDS_THROUGH_STARTTIME {
        panic!(
            "truncated {path}: {} fields after comm, need at least {PROC_FIELDS_THROUGH_STARTTIME}",
            fields.len()
        );
    }
    let state = match fields[0] {
        "R" | "S" | "D" | "T" | "t" | "W" | "P" | "I" | "K" => ProcState::Live,
        "Z" | "X" | "x" => ProcState::Exited,
        other => panic!("unsupported {path} state {other:?}"),
    };
    for (index, field) in fields.iter().enumerate().take(19).skip(1) {
        field.parse::<i64>().unwrap_or_else(|_| panic!("malformed {path}: field {index} {field:?} is not numeric"));
    }
    let pgrp = fields[2].parse::<i32>().unwrap_or_else(|_| panic!("malformed {path}: non-numeric process group"));
    let starttime =
        fields[19].parse::<u64>().unwrap_or_else(|_| panic!("malformed {path}: non-numeric starttime"));
    Some(ProcStat { state, pgrp, starttime })
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
        run_git_bounded(command(&pidfile), GitStdin::Null, 1024, deadline, Error::internal("failed")),
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
        run_git_bounded(command(&pidfile), GitStdin::Null, 1024, deadline, Error::internal("failed")),
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
    // Bind the pids to original (pid, starttime) identities while the fixture is
    // demonstrably live: the direct child is its own group leader and the
    // TERM-resistant background shell is still in that group.
    #[cfg(target_os = "linux")]
    let (_original_leader, original_descendant) = capture_original_pair(leader, grandchild);
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
    // A killed descendant can remain visible as Z/X until its new parent reaps
    // it. Quiescence, not disappearance, is the contract; the recorded starttime
    // keeps PID reuse from being mistaken for a live original.
    #[cfg(target_os = "linux")]
    assert_original_descendant_not_live(original_descendant);
    #[cfg(not(target_os = "linux"))]
    assert!(!PathBuf::from(format!("/proc/{grandchild}")).exists());
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
        run_git_bounded(final_command(&pidfile), GitStdin::Null, 1024, deadline, Error::internal("failed")),
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
