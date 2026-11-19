use super::*;
use std::path::PathBuf;

const SCRIPT: &str = r#"sh -c 'trap "" TERM; while :; do sleep 1; done' & echo $$ $! > "$1"; trap "" TERM; while :; do sleep 1; done"#;
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
#[tokio::test]
async fn spawn_reaper_failure_with_unknown_group_preserves_scratch_and_reaps_child() {
    fn unknown_group(_pid: i32) -> io::Result<bool> {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "simulated procfs error"))
    }
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
    assert!(started.elapsed() < Duration::from_millis(200), "spawn failure blocked caller");
    for _ in 0..300 {
        if !PathBuf::from(format!("/proc/{leader}")).exists()
            && !PathBuf::from(format!("/proc/{grandchild}")).exists()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(!PathBuf::from(format!("/proc/{leader}")).exists(), "leader was left as a zombie");
    assert!(!PathBuf::from(format!("/proc/{grandchild}")).exists(), "grandchild survived cleanup");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(root.exists(), "uncertain scratch was deleted despite unknown group outcome");
    std::fs::remove_dir_all(&root).unwrap();
}
