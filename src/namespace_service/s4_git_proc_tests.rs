use super::*;
use std::path::PathBuf;

const SCRIPT: &str = r#"sh -c 'trap "" TERM; while :; do sleep 1; done' & echo $$ $! > "$1"; trap "" TERM; while :; do sleep 1; done"#;

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
