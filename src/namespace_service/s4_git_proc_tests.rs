use super::*;
use std::path::PathBuf;

const SCRIPT: &str = r#"sh -c 'trap "" TERM; while :; do sleep 1; done' & echo $$ $! > "$1"; trap "" TERM; while :; do sleep 1; done"#;

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("rootyard-s4-proc-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

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

async fn wait_absent(pid: i32) {
    let path = std::path::PathBuf::from(format!("/proc/{pid}"));
    for _ in 0..50 {
        if !path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("process {pid} survived bounded process-group cleanup");
}

fn command(pidfile: &FsPath) -> Command {
    let mut cmd = base_command(FsPath::new("/bin/sh"));
    cmd.args(["-c", SCRIPT, "sh", pidfile.to_str().unwrap()]);
    cmd
}

#[cfg(unix)]
#[tokio::test]
async fn timeout_kills_process_group_and_reaps_leader() {
    let dir = TestDir::new();
    let pidfile = dir.0.join("timeout.pid");
    let deadline = Instant::now() + Duration::from_millis(700);
    let error = run_git_bounded(command(&pidfile), GitStdin::Null, 1024, deadline, Error::internal("failed"))
        .await
        .unwrap_err();
    assert_eq!(error.0, StatusCode::GATEWAY_TIMEOUT);
    let (leader, grandchild) = wait_pids(&pidfile).await;
    wait_absent(leader).await;
    wait_absent(grandchild).await;
}

#[cfg(unix)]
#[tokio::test]
async fn cancelled_future_drop_kills_process_group_and_reaps_leader() {
    let dir = TestDir::new();
    let pidfile = dir.0.join("cancel.pid");
    let deadline = Instant::now() + Duration::from_secs(30);
    let future = run_git_bounded(command(&pidfile), GitStdin::Null, 1024, deadline, Error::internal("failed"));
    tokio::pin!(future);
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
    wait_absent(leader).await;
    wait_absent(grandchild).await;
}
