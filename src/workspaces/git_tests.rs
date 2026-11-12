use super::*;
use std::path::PathBuf;
use std::time::Instant;

fn shell(script: &str, pid_file: Option<&Path>) -> Command {
    let mut command = Command::new("/bin/sh");
    command.arg("-c").arg(script);
    if let Some(path) = pid_file {
        command.arg("leader").arg(path);
    }
    command
}

fn descendant_running(pid: u32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Err(_) => false,
        Ok(stat) => stat.rsplit_once(") ").is_some_and(|(_, tail)| !tail.starts_with('Z')),
    }
}

async fn wait_for_pid(path: &Path) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(raw) = std::fs::read_to_string(path)
            && let Ok(pid) = raw.trim().parse()
        {
            return pid;
        }
        assert!(Instant::now() < deadline, "test child did not start");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn git(repo: &Path, args: &[&str]) {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["-c", "user.name=Workspace", "-c", "user.email=workspace@example.invalid"])
        .args(["-c", "commit.gpgsign=false"])
        .args(args)
        .output()
        .expect("run fixture git");
    assert!(output.status.success(), "fixture git {args:?} failed: {}", String::from_utf8_lossy(&output.stderr));
}

fn committed_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-q"]);
    std::fs::write(dir.path().join("committed.txt"), b"committed").unwrap();
    git(dir.path(), &["add", "--", "committed.txt"]);
    git(dir.path(), &["commit", "-q", "-m", "base"]);
    dir
}

#[tokio::test]
async fn huge_stdout_is_rejected_without_waiting_for_eof() {
    let started = Instant::now();
    let error = collect(shell("head -c 200000 /dev/zero", None), 4096, Duration::from_secs(5)).await.unwrap_err();
    assert_eq!(error.0, StatusCode::CONFLICT);
    assert!(started.elapsed() < Duration::from_secs(4), "stdout cap was not enforced");
}

#[tokio::test]
async fn huge_stderr_is_drained_without_deadlock() {
    let output =
        collect(shell("head -c 400000 /dev/zero >&2; printf ok", None), 4096, Duration::from_secs(5)).await.unwrap();
    assert_eq!(output, b"ok");
}

#[tokio::test]
async fn deadline_cancels_the_whole_process_group() {
    let root = tempfile::tempdir().unwrap();
    let pid_file = root.path().join("child.pid");
    let script = "sh -c 'trap \"\" TERM; echo $$ > \"$1\"; while :; do sleep 1; done' child \"$1\" & sleep 100";
    let started = Instant::now();
    let error = collect(shell(script, Some(&pid_file)), 4096, Duration::from_millis(200)).await.unwrap_err();
    assert_eq!(error.0, StatusCode::GATEWAY_TIMEOUT);
    assert!(started.elapsed() < Duration::from_secs(6));
    let pid = wait_for_pid(&pid_file).await;
    assert!(!descendant_running(pid), "timed-out Git descendant survived group cleanup");
}

#[tokio::test]
async fn cancellation_drops_the_process_group() {
    let root = tempfile::tempdir().unwrap();
    let pid_file = root.path().join("child.pid");
    let script = "sh -c 'trap \"\" TERM; echo $$ > \"$1\"; while :; do sleep 1; done' child \"$1\" & sleep 100";
    let outcome = tokio::time::timeout(
        Duration::from_millis(500),
        collect(shell(script, Some(&pid_file)), 4096, Duration::from_secs(30)),
    )
    .await;
    assert!(outcome.is_err(), "cancelled collection unexpectedly completed");
    let pid = wait_for_pid(&pid_file).await;
    let deadline = Instant::now() + Duration::from_secs(5);
    while descendant_running(pid) {
        assert!(Instant::now() < deadline, "cancelled Git descendant survived");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn native_git_success_is_returned_with_bounded_output() {
    let mut command = Command::new("git");
    command.arg("--version");
    let output = collect(command, 4096, Duration::from_secs(10)).await.unwrap();
    assert!(output.starts_with(b"git version"));
}

#[tokio::test]
async fn child_environment_scrubs_secrets_and_honors_configured_git_binary() {
    let dir = committed_repo();
    std::fs::write(dir.path().join("clean.txt"), b"clean\n").unwrap();
    let wrapper_dir = tempfile::tempdir().unwrap();
    let wrapper = wrapper_dir.path().join("git-wrapper.sh");
    std::fs::write(
        &wrapper,
        b"#!/bin/sh\nif [ -n \"${DATABASE_URL:-}\" ] || [ -n \"${GIT_INDEX_FILE:-}\" ]; then exit 91; fi\nexec git \"$@\"\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();

    run_in_job_with_git(&wrapper, dir.path(), &["add", "--", "clean.txt"], 4096, Duration::from_secs(5)).await.unwrap();
    let staged =
        run_in_job_with_git(&wrapper, dir.path(), &["ls-files", "--", "clean.txt"], 4096, Duration::from_secs(5))
            .await
            .unwrap();
    assert_eq!(staged, b"clean.txt\n");
}

#[test]
fn capacity_exhaustion_is_a_retryable_503() {
    let slots = Arc::new(Semaphore::new(1));
    let permit = slot(&slots).unwrap();
    assert_eq!(slot(&slots).unwrap_err().0, StatusCode::SERVICE_UNAVAILABLE);
    drop(permit);
    assert!(slot(&slots).is_ok());
}

async fn job_test_lock() -> tokio::sync::MutexGuard<'static, ()> {
    static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    SERIAL.lock().await
}

fn gate() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("rename_gate.c");
    std::fs::write(&source, include_str!("../../tests/fixtures/rename_gate.c")).unwrap();
    let library = dir.path().join("librootyard_rename_gate.so");
    let compiled = std::process::Command::new("cc")
        .args(["-shared", "-fPIC", "-O1", "-o"])
        .arg(&library)
        .arg(&source)
        .output()
        .expect("run cc for the rename gate");
    assert!(compiled.status.success(), "cc failed: {}", String::from_utf8_lossy(&compiled.stderr));
    let flag = dir.path().join("gate.flag");
    (dir, library, flag)
}

fn gate_env(library: &Path, flag: &Path) -> Vec<(String, String)> {
    vec![
        ("LD_PRELOAD".to_owned(), library.to_str().unwrap().to_owned()),
        ("ROOTYARD_GATE_MARKER".to_owned(), "index.lock".to_owned()),
        ("ROOTYARD_GATE_FLAG".to_owned(), flag.to_str().unwrap().to_owned()),
    ]
}

async fn wait_for_gate(flag: &Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while !flag.exists() {
        assert!(Instant::now() < deadline, "Git never reached the index.lock commit");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn disconnect_with_a_live_real_index_lock_keeps_the_owned_add() {
    let _serial = job_test_lock().await;
    let (gate_dir, library, flag) = gate();
    let dir = committed_repo();
    let repo = dir.path().to_path_buf();
    std::fs::write(repo.join("staged.txt"), b"staged").unwrap();
    let slots = Arc::new(Semaphore::new(1));
    let permit = slot(&slots).unwrap();
    let (finished_tx, finished_rx) = oneshot::channel();
    let env = gate_env(&library, &flag);
    let path = repo.clone();
    let args = ["add", "--", "staged.txt"];
    let response = spawn_job(async move {
        let _permit = permit;
        let result = run_in_job_env(&path, &args, 64 * 1024, Duration::from_secs(60), &env).await;
        let _ = finished_tx.send(());
        result
    });
    wait_for_gate(&flag, Duration::from_secs(30)).await;
    let lock = repo.join(".git/index.lock");
    assert!(lock.exists(), "the gate fired without a live index.lock");
    drop(response);
    assert_eq!(
        slot(&slots).unwrap_err().0,
        StatusCode::SERVICE_UNAVAILABLE,
        "a dropped response released the job's Git capacity"
    );
    std::fs::remove_file(&flag).unwrap();
    tokio::time::timeout(Duration::from_secs(30), finished_rx)
        .await
        .expect("owned job did not finish after the caller disconnected")
        .expect("owned job dropped its completion signal");
    assert!(!lock.exists(), "Git left an index lock");
    let staged = std::process::Command::new("git")
        .arg("-C")
        .arg(&repo)
        .args(["ls-files", "--stage", "--", "staged.txt"])
        .output()
        .unwrap();
    assert!(staged.status.success());
    assert!(String::from_utf8_lossy(&staged.stdout).contains("staged.txt"), "the owned add did not reach the index");
    assert!(slot(&slots).is_ok(), "capacity was not released after the child settled");
    run_in_job(&repo, &["reset", "HEAD", "--", "staged.txt"], 64 * 1024, Duration::from_secs(30)).await.unwrap();
    assert!(!lock.exists());
    drop(gate_dir);
}

#[tokio::test]
async fn drain_warns_past_grace_but_joins_the_owned_job() {
    let _serial = job_test_lock().await;
    let (gate_dir, library, flag) = gate();
    let dir = committed_repo();
    let repo = dir.path().to_path_buf();
    std::fs::write(repo.join("staged.txt"), b"staged").unwrap();
    let slots = Arc::new(Semaphore::new(1));
    let permit = slot(&slots).unwrap();
    let (finished_tx, finished_rx) = oneshot::channel();
    let env = gate_env(&library, &flag);
    let path = repo.clone();
    let args = ["add", "--", "staged.txt"];
    let response = spawn_job(async move {
        let _permit = permit;
        let result = run_in_job_env(&path, &args, 64 * 1024, Duration::from_secs(60), &env).await;
        let _ = finished_tx.send(());
        result
    });
    wait_for_gate(&flag, Duration::from_secs(30)).await;
    let lock = repo.join(".git/index.lock");
    assert!(lock.exists(), "the gate fired without a live index.lock");
    drop(response);
    let shutdown = tokio::spawn(drain(Duration::from_millis(50)));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!shutdown.is_finished(), "drain aborted or detached an owned job after the grace warning threshold");
    assert!(lock.exists(), "the owned child was torn down while the index lock was live");
    std::fs::remove_file(&flag).unwrap();
    tokio::time::timeout(Duration::from_secs(30), shutdown)
        .await
        .expect("drain did not return after the owned job finished")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(30), finished_rx)
        .await
        .expect("owned job did not finish during drain")
        .expect("owned job dropped its completion signal");
    assert!(!lock.exists(), "Git left an index lock");
    assert!(slot(&slots).is_ok(), "capacity was not released after drain");
    drop(gate_dir);
}

#[tokio::test]
async fn foreign_index_lock_is_preserved_and_the_mutation_fails_cleanly() {
    let dir = committed_repo();
    let repo = dir.path().to_path_buf();
    std::fs::write(repo.join("staged.txt"), b"staged").unwrap();
    let foreign = repo.join(".git/index.lock");
    std::fs::write(&foreign, b"another writer\n").unwrap();
    let error = run_in_job(&repo, &["add", "--", "staged.txt"], 64 * 1024, Duration::from_secs(30)).await.unwrap_err();
    assert_eq!(error.0, StatusCode::CONFLICT);
    assert_eq!(std::fs::read(&foreign).unwrap(), b"another writer\n");
}

#[tokio::test]
async fn timed_out_owned_job_releases_capacity_after_clean_cleanup() {
    let _serial = job_test_lock().await;
    let slots = Arc::new(Semaphore::new(1));
    let permit = slot(&slots).unwrap();
    let (finished_tx, finished_rx) = oneshot::channel();
    let response = spawn_job(async move {
        let _permit = permit;
        let result = collect(shell("sleep 100", None), 4096, Duration::from_millis(200)).await;
        let _ = finished_tx.send(result.as_ref().map(|_| ()).map_err(|error| error.0));
        result
    });
    drop(response);
    let result = tokio::time::timeout(Duration::from_secs(15), finished_rx)
        .await
        .expect("timed-out owned job did not finish")
        .unwrap();
    assert_eq!(result.unwrap_err(), StatusCode::GATEWAY_TIMEOUT);
    assert!(slot(&slots).is_ok(), "a timed-out job retained Git capacity");
}
