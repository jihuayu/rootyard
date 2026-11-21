//! Linux final-wait witness for the `UploadPackGroup::finish` deadline phase.

use super::proc_identity::{ProcState, wait_for_original_pair};
use super::super::s4_authority::{DisposableCiView, UploadPackGroup};
use axum::http::StatusCode;
use std::os::unix::fs::PermissionsExt;
use tokio::io::AsyncReadExt;

// The descendant publishes its own readiness only after installing its TERM
// disposition. The leader ignores TERM, waits for that marker, publishes both
// original PIDs, and only then closes the inherited stdout pipe, so EOF is the
// explicit ready handshake rather than a race with process identity capture.
#[cfg(target_os = "linux")]
const FINAL_WAIT_SCRIPT: &str = r#"#!/bin/sh
trap '' TERM
sh -c 'trap "" TERM; printf "ready\n" > "$1"; while :; do sleep 1; done' sh "$0.desc.ready" >/dev/null 2>&1 &
descendant=$!
while [ ! -s "$0.desc.ready" ]; do sleep 0.05; done
sh -c 'printf "%s %s\n" "$1" "$2" > "$3"' sh "$$" "$descendant" "$0.pids"
exec >/dev/null
while :; do sleep 1; done
"#;

/// Exercise the real `UploadPackGroup::finish` final-wait phase that
/// `run_git_dir_bounded` calls after its stdout pipe reaches EOF. Fixture
/// readiness gets its own scheduling budget so it cannot race the 250 ms
/// final-wait deadline; this witness deliberately does not re-cover the
/// caller's integrated pipe phase.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn upload_pack_finish_enforces_deadline_on_final_wait_after_stdout_closes() {
    const READINESS_BUDGET: std::time::Duration = std::time::Duration::from_secs(10);
    const FINAL_WAIT_BUDGET: std::time::Duration = std::time::Duration::from_millis(250);
    let view = DisposableCiView::create().expect("disposable view");
    let root = view.path().to_path_buf();
    let wrapper = root.join("git");
    std::fs::write(&wrapper, FINAL_WAIT_SCRIPT).expect("write wrapper");
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).expect("chmod wrapper");
    // The descendant publishes its own post-trap readiness; the leader then
    // publishes both PIDs and closes the inherited stdout pipe. So EOF is the
    // explicit live-pair handshake. This scheduling budget only bounds fixture
    // startup, including spawn; it is not the product final-wait deadline.
    let readiness_deadline = tokio::time::Instant::now() + READINESS_BUDGET;
    let mut group = UploadPackGroup::spawn(&wrapper, &root, Some(view.hold())).expect("spawn");
    let (stdin, mut stdout) = group.take_pipes().expect("pipes");
    drop(stdin);
    let mut output = Vec::new();
    tokio::time::timeout_at(readiness_deadline, stdout.read_to_end(&mut output))
        .await
        .expect("fixture did not close stdout within the scheduling budget")
        .expect("drain fixture stdout");
    drop(stdout);
    assert!(output.is_empty(), "fixture wrote stdout: {output:?}");
    // Checkpoint: EOF proves stdout is closed and the pid file is complete;
    // capture both original (pid, starttime) identities while they are live.
    let (leader, descendant) = wait_for_original_pair(&wrapper.with_extension("pids"), readiness_deadline).await;
    // This is the same product final wait reached by run_git_dir_bounded after
    // stdout EOF. Its deadline starts only now, after readiness was proven.
    let deadline = tokio::time::Instant::now() + FINAL_WAIT_BUDGET;
    let error = group.finish(deadline).await.unwrap_err();
    assert_eq!(error.0, StatusCode::GATEWAY_TIMEOUT);
    assert!(root.exists(), "the disposable view vanished before the final wait was confirmed");
    // The direct leader is our child; a zombie here means cleanup did not reap it.
    assert_eq!(leader.state(), ProcState::Gone, "the original direct leader was not reaped");
    // A descendant killed during cleanup may remain visible as Z/X until its new parent
    // reaps it. The production contract is quiescence, not disappearance.
    let descendant_state = descendant.state();
    assert!(
        matches!(descendant_state, ProcState::Gone | ProcState::Exited),
        "the original descendant is still live after the timeout: {descendant_state:?}"
    );
    drop(view);
    assert!(!root.exists());
}
