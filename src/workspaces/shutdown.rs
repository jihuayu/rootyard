//! Ordered, bounded shutdown for the workspace capture producer and its helper.
//!
//! The HTTP server has been asked to stop admission and the owned Git jobs are
//! retained by the caller, not joined here. This module stops the capture
//! producer, drains accepted scans and invokes the exact-owner helper before
//! the caller joins the retained HTTP/Git work. The only helper producers are
//! the background capture worker and scan jobs that may have outlived their
//! caller's scan deadline. Capture is asked to stop and its release is awaited
//! within one total absolute grace; a
//! reserved slice of that grace is used to confirm an abort request before the
//! helper fences and unmounts. A blind `await` can wait forever on a parked
//! scan, so a confirmation timeout still runs the helper backstop, returns an
//! error, and never claims that the producer was drained.
use super::scan;
use anyhow::{Result, anyhow};
use std::{future::Future, time::Duration};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Extra room beyond one bounded scan deadline for the capture loop to observe
/// cancellation and finish its already-admitted pages.
const CAPTURE_SCAN_MARGIN: Duration = Duration::from_secs(5);

/// Slice of the total capture grace reserved for confirming that an abort
/// request actually released the task. The slice is capped and never more than
/// half the total, so a small test/config grace still leaves a strict split.
const ABORT_CONFIRMATION_LIMIT: Duration = Duration::from_secs(1);

/// One bounded capture drain budget. The helper future supplied by the caller
/// owns the same absolute normal-shutdown deadline for its fence/unmount/exit
/// and child-reap phases; this value never starts a second helper grace.
pub fn capture_shutdown_grace() -> Duration {
    scan::timeout().saturating_add(CAPTURE_SCAN_MARGIN)
}

/// Cancel the capture producer, await its release and drain accepted scans with
/// every wait bounded by one absolute deadline, then unconditionally attempt
/// helper teardown. The helper future is deadline-aware: its RPC, exit and
/// child-reap waits consume the caller's published normal-shutdown deadline
/// rather than starting a fresh helper grace. Helper teardown deliberately
/// precedes the caller's retained HTTP/Git joins so a FUSE-parked Git child can
/// be released.
///
/// The total grace is not extended: a reserved confirmation slice is taken from
/// inside it. If capture does not release before the earlier cooperative
/// deadline, abort is requested and the same `JoinHandle` is awaited only until
/// the original final deadline. A cancellation join after that abort is
/// expected completion; a later deadline miss is a distinct failure and is
/// never reported as a drained producer.
///
/// The helper future is polled even when capture or scan drain fails, because
/// its fence/unmount/join path owns the last safe cleanup attempt. A failure in
/// any part makes the returned result an error; helper failures are retained
/// alongside capture/scan failures.
pub async fn stop_capture_before_helper<H>(
    stop: CancellationToken,
    mut capture: JoinHandle<()>,
    grace: Duration,
    helper: H,
) -> Result<()>
where
    H: Future<Output = Result<()>>,
{
    stop.cancel();
    let started = tokio::time::Instant::now();
    let final_deadline = started + grace;
    let abort_confirmation = ABORT_CONFIRMATION_LIMIT.min(grace / 2);
    let capture_deadline = started + (grace - abort_confirmation);
    let mut failures = Vec::new();
    let mut abort_requested = false;

    match tokio::time::timeout_at(capture_deadline, &mut capture).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            failures.push(format!("workspace capture worker did not finish cleanly during shutdown ({error})"));
        }
        Err(_) => {
            // The earlier deadline expired. Requesting abort is not proof the
            // task released; confirm the actual JoinHandle before helper
            // teardown, but only inside the original total grace.
            abort_requested = true;
            capture.abort();
            failures.push("workspace capture worker did not stop before the abort-confirmation window".to_owned());
        }
    }

    if abort_requested {
        // A confirmation miss can leave the request pending. Helper teardown is
        // then only a backstop, not evidence that producer-before-helper held.
        match tokio::time::timeout_at(final_deadline, &mut capture).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) if error.is_cancelled() => {}
            Ok(Err(error)) => {
                failures.push(format!("workspace capture worker did not release cleanly after abort ({error})"));
            }
            Err(_) => {
                failures.push(format!(
                    "workspace capture worker abort was requested but its JoinHandle did not complete within the final {}ms grace; producer-before-helper ordering is not claimed",
                    grace.as_millis()
                ));
            }
        }
    }

    // This uses the same original final deadline. A timed-out scan caller does
    // not clear its marker until `with_frozen` really returns.
    if !scan::wait_idle_until(final_deadline).await {
        failures.push(format!("workspace scan workers did not drain within {}ms", grace.as_millis()));
    }

    // Keep helper teardown unconditional: if capture release or scan drain was
    // not confirmed, this is the fence/unmount/join backstop that releases the
    // helper and its mounts. Any unconfirmed drain remains in `failures`.
    if let Err(error) = helper.await {
        failures.push(format!("workspace FUSE helper shutdown failed: {error:#}"));
    }

    if failures.is_empty() { Ok(()) } else { Err(anyhow!(failures.join("; "))) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::time::Duration;
    use uuid::Uuid;

    struct DropSignal(Arc<AtomicBool>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn helper_runs_only_after_capture_and_scan_drain() {
        let stop = CancellationToken::new();
        let capture_done = Arc::new(AtomicBool::new(false));
        let capture = {
            let stop = stop.clone();
            let capture_done = capture_done.clone();
            tokio::spawn(async move {
                stop.cancelled().await;
                capture_done.store(true, Ordering::Release);
            })
        };

        let id = Uuid::new_v4();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let scan_task = tokio::spawn(scan::frozen(id, Duration::from_secs(5), move || {
            started_tx.send(()).expect("scan start receiver");
            release_rx.recv().expect("scan release sender");
            Ok(())
        }));
        started_rx.recv_timeout(Duration::from_secs(5)).expect("scan did not start");
        let release = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            release_tx.send(()).expect("scan release receiver");
        });

        let helper = async move {
            assert!(capture_done.load(Ordering::Acquire), "helper teardown preceded capture cancellation");
            assert!(!scan::scan_is_active(id), "helper teardown preceded scan drain");
            Ok::<(), anyhow::Error>(())
        };
        stop_capture_before_helper(stop, capture, Duration::from_secs(5), helper).await.expect("ordered shutdown");
        scan_task.await.expect("scan task").expect("scan completed");
        release.await.expect("release task");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bounded_capture_abort_still_runs_helper_and_reports_both_failures() {
        let stop = CancellationToken::new();
        let capture_dropped = Arc::new(AtomicBool::new(false));
        let (capture_started_tx, capture_started_rx) = tokio::sync::oneshot::channel();
        let capture = {
            let capture_dropped = capture_dropped.clone();
            tokio::spawn(async move {
                let _drop = DropSignal(capture_dropped);
                let _ = capture_started_tx.send(());
                std::future::pending::<()>().await;
            })
        };
        capture_started_rx.await.expect("capture task did not enter its shutdown wait");

        let helper_ran = Arc::new(AtomicBool::new(false));
        let helper_seen = helper_ran.clone();
        let helper_dropped = capture_dropped.clone();
        let outcome = tokio::time::timeout(
            Duration::from_secs(2),
            stop_capture_before_helper(stop, capture, Duration::from_millis(200), async move {
                helper_seen.store(true, Ordering::Release);
                assert!(
                    helper_dropped.load(Ordering::Acquire),
                    "helper teardown began before the aborted capture task actually released"
                );
                Err(anyhow::anyhow!("fixture helper failure"))
            }),
        )
        .await
        .expect("shutdown exceeded its bounded test deadline");
        let error = outcome.expect_err("timed-out capture must fail shutdown").to_string();

        assert!(helper_ran.load(Ordering::Acquire), "helper teardown was skipped after a failed drain");
        assert!(error.contains("capture worker did not stop"), "missing capture failure: {error}");
        assert!(!error.contains("after abort"), "expected abort cancellation was not treated as completion: {error}");
        assert!(error.contains("fixture helper failure"), "missing helper failure: {error}");
    }
}
