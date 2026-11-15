//! Ordered, bounded shutdown for the workspace capture producer and its helper.
//!
//! The HTTP server and owned Git jobs are drained before this module runs. The
//! only remaining helper producer is the background capture worker, plus scan
//! jobs that may have outlived their caller's scan deadline. Capture must stop
//! before the helper fences and unmounts, but a blind `await` can wait forever
//! on a parked scan, so the producer join and scan drain share one absolute
//! deadline. On timeout the producer is aborted and the helper teardown is
//! still attempted; any failed part is returned instead of being reported as a
//! clean shutdown.
use super::scan;
use anyhow::{Result, anyhow};
use std::{future::Future, time::Duration};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Extra room beyond one bounded scan deadline for the capture loop to observe
/// cancellation and finish its already-admitted pages.
const CAPTURE_SCAN_MARGIN: Duration = Duration::from_secs(5);

/// One bounded capture drain budget. The helper has its own pre-existing
/// fence/unmount/join and child-process grace; this value never makes that path
/// unbounded.
pub fn capture_shutdown_grace() -> Duration {
    scan::timeout().saturating_add(CAPTURE_SCAN_MARGIN)
}

/// Cancel and drain the capture producer and accepted scans within one absolute
/// deadline, then unconditionally attempt helper teardown with its existing
/// bounded fence/unmount/join and child-process grace.
///
/// The helper future is polled even when capture or scan drain fails, because
/// its fence/unmount/join path owns the last safe cleanup attempt. A failure in
/// either part makes the returned result an error; a helper failure is retained
/// alongside a capture/scan failure.
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
    let deadline = tokio::time::Instant::now() + grace;
    let mut failures = Vec::new();

    match tokio::time::timeout_at(deadline, &mut capture).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            failures.push(format!("workspace capture worker did not finish cleanly during shutdown ({error})"));
        }
        Err(_) => {
            // Do not let a wedged producer race helper teardown. Abort is
            // bounded and non-blocking; an OS scan already inside the pool is
            // still observed by `scan::wait_idle_until` and the helper fence.
            capture.abort();
            failures.push(format!("workspace capture worker did not stop within {}ms", grace.as_millis()));
        }
    }

    // This uses the same absolute deadline as the capture join. A timed-out
    // scan caller does not clear its marker until `with_frozen` really returns.
    if !scan::wait_idle_until(deadline).await {
        failures.push(format!("workspace scan workers did not drain within {}ms", grace.as_millis()));
    }

    // Keep helper teardown unconditional: if the producer drain failed, this is
    // the fence/unmount/join backstop that releases the helper and its mounts.
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
        let capture = {
            let capture_dropped = capture_dropped.clone();
            tokio::spawn(async move {
                let _drop = DropSignal(capture_dropped);
                std::future::pending::<()>().await;
            })
        };

        let helper_ran = Arc::new(AtomicBool::new(false));
        let helper_seen = helper_ran.clone();
        let outcome = tokio::time::timeout(
            Duration::from_secs(2),
            stop_capture_before_helper(stop, capture, Duration::from_millis(25), async move {
                helper_seen.store(true, Ordering::Release);
                Err(anyhow::anyhow!("fixture helper failure"))
            }),
        )
        .await
        .expect("shutdown exceeded its bounded test deadline");
        let error = outcome.expect_err("timed-out capture must fail shutdown").to_string();

        assert!(helper_ran.load(Ordering::Acquire), "helper teardown was skipped after a failed drain");
        assert!(error.contains("capture worker did not stop"), "missing capture failure: {error}");
        assert!(error.contains("fixture helper failure"), "missing helper failure: {error}");
        tokio::time::timeout(Duration::from_secs(1), async {
            while !capture_dropped.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("aborted capture task did not drop");
    }
}
