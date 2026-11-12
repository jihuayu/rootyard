use super::*;
use std::sync::atomic::AtomicUsize;
use uuid::Uuid;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bulkhead_bounds_concurrency_and_retains_permit_across_caller_timeout() {
    let sem = Arc::new(Semaphore::new(2));
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let release_rx = Arc::new(Mutex::new(release_rx));

    let mut handles = Vec::new();
    for _ in 0..2 {
        let sem = sem.clone();
        let active = active.clone();
        let peak = peak.clone();
        let started_tx = started_tx.clone();
        let release_rx = release_rx.clone();
        handles.push(tokio::spawn(async move {
            run_on(&sem, Duration::from_millis(200), Duration::from_millis(80), move || {
                let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                started_tx.send(()).unwrap();
                let _ = lock(&release_rx).recv();
                active.fetch_sub(1, Ordering::SeqCst);
                Ok(())
            })
            .await
        }));
    }
    started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    started_rx.recv_timeout(Duration::from_secs(5)).unwrap();

    for handle in handles {
        assert_eq!(handle.await.unwrap().unwrap_err().0, StatusCode::GATEWAY_TIMEOUT);
    }
    let third = run_on(&sem, Duration::from_millis(50), Duration::from_secs(1), || Ok(())).await;
    assert_eq!(third.unwrap_err().0, StatusCode::SERVICE_UNAVAILABLE);

    release_tx.send(()).unwrap();
    release_tx.send(()).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while sem.available_permits() < 2 {
        assert!(std::time::Instant::now() < deadline, "permits did not return after work unwound");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(peak.load(Ordering::SeqCst), 2);
    run_on(&sem, Duration::from_secs(1), Duration::from_secs(1), || Ok(())).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocking_propagates_worker_scope_only() {
    let context = worker::OperationContext::new(worker::WorkerKind::WorkspaceCapture);
    let (caller, observed) = worker::run(&context, worker::Phase::Reconcile, async {
        let caller = worker::blocking_scope().expect("worker scope");
        let observed = run(|| Ok(worker::current())).await.expect("run ok");
        (caller, observed)
    })
    .await;
    let observed = observed.expect("worker scope on blocking thread");
    assert_eq!(observed.operation_id, caller.operation_id);
    assert!(run(|| Ok(worker::current())).await.unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lock_mutation_drains_inflight_scans_blocks_new_scans_and_cleans_up_on_timeout() {
    let id = Uuid::new_v4();
    let scan = begin_scan(id).expect("idle workspace allows scan");
    let worker_clone = scan.clone();
    assert!(scan.is_unchanged());

    let timed_out = lock_mutation(id, Duration::from_millis(40)).await;
    assert_eq!(timed_out.err().map(|e| e.0), Some(StatusCode::GATEWAY_TIMEOUT));

    let waiter_task = tokio::spawn(async move { lock_mutation(id, Duration::from_secs(2)).await });
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while coordinator::test_waiters_and_present(id).0 == 0 {
        assert!(std::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(begin_scan(id).is_none(), "queued foreground mutation must block new background scans");
    assert!(scan.is_unchanged(), "in-flight scan remains valid until it completes");

    drop(scan);
    assert!(!waiter_task.is_finished(), "cloned worker token still holds active_scans > 0");
    drop(worker_clone);

    let guard = waiter_task.await.unwrap().expect("mutation acquired once scan drains");
    assert!(begin_scan(id).is_none());
    drop(guard);
    assert!(!coordinator::test_waiters_and_present(id).1, "idle entry must be pruned");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_cleanup_never_rejects_under_io_saturation_and_runs_on_cancellation() {
    let mut held_io = Vec::new();
    while let Ok(p) = io_slots().clone().try_acquire_owned() {
        held_io.push(p);
    }
    let io_rejected = run_on(io_slots(), Duration::from_millis(20), Duration::from_secs(1), || Ok(())).await;
    assert_eq!(io_rejected.unwrap_err().0, StatusCode::SERVICE_UNAVAILABLE);

    let ran = Arc::new(AtomicBool::new(false));
    let ran_clone = ran.clone();
    assert_eq!(
        run_cleanup(move || {
            ran_clone.store(true, Ordering::SeqCst);
            7usize
        })
        .await
        .unwrap(),
        7
    );
    assert!(ran.load(Ordering::SeqCst));
    drop(held_io);

    // Cancel caller mid-acquire_owned().await on cleanup_bulkhead: Drop must still dispatch cleanup.
    let mut held_cleanup = Vec::new();
    while let Ok(p) = crate::workspaces::cleanup::cleanup_bulkhead().clone().try_acquire_owned() {
        held_cleanup.push(p);
    }
    let drop_ran = Arc::new(AtomicBool::new(false));
    let drop_ran_clone = drop_ran.clone();
    let task = tokio::spawn(async move {
        let _ = run_cleanup(move || drop_ran_clone.store(true, Ordering::SeqCst)).await;
    });
    tokio::time::sleep(Duration::from_millis(25)).await;
    task.abort();
    let _ = task.await;
    drop(held_cleanup);

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !drop_ran.load(Ordering::SeqCst) {
        assert!(std::time::Instant::now() < deadline, "cancelled run_cleanup dropped work without executing");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detached_mutating_worker_holds_scan_token_and_signals_abandonment() {
    let id = Uuid::new_v4();
    let mutation = lock_mutation(id, Duration::from_secs(1)).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let ws_dir = dir.path().join("ws");
    std::fs::create_dir(&ws_dir).unwrap();

    let worker_fence = mutation.freeze_guard();
    let guard_fence = mutation.freeze_guard();
    let sem = Arc::new(Semaphore::new(1));
    let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let observed_abandoned = Arc::new(AtomicBool::new(false));
    let obs_clone = observed_abandoned.clone();
    let ws_dir_worker = ws_dir.clone();

    let caller = tokio::spawn(async move {
        run_on_with_abandon(&sem, Duration::from_secs(1), Duration::from_millis(50), move |abandoned| {
            let _wf = worker_fence;
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            obs_clone.store(abandoned.is_abandoned(), Ordering::SeqCst);
            Ok(DirCleanupGuard::with_fence(ws_dir_worker, Some(guard_fence)))
        })
        .await
    });
    started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(caller.await.unwrap().err().map(|e| e.0), Some(StatusCode::GATEWAY_TIMEOUT));
    drop(mutation);

    // Even after _mutation dropped, both begin_scan and a new lock_mutation must remain fenced!
    assert!(begin_scan(id).is_none());
    let next_mutation = tokio::spawn(async move { lock_mutation(id, Duration::from_secs(5)).await });
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(!next_mutation.is_finished(), "next mutation must wait for detached worker + Drop cleanup");

    release_tx.send(()).unwrap();
    let next_guard = next_mutation.await.unwrap().unwrap();
    assert!(observed_abandoned.load(Ordering::SeqCst));
    assert!(
        !ws_dir.exists(),
        "dropped DirCleanupGuard from detached worker must remove uncommitted dir before next mutation"
    );
    drop(next_guard);
}
