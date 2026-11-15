use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

#[test]
fn bound_parses_default_and_respects_budget_invariant() {
    let default = RevocationBound::from_raw(None).unwrap();
    assert_eq!(default.total, Duration::from_millis(DEFAULT_REVOCATION_BOUND_MS));
    assert!(default.check_interval + default.reauth_timeout + default.stop_grace <= default.total);

    for ms in [MIN_REVOCATION_BOUND_MS, 500, 1_500, 10_000, MAX_REVOCATION_BOUND_MS] {
        let b = RevocationBound::from_ms(ms).unwrap();
        assert!(b.check_interval + b.reauth_timeout + b.stop_grace <= b.total, "ms={ms}");
    }
}

#[test]
fn bound_rejects_invalid_and_out_of_range_values() {
    for bad in ["0", "299", "60001", "-1", "fast", ""] {
        assert!(RevocationBound::from_raw(Some(bad)).is_err(), "expected err for {bad:?}");
    }
}

#[tokio::test]
async fn check_bounded_fails_closed_on_timeout_and_revocation() {
    let timed_out = check_bounded(Duration::from_millis(20), async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        Ok::<bool, crate::Error>(true)
    })
    .await;
    assert!(timed_out.is_err());
    assert!(check_bounded(Duration::from_millis(100), async { Ok::<bool, crate::Error>(false) }).await.is_err());
    assert!(
        check_bounded(Duration::from_millis(100), async { Err::<bool, crate::Error>(crate::Error::internal("down")) })
            .await
            .is_err()
    );
    assert!(check_bounded(Duration::from_millis(100), async { Ok::<bool, crate::Error>(true) }).await.is_ok());
}

fn pid_terminated(pid: i32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Err(_) => true,
        Ok(text) => text.rsplit_once(") ").is_some_and(|(_, tail)| tail.starts_with('Z') || tail.starts_with('X')),
    }
}

#[tokio::test]
async fn revoked_subprocess_group_terminates_within_bound() {
    let bound = RevocationBound::from_ms(600).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let pid_file = dir.path().join("child.pid");
    let mut cmd = tokio::process::Command::new("/bin/sh");
    cmd.args([
        "-c",
        "sh -c 'trap \"\" TERM; echo $$ > \"$1\"; while :; do sleep 1; done' child \"$1\" & echo ready; wait",
        "leader",
    ])
    .arg(&pid_file);

    let allow = Arc::new(AtomicBool::new(true));
    let allow_revoke = allow.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(120)).await;
        allow_revoke.store(false, Ordering::SeqCst);
    });
    let started = Instant::now();
    let result = collect_git_output_reauthorized(cmd, 4096, Duration::from_secs(10), bound, || {
        let allow = allow.clone();
        async move { if allow.load(Ordering::SeqCst) { Ok(()) } else { Err(io::Error::other("revoked")) } }
    })
    .await;
    let elapsed = started.elapsed();
    assert!(result.is_err());
    assert!(elapsed < bound.total, "revocation took {elapsed:?} >= {:?}", bound.total);
    if let Ok(raw) = std::fs::read_to_string(&pid_file)
        && let Ok(descendant) = raw.trim().parse::<i32>()
    {
        assert!(pid_terminated(descendant), "descendant {descendant} survived");
    }
}

#[tokio::test]
async fn concurrent_revoked_subprocesses_clean_without_leaking_children() {
    let bound = RevocationBound::from_ms(600).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let allow = Arc::new(AtomicBool::new(true));
    let mut handles = Vec::new();
    let mut pid_files = Vec::new();
    for idx in 0..4 {
        let pid_file = dir.path().join(format!("child-{idx}.pid"));
        let mut cmd = tokio::process::Command::new("/bin/sh");
        cmd.args([
            "-c",
            "sh -c 'trap \"\" TERM; echo $$ > \"$1\"; while :; do sleep 1; done' child \"$1\" & echo ok; wait",
            "leader",
        ])
        .arg(&pid_file);
        pid_files.push(pid_file);
        let allow_task = allow.clone();
        handles.push(tokio::spawn(async move {
            collect_git_output_reauthorized(cmd, 4096, Duration::from_secs(10), bound, || {
                let allow = allow_task.clone();
                async move { if allow.load(Ordering::SeqCst) { Ok(()) } else { Err(io::Error::other("revoked")) } }
            })
            .await
        }));
    }
    tokio::time::sleep(Duration::from_millis(120)).await;
    allow.store(false, Ordering::SeqCst);
    for handle in handles {
        assert!(handle.await.unwrap().is_err());
    }
    for pid_file in pid_files {
        if let Ok(raw) = std::fs::read_to_string(pid_file)
            && let Ok(pid) = raw.trim().parse::<i32>()
        {
            assert!(pid_terminated(pid), "concurrent descendant {pid} leaked");
        }
    }
}

#[tokio::test]
async fn stream_body_with_reauth_aborts_slow_consumer_within_bound() {
    let bound = RevocationBound::from_ms(400).unwrap();
    let counters = Arc::new(crate::metrics::TransferCounters::default());
    let allow = Arc::new(AtomicBool::new(true));
    let allow_stream = allow.clone();
    let source = futures_util::stream::repeat_with(|| {
        Ok::<axum::body::Bytes, io::Error>(axum::body::Bytes::from_static(&[b'x'; 64 * 1024]))
    })
    .take(256);
    let body = Body::from_stream(source);
    let guarded = stream_body_with_counters(counters.clone(), body, bound, move || {
        let allow = allow_stream.clone();
        async move { if allow.load(Ordering::SeqCst) { Ok(()) } else { Err(io::Error::other("revoked")) } }
    });
    let mut data = guarded.into_data_stream();
    assert!(data.next().await.unwrap().is_ok());
    // Simulate a slow consumer pausing long enough for buffered slots to fill.
    tokio::time::sleep(Duration::from_millis(40)).await;
    allow.store(false, Ordering::SeqCst);
    let started = Instant::now();
    let mut saw_err = false;
    let mut drained = 0usize;
    while let Some(item) = data.next().await {
        if item.is_err() {
            saw_err = true;
            break;
        }
        drained += 1;
    }
    assert!(saw_err, "slow consumer escaped without stream error");
    assert!(drained < 255, "entire stream drained ({drained} chunks)");
    assert!(started.elapsed() < bound.total);
}
