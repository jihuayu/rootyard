//! Cancellation-safe per-database mirror ordering tests for `run_serialized_pg_to_raft_step` (#153).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::run_serialized_pg_to_raft_step;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serialized_pg_to_raft_step_prevents_out_of_order_read_before_apply() {
    let serialize = Arc::new(tokio::sync::Mutex::new(()));
    let events = Arc::new(Mutex::new(Vec::<&'static str>::new()));
    let task1_in_apply = Arc::new(tokio::sync::Notify::new());
    let task1 = {
        let (serialize, task1_in_apply) = (serialize.clone(), task1_in_apply.clone());
        let (read_events, apply_events) = (events.clone(), events.clone());
        async move {
            run_serialized_pg_to_raft_step(
                serialize,
                || async move {
                    read_events.lock().unwrap().push("read-1");
                    Ok(())
                },
                move |()| {
                    task1_in_apply.notify_one();
                    std::thread::sleep(Duration::from_millis(40));
                    apply_events.lock().unwrap().push("apply-1");
                    Ok(())
                },
            )
            .await
        }
    };
    let task2 = {
        let (serialize, task1_in_apply) = (serialize.clone(), task1_in_apply.clone());
        let (read_events, apply_events) = (events.clone(), events.clone());
        async move {
            task1_in_apply.notified().await;
            run_serialized_pg_to_raft_step(
                serialize,
                || async move {
                    read_events.lock().unwrap().push("read-2");
                    Ok(())
                },
                move |()| {
                    apply_events.lock().unwrap().push("apply-2");
                    Ok(())
                },
            )
            .await
        }
    };
    let (first, second) = tokio::join!(task1, task2);
    first.expect("task1");
    second.expect("task2");
    assert_eq!(*events.lock().unwrap(), vec!["read-1", "apply-1", "read-2", "apply-2"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_caller_keeps_serialization_lock_until_blocking_raft_apply_finishes() {
    let serialize = Arc::new(tokio::sync::Mutex::new(()));
    let events = Arc::new(Mutex::new(Vec::<&'static str>::new()));
    let apply1_started = Arc::new(tokio::sync::Notify::new());
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let handle1 = {
        let (serialize, apply1_started) = (serialize.clone(), apply1_started.clone());
        let (read_events, apply_events) = (events.clone(), events.clone());
        tokio::spawn(async move {
            run_serialized_pg_to_raft_step(
                serialize,
                || async move {
                    read_events.lock().unwrap().push("read-1");
                    Ok(())
                },
                move |()| {
                    apply_events.lock().unwrap().push("apply-1-start");
                    apply1_started.notify_one();
                    release_rx.recv().expect("release");
                    apply_events.lock().unwrap().push("apply-1-done");
                    Ok(())
                },
            )
            .await
        })
    };
    apply1_started.notified().await;
    handle1.abort();
    let err = handle1.await.expect_err("caller 1 must cancel");
    assert!(err.is_cancelled());
    events.lock().unwrap().push("caller-1-cancelled");
    let handle2 = {
        let (serialize, read_events, apply_events) = (serialize.clone(), events.clone(), events.clone());
        tokio::spawn(async move {
            run_serialized_pg_to_raft_step(
                serialize,
                || async move {
                    read_events.lock().unwrap().push("read-2");
                    Ok(())
                },
                move |()| {
                    apply_events.lock().unwrap().push("apply-2");
                    Ok(())
                },
            )
            .await
        })
    };
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert_eq!(*events.lock().unwrap(), vec!["read-1", "apply-1-start", "caller-1-cancelled"]);
    release_tx.send(()).expect("send release");
    handle2.await.expect("join 2").expect("step 2");
    assert_eq!(
        *events.lock().unwrap(),
        vec!["read-1", "apply-1-start", "caller-1-cancelled", "apply-1-done", "read-2", "apply-2"]
    );
}
