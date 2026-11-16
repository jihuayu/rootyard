use super::*;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::oneshot;

fn row() -> StartupRow {
    StartupRow { id: Uuid::nil(), epoch: 1, until: i64::MAX }
}

struct FakeStarted {
    phase: &'static str,
    events: Arc<Mutex<Vec<&'static str>>>,
    release: oneshot::Receiver<()>,
}

impl StartedWork for FakeStarted {
    fn join(self: Box<Self>) -> JoinFuture {
        Box::pin(async move {
            self.events.lock().unwrap().push(self.phase);
            let _ = self.release.await;
            Ok(())
        })
    }
}

struct PhasedStarted {
    events: Arc<Mutex<Vec<&'static str>>>,
    entered: oneshot::Sender<()>,
    release: oneshot::Receiver<()>,
}

impl StartedWork for PhasedStarted {
    fn join(self: Box<Self>) -> JoinFuture {
        Box::pin(async move {
            for phase in ["reserved", "postspawn", "promote"] {
                self.events.lock().unwrap().push(phase);
            }
            let _ = self.entered.send(());
            let _ = self.release.await;
            Ok(())
        })
    }
}

#[tokio::test]
async fn stop_before_query_submits_no_work() {
    let stop = CancellationToken::new();
    stop.cancel();
    let called = Arc::new(AtomicBool::new(false));
    let seen = called.clone();
    let result = produce_serial(stop, vec![row()], move |_row| -> StartFuture {
        seen.store(true, Ordering::SeqCst);
        Box::pin(async {
            let (_release, release) = oneshot::channel();
            Ok(Box::new(FakeStarted { phase: "should-not-run", events: Arc::new(Mutex::new(Vec::new())), release })
                as Box<dyn StartedWork>)
        })
    })
    .await;
    assert!(matches!(result, Err(ProduceError::Stopped)));
    assert!(!called.load(Ordering::SeqCst), "a stopped producer must not admit a row");
}

#[tokio::test]
async fn stop_during_permit_wait_submits_no_work() {
    let stop = CancellationToken::new();
    let (polled_tx, polled_rx) = oneshot::channel();
    let (permit_tx, permit_rx) = oneshot::channel::<()>();
    let submitted = Arc::new(AtomicBool::new(false));
    let seen = submitted.clone();
    let start_stop = stop.clone();
    let producer = tokio::spawn(produce_serial(start_stop, vec![row()], move |_row| -> StartFuture {
        Box::pin(async move {
            let _ = polled_tx.send(());
            let _ = permit_rx.await;
            seen.store(true, Ordering::SeqCst);
            let (_release, release) = oneshot::channel();
            Ok(Box::new(FakeStarted { phase: "should-not-run", events: Arc::new(Mutex::new(Vec::new())), release })
                as Box<dyn StartedWork>)
        })
    }));

    polled_rx.await.unwrap();
    stop.cancel();
    let result = producer.await.unwrap();
    assert!(matches!(result, Err(ProduceError::Stopped)));
    assert!(!submitted.load(Ordering::SeqCst), "permit-wait cancellation must submit no closure");
    drop(permit_tx);
}

#[tokio::test]
async fn stop_after_submission_waits_for_the_real_join() {
    let stop = CancellationToken::new();
    let producer_stop = stop.clone();
    let events = Arc::new(Mutex::new(Vec::new()));
    let (started_tx, started_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let producer_events = events.clone();
    let producer = tokio::spawn(produce_serial(producer_stop, vec![row()], move |_row| -> StartFuture {
        let events = producer_events.clone();
        Box::pin(async move {
            let _ = started_tx.send(());
            Ok(Box::new(FakeStarted { phase: "queued", events, release: release_rx }) as Box<dyn StartedWork>)
        })
    }));

    started_rx.await.unwrap();
    stop.cancel();
    assert!(
        tokio::time::timeout(Duration::from_millis(25), &mut producer).await.is_err(),
        "the producer returned before the submitted join completed"
    );
    release_tx.send(()).unwrap();
    assert!(producer.await.unwrap().is_ok());
    assert_eq!(events.lock().unwrap().clone(), vec!["queued"]);
}

#[tokio::test]
async fn submitted_reserved_post_spawn_and_promote_phases_complete_before_return() {
    let stop = CancellationToken::new();
    let events = Arc::new(Mutex::new(Vec::new()));
    let (entered_tx, entered_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let producer_events = events.clone();
    let producer = tokio::spawn(produce_serial(stop.clone(), vec![row()], move |_row| -> StartFuture {
        let events = producer_events.clone();
        Box::pin(async move {
            Ok(Box::new(PhasedStarted { events, entered: entered_tx, release: release_rx }) as Box<dyn StartedWork>)
        })
    }));

    entered_rx.await.unwrap();
    assert_eq!(
        events.lock().unwrap().clone(),
        vec!["reserved", "postspawn", "promote"],
        "the submitted owner did not reach all retained phases before the join wait"
    );
    stop.cancel();
    assert!(
        tokio::time::timeout(Duration::from_millis(25), &mut producer).await.is_err(),
        "stop-after-submission must not complete the owner early"
    );
    release_tx.send(()).unwrap();
    assert!(producer.await.unwrap().is_ok());
}

#[tokio::test]
async fn deadline_leaves_the_same_owner_retained() {
    let stop = CancellationToken::new();
    let (release_tx, release_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let _ = release_rx.await;
        StartupOutcome::Completed(Ok(()))
    });
    let mut startup = StartupReconcile::from_task(stop, task);
    let first = startup.join_until(tokio::time::Instant::now() + Duration::from_millis(20)).await;
    assert!(matches!(first, Err(StartupJoinError::Deadline)));
    assert!(startup.is_pending(), "a timed-out observation must retain the owner");

    release_tx.send(()).unwrap();
    let second = startup.join_until(tokio::time::Instant::now() + Duration::from_secs(1)).await.unwrap();
    assert!(matches!(second, StartupOutcome::Completed(Ok(()))));
    assert!(!startup.is_pending());
}

#[tokio::test]
async fn cooperative_stop_is_a_typed_stopped_outcome() {
    let stop = CancellationToken::new();
    let task = tokio::spawn({
        let stop = stop.clone();
        async move {
            stop.cancelled().await;
            StartupOutcome::Stopped
        }
    });
    let startup = StartupReconcile::from_task(stop.clone(), task);
    startup.stop();
    let outcome = startup.join().await.unwrap();
    assert!(matches!(outcome, StartupOutcome::Stopped));
}

#[tokio::test]
async fn producer_panic_is_a_typed_join_failure() {
    let task = tokio::spawn(async {
        if true {
            panic!("injected startup producer panic");
        }
        StartupOutcome::Completed(Ok(()))
    });
    let mut startup = StartupReconcile::from_task(CancellationToken::new(), task);
    let result = startup.wait().await;
    assert!(matches!(result, Err(StartupJoinError::Panicked)));
    assert!(!startup.is_pending());
}
