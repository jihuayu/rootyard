use super::{BoxFuture, Check, PackExit, PackOwner, producer_body};
use crate::ci_pins::s4_authority::StreamSlot;
use axum::body::Body;
use bytes::Bytes;
use futures_util::StreamExt;
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{Semaphore, mpsc, oneshot},
    time::{Instant, timeout},
};

struct FakeOwner {
    reads: mpsc::Receiver<Vec<u8>>,
    pending: Vec<u8>,
    offset: usize,
    exit: PackExit,
    cancelled: Arc<AtomicBool>,
    observed: ObservedSlot,
}

/// Drops the slot before signalling task completion, without drop-order guesses.
struct ObservedSlot {
    slot: Option<StreamSlot>,
    done: Option<oneshot::Sender<()>>,
}

impl Drop for ObservedSlot {
    fn drop(&mut self) {
        drop(self.slot.take());
        if let Some(done) = self.done.take() {
            let _ = done.send(());
        }
    }
}

impl PackOwner for FakeOwner {
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<usize>> {
        Box::pin(async move {
            if self.offset >= self.pending.len() {
                let Some(next) = self.reads.recv().await else {
                    return Ok(0);
                };
                self.pending = next;
                self.offset = 0;
            }
            let available = self.pending.len() - self.offset;
            let n = available.min(buf.len());
            buf[..n].copy_from_slice(&self.pending[self.offset..self.offset + n]);
            self.offset += n;
            Ok(n)
        })
    }

    fn finish<'a>(&'a mut self, _deadline: Instant) -> BoxFuture<'a, PackExit> {
        let exit = self.exit;
        Box::pin(async move { exit })
    }

    fn cancel<'a>(&'a mut self) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.cancelled.store(true, Ordering::SeqCst);
        })
    }
}

struct Harness {
    owner_tx: mpsc::Sender<Vec<u8>>,
    cancelled: Arc<AtomicBool>,
    done: oneshot::Receiver<()>,
    semaphore: Arc<Semaphore>,
    body: Body,
}

fn harness_with<F>(deadline: Instant, exit: PackExit, check: F) -> Harness
where
    F: FnMut() -> Check + Send + 'static,
{
    let (owner_tx, reads) = mpsc::channel(8);
    let (done_tx, done) = oneshot::channel();
    let cancelled = Arc::new(AtomicBool::new(false));
    let semaphore = Arc::new(Semaphore::new(1));
    let permit = semaphore.clone().try_acquire_owned().expect("one slot");
    let owner = FakeOwner {
        reads,
        pending: Vec::new(),
        offset: 0,
        exit,
        cancelled: cancelled.clone(),
        observed: ObservedSlot { slot: Some(StreamSlot::from_permit(permit)), done: Some(done_tx) },
    };
    Harness { owner_tx, cancelled, done, semaphore, body: producer_body(owner, deadline, check) }
}

fn live_harness(deadline: Instant, exit: PackExit) -> (Harness, Arc<AtomicBool>, mpsc::UnboundedReceiver<()>) {
    let auth = Arc::new(AtomicBool::new(true));
    let (checks_tx, checks) = mpsc::unbounded_channel();
    let check_auth = auth.clone();
    let check = move || -> Check {
        let live = check_auth.load(Ordering::SeqCst);
        let _ = checks_tx.send(());
        Box::pin(async move { live })
    };
    (harness_with(deadline, exit, check), auth, checks)
}

async fn wait_done(done: oneshot::Receiver<()>) {
    timeout(Duration::from_secs(2), done)
        .await
        .expect("producer cleanup timed out")
        .expect("producer owner dropped without signalling");
}

fn assert_slot_free(semaphore: &Arc<Semaphore>) {
    assert!(semaphore.clone().try_acquire_owned().is_ok(), "stream slot leaked after cleanup");
}

#[tokio::test]
async fn healthy_producer_preserves_exact_chunks_and_success() {
    let (h, auth, _checks) = live_harness(Instant::now() + Duration::from_secs(30), PackExit::Success);
    h.owner_tx.send(b"alpha".to_vec()).await.expect("alpha");
    h.owner_tx.send(b"beta".to_vec()).await.expect("beta");
    drop(h.owner_tx);

    let mut body = h.body.into_data_stream();
    assert_eq!(body.next().await.expect("chunk").expect("ok"), Bytes::from_static(b"alpha"));
    assert_eq!(body.next().await.expect("chunk").expect("ok"), Bytes::from_static(b"beta"));
    assert!(body.next().await.is_none(), "healthy body did not end exactly");
    wait_done(h.done).await;
    assert!(auth.load(Ordering::SeqCst));
    assert!(!h.cancelled.load(Ordering::SeqCst), "healthy transfer was cancelled");
    assert_slot_free(&h.semaphore);
}

#[tokio::test]
async fn git_failure_is_surfaced_after_the_exact_delivered_chunks() {
    let (h, _auth, _checks) = live_harness(Instant::now() + Duration::from_secs(30), PackExit::Failed);
    h.owner_tx.send(b"partial".to_vec()).await.expect("partial chunk");
    drop(h.owner_tx);

    let mut body = h.body.into_data_stream();
    assert_eq!(body.next().await.expect("chunk").expect("ok"), Bytes::from_static(b"partial"));
    let error = body.next().await.expect("terminal item").expect_err("failed child reported success");
    assert_eq!(error.to_string(), "upload-pack failed");
    assert!(body.next().await.is_none());
    wait_done(h.done).await;
    assert_slot_free(&h.semaphore);
}

#[tokio::test]
async fn full_channel_revocation_suppresses_queued_chunk_and_cancels_before_drain() {
    let calls = Arc::new(AtomicUsize::new(0));
    let check_calls = calls.clone();
    let check = move || -> Check {
        let call = check_calls.fetch_add(1, Ordering::SeqCst) + 1;
        Box::pin(async move { call == 1 })
    };
    let h = harness_with(Instant::now() + Duration::from_secs(30), PackExit::Success, check);
    h.owner_tx.send(b"queued".to_vec()).await.expect("queued chunk");

    // The body is never polled: the first chunk fills the only slot, so the
    // second live proof runs while delivery is blocked.
    wait_done(h.done).await;
    assert!(calls.load(Ordering::SeqCst) >= 2, "producer did not recheck while delivery was blocked");
    assert!(h.cancelled.load(Ordering::SeqCst), "revocation did not cancel the Git owner");
    assert_slot_free(&h.semaphore);

    let mut body = h.body.into_data_stream();
    assert!(body.next().await.expect("terminal item").is_err(), "queued chunk escaped after revocation");
    assert!(body.next().await.is_none());
}

#[tokio::test]
async fn absolute_deadline_cleans_up_unpolled_body_and_suppresses_queued_chunk() {
    let (h, _auth, _checks) = live_harness(Instant::now() + Duration::from_millis(150), PackExit::Success);
    h.owner_tx.send(b"queued".to_vec()).await.expect("queued chunk");

    wait_done(h.done).await;
    assert!(h.cancelled.load(Ordering::SeqCst), "deadline did not cancel the Git owner");
    assert_slot_free(&h.semaphore);

    let mut body = h.body.into_data_stream();
    let error = body.next().await.expect("terminal item").expect_err("queued chunk escaped after deadline");
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(body.next().await.is_none());
}

#[tokio::test]
async fn deadline_cleanup_is_not_wedged_by_a_pending_authorization_probe() {
    let (entered_tx, mut entered) = mpsc::unbounded_channel();
    let check = move || -> Check {
        let _ = entered_tx.send(());
        Box::pin(std::future::pending::<bool>())
    };
    let h = harness_with(Instant::now() + Duration::from_millis(500), PackExit::Success, check);
    h.owner_tx.send(b"pending".to_vec()).await.expect("chunk");

    timeout(Duration::from_secs(1), entered.recv())
        .await
        .expect("probe did not start")
        .expect("probe event");
    wait_done(h.done).await;
    assert!(h.cancelled.load(Ordering::SeqCst), "deadline cleanup was wedged by the suspended probe");
    assert_slot_free(&h.semaphore);

    let mut body = h.body.into_data_stream();
    let error = body.next().await.expect("terminal item").expect_err("suspended probe yielded data");
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
}

#[tokio::test]
async fn body_drop_cancels_pending_authorization_and_releases_slot() {
    let (entered_tx, mut entered) = mpsc::unbounded_channel();
    let check = move || -> Check {
        let _ = entered_tx.send(());
        Box::pin(std::future::pending::<bool>())
    };
    let h = harness_with(Instant::now() + Duration::from_secs(30), PackExit::Success, check);
    h.owner_tx.send(b"pending".to_vec()).await.expect("chunk");

    timeout(Duration::from_secs(1), entered.recv())
        .await
        .expect("probe did not start")
        .expect("probe event");
    drop(h.body);

    wait_done(h.done).await;
    assert!(h.cancelled.load(Ordering::SeqCst), "body drop did not cancel the Git owner");
    assert_slot_free(&h.semaphore);
}
