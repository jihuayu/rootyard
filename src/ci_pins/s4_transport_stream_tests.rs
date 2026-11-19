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
    sync::{Notify, Semaphore, mpsc, oneshot},
    time::{Instant, timeout},
};

struct FakeOwner {
    chunks: mpsc::Receiver<Vec<u8>>,
    chunk_read: mpsc::UnboundedSender<()>,
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
                let Some(next) = self.chunks.recv().await else {
                    return Ok(0);
                };
                self.pending = next;
                self.offset = 0;
            }
            let available = self.pending.len() - self.offset;
            let n = available.min(buf.len());
            buf[..n].copy_from_slice(&self.pending[self.offset..self.offset + n]);
            self.offset += n;
            let _ = self.chunk_read.send(());
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
    chunk_read: mpsc::UnboundedReceiver<()>,
    cancelled: Arc<AtomicBool>,
    done: oneshot::Receiver<()>,
    semaphore: Arc<Semaphore>,
    body: Body,
}

fn harness_with<P, D>(deadline: Instant, exit: PackExit, producer_check: P, delivery_check: D) -> Harness
where
    P: FnMut() -> Check + Send + 'static,
    D: FnMut() -> Check + Send + 'static,
{
    let (owner_tx, chunks) = mpsc::channel(8);
    let (chunk_read, chunk_read_rx) = mpsc::unbounded_channel();
    let (done_tx, done) = oneshot::channel();
    let cancelled = Arc::new(AtomicBool::new(false));
    let semaphore = Arc::new(Semaphore::new(1));
    let permit = semaphore.clone().try_acquire_owned().expect("one slot");
    let owner = FakeOwner {
        chunks,
        chunk_read,
        pending: Vec::new(),
        offset: 0,
        exit,
        cancelled: cancelled.clone(),
        observed: ObservedSlot { slot: Some(StreamSlot::from_permit(permit)), done: Some(done_tx) },
    };
    Harness {
        owner_tx,
        chunk_read: chunk_read_rx,
        cancelled,
        done,
        semaphore,
        body: producer_body(owner, deadline, producer_check, delivery_check),
    }
}

fn live_checker(auth: Arc<AtomicBool>) -> impl FnMut() -> Check + Send + 'static {
    move || -> Check {
        let live = auth.load(Ordering::SeqCst);
        Box::pin(async move { live })
    }
}

fn signaled_checker(
    auth: Arc<AtomicBool>,
    entered: mpsc::UnboundedSender<()>,
) -> impl FnMut() -> Check + Send + 'static {
    move || -> Check {
        let live = auth.load(Ordering::SeqCst);
        let _ = entered.send(());
        Box::pin(async move { live })
    }
}

fn pending_checker(entered: mpsc::UnboundedSender<()>) -> impl FnMut() -> Check + Send + 'static {
    move || -> Check {
        let _ = entered.send(());
        Box::pin(std::future::pending::<bool>())
    }
}

fn live_harness(deadline: Instant, exit: PackExit) -> (Harness, Arc<AtomicBool>, mpsc::UnboundedReceiver<()>) {
    let auth = Arc::new(AtomicBool::new(true));
    let (checks_tx, checks) = mpsc::unbounded_channel();
    let producer = signaled_checker(auth.clone(), checks_tx);
    let delivery = live_checker(auth.clone());
    (harness_with(deadline, exit, producer, delivery), auth, checks)
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

fn axum_io_error(error: axum::Error) -> io::Error {
    *error.into_inner().downcast::<io::Error>().expect("axum body error must wrap io::Error")
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
    let producer = move || -> Check {
        let call = check_calls.fetch_add(1, Ordering::SeqCst) + 1;
        Box::pin(async move { call == 1 })
    };
    let delivery = live_checker(Arc::new(AtomicBool::new(true)));
    let h = harness_with(Instant::now() + Duration::from_secs(30), PackExit::Success, producer, delivery);
    h.owner_tx.send(b"queued".to_vec()).await.expect("queued chunk");

    // The body is never polled: the first chunk fills the only slot, so the
    // producer's immediate and periodic background checks see the revocation.
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
    assert_eq!(axum_io_error(error).kind(), io::ErrorKind::TimedOut);
    assert!(body.next().await.is_none());
}

#[tokio::test]
async fn deadline_cleanup_is_not_wedged_by_a_pending_authorization_probe() {
    let (entered_tx, mut entered) = mpsc::unbounded_channel();
    let producer = pending_checker(entered_tx);
    let delivery = live_checker(Arc::new(AtomicBool::new(true)));
    let h = harness_with(Instant::now() + Duration::from_millis(500), PackExit::Success, producer, delivery);
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
    assert_eq!(axum_io_error(error).kind(), io::ErrorKind::TimedOut);
}

#[tokio::test]
async fn body_drop_cancels_pending_authorization_and_releases_slot() {
    let (entered_tx, mut entered) = mpsc::unbounded_channel();
    let producer = pending_checker(entered_tx);
    let delivery = live_checker(Arc::new(AtomicBool::new(true)));
    let h = harness_with(Instant::now() + Duration::from_secs(30), PackExit::Success, producer, delivery);
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

#[tokio::test]
async fn body_live_check_denies_chunk_queued_before_background_recheck() {
    let producer = live_checker(Arc::new(AtomicBool::new(true)));
    let delivery_auth = Arc::new(AtomicBool::new(true));
    let (delivery_entered_tx, mut delivery_entered) = mpsc::unbounded_channel();
    let delivery = signaled_checker(delivery_auth.clone(), delivery_entered_tx);
    let mut h = harness_with(Instant::now() + Duration::from_secs(30), PackExit::Success, producer, delivery);
    h.owner_tx.send(b"queued".to_vec()).await.expect("queued chunk");

    timeout(Duration::from_secs(1), h.chunk_read.recv())
        .await
        .expect("chunk read timed out")
        .expect("read event");
    // The chunk is now in the one-slot queue. The producer's own probe remains
    // live, modeling the window before its next periodic check; only the hard
    // delivery boundary observes the revocation.
    delivery_auth.store(false, Ordering::SeqCst);

    let mut body = h.body.into_data_stream();
    let error = body.next().await.expect("terminal item").expect_err("body delivered a queued chunk after revocation");
    assert_eq!(error.to_string(), "checkout authorization revoked during transfer");
    assert!(delivery_entered.try_recv().is_ok(), "body live check did not run");
    wait_done(h.done).await;
    assert!(h.cancelled.load(Ordering::SeqCst), "body denial did not cancel the running producer");
    assert_slot_free(&h.semaphore);
}

#[tokio::test]
async fn body_live_check_denies_final_chunk_after_producer_finished() {
    let producer = live_checker(Arc::new(AtomicBool::new(true)));
    let delivery_auth = Arc::new(AtomicBool::new(true));
    let (delivery_entered_tx, mut delivery_entered) = mpsc::unbounded_channel();
    let gate = Arc::new(Notify::new());
    let gate_for_check = gate.clone();
    let auth_for_check = delivery_auth.clone();
    let delivery = move || -> Check {
        let auth = auth_for_check.clone();
        let gate = gate_for_check.clone();
        let entered = delivery_entered_tx.clone();
        Box::pin(async move {
            let _ = entered.send(());
            gate.notified().await;
            auth.load(Ordering::SeqCst)
        })
    };
    let h = harness_with(Instant::now() + Duration::from_secs(30), PackExit::Success, producer, delivery);
    h.owner_tx.send(b"final".to_vec()).await.expect("final chunk");
    drop(h.owner_tx);

    let mut body = h.body.into_data_stream();
    let mut next = Box::pin(body.next());
    timeout(Duration::from_secs(1), delivery_entered.recv())
        .await
        .expect("body live check did not start")
        .expect("delivery event");
    // The body has dequeued the final chunk and is paused at its hard delivery
    // boundary. With the slot free, the producer reads EOF and finishes.
    timeout(Duration::from_secs(1), h.done)
        .await
        .expect("producer did not finish")
        .expect("producer owner dropped");

    delivery_auth.store(false, Ordering::SeqCst);
    gate.notify_one();
    let item = timeout(Duration::from_secs(1), &mut next)
        .await
        .expect("body did not resume")
        .expect("body ended without a terminal item");
    drop(next);
    let error = item.expect_err("body delivered the final queued chunk after revocation");
    assert_eq!(error.to_string(), "checkout authorization revoked during transfer");
    assert!(!h.cancelled.load(Ordering::SeqCst), "finished producer was disturbed");
    assert_slot_free(&h.semaphore);
    assert!(body.next().await.is_none(), "denied body did not terminate after its terminal error");
}
