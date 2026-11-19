//! Producer-owned streaming for the S4 checkout `git-upload-pack` response.
//!
//! The response body is only a bounded view of a task that owns the Git child,
//! the stdin writer guard, the scratch hold and the stream slot. Revocation,
//! the request deadline, body disconnect and process cleanup therefore make
//! progress even when the body is never polled or its single data slot stays
//! full. The outgoing body also re-proves authority immediately before every
//! chunk; a denial closes the data receiver to wake and cancel the producer.
use super::s4_authority::{DisposableCiView, RECHECK_TIMEOUT, StreamSlot, UploadPackGroup};
use crate::{AppState, Error};
use axum::{body::Body, http::StatusCode};
use bytes::Bytes;
use futures_util::Stream;
use std::{
    future::Future,
    io::{self, ErrorKind},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::ChildStdout,
    sync::{
        mpsc::{self, error::TrySendError},
        oneshot::{self, error::TryRecvError},
    },
    time::{Instant, sleep, sleep_until, timeout_at},
};

/// Fixed chunk size of the streamed pack response.
const CHUNK: usize = 16 * 1024;
/// How often the producer re-proves authorization, independent of chunk size.
const RECHECK: Duration = Duration::from_millis(100);

pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One bounded authorization probe built immediately before it is polled.
pub(crate) type Check = BoxFuture<'static, bool>;

/// Outcome of one live authorization probe.
enum CheckOutcome {
    Live,
    Revoked,
    TimedOut,
    Closed,
}

/// Terminal state reported by the Git child after its stdout closed.
#[derive(Clone, Copy)]
enum PackExit {
    Success,
    Failed,
    TimedOut,
}

enum FinishOutcome {
    Closed,
    Revoked,
    TimedOut,
    Finished(PackExit),
}

/// The only owner of the upload-pack process, its pipes, scratch and slot.
struct RunningUploadPack {
    child: UploadPackGroup,
    stdout: ChildStdout,
    _stdin: AbortTask,
    _slot: StreamSlot,
}

/// Aborts the stdin writer as soon as the producer is dropped.
struct AbortTask(tokio::task::JoinHandle<()>);

impl Drop for AbortTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Narrow process-facing operations used by the producer and its pure tests.
trait PackOwner: Send + 'static {
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<usize>>;
    fn finish<'a>(&'a mut self, deadline: Instant) -> BoxFuture<'a, PackExit>;
    fn cancel<'a>(&'a mut self) -> BoxFuture<'a, ()>;
}

impl PackOwner for RunningUploadPack {
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<usize>> {
        Box::pin(async move { self.stdout.read(buf).await })
    }

    fn finish<'a>(&'a mut self, deadline: Instant) -> BoxFuture<'a, PackExit> {
        Box::pin(async move {
            match self.child.finish(deadline).await {
                Ok(status) if status.success() => PackExit::Success,
                Err(error) if error.0 == StatusCode::GATEWAY_TIMEOUT => PackExit::TimedOut,
                _ => PackExit::Failed,
            }
        })
    }

    fn cancel<'a>(&'a mut self) -> BoxFuture<'a, ()> {
        Box::pin(async move { self.child.kill_and_reap().await })
    }
}

/// Spawn the upload-pack child and return a body owned by its producer task.
pub(crate) fn upload_pack_body<P, D>(
    state: &AppState,
    holder: DisposableCiView,
    request: Bytes,
    deadline: Instant,
    producer_check: P,
    delivery_check: D,
) -> Result<Body, Error>
where
    P: FnMut() -> Check + Send + 'static,
    D: FnMut() -> Check + Send + 'static,
{
    let slot = StreamSlot::acquire(state)?;
    let hold = holder.hold();
    let mut child = UploadPackGroup::spawn(&state.config.git, holder.path(), Some(hold))?;
    drop(holder);
    let (mut stdin, stdout) = child.take_pipes()?;
    let stdin_guard = AbortTask(tokio::spawn(async move {
        let _ = timeout_at(deadline, async {
            let _ = stdin.write_all(&request).await;
            let _ = stdin.shutdown().await;
        })
        .await;
    }));
    Ok(producer_body(
        RunningUploadPack { child, stdout, _stdin: stdin_guard, _slot: slot },
        deadline,
        producer_check,
        delivery_check,
    ))
}

/// Detach the owned producer from the body. The body never owns process state.
fn producer_body<O, P, D>(owner: O, deadline: Instant, producer_check: P, delivery_check: D) -> Body
where
    O: PackOwner,
    P: FnMut() -> Check + Send + 'static,
    D: FnMut() -> Check + Send + 'static,
{
    let (data_tx, data_rx) = mpsc::channel::<Bytes>(1);
    let (failure_tx, failure_rx) = oneshot::channel::<io::Error>();
    let aborted = Arc::new(AtomicBool::new(false));
    tokio::spawn(run_producer(owner, deadline, producer_check, data_tx, failure_tx, aborted.clone()));
    Body::from_stream(response_stream(data_rx, failure_rx, aborted, deadline, delivery_check))
}

/// Map one probe to the stream action without ever awaiting an unbounded check.
async fn live_check<F, C>(check: &mut F, deadline: Instant, cancelled: C) -> CheckOutcome
where
    F: FnMut() -> Check,
    C: Future<Output = ()> + Send,
{
    let probe = check();
    tokio::pin!(probe);
    tokio::select! {
        biased;
        _ = cancelled => CheckOutcome::Closed,
        _ = sleep_until(deadline) => CheckOutcome::TimedOut,
        _ = sleep(RECHECK_TIMEOUT) => CheckOutcome::Revoked,
        live = &mut probe => if live { CheckOutcome::Live } else { CheckOutcome::Revoked },
    }
}

/// The hard per-chunk authority boundary at the actual outgoing Body poll.
async fn body_live_check<F>(check: &mut F, deadline: Instant) -> CheckOutcome
where
    F: FnMut() -> Check,
{
    live_check(check, deadline, std::future::pending::<()>()).await
}

async fn run_producer<O, F>(
    mut owner: O,
    deadline: Instant,
    mut check: F,
    data: mpsc::Sender<Bytes>,
    failure_tx: oneshot::Sender<io::Error>,
    aborted: Arc<AtomicBool>,
) where
    O: PackOwner,
    F: FnMut() -> Check,
{
    let mut buffer = vec![0u8; CHUNK];
    let mut ticker = tokio::time::interval_at(Instant::now() + RECHECK, RECHECK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut failure: Option<io::Error> = None;
    let mut finished = false;
    let mut clean = false;

    macro_rules! recheck {
        ($label:lifetime) => {
            match live_check(&mut check, deadline, data.closed()).await {
                CheckOutcome::Live => {}
                CheckOutcome::Revoked => {
                    failure = Some(revoked_error());
                    break $label;
                }
                CheckOutcome::TimedOut => {
                    failure = Some(timeout_error());
                    break $label;
                }
                CheckOutcome::Closed => break $label,
            }
        };
    }

    'producer: loop {
        // Reserve the only data slot before reading another chunk, so a stalled
        // body stops Git output at the same one-chunk boundary as before.
        let permit = match data.try_reserve() {
            Ok(permit) => permit,
            Err(TrySendError::Closed(())) => break 'producer,
            Err(TrySendError::Full(())) => {
                // The body is not consuming: prove authority before waiting,
                // then keep proving it even while delivery is blocked.
                recheck!('producer);
                loop {
                    tokio::select! {
                        biased;
                        _ = data.closed() => break 'producer,
                        _ = sleep_until(deadline) => {
                            failure = Some(timeout_error());
                            break 'producer;
                        }
                        _ = ticker.tick() => recheck!('producer),
                        reserved = data.reserve() => match reserved {
                            Ok(permit) => break permit,
                            Err(_) => break 'producer,
                        },
                    }
                }
            }
        };

        let read = loop {
            tokio::select! {
                biased;
                _ = data.closed() => break 'producer,
                _ = sleep_until(deadline) => {
                    failure = Some(timeout_error());
                    break 'producer;
                }
                _ = ticker.tick() => recheck!('producer),
                read = owner.read(&mut buffer) => break read,
            }
        };

        match read {
            Ok(0) => {
                finished = true;
                break 'producer;
            }
            Ok(n) => {
                permit.send(Bytes::copy_from_slice(&buffer[..n]));
            }
            Err(error) => {
                failure = Some(error);
                break 'producer;
            }
        }
    }

    if finished && failure.is_none() {
        let outcome = {
            let finish = owner.finish(deadline);
            tokio::pin!(finish);
            loop {
                tokio::select! {
                    biased;
                    _ = data.closed() => break FinishOutcome::Closed,
                    _ = sleep_until(deadline) => break FinishOutcome::TimedOut,
                    _ = ticker.tick() => match live_check(&mut check, deadline, data.closed()).await {
                        CheckOutcome::Live => {}
                        CheckOutcome::Revoked => break FinishOutcome::Revoked,
                        CheckOutcome::TimedOut => break FinishOutcome::TimedOut,
                        CheckOutcome::Closed => break FinishOutcome::Closed,
                    },
                    outcome = &mut finish => break FinishOutcome::Finished(outcome),
                }
            }
        };
        match outcome {
            FinishOutcome::Closed => {
                owner.cancel().await;
                return;
            }
            FinishOutcome::Revoked => failure = Some(revoked_error()),
            FinishOutcome::TimedOut => failure = Some(timeout_error()),
            FinishOutcome::Finished(PackExit::Success) => clean = true,
            FinishOutcome::Finished(PackExit::TimedOut) => failure = Some(timeout_error()),
            FinishOutcome::Finished(PackExit::Failed) => failure = Some(io::Error::other("upload-pack failed")),
        }
    }

    // Publish the terminal error before cleanup: it is never queued behind the
    // data channel and can never wait for a blocked data send.
    if let Some(error) = failure.take() {
        aborted.store(true, Ordering::Release);
        let _ = failure_tx.send(error);
    }
    if !clean {
        owner.cancel().await;
    }
}

/// Body-side view: one queued chunk maximum and an independent terminal signal.
fn response_stream<D>(
    mut data: mpsc::Receiver<Bytes>,
    failure: oneshot::Receiver<io::Error>,
    aborted: Arc<AtomicBool>,
    deadline: Instant,
    mut delivery_check: D,
) -> impl Stream<Item = io::Result<Bytes>> + Send + 'static
where
    D: FnMut() -> Check + Send + 'static,
{
    async_stream::stream! {
        let mut failure = failure;
        let mut failure_open = true;
        loop {
            if aborted.load(Ordering::Acquire) {
                let error = if failure_open {
                    match (&mut failure).await {
                        Ok(error) => error,
                        Err(_) => transfer_terminated_error(),
                    }
                } else {
                    transfer_terminated_error()
                };
                yield Err(error);
                return;
            }
            tokio::select! {
                biased;
                result = &mut failure, if failure_open => {
                    failure_open = false;
                    match result {
                        Ok(error) => {
                            yield Err(error);
                            return;
                        }
                        Err(_) => {}
                    }
                }
                item = data.recv() => match item {
                    Some(bytes) => {
                        if aborted.load(Ordering::Acquire) {
                            continue;
                        }
                        // The producer's periodic recheck may lag behind an
                        // enqueue. Re-prove authority at the actual outgoing
                        // poll before any byte is yielded.
                        match body_live_check(&mut delivery_check, deadline).await {
                            CheckOutcome::Live => {
                                if aborted.load(Ordering::Acquire) {
                                    continue;
                                }
                                if let Some(error) = terminal_error(&mut failure, &mut failure_open) {
                                    data.close();
                                    yield Err(error);
                                    return;
                                }
                                if aborted.load(Ordering::Acquire) {
                                    continue;
                                }
                                yield Ok(bytes);
                            }
                            CheckOutcome::Revoked => {
                                data.close();
                                yield Err(revoked_error());
                                return;
                            }
                            CheckOutcome::TimedOut => {
                                data.close();
                                yield Err(timeout_error());
                                return;
                            }
                            CheckOutcome::Closed => {
                                data.close();
                                yield Err(transfer_terminated_error());
                                return;
                            }
                        }
                    }
                    None => {
                        if aborted.load(Ordering::Acquire) {
                            continue;
                        }
                        return;
                    }
                },
            }
        }
    }
}

/// Consume a producer failure that was published while the body was checking.
fn terminal_error(failure: &mut oneshot::Receiver<io::Error>, open: &mut bool) -> Option<io::Error> {
    if !*open {
        return None;
    }
    match failure.try_recv() {
        Ok(error) => Some(error),
        Err(TryRecvError::Empty) => None,
        Err(TryRecvError::Closed) => {
            *open = false;
            None
        }
    }
}

fn revoked_error() -> io::Error {
    io::Error::other("checkout authorization revoked during transfer")
}

fn timeout_error() -> io::Error {
    io::Error::new(ErrorKind::TimedOut, "upload-pack exceeded deadline")
}

fn transfer_terminated_error() -> io::Error {
    io::Error::other("checkout transfer terminated")
}

#[cfg(test)]
#[path = "s4_transport_stream_tests.rs"]
mod tests;
