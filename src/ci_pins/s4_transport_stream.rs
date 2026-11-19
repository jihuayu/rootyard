//! Producer-owned streaming for the S4 checkout `git-upload-pack` response.
//!
//! The response body is only a bounded view of a task that owns the Git child,
//! the stdin writer guard, the scratch hold and the stream slot. Revocation,
//! the request deadline, body disconnect and process cleanup therefore make
//! progress even when the body is never polled or its single data slot stays
//! full.
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
    io::{AsyncReadExt, AsyncWriteExt, ChildStdout},
    sync::{
        mpsc::{self, error::TrySendError},
        oneshot,
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
pub(crate) fn upload_pack_body<F>(
    state: &AppState,
    holder: DisposableCiView,
    request: Bytes,
    deadline: Instant,
    check: F,
) -> Result<Body, Error>
where
    F: FnMut() -> Check + Send + 'static,
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
    Ok(producer_body(RunningUploadPack { child, stdout, _stdin: stdin_guard, _slot: slot }, deadline, check))
}

/// Detach the owned producer from the body. The body never owns process state.
fn producer_body<O, F>(owner: O, deadline: Instant, check: F) -> Body
where
    O: PackOwner,
    F: FnMut() -> Check + Send + 'static,
{
    let (data_tx, data_rx) = mpsc::channel::<Bytes>(1);
    let (failure_tx, failure_rx) = oneshot::channel::<io::Error>();
    let aborted = Arc::new(AtomicBool::new(false));
    tokio::spawn(run_producer(owner, deadline, check, data_tx, failure_tx, aborted.clone()));
    Body::from_stream(response_stream(data_rx, failure_rx, aborted))
}

/// Map one probe to the stream action without ever awaiting an unbounded check.
async fn live_check<F>(check: &mut F, data: &mpsc::Sender<Bytes>, deadline: Instant) -> CheckOutcome
where
    F: FnMut() -> Check,
{
    let probe = check();
    tokio::pin!(probe);
    tokio::select! {
        biased;
        _ = data.closed() => CheckOutcome::Closed,
        _ = sleep_until(deadline) => CheckOutcome::TimedOut,
        _ = sleep(RECHECK_TIMEOUT) => CheckOutcome::Revoked,
        live = &mut probe => if live { CheckOutcome::Live } else { CheckOutcome::Revoked },
    }
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
        () => {
            match live_check(&mut check, &data, deadline).await {
                CheckOutcome::Live => {}
                CheckOutcome::Revoked => {
                    failure = Some(revoked_error());
                    break 'producer;
                }
                CheckOutcome::TimedOut => {
                    failure = Some(timeout_error());
                    break 'producer;
                }
                CheckOutcome::Closed => break 'producer,
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
                recheck!();
                loop {
                    tokio::select! {
                        biased;
                        _ = data.closed() => break 'producer,
                        _ = sleep_until(deadline) => {
                            failure = Some(timeout_error());
                            break 'producer;
                        }
                        _ = ticker.tick() => recheck!(),
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
                _ = ticker.tick() => recheck!(),
                read = owner.read(&mut buffer) => break read,
            }
        };

        match read {
            Ok(0) => {
                finished = true;
                break 'producer;
            }
            Ok(n) => {
                // Final live proof immediately before the chunk is queued.
                recheck!();
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
                    _ = ticker.tick() => match live_check(&mut check, &data, deadline).await {
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
fn response_stream(
    mut data: mpsc::Receiver<Bytes>,
    failure: oneshot::Receiver<io::Error>,
    aborted: Arc<AtomicBool>,
) -> impl Stream<Item = io::Result<Bytes>> + Send + 'static {
    async_stream::stream! {
        let mut failure = Box::pin(failure);
        let mut failure_open = true;
        loop {
            if aborted.load(Ordering::Acquire) {
                let error = if failure_open {
                    match failure.as_mut().await {
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
                result = failure.as_mut(), if failure_open => {
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
                        yield Ok(bytes);
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
