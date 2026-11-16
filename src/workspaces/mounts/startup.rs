//! Serial, owned startup reconciliation for legacy workspace mounts.
//!
//! One producer owns at most one active ensure control job at a time. A
//! cooperative stop token prevents new row admission and cancels only work
//! that has not yet been submitted. Once an ensure closure is submitted, the
//! producer awaits its actual blocking completion; it never treats a nested
//! observation timeout or a dropped async waiter as mount completion.
use super::super::blocking::{OwnedControl, start_control_owned};
use super::{ensure, mode};
use crate::{AppState, Error};
use std::{future::Future, pin::Pin, sync::Arc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Terminal producer state. `Stopped` is a cooperative admission stop before a
/// new row was submitted, not an application error.
#[derive(Debug)]
pub enum StartupOutcome {
    Completed(Result<(), Error>),
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupJoinError {
    Panicked,
    Cancelled,
    Deadline,
    AlreadyJoined,
}

type StartupProducer = Pin<Box<dyn Future<Output = StartupOutcome> + Send>>;

/// Library-owned startup producer handle. It is stored by the service before
/// the setup future is first polled, but it is initially inert: the producer
/// future is not spawned until the first owned wait is polled. A ready stop
/// therefore creates no producer at all, while a setup win starts it exactly
/// once. Dropping a waiter cannot drop the stored future or an already-started
/// JoinHandle.
pub struct StartupReconcile {
    stop: CancellationToken,
    producer: Option<StartupProducer>,
    task: Option<JoinHandle<StartupOutcome>>,
    started: bool,
}

enum StartGate {
    Started,
    Stopped,
    AlreadyJoined,
}

impl StartupReconcile {
    /// Prepare the inert producer future. Nothing is polled or spawned here.
    pub fn prepare(state: Arc<AppState>) -> Self {
        let stop = CancellationToken::new();
        let producer: StartupProducer = Box::pin(produce(state, stop.clone()));
        Self { stop, producer: Some(producer), task: None, started: false }
    }

    /// Gate the first owner poll on the cooperative stop and spawn at most one
    /// producer. A stop observed before this point drops the unstarted future
    /// without a query, permit, or ensure.
    fn start_once(&mut self) -> StartGate {
        if self.task.is_some() {
            return StartGate::Started;
        }
        if self.started {
            return StartGate::AlreadyJoined;
        }
        if self.stop.is_cancelled() {
            self.producer = None;
            self.started = true;
            return StartGate::Stopped;
        }
        let Some(producer) = self.producer.take() else {
            self.started = true;
            return StartGate::AlreadyJoined;
        };
        self.task = Some(tokio::spawn(producer));
        self.started = true;
        StartGate::Started
    }

    /// Cooperative stop. It never aborts an already-submitted ensure closure.
    pub fn stop(&self) {
        self.stop.cancel();
    }

    pub fn is_pending(&self) -> bool {
        self.task.is_some() || (self.producer.is_some() && !self.started)
    }

    /// Await producer completion without consuming the handle on future drop.
    /// If the surrounding setup future is dropped, the handle remains here and
    /// cleanup can join the same producer under its own deadline.
    pub async fn wait(&mut self) -> Result<StartupOutcome, StartupJoinError> {
        match self.start_once() {
            StartGate::Stopped => return Ok(StartupOutcome::Stopped),
            StartGate::AlreadyJoined => return Err(StartupJoinError::AlreadyJoined),
            StartGate::Started => {}
        }
        let result = {
            let Some(task) = self.task.as_mut() else {
                return Err(StartupJoinError::AlreadyJoined);
            };
            match task.await {
                Ok(outcome) => Ok(outcome),
                Err(error) if error.is_panic() => Err(StartupJoinError::Panicked),
                Err(_) => Err(StartupJoinError::Cancelled),
            }
        };
        self.task = None;
        result
    }

    /// Bounded observation. On `Deadline`, the real producer handle remains in
    /// this owner and a later observation joins the same work.
    pub async fn join_until(&mut self, deadline: tokio::time::Instant) -> Result<StartupOutcome, StartupJoinError> {
        match self.start_once() {
            StartGate::Stopped => return Ok(StartupOutcome::Stopped),
            StartGate::AlreadyJoined => return Err(StartupJoinError::AlreadyJoined),
            StartGate::Started => {}
        }
        let result = {
            let Some(task) = self.task.as_mut() else {
                return Err(StartupJoinError::AlreadyJoined);
            };
            match tokio::time::timeout_at(deadline, task).await {
                Ok(Ok(outcome)) => Ok(outcome),
                Ok(Err(error)) if error.is_panic() => Err(StartupJoinError::Panicked),
                Ok(Err(_)) => Err(StartupJoinError::Cancelled),
                Err(_) => return Err(StartupJoinError::Deadline),
            }
        };
        self.task = None;
        result
    }

    /// Consume and join the producer. Used by the compatibility entrypoint.
    pub async fn join(mut self) -> Result<StartupOutcome, StartupJoinError> {
        match self.start_once() {
            StartGate::Stopped => return Ok(StartupOutcome::Stopped),
            StartGate::AlreadyJoined => return Err(StartupJoinError::AlreadyJoined),
            StartGate::Started => {}
        }
        let Some(task) = self.task else {
            return Err(StartupJoinError::AlreadyJoined);
        };
        match task.await {
            Ok(outcome) => Ok(outcome),
            Err(error) if error.is_panic() => Err(StartupJoinError::Panicked),
            Err(_) => Err(StartupJoinError::Cancelled),
        }
    }

    #[cfg(test)]
    fn from_task(stop: CancellationToken, task: JoinHandle<StartupOutcome>) -> Self {
        Self { stop, producer: None, task: Some(task), started: true }
    }

    #[cfg(test)]
    fn from_future(stop: CancellationToken, producer: StartupProducer) -> Self {
        Self { stop, producer: Some(producer), task: None, started: false }
    }
}

#[derive(Debug, Clone, Copy)]
struct StartupRow {
    id: Uuid,
    epoch: i64,
    until: i64,
}

#[derive(Debug)]
enum ProduceError {
    Stopped,
    Failed(Error),
}

type StartFuture = Pin<Box<dyn Future<Output = Result<Box<dyn StartedWork>, Error>> + Send>>;
type JoinFuture = Pin<Box<dyn Future<Output = Result<(), Error>> + Send>>;

/// One already-submitted ensure control job. The join has no work timeout.
trait StartedWork: Send {
    fn join(self: Box<Self>) -> JoinFuture;
}

struct NativeStarted(OwnedControl<()>);

impl StartedWork for NativeStarted {
    fn join(self: Box<Self>) -> JoinFuture {
        let NativeStarted(control) = *self;
        Box::pin(async move { control.join().await })
    }
}

async fn produce(state: Arc<AppState>, stop: CancellationToken) -> StartupOutcome {
    match reconcile_owned(state, stop).await {
        Ok(()) => StartupOutcome::Completed(Ok(())),
        Err(ProduceError::Stopped) => StartupOutcome::Stopped,
        Err(ProduceError::Failed(error)) => StartupOutcome::Completed(Err(error)),
    }
}

async fn reconcile_owned(state: Arc<AppState>, stop: CancellationToken) -> Result<(), ProduceError> {
    let mode = mode();
    if mode == "direct" {
        return Ok(());
    }
    if mode != "fuse" && mode != "fuse-helper" {
        return Err(ProduceError::Failed(Error::internal("invalid workspace mount mode")));
    }
    if stop.is_cancelled() {
        return Err(ProduceError::Stopped);
    }
    let client = tokio::select! {
        biased;
        _ = stop.cancelled() => return Err(ProduceError::Stopped),
        result = state.pool.get() => result.map_err(|error| ProduceError::Failed(Error::internal(error)))?,
    };
    let rows = tokio::select! {
        biased;
        _ = stop.cancelled() => return Err(ProduceError::Stopped),
        result = client.query(
            "SELECT id,lease_epoch,EXTRACT(EPOCH FROM lease_until)::bigint FROM workspaces \
             WHERE host_id=$1 AND state='ready' ORDER BY id",
            &[&state.storage.volume_id],
        ) => result.map_err(|error| ProduceError::Failed(Error::internal(error)))?,
    };
    drop(client);
    let rows: Vec<StartupRow> = rows
        .into_iter()
        .map(|row| {
            let id: Uuid = row.get(0);
            let epoch: i64 = row.get(1);
            let until: i64 = row.get(2);
            StartupRow { id, epoch, until }
        })
        .collect();
    let work_state = state.clone();
    produce_serial(stop, rows, move |row| {
        let state = work_state.clone();
        Box::pin(async move {
            let control = start_control_owned(move || ensure(&state, row.id, row.epoch, row.until)).await?;
            Ok(Box::new(NativeStarted(control)) as Box<dyn StartedWork>)
        })
    })
    .await
}

async fn produce_serial<F>(stop: CancellationToken, rows: Vec<StartupRow>, mut start: F) -> Result<(), ProduceError>
where
    F: FnMut(StartupRow) -> StartFuture + Send + 'static,
{
    for row in rows {
        if stop.is_cancelled() {
            return Err(ProduceError::Stopped);
        }
        let started = tokio::select! {
            biased;
            _ = stop.cancelled() => return Err(ProduceError::Stopped),
            result = start(row) => result.map_err(ProduceError::Failed)?,
        };
        // The closure is already submitted. Cooperative stop is deliberately
        // ignored here; only the actual join may complete this row.
        started.join().await.map_err(ProduceError::Failed)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "startup_tests.rs"]
mod tests;
