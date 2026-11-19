//! Synchronous, fallible service stop-signal registration.
//!
//! The two Unix streams are constructed once before the first legacy mount can
//! be admitted. The same receivers are reused after readiness; a second signal
//! registration is never created.
use std::io;
use tokio::signal::unix::{Signal, SignalKind, signal};

pub(crate) struct StopSignals {
    term: Signal,
    int: Signal,
}

impl StopSignals {
    pub(crate) fn install() -> anyhow::Result<Self> {
        Self::install_with(|| signal(SignalKind::terminate()), || signal(SignalKind::interrupt()))
    }

    fn install_with<F, G>(term: F, int: G) -> anyhow::Result<Self>
    where
        F: FnOnce() -> io::Result<Signal>,
        G: FnOnce() -> io::Result<Signal>,
    {
        let term = term().map_err(|error| anyhow::anyhow!("SIGTERM handler registration failed: {error}"))?;
        let int = int().map_err(|error| anyhow::anyhow!("SIGINT handler registration failed: {error}"))?;
        Ok(Self { term, int })
    }

    /// Wait for one stop signal. A closed stream is a finite primary error,
    /// not an unobservable infinite wait.
    pub(crate) async fn next(&mut self) -> anyhow::Result<()> {
        tokio::select! {
            biased;
            term = self.term.recv() => match term {
                Some(()) => Ok(()),
                None => Err(anyhow::anyhow!("SIGTERM signal stream closed")),
            },
            int = self.int.recv() => match int {
                Some(()) => Ok(()),
                None => Err(anyhow::anyhow!("SIGINT signal stream closed")),
            },
        }
    }
}

#[cfg(test)]
#[path = "signal_tests.rs"]
mod tests;
