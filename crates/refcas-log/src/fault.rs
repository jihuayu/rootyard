//! Deterministic storage fault injection hooks and install barriers for crash/failure probes.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex, mpsc};

use serde::{Deserialize, Serialize};

/// Named durable-IO fault injection point across log, state machine, and snapshot storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum FaultPoint {
    LogVoteSync,
    LogAppendSync,
    LogAppendEnospc,
    SmApplySync,
    SmApplyEnospc,
    SnapshotBuildWriteEnospc,
    SnapshotBuildSync,
    SnapshotInstallWriteEnospc,
    SnapshotInstallStageSync,
    SnapshotInstallCommitSync,
}

impl FaultPoint {
    /// Returns true if this fault point simulates disk-full (`ENOSPC`).
    pub fn is_enospc(self) -> bool {
        matches!(
            self,
            Self::LogAppendEnospc
                | Self::SmApplyEnospc
                | Self::SnapshotBuildWriteEnospc
                | Self::SnapshotInstallWriteEnospc
        )
    }
}

/// Firing behavior for an armed fault point.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum FaultMode {
    Once,
    Always,
}

/// Wire and test configuration entry for arming a fault point.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FaultSpec {
    pub point: FaultPoint,
    pub mode: FaultMode,
}

struct InstallPause {
    entered: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
}

/// Shared fault controller attached to `PersistentLog` and `PersistentStateMachine`.
#[derive(Default)]
pub struct FaultController {
    armed: Mutex<HashMap<FaultPoint, FaultMode>>,
    install_pause: Mutex<Option<InstallPause>>,
}

impl FaultController {
    /// Creates an inactive fault controller for normal production/test execution.
    pub fn noop() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Arms `spec.point` to return an IO error on its next invocation.
    pub fn arm(&self, spec: FaultSpec) {
        let mut guard = self.armed.lock().expect("fault controller poisoned");
        guard.insert(spec.point, spec.mode);
    }

    /// Clears any armed fault for `point`.
    pub fn clear(&self, point: FaultPoint) {
        let mut guard = self.armed.lock().expect("fault controller poisoned");
        guard.remove(&point);
    }

    /// Clears all armed faults and any pending install barrier.
    pub fn clear_all(&self) {
        self.armed.lock().expect("fault controller poisoned").clear();
        *self.install_pause.lock().expect("install pause poisoned") = None;
    }

    /// Checks whether `point` is armed, returning the injected `io::Error` if triggered.
    pub fn check(&self, point: FaultPoint) -> io::Result<()> {
        let hit = {
            let mut guard = self.armed.lock().expect("fault controller poisoned");
            match guard.get(&point).copied() {
                Some(FaultMode::Once) => {
                    guard.remove(&point);
                    true
                }
                Some(FaultMode::Always) => true,
                None => false,
            }
        };
        if hit { Err(fault_io_error(point)) } else { Ok(()) }
    }

    /// Installs a one-shot pause gate inside `install_snapshot` before SQLite commit.
    pub fn arm_install_pause(&self) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let mut guard = self.install_pause.lock().expect("install pause poisoned");
        *guard = Some(InstallPause { entered: entered_tx, release: release_rx });
        (entered_rx, release_tx)
    }

    /// Signals test coordinator and waits for release when a one-shot install pause is armed.
    pub fn pause_install_if_armed(&self) {
        let pause = self.install_pause.lock().expect("install pause poisoned").take();
        if let Some(InstallPause { entered, release }) = pause {
            let _ = entered.send(());
            let _ = release.recv();
        }
    }
}

/// Builds a realistic OS `io::Error` for the injected fault point.
pub fn fault_io_error(point: FaultPoint) -> io::Error {
    if point.is_enospc() { enospc_error(point) } else { fsync_error(point) }
}

#[cfg(unix)]
fn enospc_error(point: FaultPoint) -> io::Error {
    let base = io::Error::from_raw_os_error(28);
    io::Error::new(base.kind(), format!("injected ENOSPC at {point:?}: {base}"))
}

#[cfg(not(unix))]
fn enospc_error(point: FaultPoint) -> io::Error {
    io::Error::new(io::ErrorKind::StorageFull, format!("injected ENOSPC at {point:?}"))
}

#[cfg(unix)]
fn fsync_error(point: FaultPoint) -> io::Error {
    let base = io::Error::from_raw_os_error(5);
    io::Error::new(base.kind(), format!("injected fsync EIO at {point:?}: {base}"))
}

#[cfg(not(unix))]
fn fsync_error(point: FaultPoint) -> io::Error {
    io::Error::other(format!("injected fsync EIO at {point:?}"))
}
