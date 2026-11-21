//! Test-only owned child process guard with bounded kill/reap on assertion unwind.

use std::{
    process::{Child, ExitStatus},
    time::{Duration, Instant},
};

const REAP_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) struct OwnedChild(Option<Child>);

impl OwnedChild {
    pub(super) fn new(child: Child) -> Self {
        Self(Some(child))
    }

    pub(super) fn kill_and_reap(&mut self) -> Option<ExitStatus> {
        let mut child = self.0.take()?;
        let _ = child.kill();
        let status = reap_bounded(&mut child, REAP_TIMEOUT);
        if status.is_none() {
            self.0 = Some(child);
        }
        status
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.kill_and_reap();
    }
}

fn reap_bounded(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) | Err(_) => return None,
        }
    }
}
