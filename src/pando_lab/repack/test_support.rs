//! Test-only timing/fault hooks for the ignored repack PostgreSQL cases.
//!
//! These hooks are compiled only under `cfg(test)` and are inert unless the
//! owning test installs a barrier directory or fault point.

use anyhow::{Result, bail, ensure};
use std::path::PathBuf;
use std::sync::Mutex;

static BARRIER: Mutex<Option<PathBuf>> = Mutex::new(None);
static FAULT: Mutex<Option<String>> = Mutex::new(None);

pub(super) fn set_barrier(dir: Option<PathBuf>) {
    *BARRIER.lock().expect("repack test barrier lock") = dir;
}

pub(super) fn set_fault(point: Option<&str>) {
    *FAULT.lock().expect("repack test fault lock") = point.map(str::to_owned);
}

pub(super) async fn barrier(point: &str) -> Result<()> {
    let dir = { BARRIER.lock().expect("repack test barrier lock").clone() };
    let Some(dir) = dir else {
        return Ok(());
    };
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join(format!("{point}.ready")), b"")?;
    let started = std::time::Instant::now();
    while !dir.join(format!("{point}.release")).exists() {
        ensure!(started.elapsed().as_secs() < 30, "repack test publication barrier timeout");
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    Ok(())
}

pub(super) fn fault(point: &str) -> Result<()> {
    let fault = { FAULT.lock().expect("repack test fault lock").clone() };
    if fault.as_deref() == Some(point) {
        bail!("test fault injection after repack object-store publication before commit");
    }
    Ok(())
}
