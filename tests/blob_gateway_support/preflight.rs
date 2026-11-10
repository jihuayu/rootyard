//! Start-up preflight for the real service: every start-up refusal this fixture
//! can detect without starting the binary is reported here with its cause,
//! before any process is spawned. The run-owned database selector and Blob
//! prefix are validated by [`super::db::prepare`] and [`super::blob::open_store`].
use std::path::Path;

use anyhow::{Result, ensure};

use super::{blob, db};

pub(super) fn preflight(binary: &Path) -> Result<()> {
    ensure!(cfg!(target_os = "linux"), "the real serve-blob service requires Linux");
    ensure!(Path::new("/proc/self/stat").exists(), "the real serve-blob service requires Linux procfs");
    ensure!(binary.is_absolute(), "ROOTYARD_SERVING_BINARY must be an absolute path");
    ensure!(binary.is_file(), "ROOTYARD_SERVING_BINARY does not name a file");
    let git = std::env::var("ROOTYARD_TEST_GIT").unwrap_or_else(|_| "/usr/bin/git".to_owned());
    ensure!(
        Path::new(&git).is_absolute() && Path::new(&git).is_file(),
        "ROOTYARD_TEST_GIT must be an absolute existing git binary"
    );
    db::prepare()?;
    // Opens the production profile and store once; also proves the run-owned
    // relative prefix is accepted by the production configuration.
    let store = blob::open_store()?;
    // The identity hex is a domain-separated digest of the provider account,
    // bucket, endpoint and prefix; it carries no credential material.
    println!("blob profile: {} backend_sha256={}", blob::describe()?, store.backend_identity().as_hex());
    Ok(())
}
