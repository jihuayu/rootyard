//! Only settings used by the Blob serving profile are parsed here.
use crate::blob_git_gateway::{BlobGitConfig, SessionTokens};
use crate::blob_store::opendal::BlobStore;
use anyhow::{Result, anyhow, ensure};
use deadpool_postgres::Pool;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::{
    env,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

pub(super) fn gateway_config(
    pool: Pool,
    store: BlobStore,
) -> Result<(SocketAddr, BlobGitConfig, Option<SessionTokens>)> {
    let bind = env::var("ROOTYARD_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8080".into())
        .parse()
        .map_err(|_| anyhow!("invalid ROOTYARD_BIND"))?;
    let git = match env::var_os("ROOTYARD_GIT") {
        Some(path) => PathBuf::from(path),
        None => env::split_paths(&env::var_os("PATH").unwrap_or_default())
            .map(|directory| directory.join("git"))
            .find(|path| path.is_file())
            .ok_or_else(|| anyhow!("native Git executable is required"))?,
    };
    let git_binary = git.canonicalize().map_err(|_| anyhow!("native Git executable unavailable"))?;
    let metadata = git_binary.metadata().map_err(|_| anyhow!("native Git executable unavailable"))?;
    ensure!(metadata.is_file() && metadata.permissions().mode() & 0o111 != 0, "native Git must be executable");
    let scratch = env::var_os("ROOTYARD_SCRATCH_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("ROOTYARD_SCRATCH_DIR is required for disposable views"))?;
    ensure!(scratch.is_absolute(), "ROOTYARD_SCRATCH_DIR must be absolute");
    prepare_scratch(&scratch)?;
    let scratch_root = scratch.canonicalize().map_err(|_| anyhow!("could not resolve scratch directory"))?;
    let max_request_bytes = number("ROOTYARD_MAX_REQUEST_BYTES", 128 << 20, 64 << 10, 4 << 30)?;
    let max_inflight_bytes = number("ROOTYARD_MAX_INFLIGHT_BYTES", 256 << 20, 64 << 10, 16 << 30)?;
    ensure!(max_inflight_bytes >= max_request_bytes, "inflight byte budget is smaller than a request");
    // Repository session tokens are opt-in: no keyring means the session
    // routes answer an explicit 501 instead of using any default key.
    let sessions =
        super::session_keyring::from_environment(store.backend_identity()).map_err(|error| anyhow!("{error}"))?;
    Ok((
        bind,
        BlobGitConfig {
            pool,
            store,
            git_binary,
            scratch_root,
            max_concurrent_requests: number("ROOTYARD_MAX_CONCURRENT_GIT", 8, 1, 256)? as usize,
            max_request_bytes,
            max_response_bytes: number("ROOTYARD_MAX_OUTPUT_BYTES", 512 << 20, 64 << 10, 8 << 30)?,
            max_inflight_bytes,
            operation_deadline: Duration::from_secs(number("ROOTYARD_GIT_TIMEOUT_SECONDS", 120, 5, 900)?),
            native_limits: Default::default(),
        },
        sessions,
    ))
}

fn number(name: &'static str, default: u64, min: u64, max: u64) -> Result<u64> {
    let value = match env::var(name) {
        Ok(value) => value.parse().map_err(|_| anyhow!("invalid numeric setting {name}"))?,
        Err(env::VarError::NotPresent) => default,
        Err(_) => return Err(anyhow!("invalid numeric setting {name}")),
    };
    ensure!((min..=max).contains(&value), "setting {name} outside supported range");
    Ok(value)
}

fn prepare_scratch(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => ensure!(!meta.file_type().is_symlink() && meta.is_dir(), "scratch must be a real directory"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .recursive(true)
                .create(path)
                .map_err(|_| anyhow!("could not create scratch directory"))?;
        }
        Err(_) => return Err(anyhow!("scratch directory unavailable")),
    }
    let meta = std::fs::symlink_metadata(path).map_err(|_| anyhow!("scratch directory unavailable"))?;
    ensure!(
        meta.is_dir()
            && !meta.file_type().is_symlink()
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.permissions().mode() & 0o077 == 0,
        "scratch directory must be private and owned by the service user"
    );
    Ok(())
}
