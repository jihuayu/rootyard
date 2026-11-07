//! Independent workspace FUSE helper process (issue #91, phase 3).
//!
//! One helper child serves one API service generation. The API process no
//! longer owns a `fuser::BackgroundSession`: it talks to the child over two
//! private `UnixStream::pair` sockets and keeps only a client registration per
//! mounted workspace.
//!
//! Layout of this module:
//!
//! * [`protocol`] - framed, `deny_unknown_fields`, versioned control messages.
//! * [`client`] - parent side: spawn, environment scrub, request dispatch,
//!   heartbeat writer and bounded shutdown.
//! * [`server`] - child side: control loop, per-workspace mount/gate registry,
//!   freeze threads, heartbeat watchdog and fail-closed teardown.
//!
//! Boundaries this module deliberately keeps:
//!
//! * The child never opens PostgreSQL, `Store`, the volume lock or the HTTP
//!   router. `main` branches to [`server::run`] before `Config::from_env`.
//! * The parent sends only its storage root and a workspace UUID. The child
//!   validates the root as an existing, symlink-free directory and composes
//!   `workspace-service/{workspaces,uppers,mounts,lazy-cache}/<uuid>` itself, so
//!   there is no "read this path" command on the control socket.
//! * The inherited sockets are anonymous `AF_UNIX` stream pairs. The child opens
//!   no filesystem listener and cannot be reached from outside its parent.
//! * The child inherits `PATH`, `LC_ALL`, the object-store credentials the
//!   parent already had, and the lazy hydration timeout - nothing else. It never
//!   sees `DATABASE_URL`, API tokens, operator credentials or any other secret.
//! * All workspaces in one child share the process-wide four-thread FUSE read
//!   pool and the two-worker lazy hydration runtime. A mount therefore does not
//!   multiply threads or remote connections.
//!
//! Known and intentional limitation: a child crash takes every mount in that
//! child down at once. There is no per-workspace process isolation; the parent
//! observes the control EOF, marks every registered workspace unusable and
//! reports `mounted(id) == false` instead of pretending one workspace survived.
use std::{
    ffi::OsString,
    io,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};
use uuid::Uuid;

pub mod client;
pub mod protocol;
pub mod server;

pub use client::{HelperClient, HelperError, RemoteFreezeToken};
pub use server::run as run_child;

/// Argument that puts the service binary into helper mode. `main` checks it
/// before it builds the HTTP runtime, reads `DATABASE_URL` or touches storage.
pub const HELPER_ARG: &str = "--workspace-fuse-helper";

/// The complete environment the child is allowed to inherit. Everything else -
/// `DATABASE_URL`, `ROOTYARD_API*`, operator/Vault credentials, proxy settings -
/// is dropped by `Command::env_clear`.
pub const INHERITED_ENV: &[&str] = &[
    "PATH",
    "LC_ALL",
    "ROOTYARD_OBJECT_STORE_ENDPOINT",
    "ROOTYARD_OBJECT_STORE_BUCKET",
    "ROOTYARD_OBJECT_STORE_REGION",
    "ROOTYARD_OBJECT_STORE_ACCESS_KEY",
    "ROOTYARD_OBJECT_STORE_SECRET_KEY",
    "ROOTYARD_OBJECT_STORE_SESSION_TOKEN",
    "ROOTYARD_WORKSPACE_LAZY_TIMEOUT_MS",
];

/// Fixed child-side paths for one workspace. The UUID is the only variable
/// component, so no caller-supplied path can escape the storage root.
#[derive(Debug, Clone)]
pub struct WorkspacePaths {
    pub root: PathBuf,
    pub lower: PathBuf,
    pub upper: PathBuf,
    pub mountpoint: PathBuf,
}

pub fn workspace_paths(root: &Path, id: Uuid) -> WorkspacePaths {
    let name = id.to_string();
    WorkspacePaths {
        root: root.to_path_buf(),
        lower: root.join("workspace-service/workspaces").join(&name),
        upper: root.join("workspace-service/uppers").join(&name),
        mountpoint: root.join("workspace-service/mounts").join(&name),
    }
}

/// Copy only the whitelisted variables from a lookup function.
///
/// Kept as a pure function so the scrub list is unit-testable without spawning
/// a process.
pub fn helper_env<F>(lookup: F) -> Vec<(String, OsString)>
where
    F: Fn(&str) -> Option<OsString>,
{
    INHERITED_ENV
        .iter()
        .filter_map(|name| lookup(name).map(|value| ((*name).to_owned(), value)))
        .collect()
}

/// Validate the parent-supplied storage root inside the child.
///
/// The path must be absolute, must open as a directory with `O_NOFOLLOW` (so a
/// symlinked or replaced root is refused) and is returned canonicalized. Every
/// later path is composed from this value and one UUID.
pub fn validate_root(raw: &str) -> io::Result<PathBuf> {
    let path = Path::new(raw);
    if raw.is_empty() || !path.is_absolute() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "helper root must be an absolute path"));
    }
    let dir = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| io::Error::new(error.kind(), format!("helper root is not openable: {error}")))?;
    if !dir.metadata()?.is_dir() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "helper root is not a directory"));
    }
    path.canonicalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn only_whitelisted_environment_reaches_the_child() {
        let names = ["PATH", "DATABASE_URL", "ROOTYARD_API_TOKEN", "VAULT_TOKEN", "AWS_SECRET_ACCESS_KEY"];
        let env = helper_env(|name| names.contains(&name).then(|| OsString::from(format!("value-{name}"))));
        assert_eq!(env, vec![("PATH".to_owned(), OsString::from("value-PATH"))]);
        let env = helper_env(|name| {
            (name == "ROOTYARD_OBJECT_STORE_SECRET_KEY").then(|| OsString::from("s3-secret"))
        });
        assert_eq!(env.len(), 1);
        assert!(helper_env(|name| (name == "DATABASE_URL").then(|| OsString::from("postgres://x"))).is_empty());
    }

    #[test]
    fn workspace_paths_are_uuid_only_and_stay_under_the_root() {
        let root = Path::new("/var/lib/rootyard");
        let id = Uuid::nil();
        let paths = workspace_paths(root, id);
        assert_eq!(paths.lower, root.join("workspace-service/workspaces").join(id.to_string()));
        assert_eq!(paths.upper, root.join("workspace-service/uppers").join(id.to_string()));
        assert_eq!(paths.mountpoint, root.join("workspace-service/mounts").join(id.to_string()));
        assert!(paths.upper.starts_with(root) && paths.mountpoint.starts_with(root));
    }

    #[test]
    fn root_validation_rejects_relative_and_symlinked_roots() {
        assert!(validate_root("data").is_err());
        assert!(validate_root("").is_err());
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("store");
        fs::create_dir(&real).unwrap();
        assert_eq!(validate_root(real.to_str().unwrap()).unwrap(), real.canonicalize().unwrap());
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(validate_root(link.to_str().unwrap()).is_err(), "a symlinked root must be refused");
    }
}
