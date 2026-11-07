use anyhow::{Context, Result, bail};
use std::{env, net::SocketAddr, path::PathBuf, sync::OnceLock, time::Duration};

const WORKSPACE_UNSAFE_REMOTE_DELETE: &str = "ROOTYARD_WORKSPACE_UNSAFE_REMOTE_DELETE";
static WORKSPACE_UNSAFE_REMOTE_DELETE_ENABLED: OnceLock<bool> = OnceLock::new();

/// Startup-validated switch for the legacy physical delete of workspace
/// checkpoint objects. The name is intentionally unsafe: this is not a
/// substitute for a PITR-aware external delete broker.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WorkspaceRemoteDeletePolicy {
    unsafe_remote_delete: bool,
}

impl WorkspaceRemoteDeletePolicy {
    pub fn from_env() -> Result<Self> {
        let value = match env::var(WORKSPACE_UNSAFE_REMOTE_DELETE) {
            Ok(value) => Some(value),
            Err(env::VarError::NotPresent) => None,
            Err(env::VarError::NotUnicode(_)) => bail!("{WORKSPACE_UNSAFE_REMOTE_DELETE} must be true or false"),
        };
        Self::from_value(value.as_deref())
    }

    fn from_value(value: Option<&str>) -> Result<Self> {
        let unsafe_remote_delete = match value {
            None | Some("false") => false,
            Some("true") => true,
            Some(_) => bail!("{WORKSPACE_UNSAFE_REMOTE_DELETE} must be true or false"),
        };
        Ok(Self { unsafe_remote_delete })
    }

    pub fn enabled(self) -> bool {
        self.unsafe_remote_delete
    }

    fn install(self) {
        let _ = WORKSPACE_UNSAFE_REMOTE_DELETE_ENABLED.set(self.unsafe_remote_delete);
    }
}

/// Validate the workspace remote-delete switch once, before serving starts.
/// Invalid values fail startup; a missing value keeps the safe default off.
pub fn init_workspace_remote_delete_policy() -> Result<()> {
    WorkspaceRemoteDeletePolicy::from_env()?.install();
    Ok(())
}

/// Fail closed until startup installed an explicit unsafe opt-in.
pub fn workspace_unsafe_remote_delete() -> bool {
    *WORKSPACE_UNSAFE_REMOTE_DELETE_ENABLED.get().unwrap_or(&false)
}

#[derive(Clone)]
pub struct Config {
    pub database_url: String,
    pub data_dir: PathBuf,
    pub bind: SocketAddr,
    pub git: PathBuf,
    pub max_request_bytes: u64,
    pub max_output_bytes: u64,
    pub max_concurrent_git: usize,
    pub git_timeout: Duration,
    pub git_memory_bytes: u64,
    pub max_repo_bytes: u64,
    pub max_pending_deliveries: i64,
    pub outbox_worker: bool,
    pub metrics_bind: Option<SocketAddr>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let data_dir = PathBuf::from(env::var("ROOTYARD_DATA_DIR").unwrap_or_else(|_| "data".into()));
        let git = if let Ok(path) = env::var("ROOTYARD_GIT") {
            PathBuf::from(path)
        } else {
            env::split_paths(&env::var_os("PATH").unwrap_or_default())
                .map(|dir| dir.join("git"))
                .find(|path| path.is_file())
                .context("git executable is required")?
        };
        let git = git.canonicalize().context("ROOTYARD_GIT must point to Git")?;
        let database_url = env::var("DATABASE_URL").context("DATABASE_URL is required")?;
        let _pg: tokio_postgres::Config = database_url.parse().context("invalid DATABASE_URL")?;
        Ok(Self {
            metrics_bind: env::var("ROOTYARD_METRICS_BIND")
                .ok()
                .map(|v| crate::metrics::validate_bind(v.parse()?))
                .transpose()?,
            database_url,
            data_dir,
            bind: env::var("ROOTYARD_BIND").unwrap_or_else(|_| "127.0.0.1:8080".into()).parse()?,
            git,
            max_request_bytes: number("ROOTYARD_MAX_REQUEST_BYTES", 128 * 1024 * 1024)?,
            max_output_bytes: number("ROOTYARD_MAX_OUTPUT_BYTES", 512 * 1024 * 1024)?,
            max_concurrent_git: number("ROOTYARD_MAX_CONCURRENT_GIT", 8)?.try_into()?,
            git_timeout: Duration::from_secs(number("ROOTYARD_GIT_TIMEOUT_SECONDS", 120)?),
            git_memory_bytes: number("ROOTYARD_GIT_MEMORY_BYTES", 1024 * 1024 * 1024)?,
            max_repo_bytes: number("ROOTYARD_MAX_REPO_BYTES", 1024 * 1024 * 1024)?,
            max_pending_deliveries: number("ROOTYARD_MAX_PENDING_DELIVERIES", 100_000)?.try_into()?,
            outbox_worker: match env::var("ROOTYARD_OUTBOX_WORKER").as_deref() {
                Ok("false") => false,
                Ok("true") | Err(_) => true,
                _ => bail!("ROOTYARD_OUTBOX_WORKER must be true or false"),
            },
        })
    }
}

fn number(name: &str, default: u64) -> Result<u64> {
    let n = match env::var(name) {
        Ok(v) => v.parse().with_context(|| format!("invalid {name}"))?,
        Err(_) => default,
    };
    if n == 0 {
        bail!("{name} must be positive");
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::WorkspaceRemoteDeletePolicy;

    #[test]
    fn workspace_remote_delete_defaults_to_disabled() {
        assert!(!WorkspaceRemoteDeletePolicy::from_value(None).unwrap().enabled());
        assert!(!WorkspaceRemoteDeletePolicy::from_value(Some("false")).unwrap().enabled());
    }

    #[test]
    fn workspace_remote_delete_accepts_only_explicit_true() {
        assert!(WorkspaceRemoteDeletePolicy::from_value(Some("true")).unwrap().enabled());
        for invalid in ["", "TRUE", "True", "1", "yes", "on", " true", "true "] {
            assert!(
                WorkspaceRemoteDeletePolicy::from_value(Some(invalid)).is_err(),
                "accepted invalid value {invalid:?}"
            );
        }
    }
}
