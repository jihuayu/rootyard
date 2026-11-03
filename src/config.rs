use anyhow::{Context, Result, bail};
use std::{env, net::SocketAddr, path::PathBuf, time::Duration};

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
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let data_dir =
            PathBuf::from(env::var("ROOTYARD_DATA_DIR").unwrap_or_else(|_| "data".into()));
        let git = if let Ok(path) = env::var("ROOTYARD_GIT") {
            PathBuf::from(path)
        } else {
            env::split_paths(&env::var_os("PATH").unwrap_or_default())
                .map(|dir| dir.join("git"))
                .find(|path| path.is_file())
                .context("git executable is required")?
        };
        let git = git
            .canonicalize()
            .context("ROOTYARD_GIT must point to Git")?;
        let database_url = env::var("DATABASE_URL").context("DATABASE_URL is required")?;
        // TLS termination for PG belongs to a private local proxy in phase one.
        // Never silently downgrade a request for TLS.
        let pg: tokio_postgres::Config = database_url.parse().context("invalid DATABASE_URL")?;
        if matches!(pg.get_ssl_mode(), tokio_postgres::config::SslMode::Require) {
            bail!("PostgreSQL TLS is not built in: use a local TLS proxy, not sslmode=require");
        }
        Ok(Self {
            database_url,
            data_dir,
            bind: env::var("ROOTYARD_BIND")
                .unwrap_or_else(|_| "127.0.0.1:8080".into())
                .parse()?,
            git,
            max_request_bytes: number("ROOTYARD_MAX_REQUEST_BYTES", 128 * 1024 * 1024)?,
            max_output_bytes: number("ROOTYARD_MAX_OUTPUT_BYTES", 512 * 1024 * 1024)?,
            max_concurrent_git: number("ROOTYARD_MAX_CONCURRENT_GIT", 8)?.try_into()?,
            git_timeout: Duration::from_secs(number("ROOTYARD_GIT_TIMEOUT_SECONDS", 120)?),
            git_memory_bytes: number("ROOTYARD_GIT_MEMORY_BYTES", 1024 * 1024 * 1024)?,
            max_repo_bytes: number("ROOTYARD_MAX_REPO_BYTES", 1024 * 1024 * 1024)?,
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
