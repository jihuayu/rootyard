//! Lab code is deliberately separate from rootyard::Storage and all serving routes.
mod hook;
mod http;
mod store;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::Command,
};
use tokio_postgres::{Client, NoTls};
use uuid::Uuid;

const LIMIT: usize = 32 * 1024 * 1024;
const ZERO: &str = "0000000000000000000000000000000000000000";

#[derive(Clone)]
struct Config {
    database: String,
    root: PathBuf,
    git: PathBuf,
}
impl Config {
    fn load() -> Result<Self> {
        ensure!(
            std::env::var("PANDO_SYNTHETIC_ONLY").as_deref() == Ok("1"),
            "set PANDO_SYNTHETIC_ONLY=1 for this non-production experiment"
        );
        let database = std::env::var("PANDO_DATABASE_URL")?;
        let db: tokio_postgres::Config = database.parse()?;
        validate_database_address(&db)?;
        let root = PathBuf::from(std::env::var("PANDO_ROOT")?);
        ensure!(
            root.is_absolute(),
            "PANDO_ROOT must be absolute and disposable"
        );
        let git = PathBuf::from(std::env::var("PANDO_GIT")?);
        ensure!(git.is_absolute(), "PANDO_GIT must be absolute");
        ensure!(
            root.is_dir(),
            "create an existing disposable PANDO_ROOT directory first"
        );
        std::fs::create_dir_all(root.join("sessions"))?;
        std::fs::create_dir_all(root.join("objects"))?;
        std::fs::File::open(&root)?.sync_all()?;
        Ok(Self {
            database,
            root,
            git,
        })
    }
    async fn db(&self) -> Result<Client> {
        let (c, conn) = tokio_postgres::connect(&self.database, NoTls).await?;
        tokio::spawn(async move {
            if conn.await.is_err() {
                eprintln!("pando lab database connection ended");
            }
        });
        c.batch_execute(
            "SET statement_timeout='20s'; SET lock_timeout='10s'; SET synchronous_commit=on",
        )
        .await?;
        Ok(c)
    }
    fn git_command(&self, repo: &Path) -> Command {
        let mut c = Command::new(&self.git);
        // The native receive hook needs its Git-created quarantine environment.
        // Entry points outside that hook never inherit object routing or config
        // from the shell that launched the experiment.
        let hook = std::env::args().next().is_some_and(|s| {
            Path::new(&s)
                .file_name()
                .is_some_and(|n| n == "proc-receive" || n == "pre-receive")
        });
        if !hook {
            for (key, _) in std::env::vars_os() {
                if key.to_string_lossy().starts_with("GIT_") && key != "GIT_EXEC_PATH" {
                    c.env_remove(key);
                }
            }
        }
        c.current_dir(repo)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .kill_on_drop(true);
        c
    }
    async fn git(&self, repo: &Path, args: &[&str], input: &[u8]) -> Result<Vec<u8>> {
        let mut c = self.git_command(repo);
        c.args(args);
        let o = execute(c, input.to_vec()).await?;
        ensure!(
            o.status.success(),
            "Git command failed: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        Ok(o.stdout)
    }
}

async fn execute(mut c: Command, input: Vec<u8>) -> Result<std::process::Output> {
    c.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut p = c.spawn()?;
    let mut stdin = p.stdin.take().context("missing subprocess stdin")?;
    let stdout = p.stdout.take().context("missing subprocess stdout")?;
    let stderr = p.stderr.take().context("missing subprocess stderr")?;
    let writer = async move {
        stdin.write_all(&input).await?;
        stdin.shutdown().await
    };
    let run = async {
        let (stdout, stderr, write, status) = tokio::try_join!(
            bounded_read(stdout, LIMIT * 4),
            bounded_read(stderr, 1024 * 1024),
            async { Ok::<_, anyhow::Error>(writer.await) },
            async { Ok::<_, anyhow::Error>(p.wait().await?) }
        )?;
        if status.success() {
            write?;
        }
        Ok::<_, anyhow::Error>(std::process::Output {
            status,
            stdout,
            stderr,
        })
    };
    match tokio::time::timeout(std::time::Duration::from_secs(45), run).await {
        Ok(Ok(result)) => Ok(result),
        other => {
            let _ = p.kill().await;
            match other {
                Ok(Err(e)) => Err(e),
                Err(_) => bail!("lab subprocess timeout"),
                _ => unreachable!(),
            }
        }
    }
}

async fn bounded_read(reader: impl AsyncRead + Unpin, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .await?;
    ensure!(bytes.len() <= limit, "lab subprocess output limit");
    Ok(bytes)
}

struct Session(PathBuf);
impl Session {
    fn new(config: &Config) -> Result<Self> {
        let p = config
            .root
            .join("sessions")
            .join(Uuid::new_v4().to_string());
        std::fs::create_dir(&p)?;
        Ok(Self(p))
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Pack {
    id: Uuid,
    pack_sha256: String,
    idx_sha256: String,
}
#[derive(Clone, Serialize, Deserialize)]
struct Snapshot {
    repo: Uuid,
    generation: i64,
    storage_generation: i64,
    refs: BTreeMap<String, String>,
    packs: Vec<Pack>,
}
#[derive(Default, Deserialize)]
struct Control {
    #[serde(default)]
    fault: String,
    barrier: Option<PathBuf>,
}
fn control(config: &Config) -> Result<Control> {
    match std::fs::read(config.root.join("control.json")) {
        Ok(v) => Ok(serde_json::from_slice(&v)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Control::default()),
        Err(e) => Err(e.into()),
    }
}

async fn permitted(c: &Client, repo: Uuid, principal: &str, write: bool) -> Result<bool> {
    Ok(c.query_opt(
        "SELECT write_allowed FROM pando_lab.acl WHERE repo=$1 AND principal=$2",
        &[&repo, &principal],
    )
    .await?
    .is_some_and(|r| !write || r.get::<_, bool>(0)))
}

pub async fn run() -> Result<()> {
    let config = Config::load()?;
    if std::env::args().next().is_some_and(|s| {
        Path::new(&s)
            .file_name()
            .is_some_and(|n| n == "pre-receive")
    }) {
        return hook::pre_receive(&config).await;
    }
    if std::env::args().next().is_some_and(|s| {
        Path::new(&s)
            .file_name()
            .is_some_and(|n| n == "proc-receive")
    }) {
        return hook::run(&config).await;
    }
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("init") if args.len() == 1 => {
            config
                .db()
                .await?
                .batch_execute(include_str!("../../experimental/pando/schema.sql"))
                .await?;
        }
        Some("create-repo") if args.len() == 3 => {
            let id: Uuid = args[1].parse()?;
            ensure!(
                !args[2].is_empty() && args[2].len() <= 64,
                "invalid synthetic principal"
            );
            let mut c = config.db().await?;
            let t = c.transaction().await?;
            t.execute("INSERT INTO pando_lab.repositories(id) VALUES($1)", &[&id])
                .await?;
            t.execute(
                "INSERT INTO pando_lab.acl VALUES($1,$2,true)",
                &[&id, &args[2]],
            )
            .await?;
            t.commit().await?;
        }
        Some("serve") if args.len() == 1 => http::serve(Arc::new(config)).await?,
        Some("hook") if args.len() == 1 => hook::run(&config).await?,
        _ => bail!("usage: rootyard-pando-lab init | create-repo <uuid> <principal> | serve"),
    }
    Ok(())
}

fn validate_database_address(db: &tokio_postgres::Config) -> Result<()> {
    ensure!(
        !db.get_hosts().is_empty()
            && db.get_hosts().iter().all(
                |h| matches!(h,tokio_postgres::config::Host::Tcp(s) if s=="127.0.0.1" || s=="::1")
            ),
        "lab database must use literal loopback TCP"
    );
    // hostaddr overrides the network target while host can remain loopback.
    ensure!(
        db.get_hostaddrs().iter().all(std::net::IpAddr::is_loopback),
        "lab database hostaddr must be loopback"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn database_address_rejects_remote_overrides() {
        for dsn in [
            "host=127.0.0.1 hostaddr=192.0.2.1",
            "host=::1 hostaddr=2001:db8::1",
            "host=127.0.0.1,127.0.0.1 hostaddr=127.0.0.1,192.0.2.1",
            "host=remote.invalid hostaddr=127.0.0.1",
            "hostaddr=127.0.0.1",
        ] {
            assert!(
                validate_database_address(&dsn.parse().unwrap()).is_err(),
                "{dsn}"
            );
        }
        for dsn in [
            "host=127.0.0.1",
            "host=::1",
            "host=127.0.0.1 hostaddr=127.0.0.1",
            "host=::1 hostaddr=::1",
        ] {
            assert!(
                validate_database_address(&dsn.parse().unwrap()).is_ok(),
                "{dsn}"
            );
        }
    }
}
