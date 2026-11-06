//! Lab code is deliberately separate from rootyard::Storage and all serving routes.
pub mod delta;
pub mod export;
pub mod graph;
mod hook;
mod http;
pub mod lifecycle;
pub mod migration;
pub mod object_format;
pub mod object_store;
pub mod repack;
mod remote;
pub mod rollback;
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
        Some("verify-delta") if args.len() == 2 => {
            let bytes = std::fs::read(&args[1])?;
            let report = delta::verify_pack(&bytes, &delta::Limits::default())?;
            println!("{}", serde_json::to_string(&report)?);
        }
        Some("walk-graph") if args.len() >= 2 => {
            let repo: Uuid = args[1].parse()?;
            let mut wants = Vec::new();
            let mut haves = Vec::new();
            let mut in_haves = false;
            for arg in &args[2..] {
                if arg == "--have" {
                    in_haves = true;
                } else if let Some(stripped) = arg.strip_prefix('^') {
                    haves.push(stripped.to_owned());
                } else if in_haves {
                    haves.push(arg.clone());
                    in_haves = false;
                } else {
                    wants.push(arg.clone());
                }
            }
            let snap = store::snapshot(&config, repo).await?;
            let mut obj_store = graph::ObjectStore::default();
            for pack in &snap.packs {
                object_store::ensure_local_pack_cached(&config, repo, pack).await?;
                let prefix = config
                    .root
                    .join("objects")
                    .join(repo.to_string())
                    .join(pack.id.to_string());
                let pack_bytes = std::fs::read(prefix.with_extension("pack"))?;
                let report = delta::verify_pack(&pack_bytes, &delta::Limits::default())?;
                obj_store.insert_pack(&report);
            }
            if wants.is_empty() {
                wants = snap.refs.values().cloned().collect();
            }
            let report = graph::walk_reachable(&obj_store, &wants, &haves)?;
            println!("{}", serde_json::to_string(&report)?);
        }
        Some("diff-export") if args.len() >= 2 => {
            let repo: Uuid = args[1].parse()?;
            let mut haves = Vec::new();
            let mut in_haves = false;
            for arg in &args[2..] {
                if arg == "--have" {
                    in_haves = true;
                } else if let Some(stripped) = arg.strip_prefix('^') {
                    haves.push(stripped.to_owned());
                } else if in_haves {
                    haves.push(arg.clone());
                    in_haves = false;
                }
            }
            let report = export::diff_export(&config, repo, &haves).await?;
            println!("{}", serde_json::to_string(&report)?);
        }
        Some("gc") if args.len() == 1 || args.len() == 2 => {
            let repo = args.get(1).map(|s| s.parse::<Uuid>()).transpose()?;
            let report = store::gc(&config, repo).await?;
            println!("{}", serde_json::to_string(&report)?);
        }
        Some("migrate") if args.len() == 3 => {
            let repo: Uuid = args[1].parse()?;
            let report = migration::migrate_full(&config, repo, Path::new(&args[2])).await?;
            println!("{}", serde_json::to_string(&report)?);
        }
        Some("migrate-step") if args.len() == 4 => {
            let repo: Uuid = args[1].parse()?;
            let report =
                migration::migrate_step(&config, repo, Path::new(&args[2]), &args[3]).await?;
            println!("{}", serde_json::to_string(&report)?);
        }
        Some("rollback") if args.len() == 3 => {
            let repo: Uuid = args[1].parse()?;
            let report = rollback::rollback(&config, repo, Path::new(&args[2])).await?;
            println!("{}", serde_json::to_string(&report)?);
        }
        Some("migration-status") if args.len() == 2 => {
            let repo: Uuid = args[1].parse()?;
            let report = migration::status(&config, repo).await?;
            println!("{}", serde_json::to_string(&report)?);
        }
        Some("repack") if args.len() >= 2 => {
            let repo: Uuid = args[1].parse()?;
            let mut opts = repack::RepackOptions::default();
            let mut i = 2usize;
            while i < args.len() {
                match args[i].as_str() {
                    "--prune-superseded" => {
                        opts.prune_superseded = true;
                        i += 1;
                    }
                    "--no-object-store" => {
                        opts.sync_object_store = false;
                        i += 1;
                    }
                    "--pin-oid" => {
                        let oid = args.get(i + 1).context("missing value for --pin-oid")?;
                        opts.pin_oids.push(oid.clone());
                        i += 2;
                    }
                    other => bail!("unknown repack flag '{other}'"),
                }
            }
            let report = repack::repack_repo(&config, repo, &opts).await?;
            println!("{}", serde_json::to_string(&report)?);
        }
        Some("pin-root") if args.len() == 4 => {
            let repo: Uuid = args[1].parse()?;
            let report = repack::pin_root(&config, repo, &args[2], &args[3]).await?;
            println!("{}", serde_json::to_string(&report)?);
        }
        Some("unpin-root") if args.len() == 3 => {
            let repo: Uuid = args[1].parse()?;
            let report = repack::unpin_root(&config, repo, &args[2]).await?;
            println!("{}", serde_json::to_string(&report)?);
        }
        Some("object-store-put") if args.len() >= 3 => {
            let repo: Uuid = args[1].parse()?;
            let pack_id: Uuid = args[2].parse()?;
            let mut opts = object_store::ObjectStorePutOptions::default();
            let mut i = 3usize;
            while i < args.len() {
                match args[i].as_str() {
                    "--chunk-size" => {
                        opts.chunk_size = args
                            .get(i + 1)
                            .context("missing value for --chunk-size")?
                            .parse()?;
                        i += 2;
                    }
                    "--fail-after-chunks" => {
                        opts.fail_after_chunks = Some(
                            args.get(i + 1)
                                .context("missing value for --fail-after-chunks")?
                                .parse()?,
                        );
                        i += 2;
                    }
                    "--corrupt-chunk" => {
                        opts.corrupt_chunk_part = Some(
                            args.get(i + 1)
                                .context("missing value for --corrupt-chunk")?
                                .parse()?,
                        );
                        i += 2;
                    }
                    "--bucket" => {
                        opts.bucket = args
                            .get(i + 1)
                            .context("missing value for --bucket")?
                            .clone();
                        i += 2;
                    }
                    other => bail!("unknown object-store-put flag '{other}'"),
                }
            }
            let report = object_store::put_pack(&config, repo, pack_id, &opts).await?;
            println!("{}", serde_json::to_string(&report)?);
        }
        Some("object-store-get") if args.len() == 3 => {
            let repo: Uuid = args[1].parse()?;
            let pack_id: Uuid = args[2].parse()?;
            let report = object_store::get_pack(&config, repo, pack_id).await?;
            println!("{}", serde_json::to_string(&report)?);
        }
        Some("object-store-verify") if args.len() == 2 => {
            let repo: Uuid = args[1].parse()?;
            let report = object_store::verify_repo_store(&config, repo).await?;
            println!("{}", serde_json::to_string(&report)?);
        }
        Some("object-store-status") if args.len() == 2 => {
            let repo: Uuid = args[1].parse()?;
            let report = object_store::status(&config, repo).await?;
            println!("{}", serde_json::to_string(&report)?);
        }
        Some("lifecycle-evaluate") if args.len() >= 2 => {
            let repo: Uuid = args[1].parse()?;
            let mut opts = lifecycle::LifecycleEvaluateOptions::default();
            let mut i = 2usize;
            while i < args.len() {
                match args[i].as_str() {
                    "--max-packs" => {
                        opts.max_active_packs = Some(
                            args.get(i + 1)
                                .context("missing value for --max-packs")?
                                .parse()?,
                        );
                        i += 2;
                    }
                    "--cold-age-secs" => {
                        opts.cold_transition_age_secs = Some(
                            args.get(i + 1)
                                .context("missing value for --cold-age-secs")?
                                .parse()?,
                        );
                        i += 2;
                    }
                    "--cold-evict-local" => {
                        opts.cold_evict_local = true;
                        i += 1;
                    }
                    "--auto-repack" => {
                        opts.auto_repack_enabled = Some(true);
                        i += 1;
                    }
                    "--no-auto-repack" => {
                        opts.auto_repack_enabled = Some(false);
                        i += 1;
                    }
                    "--kms-key-id" => {
                        opts.kms_key_id = Some(
                            args.get(i + 1)
                                .context("missing value for --kms-key-id")?
                                .clone(),
                        );
                        i += 2;
                    }
                    "--cipher-suite" => {
                        opts.cipher_suite = Some(
                            args.get(i + 1)
                                .context("missing value for --cipher-suite")?
                                .clone(),
                        );
                        i += 2;
                    }
                    other => bail!("unknown lifecycle-evaluate flag '{other}'"),
                }
            }
            let report = lifecycle::evaluate_lifecycle(&config, repo, &opts).await?;
            println!("{}", serde_json::to_string(&report)?);
        }
        Some("kms-rotate") if args.len() == 3 => {
            let repo: Uuid = args[1].parse()?;
            let report = lifecycle::rotate_kms_key(&config, repo, &args[2]).await?;
            println!("{}", serde_json::to_string(&report)?);
        }
        Some("object-format-detect") | Some("verify-object-format") | Some("compat-matrix") => {
            object_format::run_cli_command(&config, &args).await?;
        }
        _ => bail!(
            "usage: rootyard-pando-lab init | create-repo <uuid> <principal> | serve | verify-delta <pack> | walk-graph <repo> [wants... ^haves...] | diff-export <repo> [^haves...] | gc [repo] | migrate <repo> <gitfs_path> | migrate-step <repo> <gitfs_path> <copy|verify|drain|fence|switchover> | rollback <repo> <gitfs_path> | migration-status <repo> | repack <repo> [--prune-superseded] [--no-object-store] [--pin-oid <oid>...] | pin-root <repo> <name> <oid> | unpin-root <repo> <name> | object-store-put <repo> <pack_id> [--chunk-size <bytes>] [--fail-after-chunks <n>] [--corrupt-chunk <part>] | object-store-get <repo> <pack_id> | object-store-verify <repo> | object-store-status <repo> | lifecycle-evaluate <repo> [--max-packs <n>] [--cold-evict-local] [--auto-repack] | kms-rotate <repo> <new_key_id> | object-format-detect <repo_or_path> | verify-object-format <repo> [--format <sha1|sha256>] | compat-matrix [<repo>] [--client-format <sha1|sha256>] [--protocol-v2]"
        ),
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
