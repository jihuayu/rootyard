//! Offline paired backups. A volume flock and PostgreSQL table locks are barriers,
//! not a claim of online cross-store atomicity or zero data loss.
use crate::config::Config;
use anyhow::{Context, Result, bail, ensure};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{io::AsyncReadExt, process::Command};
use tokio_postgres::{Client, GenericClient};
use uuid::Uuid;

const TABLES: &[&str] = &[
    "audit_events",
    "ci_checkout_jobs",
    "ci_mirror_evictions",
    "ci_mirror_nodes",
    "ci_runs",
    "cluster_operator_tokens",
    "cluster_transport_nonces",
    "event_deliveries",
    "forge_branch_rules",
    "forge_check_runs",
    "forge_creation_requests",
    "forge_issue_comments",
    "forge_issue_counters",
    "forge_issues",
    "forge_pull_counters",
    "forge_pull_reviews",
    "forge_pulls",
    "forge_trusted_check_contexts",
    "forge_webhook_callbacks",
    "forge_webhook_deliveries",
    "forge_webhooks",
    "git_operations",
    "lfs_locks",
    "lfs_objects",
    "namespaces",
    "operation_resolutions",
    "organization_audit_log",
    "organization_creation_keys",
    "organization_memberships",
    "organization_team_members",
    "organization_teams",
    "organizations",
    "outbox_events",
    "recovery_resolutions",
    "repositories",
    "repository_audit_log",
    "repository_collaborators",
    "repository_ref_projection",
    "repository_shard_routes",
    "repository_team_members",
    "repository_teams",
    "sandbox_jobs",
    "schema_migrations",
    "shard_failover_operations",
    "shard_marker_transitions",
    "shard_nodes",
    "shard_replication_operations",
    "shard_virtual_buckets",
    "tokens",
    "users",
    "web_sessions",
    "workspace_capture_state",
    "workspace_checkpoints",
    "workspace_creations",
    "workspace_entries",
    "workspace_events",
    "workspace_namespace_mounts",
    "workspace_namespaces",
    "workspace_operations",
    "workspace_view_history",
    "workspace_views",
    "workspaces",
];
mod catalog;
mod authority;
use catalog::{FORMAT, catalogs as schema_catalogs, digest as schema_contract_digest, versions as schema_versions};
const MAX_ENTRIES: usize = 2_000_000;
const MAX_MANIFEST: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Entry {
    kind: String,
    mode: u32,
    bytes: u64,
    sha256: Option<String>,
    target: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Repository {
    id: Uuid,
    generation: i64,
    incident_revision: i64,
    state: String,
    recovery_reason: Option<String>,
    unknown_operations: i64,
    // Diagnostic refs are not synthesized push receipts or an event watermark.
    refs: Option<String>,
    head: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: u32,
    backup_id: Uuid,
    volume_id: Uuid,
    schema_contract_sha256: String,
    boundary_unix_seconds: u64,
    rootyard_version: String,
    binary_sha256: String,
    postgres_version: String,
    pg_dump_version: String,
    git_version: String,
    schema_versions: Vec<i32>,
    consistency: String,
    journal_record_files: usize,
    repositories: Vec<Repository>,
    files: BTreeMap<String, Entry>,
}

fn hash(path: &Path) -> Result<String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    ensure!(file.metadata()?.is_file(), "expected regular file");
    let mut digest = Sha256::new();
    let mut buf = [0; 128 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        digest.update(&buf[..n]);
    }
    Ok(hex::encode(digest.finalize()))
}
fn private_dir(path: &Path) -> Result<()> {
    fs::DirBuilder::new().mode(0o700).create(path)?;
    Ok(())
}
use std::os::unix::fs::DirBuilderExt;

// No symlink components, '..', root alias, or ambiguous relative paths. Parents
// must exist and be operator-controlled. A hostile same-UID writer is unsupported.
fn absolute(path: &Path, exists: bool) -> Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    ensure!(
        path.components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_))),
        "noncanonical path"
    );
    ensure!(path.file_name().is_some(), "root path is not a target");
    let mut current = PathBuf::new();
    let count = path.components().count();
    for (i, part) in path.components().enumerate() {
        current.push(part);
        if !exists && i + 1 == count {
            break;
        }
        let meta = fs::symlink_metadata(&current)?;
        ensure!(
            meta.is_dir() && !meta.file_type().is_symlink(),
            "path component is not a real directory"
        );
    }
    if !exists {
        ensure!(
            fs::symlink_metadata(&path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "destination must not exist"
        );
    }
    Ok(path)
}
fn disjoint(a: &Path, b: &Path) -> Result<()> {
    ensure!(
        !a.starts_with(b) && !b.starts_with(a),
        "source and destination overlap"
    );
    Ok(())
}
fn restore_guard_path(target: &Path) -> Result<PathBuf> {
    let path = if target.is_absolute() {
        target.to_owned()
    } else {
        std::env::current_dir()?.join(target)
    };
    let mut name = std::ffi::OsString::from(".");
    name.push(path.file_name().context("invalid restore target")?);
    name.push(".rootyard-restoring");
    Ok(path.parent().context("missing target parent")?.join(name))
}
/// Crash-persistent admission guard. Only a reviewed operator may remove a
/// leftover guard after discarding/recovering BOTH isolated targets.
pub fn ensure_not_restoring(target: &Path) -> Result<()> {
    ensure!(
        fs::symlink_metadata(restore_guard_path(target)?)
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "incomplete restore guard blocks service startup"
    );
    Ok(())
}
fn volume_identity(root: &Path) -> Result<Uuid> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(root.join(".volume-id"))?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.len() == 36 && meta.nlink() == 1 && meta.mode() & 0o7777 == 0o600,
        "missing or invalid volume identity"
    );
    let mut value = String::new();
    file.read_to_string(&mut value)?;
    Ok(value.parse()?)
}
fn volume_lock(root: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(root.join(".rootyard.lock"))?;
    let meta = file.metadata()?;
    ensure!(meta.is_file() && meta.nlink() == 1, "invalid volume lock");
    file.try_lock_exclusive()
        .context("offline backup requires Rootyard and all Git descendants to be stopped")?;
    Ok(file)
}
fn allowed_link(path: &str, target: &str) -> bool {
    matches!(
        path,
        "managed-hooks/pre-receive"
            | "managed-hooks/post-receive"
            | "managed-hooks/reference-transaction"
    ) && target == ".runner"
}
fn inventory(root: &Path) -> Result<BTreeMap<String, Entry>> {
    let meta = fs::symlink_metadata(root)?;
    ensure!(
        meta.is_dir() && !meta.file_type().is_symlink(),
        "volume root must be a real directory"
    );
    let mut entries = BTreeMap::new();
    fn visit(root: &Path, path: &Path, entries: &mut BTreeMap<String, Entry>) -> Result<()> {
        let mut children = fs::read_dir(path)?.collect::<std::io::Result<Vec<_>>>()?;
        children.sort_by_key(|e| e.file_name());
        for child in children {
            let path = child.path();
            let name = path
                .strip_prefix(root)?
                .to_str()
                .context("non UTF-8 filename unsupported")?
                .to_owned();
            ensure!(
                name.len() <= 4096 && !name.contains(['\n', '\r']),
                "invalid filename"
            );
            ensure!(
                entries.len() < MAX_ENTRIES,
                "backup file count exceeds bound"
            );
            let meta = fs::symlink_metadata(&path)?;
            ensure!(
                meta.dev() == fs::metadata(root)?.dev(),
                "nested mount unsupported"
            );
            let mode = meta.mode() & 0o7777;
            ensure!(mode & 0o7000 == 0, "special file modes unsupported");
            let entry = if meta.file_type().is_symlink() {
                let target = fs::read_link(&path)?
                    .to_str()
                    .context("non UTF-8 link")?
                    .to_owned();
                ensure!(
                    allowed_link(&name, &target),
                    "unsupported or external symlink"
                );
                Entry {
                    kind: "symlink".into(),
                    mode,
                    bytes: 0,
                    sha256: None,
                    target: Some(target),
                }
            } else if meta.is_file() {
                ensure!(meta.nlink() == 1, "hard-linked files unsupported");
                Entry {
                    kind: "file".into(),
                    mode,
                    bytes: meta.len(),
                    sha256: Some(hash(&path)?),
                    target: None,
                }
            } else if meta.is_dir() {
                Entry {
                    kind: "directory".into(),
                    mode,
                    bytes: 0,
                    sha256: None,
                    target: None,
                }
            } else {
                bail!("special files unsupported");
            };
            entries.insert(name, entry);
            if meta.is_dir() {
                visit(root, &path, entries)?;
            }
        }
        Ok(())
    }
    visit(root, root, &mut entries)?;
    Ok(entries)
}
fn copy_volume(source: &Path, target: &Path, entries: &BTreeMap<String, Entry>) -> Result<()> {
    private_dir(target)?;
    for (name, entry) in entries {
        ensure!(
            Path::new(name)
                .components()
                .all(|c| matches!(c, Component::Normal(_))),
            "invalid manifest path"
        );
        let dest = target.join(name);
        match entry.kind.as_str() {
            "directory" => private_dir(&dest)?,
            "file" => {
                let mut input = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(source.join(name))?;
                let mut output = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&dest)?;
                std::io::copy(&mut input, &mut output)?;
                output.set_permissions(fs::Permissions::from_mode(entry.mode))?;
                output.sync_all()?;
            }
            "symlink" => {
                let link = entry.target.as_deref().context("missing link")?;
                ensure!(allowed_link(name, link), "invalid link");
                std::os::unix::fs::symlink(link, dest)?;
            }
            _ => bail!("unsupported entry"),
        }
    }
    for (name, entry) in entries.iter().rev() {
        if entry.kind == "directory" {
            fs::set_permissions(target.join(name), fs::Permissions::from_mode(entry.mode))?;
            File::open(target.join(name))?.sync_all()?;
        }
    }
    File::open(target)?.sync_all()?;
    ensure!(
        inventory(target)? == *entries,
        "copied volume checksum mismatch"
    );
    Ok(())
}
fn publish(source: &Path, target: &Path) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let source = std::ffi::CString::new(source.as_os_str().as_bytes())?;
    let target = std::ffi::CString::new(target.as_os_str().as_bytes())?;
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            target.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn command(exe: impl AsRef<std::ffi::OsStr>) -> Command {
    let mut cmd = Command::new(exe);
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_NO_LAZY_FETCH", "1")
        .kill_on_drop(true);
    // Custom packaged PG binaries may need a trusted deployment library path.
    if let Some(path) = std::env::var_os("LD_LIBRARY_PATH") {
        cmd.env("LD_LIBRARY_PATH", path);
    }
    let parent = std::process::id() as libc::pid_t;
    // A killed CLI must not leave dump/restore subprocesses running indefinitely.
    // PostgreSQL commit acknowledgment can still be lost; failure is ambiguous.
    unsafe {
        cmd.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() != parent {
                libc::_exit(125);
            }
            Ok(())
        });
    }
    cmd
}
async fn checked(cmd: &mut Command) -> Result<Vec<u8>> {
    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    let mut child = cmd.spawn()?;
    let mut output = Vec::new();
    let result = tokio::time::timeout(std::time::Duration::from_secs(3600), async {
        child
            .stdout
            .take()
            .context("missing command output")?
            .take(64 * 1024 * 1024 + 1)
            .read_to_end(&mut output)
            .await?;
        ensure!(
            output.len() <= 64 * 1024 * 1024,
            "backup subprocess output exceeds bound"
        );
        let status = child.wait().await?;
        ensure!(
            status.success(),
            "backup subprocess failed; diagnostics suppressed"
        );
        Ok::<(), anyhow::Error>(())
    })
    .await;
    if !matches!(result, Ok(Ok(()))) {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    result??;
    Ok(output)
}

fn pg_command(config: &Config, exe: &str) -> Result<Command> {
    let cfg: tokio_postgres::Config = config.database_url.parse()?;
    ensure!(
        cfg.get_hosts().len() == 1 && cfg.get_ports().len() <= 1,
        "backup needs one explicit database host"
    );
    let host = match &cfg.get_hosts()[0] {
        tokio_postgres::config::Host::Tcp(host) => std::ffi::OsString::from(host),
        tokio_postgres::config::Host::Unix(path) => path.as_os_str().to_owned(),
    };
    let mut cmd = command(exe);
    cmd.env("PGHOST", host)
        .env(
            "PGPORT",
            cfg.get_ports().first().copied().unwrap_or(5432).to_string(),
        )
        .env(
            "PGDATABASE",
            cfg.get_dbname().context("explicit database required")?,
        )
        .env(
            "PGUSER",
            cfg.get_user().context("explicit database user required")?,
        )
        .env("PGCONNECT_TIMEOUT", "5")
        .env("PGPASSFILE", "/dev/null")
        // Detect dead CLI sockets even while PostgreSQL is blocked on a lock.
        .env("PGOPTIONS", "-c client_connection_check_interval=1000");
    if cfg.get_ssl_mode() == tokio_postgres::config::SslMode::Require {
        let ca = std::env::var("ROOTYARD_PG_CA_PEM")
            .context("PostgreSQL TLS backup needs ROOTYARD_PG_CA_PEM")?;
        ensure!(Path::new(&ca).is_file(), "PostgreSQL CA file unavailable");
        cmd.env("PGSSLMODE", "verify-full").env("PGSSLROOTCERT", ca);
        match (std::env::var("ROOTYARD_PG_CLIENT_CERT_PEM").ok(), std::env::var("ROOTYARD_PG_CLIENT_KEY_PEM").ok()) {
            (Some(cert), Some(key)) => { cmd.env("PGSSLCERT", cert).env("PGSSLKEY", key); }
            (None, None) => {}
            _ => bail!("PostgreSQL client certificate and key must be configured together"),
        }
    } else {
        ensure!(std::env::var_os("ROOTYARD_PG_CA_PEM").is_none(), "refusing PostgreSQL TLS downgrade");
        cmd.env("PGSSLMODE", "disable");
    }
    if let Some(password) = cfg.get_password() {
        use std::os::unix::ffi::OsStrExt;
        cmd.env("PGPASSWORD", std::ffi::OsStr::from_bytes(password));
    }
    Ok(cmd)
}
async fn pg(config: &Config) -> Result<Client> {
    let mut parsed: tokio_postgres::Config = config.database_url.parse()?;
    parsed.connect_timeout(std::time::Duration::from_secs(5));
    ensure!(
        parsed.get_options().is_none(),
        "backup requires dedicated database, default public schema, no connection options"
    );
    let client = crate::db::connect_config(parsed).await?;
    client.batch_execute("SET application_name='rootyard-backup'; SET lock_timeout='5s'; SET statement_timeout='60s'").await?;
    Ok(client)
}
async fn database_scope(client: &(impl GenericClient + Sync), empty: bool) -> Result<()> {
    let extras: i64 = client.query_one("SELECT (SELECT count(*) FROM pg_namespace WHERE nspname NOT IN ('public','information_schema') AND nspname !~ '^pg_') + (SELECT count(*) FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='public' AND NOT (t.typrelid<>0 AND EXISTS(SELECT 1 FROM pg_class c WHERE c.oid=t.typrelid AND c.relkind='r')) AND NOT (t.typelem<>0 AND t.typtype='b' AND EXISTS(SELECT 1 FROM pg_type e JOIN pg_class c ON c.oid=e.typrelid WHERE e.oid=t.typelem AND e.typarray=t.oid AND c.relkind='r'))) + (SELECT count(*) FROM pg_extension WHERE extname<>'plpgsql') + (SELECT count(*) FROM pg_largeobject_metadata)", &[]).await?.get(0);
    let routines: i64 = client.query_one("SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public'", &[]).await?.get(0);
    let other_objects: i64 = client.query_one("SELECT (SELECT count(*) FROM pg_collation c JOIN pg_namespace n ON n.oid=c.collnamespace WHERE n.nspname='public') + (SELECT count(*) FROM pg_conversion c JOIN pg_namespace n ON n.oid=c.connamespace WHERE n.nspname='public') + (SELECT count(*) FROM pg_operator c JOIN pg_namespace n ON n.oid=c.oprnamespace WHERE n.nspname='public') + (SELECT count(*) FROM pg_opclass c JOIN pg_namespace n ON n.oid=c.opcnamespace WHERE n.nspname='public') + (SELECT count(*) FROM pg_opfamily c JOIN pg_namespace n ON n.oid=c.opfnamespace WHERE n.nspname='public') + (SELECT count(*) FROM pg_ts_config c JOIN pg_namespace n ON n.oid=c.cfgnamespace WHERE n.nspname='public') + (SELECT count(*) FROM pg_ts_dict c JOIN pg_namespace n ON n.oid=c.dictnamespace WHERE n.nspname='public') + (SELECT count(*) FROM pg_ts_parser c JOIN pg_namespace n ON n.oid=c.prsnamespace WHERE n.nspname='public') + (SELECT count(*) FROM pg_ts_template c JOIN pg_namespace n ON n.oid=c.tmplnamespace WHERE n.nspname='public') + (SELECT count(*) FROM pg_statistic_ext c JOIN pg_namespace n ON n.oid=c.stxnamespace WHERE n.nspname='public') + (SELECT count(*) FROM pg_publication) + (SELECT count(oid) FROM pg_subscription WHERE subdbid=(SELECT oid FROM pg_database WHERE datname=current_database()))", &[]).await?.get(0);
    ensure!(other_objects == 0, "unsupported database objects");
    let event_triggers: i64 = client
        .query_one("SELECT count(*) FROM pg_event_trigger", &[])
        .await?
        .get(0);
    ensure!(!empty || routines == 0, "restore target contains routines");
    ensure!(event_triggers == 0, "database event triggers unsupported");
    ensure!(
        extras == 0,
        "dedicated Rootyard database must not contain extra schemas, routines, types or extensions"
    );
    Ok(())
}
async fn schema(client: &(impl GenericClient + Sync), format: u32) -> Result<Vec<i32>> {
    database_scope(client, false).await?;
    let tables = catalog::relations(format, true)?;
    let expected_relations = catalog::relations(format, false)?;
    let names: Vec<String> = client.query("SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','f','S') ORDER BY c.relname", &[]).await?.iter().map(|r| r.get(0)).collect();
    ensure!(
        names == expected_relations,
        "backup supports only the exact Rootyard public schema"
    );
    let regular: i64 = client.query_one("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='r' AND c.relpersistence='p'", &[]).await?.get(0);
    ensure!(
        regular == tables.len() as i64,
        "only permanent Rootyard tables supported"
    );
    let versions: Vec<i32> = client
        .query(
            "SELECT version FROM public.schema_migrations ORDER BY version",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    ensure!(
        versions == schema_versions(format)?,
        "unsupported migration version"
    );
    client.batch_execute("SET search_path=pg_catalog").await?;
    // Both versions use this catalog projection. Version-specific immutable
    // fixtures below, not the query text, define the accepted schema shapes.
    let actual: serde_json::Value = client
        .query_one(include_str!("../schema/060_catalog.sql"), &[])
        .await?
        .get(0);
    // Only complete reviewed catalog shapes are accepted. In particular a
    // legacy format4 archive must restore schema007, never a schema008 hybrid.
    ensure!(
        schema_catalogs(format)?.contains(&actual),
        "schema structure or protection differs from reviewed migrations"
    );
    let incomplete: bool = client
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM public.forge_creation_requests WHERE response IS NULL)",
            &[],
        )
        .await?
        .get(0);
    ensure!(
        !incomplete,
        "incomplete Forge creation request in committed snapshot"
    );
    Ok(versions)
}
async fn repositories(client: &(impl GenericClient + Sync)) -> Result<Vec<Repository>> {
    Ok(client.query("SELECT r.id,r.storage_generation,r.state,r.recovery_reason,r.incident_revision,(SELECT count(*) FROM public.git_operations o WHERE o.repository_id=r.id AND o.outcome='unknown') FROM public.repositories r ORDER BY r.id", &[]).await?.iter().map(|r| Repository {
        id: r.get(0), generation: r.get(1), state: r.get(2), recovery_reason: r.get(3), incident_revision: r.get(4), unknown_operations: r.get(5), refs: None, head: None,
    }).collect())
}
async fn git_inventory(
    config: &Config,
    root: &Path,
    repos: &mut [Repository],
    fsck: bool,
) -> Result<()> {
    for repo in repos {
        let path = root.join("repos").join(format!("{}.git", repo.id));
        if !path.exists() {
            ensure!(
                repo.state == "provisioning",
                "ready or recovering repository missing"
            );
            continue;
        }
        for name in [
            "objects/info/alternates",
            "objects/info/http-alternates",
            "shallow",
            "commondir",
            "gitdir",
            "worktrees",
        ] {
            ensure!(
                !path.join(name).exists(),
                "external or incomplete object storage unsupported"
            );
        }
        let config_text = fs::read_to_string(path.join("config"))?;
        ensure!(
            !config_text.to_ascii_lowercase().contains("[include")
                && !config_text.to_ascii_lowercase().contains("promisor")
                && !config_text.to_ascii_lowercase().contains("partialclone"),
            "external Git configuration unsupported"
        );
        let run = |args: &[&str]| {
            let mut cmd = command(&config.git);
            cmd.args([
                "--no-replace-objects",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=false",
                "--git-dir",
            ])
            .arg(&path)
            .args(args);
            cmd
        };
        ensure!(
            checked(&mut run(&["rev-parse", "--is-bare-repository"])).await? == b"true\n",
            "only standalone bare repositories supported"
        );
        let identity = checked(&mut run(&["config", "--get", "rootyard.repositoryId"])).await?;
        ensure!(
            String::from_utf8(identity)?.trim() == repo.id.to_string(),
            "repository identity mismatch"
        );
        repo.refs = Some(String::from_utf8(
            checked(&mut run(&[
                "for-each-ref",
                "--format=%(refname) %(objectname) %(symref)",
            ]))
            .await?,
        )?);
        repo.head = Some(fs::read_to_string(path.join("HEAD"))?);
        if fsck {
            checked(&mut run(&["fsck", "--full", "--strict"])).await?;
        }
    }
    Ok(())
}

/// Operator must already have stopped serving; this command never stops services.
pub async fn create(config: &Config, destination: &Path) -> Result<()> {
    let started = Instant::now();
    let root = absolute(&config.data_dir, true)?;
    let destination = absolute(destination, false)?;
    disjoint(&root, &destination)?;
    ensure_not_restoring(&root)?;
    let _volume = volume_lock(&root)?;
    let volume_id = volume_identity(&root)?;
    let mut client = pg(config).await?;
    // Acquire this BEFORE beginning REPEATABLE READ: SELECT would otherwise fix
    // the snapshot before waiting for old transactions/migrations to commit.
    client
        .query_one("SELECT pg_advisory_lock(738390103)", &[])
        .await?;
    let tx = client
        .build_transaction()
        .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
        .start()
        .await?;
    let list = TABLES
        .iter()
        .map(|t| format!("public.{t}"))
        .collect::<Vec<_>>()
        .join(",");
    tx.batch_execute(&format!("LOCK TABLE {list} IN SHARE MODE"))
        .await?;
    // No snapshot-taking SELECT occurs before all DML/DDL table locks are held.
    let versions = schema(&tx, FORMAT).await?;
    let snapshot: String = tx
        .query_one("SELECT pg_export_snapshot()", &[])
        .await?
        .get(0);
    let boundary = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let postgres_version: String = tx.query_one("SHOW server_version", &[]).await?.get(0);
    ensure!(
        postgres_version.starts_with("17."),
        "this format is verified only with PostgreSQL 17"
    );
    let mut repos = repositories(&tx).await?;
    let foreign_volumes: i64 = tx
        .query_one(
            "SELECT count(*) FROM public.recovery_resolutions WHERE volume_id<>$1",
            &[&volume_id],
        )
        .await?
        .get(0);
    ensure!(
        foreign_volumes == 0,
        "resolution history belongs to another volume"
    );
    let source_inventory = inventory(&root)?;
    git_inventory(config, &root, &mut repos, false).await?;
    let id = Uuid::new_v4();
    let staging = destination
        .parent()
        .unwrap()
        .join(format!(".rootyard-backup-{id}.partial"));
    private_dir(&staging)?;
    let mut dump = pg_command(config, "pg_dump")?;
    dump.args([
        "--no-password",
        "--lock-wait-timeout=5s",
        "--format=custom",
        "--schema=public",
        "--no-owner",
        "--no-privileges",
        "--snapshot",
        &snapshot,
        "--file",
    ])
    .arg(staging.join("metadata.dump"));
    checked(&mut dump).await?;
    fs::set_permissions(
        staging.join("metadata.dump"),
        fs::Permissions::from_mode(0o600),
    )?;
    File::open(staging.join("metadata.dump"))?.sync_all()?;
    copy_volume(&root, &staging.join("volume"), &source_inventory)?;
    ensure!(
        inventory(&root)? == source_inventory,
        "volume changed during barrier"
    );
    // Prove the exporting session still owns its transaction before publishing.
    tx.query_one("SELECT 1", &[]).await?;
    let mut files = BTreeMap::new();
    files.insert(
        "metadata.dump".into(),
        Entry {
            kind: "file".into(),
            mode: 0o600,
            bytes: fs::metadata(staging.join("metadata.dump"))?.len(),
            sha256: Some(hash(&staging.join("metadata.dump"))?),
            target: None,
        },
    );
    for (name, entry) in source_inventory {
        files.insert(format!("volume/{name}"), entry);
    }
    let manifest = Manifest {
        format: FORMAT,
        backup_id: id,
        volume_id,
        schema_contract_sha256: schema_contract_digest(FORMAT)?,
        boundary_unix_seconds: boundary,
        rootyard_version: env!("CARGO_PKG_VERSION").into(),
        binary_sha256: hash(&std::env::current_exe()?)?,
        postgres_version,
        pg_dump_version: String::from_utf8(checked(command("pg_dump").arg("--version")).await?)?
            .trim()
            .into(),
        git_version: String::from_utf8(checked(command(&config.git).arg("--version")).await?)?
            .trim()
            .into(),
        schema_versions: versions,
        consistency: "offline-volume-flock+postgres-share-locks+exported-snapshot".into(),
        journal_record_files: files
            .keys()
            .filter(|p| p.starts_with("volume/journal/") && p.ends_with("/operation.json"))
            .count(),
        repositories: repos,
        files,
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    ensure!(
        manifest_bytes.len() as u64 <= MAX_MANIFEST,
        "manifest exceeds format bound"
    );
    write_private(&staging.join("manifest.json"), &manifest_bytes)?;
    File::open(&staging)?.sync_all()?;
    tx.commit().await?;
    write_private(
        &staging.join("COMPLETE"),
        hash(&staging.join("manifest.json"))?.as_bytes(),
    )?;
    File::open(&staging)?.sync_all()?;
    // Drop connection releases session migration lock; never modify source data.
    drop(client);
    ensure!(!destination.exists(), "destination appeared during backup");
    publish(&staging, &destination)?;
    File::open(destination.parent().unwrap())?.sync_all()?;
    println!(
        "{}",
        serde_json::json!({"backup_id":id,"complete":true,"elapsed_seconds":started.elapsed().as_secs_f64(),"boundary_unix_seconds":boundary,"unknown_operations":manifest.repositories.iter().map(|r|r.unknown_operations).sum::<i64>()})
    );
    Ok(())
}

fn verify(source: &Path) -> Result<Manifest> {
    let manifest_meta = fs::symlink_metadata(source.join("manifest.json"))?;
    ensure!(
        manifest_meta.is_file()
            && manifest_meta.nlink() == 1
            && manifest_meta.len() <= MAX_MANIFEST,
        "invalid manifest"
    );
    let complete = fs::symlink_metadata(source.join("COMPLETE"))?;
    ensure!(
        complete.is_file() && complete.len() == 64 && complete.nlink() == 1,
        "invalid completion marker"
    );
    let mut expected = String::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(source.join("COMPLETE"))?
        .take(65)
        .read_to_string(&mut expected)?;
    ensure!(
        expected.len() == 64 && hash(&source.join("manifest.json"))? == expected,
        "incomplete or damaged manifest"
    );
    let manifest: Manifest = serde_json::from_slice(&fs::read(source.join("manifest.json"))?)?;
    ensure!(
        matches!(manifest.format, 4 | 5 | 6)
            && manifest.schema_versions == schema_versions(manifest.format)?
            && manifest.schema_contract_sha256 == schema_contract_digest(manifest.format)?,
        "unsupported backup format"
    );
    ensure!(
        volume_identity(&source.join("volume"))? == manifest.volume_id,
        "backup volume identity mismatch"
    );
    let mut actual = inventory(&source.join("volume"))?
        .into_iter()
        .map(|(n, e)| (format!("volume/{n}"), e))
        .collect::<BTreeMap<_, _>>();
    let dump = source.join("metadata.dump");
    let metadata = fs::symlink_metadata(&dump)?;
    ensure!(
        metadata.is_file() && metadata.nlink() == 1,
        "invalid dump file"
    );
    actual.insert(
        "metadata.dump".into(),
        Entry {
            kind: "file".into(),
            mode: metadata.mode() & 0o7777,
            bytes: metadata.len(),
            sha256: Some(hash(&dump)?),
            target: None,
        },
    );
    ensure!(
        actual == manifest.files,
        "backup inventory or checksum mismatch"
    );
    ensure!(
        manifest.journal_record_files
            == actual
                .keys()
                .filter(|p| p.starts_with("volume/journal/") && p.ends_with("/operation.json"))
                .count(),
        "journal inventory mismatch"
    );
    let mut names = fs::read_dir(source)?
        .map(|e| e.map(|v| v.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    names.sort();
    ensure!(
        names
            == ["COMPLETE", "manifest.json", "metadata.dump", "volume"]
                .map(std::ffi::OsString::from),
        "unexpected backup files"
    );
    Ok(manifest)
}

pub fn check(source: &Path) -> Result<()> {
    let source = absolute(source, true)?;
    let manifest = verify(&source)?;
    println!(
        "{}",
        serde_json::json!({"backup_id":manifest.backup_id,"checksums_verified":true,"authenticity_verified":false})
    );
    Ok(())
}

pub async fn restore(config: &Config, source: &Path, allow_legacy_schema007: bool) -> Result<()> {
    let started = Instant::now();
    let source = absolute(source, true)?;
    let target = absolute(&config.data_dir, false)?;
    disjoint(&source, &target)?;
    let manifest = verify(&source)?;
    ensure!(
        !allow_legacy_schema007 || manifest.format == 4,
        "legacy opt-in requires format4/schema007"
    );
    ensure!(
        (allow_legacy_schema007 && manifest.format == 4)
            || manifest.binary_sha256 == hash(&std::env::current_exe()?)?,
        "restore requires the exact backup binary; upgrade separately"
    );
    let client = pg(config).await?;
    client
        .query_one("SELECT pg_advisory_lock(738390103)", &[])
        .await?;
    database_scope(&client, true).await?;
    let object_count: i64 = client.query_one("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%'", &[]).await?.get(0);
    ensure!(
        object_count == 0,
        "restore requires a fresh empty dedicated database"
    );
    let sessions: i64 = client.query_one("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid()", &[]).await?.get(0);
    ensure!(
        sessions == 0,
        "restore database must have no other connections"
    );
    let version: String = client.query_one("SHOW server_version", &[]).await?.get(0);
    ensure!(version.starts_with("17."), "restore requires PostgreSQL 17");
    let guard = restore_guard_path(&target)?;
    write_private(&guard, format!("{}\n", manifest.backup_id).as_bytes())?;
    File::open(target.parent().unwrap())?.sync_all()?;
    let staging = target
        .parent()
        .unwrap()
        .join(format!(".rootyard-restore-{}.partial", Uuid::new_v4()));
    let entries = manifest
        .files
        .iter()
        .filter_map(|(n, e)| n.strip_prefix("volume/").map(|n| (n.to_owned(), e.clone())))
        .collect();
    copy_volume(&source.join("volume"), &staging, &entries)?;
    let _volume = volume_lock(&staging)?;
    ensure!(
        volume_identity(&staging)? == manifest.volume_id,
        "restored volume identity mismatch"
    );
    let mut repos = manifest.repositories.clone();
    git_inventory(config, &staging, &mut repos, true).await?;
    ensure!(
        repos == manifest.repositories,
        "restored native refs/HEAD differ from manifest"
    );
    // An archive is executable SQL. --trust-backup is a required operator choice,
    // not an assertion that hashes authenticate it. Destination stays isolated.
    let mut restore = pg_command(config, "pg_restore")?;
    restore
        .args([
            "--no-password",
            "--dbname",
            "",
            "--single-transaction",
            "--clean",
            "--if-exists",
            "--exit-on-error",
            "--no-owner",
            "--no-privileges",
        ])
        .arg(source.join("metadata.dump"));
    checked(&mut restore).await?;
    ensure!(
        schema(&client, manifest.format).await? == manifest.schema_versions,
        "restored schema mismatch"
    );
    let restored_foreign_volumes: i64 = client
        .query_one(
            "SELECT count(*) FROM public.recovery_resolutions WHERE volume_id<>$1",
            &[&manifest.volume_id],
        )
        .await?
        .get(0);
    ensure!(
        restored_foreign_volumes == 0,
        "restored resolutions belong to another volume"
    );
    let mut metadata_repos = repositories(&client).await?;
    for repo in &mut metadata_repos {
        if let Some(old) = manifest.repositories.iter().find(|old| old.id == repo.id) {
            repo.refs.clone_from(&old.refs);
            repo.head.clone_from(&old.head);
        }
    }
    ensure!(
        metadata_repos == manifest.repositories,
        "restored metadata mismatch"
    );
    // A backup can predate cancellation. Never resurrect any previously issued
    // checkout bearer after restoring old authority; plan and native pins remain
    // evidence, not permission to mint a credential for the same job again.
    if manifest.format >= 5 {
        client.execute("UPDATE public.ci_checkout_jobs SET revoked=true WHERE plan IS NOT NULL AND NOT revoked", &[]).await?;
        let unsafe_grants: bool = client.query_one("SELECT EXISTS (SELECT 1 FROM public.ci_checkout_jobs WHERE plan IS NOT NULL AND NOT revoked)", &[]).await?.get(0);
        ensure!(
            !unsafe_grants,
            "restored checkout credentials were not invalidated"
        );
    }
    if manifest.format >= 6 { authority::fence(&client).await?; }
    ensure!(!target.exists(), "destination appeared during restore");
    publish(&staging, &target)?;
    File::open(target.parent().unwrap())?.sync_all()?;
    fs::remove_file(&guard)?;
    File::open(target.parent().unwrap())?.sync_all()?;
    println!(
        "{}",
        serde_json::json!({"backup_id":manifest.backup_id,"restored":true,"started_service":false,"elapsed_seconds":started.elapsed().as_secs_f64(),"unknown_operations":manifest.repositories.iter().map(|r|r.unknown_operations).sum::<i64>()})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn traversal_links_specials_and_overlap_fail_closed() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(absolute(&tmp.path().join("../escape"), false).is_err());
        assert!(disjoint(tmp.path(), &tmp.path().join("backup")).is_err());
        std::os::unix::fs::symlink("/etc", tmp.path().join("escape")).unwrap();
        assert!(inventory(tmp.path()).is_err());
        assert!(!allowed_link("repos/evil.git/objects", "../../other"));
        assert!(allowed_link("managed-hooks/pre-receive", ".runner"));
    }
    #[test]
    fn publication_never_replaces_an_existing_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("staging");
        let target = tmp.path().join("already-exists");
        private_dir(&source).unwrap();
        private_dir(&target).unwrap();
        write_private(&source.join("sentinel"), b"not published").unwrap();
        assert!(publish(&source, &target).is_err());
        assert!(source.join("sentinel").exists());
        assert!(!target.join("sentinel").exists());
    }
    #[test]
    fn restore_guard_blocks_nonexistent_target() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("not-created");
        assert!(ensure_not_restoring(&target).is_ok());
        write_private(&restore_guard_path(&target).unwrap(), b"test backup id").unwrap();
        assert!(ensure_not_restoring(&target).is_err());
        assert!(!target.exists());
    }
    #[test]
    fn private_copy_preserves_bytes_and_modes() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        private_dir(&source).unwrap();
        write_private(&source.join("hidden"), b"durable evidence").unwrap();
        let before = inventory(&source).unwrap();
        let target = tmp.path().join("new");
        copy_volume(&source, &target, &before).unwrap();
        assert_eq!(inventory(&target).unwrap(), before);
        fs::write(target.join("hidden"), b"changed").unwrap();
        assert_ne!(inventory(&target).unwrap(), before);
    }
}
