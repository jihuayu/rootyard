//! Bounded database tools, frozen schema checks and native Git inspection.
use super::*;

pub(super) fn command(exe: impl AsRef<std::ffi::OsStr>) -> Command {
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
pub(super) async fn checked(cmd: &mut Command) -> Result<Vec<u8>> {
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

pub(super) fn pg_command(config: &Config, exe: &str) -> Result<Command> {
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
pub(super) async fn pg(config: &Config) -> Result<Client> {
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
pub(super) async fn database_scope(client: &(impl GenericClient + Sync), empty: bool) -> Result<()> {
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
pub(super) async fn schema(client: &(impl GenericClient + Sync), format: u32) -> Result<Vec<i32>> {
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
        .query_one(include_str!("../../schema/060_catalog.sql"), &[])
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
pub(super) async fn repositories(client: &(impl GenericClient + Sync)) -> Result<Vec<Repository>> {
    Ok(client.query("SELECT r.id,r.storage_generation,r.state,r.recovery_reason,r.incident_revision,(SELECT count(*) FROM public.git_operations o WHERE o.repository_id=r.id AND o.outcome='unknown') FROM public.repositories r ORDER BY r.id", &[]).await?.iter().map(|r| Repository {
        id: r.get(0), generation: r.get(1), state: r.get(2), recovery_reason: r.get(3), incident_revision: r.get(4), unknown_operations: r.get(5), refs: None, head: None,
    }).collect())
}
pub(super) async fn git_inventory(
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

