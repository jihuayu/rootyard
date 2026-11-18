//! PostgreSQL 17 database-level durable read-only & freeze markers (`pg_db_role_setting`)
//! plus ephemeral dedicated backup role provisioning outside `public` schema (#153).

use tokio_postgres::GenericClient;
use uuid::Uuid;

use crate::config::Config;

use super::pg_cutpoint::pg_err;
use super::types::PairedBackupError;

/// Database-wide durable freeze setting stored in PostgreSQL `pg_db_role_setting`
/// (outside the `public` schema catalog so `schema 151` / `format 30` stays unmodified).
pub const PG_FREEZE_SETTING: &str = "rootyard.paired_backup_freeze";

pub async fn read_pg_database_freeze_marker(
    client: &(impl GenericClient + Sync),
) -> Result<Option<String>, PairedBackupError> {
    let prefix = format!("{PG_FREEZE_SETTING}=");
    let row = client
        .query_opt(
            "SELECT setting FROM pg_db_role_setting s, unnest(s.setconfig) AS setting \
             WHERE s.setdatabase = (SELECT oid FROM pg_database WHERE datname = current_database()) \
               AND s.setrole = 0 AND setting LIKE $1 LIMIT 1",
            &[&format!("{prefix}%")],
        )
        .await
        .map_err(pg_err)?;
    Ok(row.and_then(|r| r.get::<_, String>(0).strip_prefix(&prefix).map(str::to_owned)))
}

pub(super) async fn set_pg_database_freeze_marker(
    client: &(impl GenericClient + Sync),
    marker: Option<&str>,
) -> Result<(), PairedBackupError> {
    let db_name: String = client.query_one("SELECT current_database()", &[]).await.map_err(pg_err)?.get(0);
    let quoted_db = db_name.replace('"', "\"\"");
    let sql = match marker {
        Some(val) => {
            if val.chars().any(|c| !c.is_ascii_alphanumeric() && c != '-' && c != ':') {
                return Err(PairedBackupError::InvalidArgument("invalid characters in PG freeze marker"));
            }
            format!("ALTER DATABASE \"{quoted_db}\" SET {PG_FREEZE_SETTING} = '{val}'")
        }
        None => format!("ALTER DATABASE \"{quoted_db}\" RESET {PG_FREEZE_SETTING}"),
    };
    client.batch_execute(&sql).await.map_err(pg_err)?;
    Ok(())
}

pub async fn read_pg_database_read_only(client: &(impl GenericClient + Sync)) -> Result<bool, PairedBackupError> {
    let row = client
        .query_opt(
            "SELECT setting FROM pg_db_role_setting s, unnest(s.setconfig) AS setting \
             WHERE s.setdatabase = (SELECT oid FROM pg_database WHERE datname = current_database()) \
               AND s.setrole = 0 AND setting LIKE 'default_transaction_read_only=%' LIMIT 1",
            &[],
        )
        .await
        .map_err(pg_err)?;
    Ok(row.is_some_and(|r| {
        matches!(
            r.get::<_, String>(0).as_str(),
            "default_transaction_read_only=on" | "default_transaction_read_only=true"
        )
    }))
}

pub(super) async fn set_pg_database_read_only(
    client: &(impl GenericClient + Sync),
    read_only: bool,
) -> Result<(), PairedBackupError> {
    let db_name: String = client.query_one("SELECT current_database()", &[]).await.map_err(pg_err)?.get(0);
    let quoted_db = db_name.replace('"', "\"\"");
    let sql = if read_only {
        format!("ALTER DATABASE \"{quoted_db}\" SET default_transaction_read_only = on")
    } else {
        format!("ALTER DATABASE \"{quoted_db}\" RESET default_transaction_read_only")
    };
    client.batch_execute(&sql).await.map_err(pg_err)?;
    Ok(())
}

/// Provision an ephemeral dedicated backup login role with
/// `ALTER ROLE "<role>" IN DATABASE "<db>" SET default_transaction_read_only = off`
/// so `crate::backup::create` (`LOCK TABLE ... IN SHARE MODE` + `pg_dump`) runs without
/// ever relaxing `ALTER DATABASE "<db>" SET default_transaction_read_only = on` for normal sessions.
pub(super) async fn provision_ephemeral_backup_role(
    src_config: &Config,
) -> Result<(Config, String, String), PairedBackupError> {
    let parsed: tokio_postgres::Config = src_config.database_url.parse().map_err(pg_err)?;
    let host = match parsed.get_hosts().first() {
        Some(tokio_postgres::config::Host::Tcp(h)) => h.clone(),
        _ => return Err(PairedBackupError::InvalidArgument("TCP PostgreSQL host required for paired backup")),
    };
    let port = parsed.get_ports().first().copied().unwrap_or(5432);
    let client = crate::db::connect_config(parsed).await.map_err(|e| PairedBackupError::Postgres(e.to_string()))?;
    client.batch_execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ WRITE").await.map_err(pg_err)?;
    let db_name: String = client.query_one("SELECT current_database()", &[]).await.map_err(pg_err)?.get(0);
    let quoted_db = db_name.replace('"', "\"\"");
    let role_name = format!("paired_bkp_{}", &Uuid::new_v4().simple().to_string()[..16]);
    let role_pw = Uuid::new_v4().simple().to_string();
    let sql = format!(
        "CREATE ROLE \"{role_name}\" LOGIN SUPERUSER PASSWORD '{role_pw}'; \
         ALTER ROLE \"{role_name}\" IN DATABASE \"{quoted_db}\" SET default_transaction_read_only = off;"
    );
    client.batch_execute(&sql).await.map_err(pg_err)?;
    drop(client);

    let mut role_cfg = src_config.clone();
    role_cfg.database_url = format!("postgres://{role_name}:{role_pw}@{host}:{port}/{db_name}");
    Ok((role_cfg, role_name, db_name))
}

pub(super) async fn drop_ephemeral_backup_role(
    src_config: &Config,
    role_name: &str,
    db_name: &str,
) -> Result<(), PairedBackupError> {
    if !role_name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(PairedBackupError::InvalidArgument("invalid ephemeral backup role identifier"));
    }
    let parsed: tokio_postgres::Config = src_config.database_url.parse().map_err(pg_err)?;
    let client = crate::db::connect_config(parsed).await.map_err(|e| PairedBackupError::Postgres(e.to_string()))?;
    client.batch_execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ WRITE").await.map_err(pg_err)?;
    let quoted_db = db_name.replace('"', "\"\"");
    let sql = format!(
        "ALTER ROLE \"{role_name}\" IN DATABASE \"{quoted_db}\" RESET ALL; \
         DROP ROLE IF EXISTS \"{role_name}\";"
    );
    client.batch_execute(&sql).await.map_err(pg_err)?;
    Ok(())
}
