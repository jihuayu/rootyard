//! PostgreSQL 17 database-level durable read-only & freeze markers (`pg_db_role_setting`)
//! plus ephemeral dedicated backup role provisioning outside `public` schema (#153).

use std::time::{Duration, Instant};

use tokio_postgres::GenericClient;
use uuid::Uuid;

use crate::config::Config;

use super::pg_cutpoint::pg_err;
use super::types::PairedBackupError;

/// Database-wide durable freeze setting stored in PostgreSQL `pg_db_role_setting`
/// (outside the `public` schema catalog so `schema 151` / `format 30` stays unmodified).
pub const PG_FREEZE_SETTING: &str = "rootyard.paired_backup_freeze";

/// Advisory lock serializing exclusive freeze entry against `journal::retire` shared-lock
/// transactions, so an in-flight resolution cannot race the durable read-only latch.
pub const PAIRED_FREEZE_JOURNAL_LOCK_KEY: i64 = 738_390_153;

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

/// Fail-closed termination & exit barrier: every `pg_terminate_backend(pid)` boolean return
/// value is inspected, then `pg_stat_activity` is polled until no other client backend on
/// `current_database()` still holds a transaction/xid or an active/in-transaction state.
pub async fn terminate_and_await_other_pg_sessions(
    client: &(impl GenericClient + Sync),
    timeout: Duration,
) -> Result<usize, PairedBackupError> {
    let rows = client
        .query(
            "SELECT pid, pg_terminate_backend(pid) FROM pg_stat_activity \
             WHERE datname = current_database() AND pid <> pg_backend_pid() \
               AND (backend_type = 'client backend' OR backend_type IS NULL)",
            &[],
        )
        .await
        .map_err(|_| PairedBackupError::FreezeNotHeld("failed to terminate pre-existing PostgreSQL client backends"))?;
    let mut terminated: Vec<i32> = Vec::with_capacity(rows.len());
    for row in rows {
        let pid: i32 = row.get(0);
        let terminated_ok: Option<bool> = row.get(1);
        if terminated_ok != Some(true) {
            return Err(PairedBackupError::FreezeNotHeld(
                "pg_terminate_backend returned false/NULL for a pre-existing client backend",
            ));
        }
        terminated.push(pid);
    }
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = remaining_other_client_backends(client, &terminated).await?;
        if remaining == 0 {
            return Ok(terminated.len());
        }
        if Instant::now() >= deadline {
            return Err(PairedBackupError::FreezeNotHeld(
                "pre-existing PostgreSQL write sessions failed to exit before the freeze deadline",
            ));
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn remaining_other_client_backends(
    client: &(impl GenericClient + Sync),
    terminated_pids: &[i32],
) -> Result<i64, PairedBackupError> {
    let pids: Vec<i32> = terminated_pids.to_vec();
    let sql = "SELECT count(*)::bigint FROM pg_stat_activity \
         WHERE datname = current_database() AND pid <> pg_backend_pid() \
           AND (backend_type = 'client backend' OR backend_type IS NULL) \
           AND (pid = ANY($1) OR backend_xid IS NOT NULL OR state IS NULL \
                OR state IN ('active', 'idle in transaction', 'idle in transaction (aborted)', \
                             'fastpath function call'))";
    let count: i64 = client.query_one(sql, &[&pids]).await.map_err(pg_err)?.get(0);
    Ok(count)
}

/// Verify that no concurrent PostgreSQL write session or open transaction exists.
pub async fn verify_no_active_pg_writers(client: &(impl GenericClient + Sync)) -> Result<(), PairedBackupError> {
    verify_no_active_pg_writers_except_fence(client, None).await
}

/// Verify no concurrent PostgreSQL writer exists while allowing exactly the dedicated
/// `PgTableShareFence` backend (its `backend_xid` is NULL) to stay in its lock transaction.
pub async fn verify_no_active_pg_writers_except_fence(
    client: &(impl GenericClient + Sync),
    allowed_fence_pid: Option<i32>,
) -> Result<(), PairedBackupError> {
    let sql = "SELECT count(*)::bigint FROM pg_stat_activity \
         WHERE datname = current_database() AND pid <> pg_backend_pid() \
           AND NOT ($1::int IS NOT NULL AND pid = $1 AND backend_xid IS NULL) \
           AND (backend_type = 'client backend' OR backend_type IS NULL) \
           AND (backend_xid IS NOT NULL \
                OR state IS NULL \
                OR state IN ('active','idle in transaction','idle in transaction (aborted)'))";
    let count: i64 = client.query_one(sql, &[&allowed_fence_pid]).await.map_err(pg_err)?.get(0);
    if count != 0 {
        return Err(PairedBackupError::FreezeNotHeld(
            "concurrent PostgreSQL write session/transaction active; refusing cutpoint capture",
        ));
    }
    Ok(())
}

/// Fail-closed maintenance write guard: refuse writes and journal deletion whenever the
/// durable PostgreSQL freeze marker, database-wide `default_transaction_read_only`, or the
/// storage-authority remote-delete fence is active.
pub async fn enforce_maintenance_pg_write_guard(
    client: &(impl GenericClient + Sync),
    check_delete_fence: bool,
) -> Result<(), PairedBackupError> {
    if read_pg_database_freeze_marker(client).await?.is_some() {
        return Err(PairedBackupError::FreezeNotHeld(
            "PostgreSQL durable paired_backup_freeze marker is active; maintenance path refuses to write",
        ));
    }
    if read_pg_database_read_only(client).await? {
        return Err(PairedBackupError::FreezeNotHeld(
            "PostgreSQL database default_transaction_read_only is on; maintenance path refuses to write",
        ));
    }
    if check_delete_fence {
        let present: bool = client
            .query_one("SELECT to_regclass('public.pando_storage_authorities') IS NOT NULL", &[])
            .await
            .map_err(pg_err)?
            .get(0);
        if present {
            let row = client
                .query_one(
                    "SELECT remote_delete_fenced FROM public.pando_storage_authorities WHERE singleton = true",
                    &[],
                )
                .await
                .map_err(pg_err)?;
            if row.get::<_, bool>(0) {
                return Err(PairedBackupError::DeleterNotFenced(
                    "pando_storage_authorities.remote_delete_fenced is active; journal deletion refused",
                ));
            }
        }
    }
    Ok(())
}

pub(super) async fn set_pg_database_read_only(
    client: &(impl GenericClient + Sync),
    read_only: bool,
) -> Result<(), PairedBackupError> {
    let db_name: String = client.query_one("SELECT current_database()", &[]).await.map_err(pg_err)?.get(0);
    let quoted_db = db_name.replace('"', "\"\"");
    let sql = if read_only {
        format!(
            "ALTER DATABASE \"{quoted_db}\" SET default_transaction_read_only = on; \
             ALTER DATABASE \"{quoted_db}\" SET lock_timeout = '250ms'"
        )
    } else {
        format!(
            "ALTER DATABASE \"{quoted_db}\" RESET default_transaction_read_only; \
             ALTER DATABASE \"{quoted_db}\" RESET lock_timeout"
        )
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

pub(super) async fn verify_pg_quiescent_before_freeze(
    client: &(impl GenericClient + Sync),
) -> Result<(), PairedBackupError> {
    let row = client
        .query_one(
            "SELECT \
               (SELECT count(*)::bigint FROM public.repositories WHERE transition_state <> 'stable'), \
               (SELECT count(*)::bigint FROM public.git_operations WHERE outcome = 'unknown') \
               + (SELECT count(*)::bigint FROM public.ref_store_operations WHERE state NOT IN ('committed','rejected','cancelled')) \
               + (SELECT count(*)::bigint FROM public.ref_store_publication_decisions WHERE state = 'OPEN'), \
               EXISTS(SELECT 1 FROM public.schema_migrations WHERE version = 152), \
               to_regclass('public.ref_store_public_operations') IS NOT NULL",
            &[],
        )
        .await
        .map_err(pg_err)?;
    let (transitioning, inflight): (i64, i64) = (row.get(0), row.get(1));
    if transitioning != 0 {
        return Err(PairedBackupError::FreezeNotHeld("repository storage transition in progress"));
    }
    if inflight != 0 {
        return Err(PairedBackupError::UnknownInFlightOperations(inflight as usize));
    }

    let registered: bool = row.get(2);
    let public_operations_present: bool = row.get(3);
    if registered != public_operations_present {
        return Err(PairedBackupError::FreezeNotHeld("migration 152 public operation catalog is incomplete"));
    }
    if public_operations_present {
        // A private A4 terminal can commit before its separate A5 public mirror.
        // The wrapper remains unresolved even when every core operation is terminal.
        let pending: i64 = client
            .query_one("SELECT count(*)::bigint FROM public.ref_store_public_operations WHERE state = 'pending'", &[])
            .await
            .map_err(pg_err)?
            .get(0);
        if pending != 0 {
            return Err(PairedBackupError::UnknownInFlightOperations(pending as usize));
        }
    }
    Ok(())
}
