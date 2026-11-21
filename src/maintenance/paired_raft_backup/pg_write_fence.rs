//! Kernel-enforced PostgreSQL table write fence: a dedicated session holds
//! `LOCK TABLE <all public base tables> IN SHARE MODE` so no other session can
//! acquire the `RowExclusiveLock` required by `INSERT`/`UPDATE`/`DELETE`/DDL (#153).

use std::fmt;
use std::time::{Duration, Instant};

use tokio_postgres::Client;

use super::pg_cutpoint::pg_err;
use super::types::PairedBackupError;

pub struct PgTableShareFence {
    client: Client,
    backend_pid: i32,
    locked_tables: usize,
}

impl fmt::Debug for PgTableShareFence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PgTableShareFence")
            .field("backend_pid", &self.backend_pid)
            .field("locked_tables", &self.locked_tables)
            .finish()
    }
}

pub async fn acquire_pg_table_share_fence(
    database_url: &str,
    timeout: Duration,
) -> Result<PgTableShareFence, PairedBackupError> {
    let client = crate::db::connect_url(database_url).await.map_err(|e| PairedBackupError::Postgres(e.to_string()))?;
    client
        .batch_execute(
            "SET application_name = 'rootyard-paired-write-fence'; \
             SET SESSION CHARACTERISTICS AS TRANSACTION READ WRITE; \
             BEGIN ISOLATION LEVEL REPEATABLE READ;",
        )
        .await
        .map_err(pg_err)?;
    let rows = client
        .query(
            "SELECT c.relname FROM pg_class c \
             JOIN pg_namespace n ON n.oid = c.relnamespace \
             WHERE n.nspname = 'public' AND c.relkind = 'r' \
             ORDER BY c.relname",
            &[],
        )
        .await
        .map_err(pg_err)?;
    if rows.is_empty() {
        let _ = client.batch_execute("ROLLBACK").await;
        return Err(PairedBackupError::FreezeNotHeld("PostgreSQL public schema has no base tables to write-fence"));
    }
    let tables: Vec<String> =
        rows.iter().map(|row| format!("public.\"{}\"", row.get::<_, String>(0).replace('"', "\"\""))).collect();
    let lock_sql = format!(
        "SAVEPOINT ry_share_fence; SET LOCAL lock_timeout = '200ms'; \
         LOCK TABLE {} IN SHARE MODE; RELEASE SAVEPOINT ry_share_fence;",
        tables.join(", ")
    );
    let deadline = Instant::now() + timeout;
    loop {
        match client.batch_execute(&lock_sql).await {
            Ok(()) => break,
            Err(_) => {
                let _ = client.batch_execute("ROLLBACK TO SAVEPOINT ry_share_fence").await;
                if Instant::now() >= deadline {
                    let _ = client.batch_execute("ROLLBACK").await;
                    return Err(PairedBackupError::FreezeNotHeld(
                        "failed to acquire PostgreSQL SHARE table write fence",
                    ));
                }
                tokio::time::sleep(Duration::from_millis(40)).await;
            }
        }
    }
    let backend_pid: i32 = client.query_one("SELECT pg_backend_pid()", &[]).await.map_err(pg_err)?.get(0);
    Ok(PgTableShareFence { client, backend_pid, locked_tables: rows.len() })
}

impl PgTableShareFence {
    pub fn backend_pid(&self) -> i32 {
        self.backend_pid
    }

    pub async fn verify_held(&self) -> Result<(), PairedBackupError> {
        let row = self
            .client
            .query_one(
                "SELECT \
                   (SELECT count(*)::bigint FROM pg_locks l JOIN pg_class c ON c.oid = l.relation \
                      JOIN pg_namespace n ON n.oid = c.relnamespace \
                     WHERE l.pid = pg_backend_pid() AND l.mode = 'ShareLock' AND l.granted \
                       AND n.nspname = 'public' AND c.relkind = 'r'), \
                   (SELECT count(*)::bigint FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
                     WHERE n.nspname = 'public' AND c.relkind = 'r'), \
                   pg_backend_pid(), \
                   (SELECT backend_xid IS NULL FROM pg_stat_activity WHERE pid = pg_backend_pid())",
                &[],
            )
            .await
            .map_err(pg_err)?;
        let granted_count: i64 = row.get(0);
        let total_public_tables: i64 = row.get(1);
        let current_pid: i32 = row.get(2);
        let no_xid: Option<bool> = row.get(3);
        if current_pid != self.backend_pid
            || granted_count as usize != self.locked_tables
            || total_public_tables as usize != self.locked_tables
            || no_xid != Some(true)
        {
            return Err(PairedBackupError::FreezeNotHeld("PostgreSQL SHARE table write fence lost or dirty"));
        }
        Ok(())
    }

    pub async fn release(self) -> Result<(), PairedBackupError> {
        self.client.batch_execute("ROLLBACK").await.map_err(pg_err)?;
        Ok(())
    }
}
