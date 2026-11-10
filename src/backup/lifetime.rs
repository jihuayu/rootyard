//! Real PostgreSQL session advisory barriers shared by backup, restore and
//! every serving lifecycle.
//!
//! The legacy volume flock only excludes the native GitFS process; it says
//! nothing about `serve-blob`, which never opens that volume. The barrier both
//! sides really share is the PostgreSQL session lock on [`BARRIER_KEY`]:
//!
//! * `serve-blob` (and the control-plane worker) holds a **shared** session
//!   lock for the whole process lifetime;
//! * offline backup and restore take the **exclusive** session lock before
//!   fixing any snapshot, and hold it until every read, dump, export, import
//!   and publication step has finished.
//!
//! `pg_advisory_lock(<bigint>)` lands in the single-key advisory space, which
//! `pg_locks` reports as `classid=0, objid=<key>, objsubid=1` with the mode
//! `ExclusiveLock`/`ShareLock`. The holder is verified by the exact backend
//! pid and lock coordinates, so an unrelated session on the same database can
//! never be mistaken for our barrier.
//!
//! The witness does not borrow the client. The caller keeps owning its client
//! (and so can open its exported snapshot transaction mutably), while the
//! witness records the backend pid and the database tid used in the key,
//! checks them on every use and holds the barrier until an explicit bounded
//! release or until the owning session closes (error paths included).
use anyhow::{Context, Result};
use std::time::Duration;
use tokio::time::Instant;
use tokio_postgres::{Client, GenericClient};

/// Same key the legacy migration/maintenance barrier uses, so no path can hold
/// a barrier the others do not observe.
pub(super) const BARRIER_KEY: i64 = 738390103;
/// A barrier wait is bounded; an unaccounted holder is not treated as success.
pub(super) const BARRIER_WAIT: Duration = Duration::from_secs(30);
/// Every barrier statement is bounded so a stalled server cannot hang a
/// backup or a serving start.
const QUERY_BOUND: Duration = Duration::from_secs(5);

/// `pg_advisory_lock(738390103::bigint)` is one key in the single-key space. Its
/// `pg_locks` shape was verified against real PostgreSQL 17:
///
/// ```text
/// locktype=advisory classid=0 objid=738390103 objsubid=1 mode=ExclusiveLock
/// ```
///
/// so the exact filter is `classid=0, objid=KEY::int, objsubid=1`. The lock
/// lives in this database, and the holder is identified by the exact backend
/// pid, never by "some session on this database".
const HOLDER_SQL: &str = "SELECT count(*) FROM pg_locks \
     WHERE locktype='advisory' AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) \
       AND classid=0 AND objid=$1::int AND objsubid=1 AND pid=pg_backend_pid() AND mode=$2::text AND granted";

async fn bounded_query(
    client: &(impl GenericClient + Sync),
    sql: &str,
    params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
) -> Result<Vec<tokio_postgres::Row>, anyhow::Error> {
    tokio::time::timeout_at(Instant::now() + QUERY_BOUND, client.query(sql, params))
        .await
        .map_err(|_| anyhow::anyhow!("barrier statement exceeded its bound"))?
        .context("barrier statement failed")
}

async fn backend_pid(client: &(impl GenericClient + Sync)) -> Result<i32> {
    let rows = bounded_query(client, "SELECT pg_backend_pid()", &[]).await?;
    Ok(rows.into_iter().next().context("barrier session has no backend pid")?.get(0))
}

/// Exactly one granted lock row for this backend pid and key. A query error is
/// an unknown barrier state and therefore a failure, never "still held".
async fn held_by(client: &(impl GenericClient + Sync), mode: &str) -> Result<bool> {
    let rows = bounded_query(client, HOLDER_SQL, &[&(BARRIER_KEY as i32), &mode]).await?;
    let count: i64 = rows.into_iter().next().context("barrier state query returned no row")?.get(0);
    Ok(count == 1)
}

/// Exclusive session barrier held for the whole backup/restore lifecycle.
///
/// It owns no reference to the client, so the caller keeps exclusive `&mut`
/// access for its own exported-snapshot or restore transaction. It records the
/// backend pid that holds the key; every later use re-verifies that exact pid
/// still holds the exact lock row. Dropping the owning client (any error path)
/// closes the session and therefore releases the barrier implicitly; an
/// explicit [`BackupMutex::release`] proves the release when the happy path
/// ends.
pub(super) struct BackupMutex {
    pid: i32,
}

impl BackupMutex {
    /// Waits (bounded) for every shared serving session to leave, then acquires
    /// the exclusive session lock. A timeout is a refusal, never a warning.
    pub(super) async fn acquire(client: &Client) -> Result<BackupMutex> {
        let pid = backend_pid(client).await?;
        let granted: bool = tokio::time::timeout_at(
            Instant::now() + BARRIER_WAIT,
            client.query_one("SELECT pg_try_advisory_lock($1)", &[&BARRIER_KEY]),
        )
        .await
        .context("backup barrier wait exceeded; serving processes are still holding it")?
        .context("backup barrier could not be requested")?
        .get(0);
        anyhow::ensure!(granted, "serve-blob or another offline backup/restore already holds the lifecycle barrier");
        Ok(BackupMutex { pid })
    }

    /// Prove this session still holds the exact exclusive lock row.
    pub(super) async fn ensure_held(&self, client: &(impl GenericClient + Sync)) -> Result<()> {
        anyhow::ensure!(backend_pid(client).await? == self.pid, "backup barrier moved to another session");
        anyhow::ensure!(held_by(client, "ExclusiveLock").await?, "backup barrier was lost");
        Ok(())
    }

    /// Release explicitly and verify the server accepted it. On a failed
    /// release the session is closed by the caller, which also releases it.
    pub(super) async fn release(self, client: &Client) -> Result<()> {
        let released: bool = tokio::time::timeout_at(
            Instant::now() + QUERY_BOUND,
            client.query_one("SELECT pg_advisory_unlock($1)", &[&BARRIER_KEY]),
        )
        .await
        .context("backup barrier release exceeded its bound")?
        .context("backup barrier could not be released")?
        .get(0);
        anyhow::ensure!(released, "backup barrier was not owned at release");
        Ok(())
    }
}

/// Shared serving barrier held for the whole serviced lifetime.
///
/// Owns no reference to the pool or client; the serving entry point creates the
/// token after it opened its dedicated session, keeps it for the entire
/// lifetime of the server, and re-checks it on slow-path opportunities.
pub(crate) struct ServingBarrier {
    pid: i32,
}

impl ServingBarrier {
    pub(crate) async fn acquire(client: &Client, deadline: Instant) -> Result<ServingBarrier> {
        let pid = backend_pid(client).await?;
        let granted: bool = tokio::time::timeout_at(
            deadline,
            client.query_one("SELECT pg_try_advisory_lock_shared($1)", &[&BARRIER_KEY]),
        )
        .await
        .map_err(|_| anyhow::anyhow!("serving barrier wait exceeded"))?
        .map_err(|_| anyhow::anyhow!("serving barrier could not be requested"))?
        .get(0);
        anyhow::ensure!(
            granted,
            "an offline backup or restore holds the lifecycle barrier; refuse to serve this database"
        );
        Ok(ServingBarrier { pid })
    }

    /// A lost connection would silently drop the shared lock; re-check the
    /// exact row and pid before continuing to serve.
    pub(crate) async fn ensure_held(&self, client: &(impl GenericClient + Sync)) -> Result<()> {
        anyhow::ensure!(backend_pid(client).await? == self.pid, "serving barrier moved to another session");
        anyhow::ensure!(held_by(client, "ShareLock").await?, "serving barrier was lost");
        Ok(())
    }
}

/// A database-wide guard survives an interrupted restore even when a serving
/// process uses a different local data directory. It is outside the public
/// application catalog and is cleared only after durable target publication.
pub(crate) async fn ensure_database_available(client: &(impl GenericClient + Sync)) -> Result<()> {
    let rows = bounded_query(
        client,
        "SELECT EXISTS (SELECT 1 FROM pg_db_role_setting s, unnest(s.setconfig) AS setting \
         WHERE s.setdatabase=(SELECT oid FROM pg_database WHERE datname=current_database()) \
         AND s.setrole=0 AND setting LIKE 'rootyard.restore_in_progress=%')",
        &[],
    )
    .await?;
    anyhow::ensure!(!rows[0].get::<_, bool>(0), "an interrupted restore still fences this database");
    Ok(())
}

pub(super) async fn restore_marker(client: &Client, backup: Option<uuid::Uuid>) -> Result<()> {
    let database: String = bounded_query(client, "SELECT current_database()", &[]).await?[0].get(0);
    let database = database.replace('"', "\"\"");
    let sql = match backup {
        Some(id) => format!("ALTER DATABASE \"{database}\" SET rootyard.restore_in_progress = '{id}'"),
        None => format!("ALTER DATABASE \"{database}\" RESET rootyard.restore_in_progress"),
    };
    tokio::time::timeout(QUERY_BOUND, client.batch_execute(&sql))
        .await
        .context("restore database marker exceeded its bound")??;
    Ok(())
}

/// Prepare startup under the same database lock used by offline maintenance.
/// Auto migrations need an exclusive lock on this exact session. Acquire the
/// shared lifetime lock before releasing it, so no restore can enter the gap.
pub(crate) async fn prepare_serving_database(
    pool: &deadpool_postgres::Pool,
    client: &mut Client,
    deadline: Instant,
) -> Result<ServingBarrier> {
    match std::env::var("ROOTYARD_SCHEMA_MODE").as_deref() {
        Ok("external") => {
            let shared = ServingBarrier::acquire(client, deadline).await?;
            ensure_database_available(client).await?;
            tokio::time::timeout_at(deadline, crate::db::verify_schema(pool))
                .await
                .context("serving schema verification exceeded its bound")??;
            Ok(shared)
        }
        Ok("auto") | Err(_) => {
            let exclusive = BackupMutex::acquire(client).await?;
            ensure_database_available(client).await?;
            tokio::time::timeout_at(deadline, crate::db::migrate_client(client))
                .await
                .context("serving schema migration exceeded its bound")??;
            let shared = ServingBarrier::acquire(client, deadline).await?;
            exclusive.release(client).await?;
            Ok(shared)
        }
        _ => anyhow::bail!("ROOTYARD_SCHEMA_MODE must be external or auto"),
    }
}
