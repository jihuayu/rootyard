//! Deadline-aware BEGIN/COMMIT helpers shared by the RefStore controllers.
//!
//! These helpers are the only place that starts or ends a caller-owned short
//! transaction for the metadata core. They do not encode PostgreSQL protocol
//! messages themselves; they rely on the pinned `tokio-postgres` SDK.
//!
//! # BEGIN cancellation safety (SDK guarantee)
//!
//! `tokio_postgres::Client::transaction()` builds a transaction with
//! `batch_execute("BEGIN ...")`. In `tokio-postgres 0.7.18`
//! (`src/transaction_builder.rs`) the `BEGIN` message is written
//! synchronously by `batch_execute` before its response is polled, and a
//! `RollbackIfNotDone` guard is armed around that await. Dropping the builder
//! future at any point after `BEGIN` was sent (including a client-side
//! deadline) drops that guard, which queues `ROLLBACK` on the same connection
//! through the SDK's rollback API. The server therefore cannot be left in an
//! open transaction that Rust no longer owns. [`begin_bounded`] wraps exactly
//! that SDK future in `timeout_at`, so it inherits this guarantee; do not
//! reimplement `BEGIN`/`ROLLBACK` by hand.
//!
//! # COMMIT is different
//!
//! `Transaction::commit` consumes the `Transaction`, sets its `done` flag
//! before sending `COMMIT`, and then awaits the reply. If that future is
//! cancelled at the absolute deadline, or the reply is an error that could
//! also mean the reply was lost, the server may still commit. There is no
//! cancellation-safe way to turn that into a definite abort, so
//! [`commit_bounded`] reports [`RefStoreError::CommitUnknown`] with the
//! repository/operation identity; callers resolve it by querying that same
//! identity. Only an acknowledged `COMMIT` is reported as success.
//!
//! A COMMIT that was never issued because the deadline had already expired is
//! rolled back and reported as [`RefStoreError::Timeout`]. Cleanup should not
//! be relied upon for a hard physical return bound: a rollback queued or
//! awaited here may finish after the absolute deadline. What matters is that
//! it is never claimed as a successful commit or as proof of an abort after a
//! `COMMIT` was sent.
use super::contract::RefStoreError;
use super::pg::db_error;
use std::time::Duration;
use tokio::time::{Instant, timeout_at};
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

/// Start one transaction without outliving the caller's absolute deadline.
///
/// The returned `Err` is `Timeout` when the SDK has cancelled the pending
/// `BEGIN`; the SDK rollback guard then queues `ROLLBACK`, so the connection
/// returns to `idle` once the queued statement is processed. Any other error
/// is a connection/database error before a usable `Transaction` existed.
pub(crate) async fn begin_bounded(client: &mut Client, deadline: Instant) -> Result<Transaction<'_>, RefStoreError> {
    match timeout_at(deadline, client.transaction()).await {
        Ok(Ok(tx)) => Ok(tx),
        Ok(Err(error)) => Err(db_error(error)),
        Err(_) => Err(RefStoreError::Timeout),
    }
}

/// Commit or report an explicitly unknown outcome.
///
/// The absolute deadline is checked before `COMMIT` is issued: an expired
/// deadline rolls back (no `COMMIT` is sent) and returns `Timeout`. Once
/// `COMMIT` is issued, only an `Ok(())` acknowledgement is success. A timeout
/// or an error reply returns `CommitUnknown` because the transaction may still
/// commit or the reply may have been lost; this is deliberately neither a
/// conflict nor a rejection.
///
/// `operation_id` is `None` for bootstrap, whose caller resolves an unknown
/// commit through the idempotent gate/revision check instead of an operation
/// lookup.
pub(crate) async fn commit_bounded(
    tx: Transaction<'_>,
    deadline: Instant,
    repository_id: Uuid,
    operation_id: Option<Uuid>,
) -> Result<(), RefStoreError> {
    if Instant::now() >= deadline {
        // COMMIT was never sent. Bound the cleanup wait separately; dropping
        // the SDK rollback future still queues cleanup on this connection.
        let _cleanup = timeout_at(Instant::now() + Duration::from_secs(2), tx.rollback()).await;
        return Err(RefStoreError::Timeout);
    }
    match timeout_at(deadline, tx.commit()).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) | Err(_) => Err(RefStoreError::CommitUnknown { repository_id, operation_id }),
    }
}
