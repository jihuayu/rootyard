//! PostgreSQL session advisory lock guard serializing intra-deployment Pando
//! authority attestation and epoch transitions (#77).
//!
//! Concurrent healthy callers sharing the same PostgreSQL schema (e.g.,
//! `pin_recovery_root`, `pando_tombstone_delete`, and `verify_or_attest`)
//! coordinate here so they never overwrite one another's local claim intent or
//! race on `If-None-Match: *` epoch proofs, while independent databases or clones
//! retain separate PG advisory namespaces and fail closed on the shared bucket.
use anyhow::{Result, bail};
use deadpool_postgres::{Object, Pool};
use std::time::Duration;
use tokio::time::Instant;

const AUTHORITY_LOCK_TRY_SQL: &str = "WITH lock_target AS ( \
        SELECT hashtextextended( \
            $1 || (SELECT c.relnamespace::text FROM pg_class c WHERE c.oid = 'pando_storage_authorities'::regclass), \
            0 \
        ) AS key \
    ) \
    SELECT key, pg_try_advisory_lock(key) FROM lock_target";

const AUTHORITY_LOCK_RELEASE_SQL: &str = "SELECT pg_advisory_unlock($1)";
const AUTHORITY_LOCK_PREFIX: &str = "rootyard-pando-authority-v1:";

pub(super) struct AuthorityLockGuard {
    client: Option<Object>,
    key: i64,
}

impl AuthorityLockGuard {
    pub(super) async fn acquire(pool: &Pool, deadline: Instant) -> Result<Self> {
        loop {
            let client = pool.get().await?;
            let row = client.query_one(AUTHORITY_LOCK_TRY_SQL, &[&AUTHORITY_LOCK_PREFIX]).await?;
            let key: i64 = row.get(0);
            let granted: bool = row.get(1);
            if granted {
                return Ok(Self { client: Some(client), key });
            }
            // Drop the pooled connection before sleeping so waiting callers never
            // exhaust the pool and starve the active lock holder.
            drop(client);
            let now = Instant::now();
            if now >= deadline {
                bail!("timed out waiting for Pando authority advisory lock");
            }
            tokio::time::sleep(Duration::from_millis(20).min(deadline.saturating_duration_since(now))).await;
        }
    }

    pub(super) fn client(&self) -> &Object {
        self.client.as_ref().expect("Pando authority lock client taken")
    }

    pub(super) fn client_mut(&mut self) -> &mut Object {
        self.client.as_mut().expect("Pando authority lock client taken")
    }

    pub(super) async fn release(mut self) {
        if let Some(client) = self.client.take() {
            let released = tokio::time::timeout(
                Duration::from_secs(3),
                client.query_one(AUTHORITY_LOCK_RELEASE_SQL, &[&self.key]),
            )
            .await;
            if !matches!(released, Ok(Ok(row)) if row.get::<_, bool>(0)) {
                // Evict the connection so deadpool closes the session and
                // PostgreSQL tears down any session-level advisory lock.
                drop(Object::take(client));
            }
        }
    }
}

impl Drop for AuthorityLockGuard {
    fn drop(&mut self) {
        if let Some(client) = self.client.take() {
            drop(Object::take(client));
        }
    }
}
