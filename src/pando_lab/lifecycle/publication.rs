use super::super::Config;
use anyhow::{Context, Result, bail};
use tokio::task::JoinHandle;
use tokio_postgres::{Client, NoTls};
use uuid::Uuid;

const RUNNER_DOMAIN: u64 = 0x4953_5332_3152_554e;
const PUBLICATION_DOMAIN: u64 = 0x4953_5332_3150_5542;

/// Dedicated, non-pooled PostgreSQL session. Advisory locks live on this
/// connection and are released only by closing it on guard drop/cancellation.
pub(crate) struct PgSession {
    client: Option<Client>,
    connection_task: Option<JoinHandle<()>>,
}

impl PgSession {
    pub(crate) async fn connect(config: &Config) -> Result<Self> {
        let (client, connection) = tokio_postgres::connect(&config.database, NoTls)
            .await
            .context("Pando dedicated PostgreSQL connection failed")?;
        let connection_task = tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(Self { client: Some(client), connection_task: Some(connection_task) })
    }

    pub(crate) fn client(&self) -> &Client {
        self.client.as_ref().expect("owned PostgreSQL session client")
    }

    pub(crate) async fn acquire_runner(&self, repo: Uuid) -> Result<()> {
        self.acquire(repo, RUNNER_DOMAIN, "runner").await
    }

    pub(crate) async fn acquire_publication_shared(&self, repo: Uuid) -> Result<()> {
        self.acquire_shared(repo, PUBLICATION_DOMAIN, "publication").await
    }

    pub(crate) async fn acquire_publication_exclusive(&self, repo: Uuid) -> Result<()> {
        self.acquire(repo, PUBLICATION_DOMAIN, "publication").await
    }

    pub(crate) async fn unlock_publication_exclusive(&self, repo: Uuid) -> Result<()> {
        let row = self
            .client()
            .query_one("SELECT pg_advisory_unlock($1)", &[&lock_key(repo, PUBLICATION_DOMAIN)])
            .await?;
        let released: bool = row.get(0);
        if !released {
            bail!("Pando publication advisory lock was not held by this session");
        }
        Ok(())
    }

    async fn acquire(&self, repo: Uuid, domain: u64, label: &str) -> Result<()> {
        let row = self
            .client()
            .query_one("SELECT pg_try_advisory_lock($1)", &[&lock_key(repo, domain)])
            .await?;
        let acquired: bool = row.get(0);
        if !acquired {
            bail!("Pando {label} lock is busy for repository {repo}");
        }
        Ok(())
    }

    async fn acquire_shared(&self, repo: Uuid, domain: u64, label: &str) -> Result<()> {
        let row = self
            .client()
            .query_one("SELECT pg_try_advisory_lock_shared($1)", &[&lock_key(repo, domain)])
            .await?;
        let acquired: bool = row.get(0);
        if !acquired {
            bail!("Pando {label} lock is busy for repository {repo}");
        }
        Ok(())
    }
}

impl Drop for PgSession {
    fn drop(&mut self) {
        if let Some(task) = self.connection_task.take() {
            task.abort();
        }
        // Dropping the client closes the socket if the driver task did not.
        // The connection is intentionally never returned to a pool.
        let _ = self.client.take();
    }
}

pub(crate) fn lock_key(repo: Uuid, domain: u64) -> i64 {
    let raw = repo.as_u128();
    (((raw >> 64) as u64) ^ (raw as u64) ^ domain) as i64
}

pub(crate) async fn active_rotation(
    client: &Client,
    repo: Uuid,
) -> Result<Option<super::rotation::KmsRotationCheckpoint>> {
    super::db::load_db_checkpoint(client, repo).await
}

pub(crate) async fn writer_session(config: &Config, repo: Uuid) -> Result<PgSession> {
    let session = PgSession::connect(config).await?;
    session.acquire_publication_shared(repo).await?;
    Ok(session)
}

pub(crate) async fn runner_session(config: &Config, repo: Uuid) -> Result<PgSession> {
    let session = PgSession::connect(config).await?;
    session.acquire_runner(repo).await?;
    Ok(session)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advisory_keys_are_stable_and_domain_separated() {
        let repo = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        assert_eq!(lock_key(repo, RUNNER_DOMAIN), lock_key(repo, RUNNER_DOMAIN));
        assert_ne!(lock_key(repo, RUNNER_DOMAIN), lock_key(repo, PUBLICATION_DOMAIN));
        let other = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        assert_ne!(lock_key(repo, RUNNER_DOMAIN), lock_key(other, RUNNER_DOMAIN));
    }
}
