//! Shared advisory-locked remote object delete claims and stale-claim flushing (#85).
//!
//! Coordinates remote key creation (`lfs_objects`, `workspace_remote_staging_objects`)
//! with physical deletions (`purge`, expired claim sweeps) on the shared
//! `(tenant_id, namespace, digest)` key space.
use crate::{
    AppState, Error,
    storage::remote_objects::{ObjectKey, RemoteObjectStore},
};
use axum::http::StatusCode;
use deadpool_postgres::{Pool, Transaction};
use std::{collections::BTreeSet, time::Duration};
use tokio::time::{Instant, sleep};
use uuid::Uuid;

pub const DEFAULT_DELETE_CLAIM_LEASE_SECS: i64 = 30;
const CLAIM_WAIT_POLL_MS: u64 = 25;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeleteClaim {
    pub tenant_id: Uuid,
    pub namespace: String,
    pub digest: String,
    pub claim_generation: i64,
}

fn valid_claim_target(namespace: &str, digest: &str) -> Result<(), Error> {
    let valid_ns = matches!(namespace, "lfs" | "workspace");
    let valid_digest = digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !valid_ns || !valid_digest {
        return Err(Error::bad_request());
    }
    Ok(())
}

/// Acquire the per-`(tenant_id, namespace, digest)` transaction advisory lock.
/// Uses the shared domain seed `702` across LFS, Workspace GC, Workspace publish, and Purge.
pub async fn lock_object_key(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    namespace: &str,
    digest: &str,
) -> Result<(), Error> {
    valid_claim_target(namespace, digest)?;
    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended($1::uuid::text || ':' || $2::text || ':' || $3::text, 702))",
        &[&tenant_id, &namespace, &digest],
    )
    .await
    .map_err(Error::internal)?;
    Ok(())
}

/// Sort unique `(tenant_id, namespace, digest)` keys before taking advisory locks
/// so multi-key transactions never deadlock across batches or concurrent purges.
pub async fn lock_sorted_keys(tx: &Transaction<'_>, keys: &[(Uuid, &str, &str)]) -> Result<(), Error> {
    let ordered: BTreeSet<(Uuid, &str, &str)> = keys.iter().copied().collect();
    for (tenant_id, namespace, digest) in ordered {
        lock_object_key(tx, tenant_id, namespace, digest).await?;
    }
    Ok(())
}

/// Check whether any remaining DB row in the tenant references `(namespace, digest)`.
pub async fn key_has_live_refs(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    namespace: &str,
    digest: &str,
) -> Result<bool, Error> {
    valid_claim_target(namespace, digest)?;
    let has_refs: bool = match namespace {
        "lfs" => tx
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM lfs_objects WHERE tenant_id = $1 AND oid = $2)",
                &[&tenant_id, &digest],
            )
            .await
            .map_err(Error::internal)?
            .get(0),
        "workspace" => tx
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM workspace_remote_staging_objects WHERE tenant_id = $1 AND digest = $2) \
                 OR EXISTS(SELECT 1 FROM workspace_checkpoints c JOIN repositories r ON r.id = c.repository_id \
                           WHERE r.owner_id = $1 AND c.manifest_digest = $2)",
                &[&tenant_id, &digest],
            )
            .await
            .map_err(Error::internal)?
            .get(0),
        _ => return Err(Error::bad_request()),
    };
    Ok(has_refs)
}

/// Record or advance a delete claim for an unshared object under `lock_object_key`.
pub async fn upsert_delete_claim(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    namespace: &str,
    digest: &str,
    lease_secs: i64,
) -> Result<DeleteClaim, Error> {
    valid_claim_target(namespace, digest)?;
    let claim_gen: i64 = tx
        .query_one(
            "INSERT INTO remote_object_delete_claims \
             (tenant_id, namespace, digest, claim_generation, deleting, lease_until, claimed_at) \
             VALUES ($1, $2, $3, 1, true, \
                     clock_timestamp() + make_interval(secs => ($4::bigint)::double precision), \
                     clock_timestamp()) \
             ON CONFLICT (tenant_id, namespace, digest) DO UPDATE SET \
               claim_generation = remote_object_delete_claims.claim_generation + 1, \
               deleting = true, \
               lease_until = clock_timestamp() + make_interval(secs => ($4::bigint)::double precision), \
               claimed_at = clock_timestamp() \
             RETURNING claim_generation",
            &[&tenant_id, &namespace, &digest, &lease_secs.max(1)],
        )
        .await
        .map_err(Error::internal)?
        .get(0);
    Ok(DeleteClaim {
        tenant_id,
        namespace: namespace.to_owned(),
        digest: digest.to_owned(),
        claim_generation: claim_gen,
    })
}

/// Inside a publisher transaction holding `lock_object_key`, verify no delete claim is pending.
pub async fn has_active_delete_claim(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    namespace: &str,
    digest: &str,
) -> Result<bool, Error> {
    valid_claim_target(namespace, digest)?;
    let deleting: bool = tx
        .query_one(
            "SELECT EXISTS( \
                 SELECT 1 FROM remote_object_delete_claims \
                 WHERE tenant_id = $1 AND namespace = $2 AND digest = $3 AND deleting = true \
             )",
            &[&tenant_id, &namespace, &digest],
        )
        .await
        .map_err(Error::internal)?
        .get(0);
    Ok(deleting)
}

/// Before executing physical remote delete, prove our generation is still the active unexpired claim.
pub async fn verify_claim_lease(pool: &Pool, claim: &DeleteClaim) -> Result<bool, Error> {
    let client = pool.get().await.map_err(Error::internal)?;
    let valid: bool = client
        .query_one(
            "SELECT EXISTS( \
                 SELECT 1 FROM remote_object_delete_claims \
                 WHERE tenant_id = $1 AND namespace = $2 AND digest = $3 \
                   AND claim_generation = $4 AND deleting = true AND lease_until > clock_timestamp() \
             )",
            &[&claim.tenant_id, &claim.namespace, &claim.digest, &claim.claim_generation],
        )
        .await
        .map_err(Error::internal)?
        .get(0);
    Ok(valid)
}

/// Clear `deleting = false` only if the claim generation still matches ours.
pub async fn finish_claim(pool: &Pool, claim: &DeleteClaim) -> Result<(), Error> {
    let client = pool.get().await.map_err(Error::internal)?;
    client
        .execute(
            "UPDATE remote_object_delete_claims SET deleting = false \
             WHERE tenant_id = $1 AND namespace = $2 AND digest = $3 \
               AND claim_generation = $4 AND deleting = true",
            &[&claim.tenant_id, &claim.namespace, &claim.digest, &claim.claim_generation],
        )
        .await
        .map_err(Error::internal)?;
    Ok(())
}

async fn clear_expired_claim_once(
    pool: &Pool,
    store: Option<&RemoteObjectStore>,
    tenant_id: Uuid,
    namespace: &str,
    digest: &str,
    deadline: Instant,
) -> Result<bool, anyhow::Error> {
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    lock_object_key(&tx, tenant_id, namespace, digest).await.map_err(|e| anyhow::anyhow!(e.1))?;
    let row = tx
        .query_opt(
            "SELECT claim_generation, deleting, lease_until > clock_timestamp() \
             FROM remote_object_delete_claims \
             WHERE tenant_id = $1 AND namespace = $2 AND digest = $3 FOR UPDATE",
            &[&tenant_id, &namespace, &digest],
        )
        .await?;
    let Some(r) = row else {
        tx.commit().await?;
        return Ok(true);
    };
    let claim_gen: i64 = r.get(0);
    let deleting: bool = r.get(1);
    let still_leased: bool = r.get(2);
    if !deleting {
        tx.commit().await?;
        return Ok(true);
    }
    if still_leased {
        tx.commit().await?;
        return Ok(false);
    }
    let has_refs = key_has_live_refs(&tx, tenant_id, namespace, digest).await.map_err(|e| anyhow::anyhow!(e.1))?;
    if !has_refs && let Some(store) = store {
        let key = ObjectKey::new(tenant_id, namespace, digest)?;
        store.delete(&key, deadline).await?;
    }
    tx.execute(
        "UPDATE remote_object_delete_claims \
         SET deleting = false, claim_generation = claim_generation + 1 \
         WHERE tenant_id = $1 AND namespace = $2 AND digest = $3 AND claim_generation = $4",
        &[&tenant_id, &namespace, &digest, &claim_gen],
    )
    .await?;
    tx.commit().await?;
    Ok(true)
}

/// Wait while an in-flight delete claim holds an active lease, or flush an expired
/// stale delete claim under `lock_object_key` before publishing new refs.
pub async fn wait_or_clear_delete_claim(
    pool: &Pool,
    store: Option<&RemoteObjectStore>,
    tenant_id: Uuid,
    namespace: &str,
    digest: &str,
    deadline: Instant,
) -> Result<(), Error> {
    valid_claim_target(namespace, digest)?;
    loop {
        let row = {
            let client = pool.get().await.map_err(Error::internal)?;
            client
                .query_opt(
                    "SELECT lease_until > clock_timestamp() \
                     FROM remote_object_delete_claims \
                     WHERE tenant_id = $1 AND namespace = $2 AND digest = $3 AND deleting = true",
                    &[&tenant_id, &namespace, &digest],
                )
                .await
                .map_err(Error::internal)?
        };
        let Some(r) = row else {
            return Ok(());
        };
        let lease_active: bool = r.get(0);
        if lease_active {
            if Instant::now() >= deadline {
                return Err(Error(StatusCode::CONFLICT, "remote object delete claim in progress"));
            }
            sleep(Duration::from_millis(CLAIM_WAIT_POLL_MS)).await;
            continue;
        }
        if clear_expired_claim_once(pool, store, tenant_id, namespace, digest, deadline)
            .await
            .map_err(Error::internal)?
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(Error(StatusCode::CONFLICT, "remote object delete claim in progress"));
        }
        sleep(Duration::from_millis(CLAIM_WAIT_POLL_MS)).await;
    }
}

/// Sweep expired remote delete claims from crashed purges and flush their physical deletes.
pub async fn sweep_expired_claims_with_stores(
    pool: &Pool,
    lfs_store: Option<&RemoteObjectStore>,
    ws_store: Option<&RemoteObjectStore>,
    deadline: Instant,
) -> Result<usize, anyhow::Error> {
    let rows = {
        let client = pool.get().await?;
        client
            .query(
                "SELECT tenant_id, namespace, digest FROM remote_object_delete_claims \
                 WHERE deleting = true AND lease_until <= clock_timestamp() \
                 ORDER BY claimed_at LIMIT 64",
                &[],
            )
            .await?
    };
    let mut swept = 0usize;
    for row in rows {
        let tenant_id: Uuid = row.get(0);
        let ns: String = row.get(1);
        let digest: String = row.get(2);
        let store = match ns.as_str() {
            "lfs" => lfs_store,
            "workspace" => ws_store,
            _ => None,
        };
        if clear_expired_claim_once(pool, store, tenant_id, &ns, &digest, deadline).await? {
            swept += 1;
        }
    }
    Ok(swept)
}

pub async fn sweep_expired_claims(state: &AppState, deadline: Instant) -> Result<usize, anyhow::Error> {
    let lfs_store = if std::env::var_os("ROOTYARD_OBJECT_STORE_ENDPOINT").is_some() {
        Some(RemoteObjectStore::from_env(state.storage.root.join("remote-objects"))?)
    } else {
        None
    };
    let ws_store = Some(RemoteObjectStore::from_env(state.storage.root.join("workspace-service/local-object-cache"))?);
    sweep_expired_claims_with_stores(&state.pool, lfs_store.as_ref(), ws_store.as_ref(), deadline).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn valid_claim_target_rejects_bad_ns_or_digest() {
        let ok = "a".repeat(64);
        assert!(valid_claim_target("lfs", &ok).is_ok());
        assert!(valid_claim_target("workspace", &ok).is_ok());
        assert!(valid_claim_target("pando", &ok).is_err());
        assert!(valid_claim_target("lfs", "short").is_err());
        assert!(valid_claim_target("lfs", &"A".repeat(64)).is_err());
    }

    #[tokio::test]
    async fn expired_claim_flushes_unshared_stale_bytes_and_preserves_live_refs() {
        let Ok(base) = std::env::var("ROOTYARD_TEST_DATABASE_URL") else {
            return;
        };
        let admin = crate::db::pool(&base).unwrap();
        let schema = format!("claims_{}", Uuid::new_v4().simple());
        admin.get().await.unwrap().batch_execute(&format!("CREATE SCHEMA {schema}")).await.unwrap();
        let mut url = reqwest::Url::parse(&base).unwrap();
        url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
        let pool = crate::db::pool(url.as_str()).unwrap();
        let c = pool.get().await.unwrap();
        c.batch_execute(
            "CREATE TABLE namespaces(id uuid PRIMARY KEY); \
             CREATE TABLE repositories(id uuid PRIMARY KEY, owner_id uuid NOT NULL REFERENCES namespaces(id)); \
             CREATE TABLE lfs_objects(tenant_id uuid NOT NULL, repository_id uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE, oid text NOT NULL, PRIMARY KEY(tenant_id, repository_id, oid)); \
             CREATE TABLE workspace_checkpoints(id uuid PRIMARY KEY, repository_id uuid NOT NULL, manifest_digest text); \
             CREATE TABLE workspace_remote_staging_objects(checkpoint_id uuid NOT NULL, tenant_id uuid NOT NULL, digest text NOT NULL); \
             CREATE TABLE remote_object_delete_claims( \
               tenant_id uuid NOT NULL, namespace text NOT NULL, digest text NOT NULL, \
               claim_generation bigint NOT NULL DEFAULT 1, deleting boolean NOT NULL DEFAULT true, \
               lease_until timestamptz NOT NULL, claimed_at timestamptz NOT NULL DEFAULT clock_timestamp(), \
               PRIMARY KEY(tenant_id, namespace, digest))",
        )
        .await
        .unwrap();

        let dir = std::env::temp_dir().join(format!("ry-claim-test-{}", Uuid::new_v4()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let store = RemoteObjectStore::Local(dir.join("remote"));
        let tenant = Uuid::new_v4();
        let repo = Uuid::new_v4();
        c.execute("INSERT INTO namespaces(id) VALUES($1)", &[&tenant]).await.unwrap();
        c.execute("INSERT INTO repositories(id, owner_id) VALUES($1, $2)", &[&repo, &tenant]).await.unwrap();

        let payload = b"stale-purge-payload";
        let oid = hex::encode(Sha256::digest(payload));
        let staged_file = dir.join("stale.bin");
        tokio::fs::write(&staged_file, payload).await.unwrap();
        let key = ObjectKey::new(tenant, "lfs", &oid).unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        store.put_file(&key, &staged_file, payload.len() as u64, deadline).await.unwrap();

        let mut c_mut = pool.get().await.unwrap();
        let tx = c_mut.transaction().await.unwrap();
        let claim = upsert_delete_claim(&tx, tenant, "lfs", &oid, 1).await.unwrap();
        assert_eq!(claim.claim_generation, 1);
        tx.commit().await.unwrap();
        assert!(verify_claim_lease(&pool, &claim).await.unwrap());

        c.execute(
            "UPDATE remote_object_delete_claims SET lease_until = clock_timestamp() - interval '1 second' \
             WHERE tenant_id=$1 AND namespace='lfs' AND digest=$2",
            &[&tenant, &oid],
        )
        .await
        .unwrap();
        wait_or_clear_delete_claim(&pool, Some(&store), tenant, "lfs", &oid, deadline).await.unwrap();
        assert!(store.head(&key, deadline).await.unwrap().is_none());

        store.put_file(&key, &staged_file, payload.len() as u64, deadline).await.unwrap();
        c.execute("INSERT INTO lfs_objects(tenant_id, repository_id, oid) VALUES($1,$2,$3)", &[&tenant, &repo, &oid])
            .await
            .unwrap();
        c.execute(
            "UPDATE remote_object_delete_claims SET deleting=true, lease_until=clock_timestamp()-interval '1 second' \
             WHERE tenant_id=$1 AND namespace='lfs' AND digest=$2",
            &[&tenant, &oid],
        )
        .await
        .unwrap();
        let swept = sweep_expired_claims_with_stores(&pool, Some(&store), None, deadline).await.unwrap();
        assert_eq!(swept, 1);
        assert!(store.head(&key, deadline).await.unwrap().is_some());

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
