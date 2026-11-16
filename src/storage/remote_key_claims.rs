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

pub const DEFAULT_DELETE_CLAIM_LEASE_SECS: i64 = 120;
const CLAIM_WAIT_POLL_MS: u64 = 25;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeleteClaim {
    pub tenant_id: Uuid,
    pub namespace: String,
    pub digest: String,
    pub claim_generation: i64,
}

pub(super) fn valid_claim_target(namespace: &str, digest: &str) -> Result<(), Error> {
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
             (tenant_id, namespace, digest, claim_generation, deleting, delete_uncertain, lease_until, claimed_at) \
             VALUES ($1, $2, $3, 1, true, false, \
                     clock_timestamp() + make_interval(secs => ($4::bigint)::double precision), \
                     clock_timestamp()) \
             ON CONFLICT (tenant_id, namespace, digest) DO UPDATE SET \
               claim_generation = remote_object_delete_claims.claim_generation + 1, \
               deleting = true, \
               delete_uncertain = false, \
               lease_until = clock_timestamp() + make_interval(secs => ($4::bigint)::double precision), \
               claimed_at = clock_timestamp() \
             WHERE remote_object_delete_claims.delete_uncertain = false \
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

/// Inside a publisher transaction holding `lock_object_key`, verify no delete claim is pending or uncertain.
pub async fn has_active_delete_claim(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    namespace: &str,
    digest: &str,
) -> Result<bool, Error> {
    valid_claim_target(namespace, digest)?;
    let active: bool = tx
        .query_one(
            "SELECT EXISTS( \
                 SELECT 1 FROM remote_object_delete_claims \
                 WHERE tenant_id = $1 AND namespace = $2 AND digest = $3 \
                   AND (deleting = true OR delete_uncertain = true) \
             )",
            &[&tenant_id, &namespace, &digest],
        )
        .await
        .map_err(Error::internal)?
        .get(0);
    Ok(active)
}

/// Execute a claimed remote object deletion while holding the per-key advisory lock
/// across recheck -> physical delete -> claim completion, persisting `delete_uncertain = true`
/// before network delete so crashes or timeouts fail closed until recovery verifies deletion.
pub async fn execute_locked_claimed_delete(
    pool: &Pool,
    store: &RemoteObjectStore,
    claim: &DeleteClaim,
    deadline: Instant,
) -> Result<(), anyhow::Error> {
    valid_claim_target(&claim.namespace, &claim.digest).map_err(|e| anyhow::anyhow!(e.1))?;
    let key = ObjectKey::new(claim.tenant_id, &claim.namespace, &claim.digest)?;
    let mut client = pool.get().await?;
    {
        let pre_tx = client.transaction().await?;
        lock_object_key(&pre_tx, claim.tenant_id, &claim.namespace, &claim.digest)
            .await
            .map_err(|e| anyhow::anyhow!(e.1))?;
        let marked = pre_tx
            .execute(
                "UPDATE remote_object_delete_claims \
                 SET delete_uncertain = true \
                 WHERE tenant_id = $1 AND namespace = $2 AND digest = $3 \
                   AND claim_generation = $4 AND deleting = true AND lease_until > clock_timestamp()",
                &[&claim.tenant_id, &claim.namespace, &claim.digest, &claim.claim_generation],
            )
            .await?;
        anyhow::ensure!(marked == 1, "delete claim lease expired or superseded before remote delete");
        pre_tx.commit().await?;
    }

    let exec_tx = client.transaction().await?;
    lock_object_key(&exec_tx, claim.tenant_id, &claim.namespace, &claim.digest)
        .await
        .map_err(|e| anyhow::anyhow!(e.1))?;
    let row = exec_tx
        .query_opt(
            "SELECT claim_generation, deleting, delete_uncertain \
             FROM remote_object_delete_claims \
             WHERE tenant_id = $1 AND namespace = $2 AND digest = $3 FOR UPDATE",
            &[&claim.tenant_id, &claim.namespace, &claim.digest],
        )
        .await?;
    let Some(r) = row else {
        anyhow::bail!("delete claim disappeared before locked remote delete");
    };
    let row_gen: i64 = r.get(0);
    let deleting: bool = r.get(1);
    let delete_uncertain: bool = r.get(2);
    if row_gen != claim.claim_generation || !deleting {
        anyhow::ensure!(
            row_gen > claim.claim_generation && !deleting && !delete_uncertain,
            "delete claim superseded while delete outcome uncertain"
        );
        exec_tx.commit().await?;
        return Ok(());
    }
    anyhow::ensure!(
        !key_has_live_refs(&exec_tx, claim.tenant_id, &claim.namespace, &claim.digest)
            .await
            .map_err(|e| anyhow::anyhow!(e.1))?,
        "refusing remote delete after live reference appeared"
    );
    store.delete(&key, deadline).await?;
    let cleared = exec_tx
        .execute(
            "UPDATE remote_object_delete_claims \
             SET deleting = false, delete_uncertain = false \
             WHERE tenant_id = $1 AND namespace = $2 AND digest = $3 \
               AND claim_generation = $4 AND deleting = true",
            &[&claim.tenant_id, &claim.namespace, &claim.digest, &claim.claim_generation],
        )
        .await?;
    anyhow::ensure!(cleared == 1, "delete claim generation changed during remote delete completion");
    exec_tx.commit().await?;
    Ok(())
}

enum ClearClaimOutcome {
    Cleared,
    StillLeased,
    Uncertain,
}

async fn clear_expired_claim_once(
    pool: &Pool,
    store: Option<&RemoteObjectStore>,
    tenant_id: Uuid,
    namespace: &str,
    digest: &str,
    deadline: Instant,
) -> Result<ClearClaimOutcome, anyhow::Error> {
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    lock_object_key(&tx, tenant_id, namespace, digest).await.map_err(|e| anyhow::anyhow!(e.1))?;
    let row = tx
        .query_opt(
            "SELECT claim_generation, deleting, delete_uncertain, lease_until > clock_timestamp() \
             FROM remote_object_delete_claims \
             WHERE tenant_id = $1 AND namespace = $2 AND digest = $3 FOR UPDATE",
            &[&tenant_id, &namespace, &digest],
        )
        .await?;
    let Some(r) = row else {
        tx.commit().await?;
        return Ok(ClearClaimOutcome::Cleared);
    };
    let claim_gen: i64 = r.get(0);
    let deleting: bool = r.get(1);
    let delete_uncertain: bool = r.get(2);
    let still_leased: bool = r.get(3);
    if delete_uncertain {
        tx.commit().await?;
        return Ok(ClearClaimOutcome::Uncertain);
    }
    if !deleting {
        tx.commit().await?;
        return Ok(ClearClaimOutcome::Cleared);
    }
    if still_leased {
        tx.commit().await?;
        return Ok(ClearClaimOutcome::StillLeased);
    }
    let has_refs = key_has_live_refs(&tx, tenant_id, namespace, digest).await.map_err(|e| anyhow::anyhow!(e.1))?;
    if !has_refs && let Some(store) = store {
        let key = ObjectKey::new(tenant_id, namespace, digest)?;
        store.delete(&key, deadline).await?;
        anyhow::ensure!(
            store.head(&key, deadline).await?.is_none(),
            "remote key still present after stale claim cleanup"
        );
    }
    tx.execute(
        "UPDATE remote_object_delete_claims \
         SET deleting = false, delete_uncertain = false, claim_generation = claim_generation + 1 \
         WHERE tenant_id = $1 AND namespace = $2 AND digest = $3 AND claim_generation = $4",
        &[&tenant_id, &namespace, &digest, &claim_gen],
    )
    .await?;
    tx.commit().await?;
    Ok(ClearClaimOutcome::Cleared)
}

async fn recover_claim_once(
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
            "SELECT claim_generation, deleting, delete_uncertain, lease_until > clock_timestamp() \
             FROM remote_object_delete_claims \
             WHERE tenant_id = $1 AND namespace = $2 AND digest = $3 FOR UPDATE",
            &[&tenant_id, &namespace, &digest],
        )
        .await?;
    let Some(r) = row else {
        tx.commit().await?;
        return Ok(false);
    };
    let claim_gen: i64 = r.get(0);
    let deleting: bool = r.get(1);
    let delete_uncertain: bool = r.get(2);
    let still_leased: bool = r.get(3);
    if !deleting && !delete_uncertain {
        tx.commit().await?;
        return Ok(false);
    }
    if still_leased && !delete_uncertain {
        tx.commit().await?;
        return Ok(false);
    }
    let has_refs = key_has_live_refs(&tx, tenant_id, namespace, digest).await.map_err(|e| anyhow::anyhow!(e.1))?;
    if has_refs {
        anyhow::ensure!(!delete_uncertain, "live references exist on uncertain delete claim");
    } else if let Some(store) = store {
        let key = ObjectKey::new(tenant_id, namespace, digest)?;
        store.delete(&key, deadline).await?;
        anyhow::ensure!(
            store.head(&key, deadline).await?.is_none(),
            "remote key still present after uncertain-delete recovery"
        );
    } else if delete_uncertain {
        anyhow::bail!("missing object store to verify uncertain delete claim");
    }
    tx.execute(
        "UPDATE remote_object_delete_claims \
         SET deleting = false, delete_uncertain = false, claim_generation = claim_generation + 1 \
         WHERE tenant_id = $1 AND namespace = $2 AND digest = $3 AND claim_generation = $4",
        &[&tenant_id, &namespace, &digest, &claim_gen],
    )
    .await?;
    tx.commit().await?;
    Ok(true)
}

/// Wait while an in-flight delete claim holds an active lease, fail closed on uncertain
/// delete outcomes, or flush an expired stale delete claim under `lock_object_key`.
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
                    "SELECT delete_uncertain, lease_until > clock_timestamp() \
                     FROM remote_object_delete_claims \
                     WHERE tenant_id = $1 AND namespace = $2 AND digest = $3 \
                       AND (deleting = true OR delete_uncertain = true)",
                    &[&tenant_id, &namespace, &digest],
                )
                .await
                .map_err(Error::internal)?
        };
        let Some(r) = row else {
            return Ok(());
        };
        let delete_uncertain: bool = r.get(0);
        let lease_active: bool = r.get(1);
        if delete_uncertain {
            return Err(Error(
                StatusCode::SERVICE_UNAVAILABLE,
                "remote object delete outcome is uncertain; key reuse fenced pending recovery",
            ));
        }
        if lease_active {
            if Instant::now() >= deadline {
                return Err(Error(StatusCode::CONFLICT, "remote object delete claim in progress"));
            }
            sleep(Duration::from_millis(CLAIM_WAIT_POLL_MS)).await;
            continue;
        }
        match clear_expired_claim_once(pool, store, tenant_id, namespace, digest, deadline).await {
            Ok(ClearClaimOutcome::Cleared) => return Ok(()),
            Ok(ClearClaimOutcome::Uncertain) => {
                return Err(Error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "remote object delete outcome is uncertain; key reuse fenced pending recovery",
                ));
            }
            Ok(ClearClaimOutcome::StillLeased) => {}
            Err(_) => {
                return Err(Error(StatusCode::SERVICE_UNAVAILABLE, "remote object delete verification failed"));
            }
        }
        if Instant::now() >= deadline {
            return Err(Error(StatusCode::CONFLICT, "remote object delete claim in progress"));
        }
        sleep(Duration::from_millis(CLAIM_WAIT_POLL_MS)).await;
    }
}

/// Sweep expired or uncertain remote delete claims from crashed/failed purges.
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
                 WHERE (deleting = true AND lease_until <= clock_timestamp()) \
                    OR delete_uncertain = true \
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
        if recover_claim_once(pool, store, tenant_id, &ns, &digest, deadline).await? {
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
