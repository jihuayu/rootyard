//! Commit Pando refs, pack-set membership and event outbox in one PG CAS.
//! Remote encrypted pack publication precedes this transaction; an orphaned
//! ready pack is harmless, while a PG ref must never point at an absent pack.
use super::{prepare::PreparedPush, snapshot::Snapshot};
use crate::{
    AppState, Error, auth,
    browse::policy,
    db::{Identity, Repository},
    events::{self, OperationRecord, RefEventInput},
    journal::RefChange,
    storage::ref_publication::PublicationGuard,
};
use axum::http::StatusCode;
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tokio::time::Instant;
use uuid::Uuid;

const MAX_PACKS: usize = 256;
fn conflict() -> Error {
    Error(StatusCode::CONFLICT, "Pando refs changed; retry from current refs")
}

/// Caller has completed native receive-pack in a disposable Snapshot and
/// staged any new closure. It must retain the exact-ref guard, but release the
/// local snapshot read lock before this method enters the publication window.
pub async fn publish(
    state: &Arc<AppState>,
    repo: &Repository,
    actor: &Identity,
    tenant_id: Uuid,
    snapshot: &Snapshot,
    prepared: &PreparedPush,
    requested: &[RefChange],
    guard: &PublicationGuard,
    deadline: Instant,
) -> Result<i64, Error> {
    if repo.storage_backend != "pando"
        || snapshot.storage_generation != repo.storage_generation
        || guard.repository_id() != repo.id
        || guard.storage_generation() != repo.storage_generation
        || prepared.changes.is_empty()
        || requested.len() != prepared.changes.len()
        || requested.len() != guard.refs().len()
    {
        return Err(conflict());
    }
    let expected: BTreeMap<_, _> =
        requested.iter().map(|change| (change.ref_name.as_str(), (&change.old_oid, &change.new_oid))).collect();
    if expected.len() != requested.len()
        || prepared
            .changes
            .iter()
            .any(|change| expected.get(change.ref_name.as_str()) != Some(&(&change.old_oid, &change.new_oid)))
        || guard.refs().iter().any(|name| !expected.contains_key(name.as_str()))
    {
        return Err(conflict());
    }
    if let Some(pack) = &prepared.pack {
        if pack.repository_id != repo.id
            || pack.tenant_id != tenant_id
            || pack.storage_generation != repo.storage_generation
            || pack.object_format != repo.object_format
        {
            return Err(conflict());
        }
    }
    guard.ensure_active()?;
    crate::sharding::fencing::check_before_push(state, repo).await?;
    let window = guard.enter_window(&state.storage, deadline).await?;
    window.ensure_active()?;
    crate::sharding::fencing::check_before_push(state, repo).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, actor, &repo.owner, &repo.name, auth::Role::Write).await?;
    if access.repo_id != repo.id || access.owner_id != tenant_id {
        return Err(conflict());
    }
    let current = tx
        .query_one(
            "SELECT r.storage_generation,r.storage_backend,r.object_format,r.transition_state,
        s.state,s.storage_generation AS pando_generation,s.ref_generation,s.operation_sequence,
        s.object_format AS pando_format,s.pack_ids FROM repositories r JOIN pando_repository_states s
        ON s.repository_id=r.id WHERE r.id=$1 AND s.tenant_id=$2 FOR UPDATE OF s",
            &[&repo.id, &tenant_id],
        )
        .await
        .map_err(Error::internal)?;
    if current.get::<_, i64>("storage_generation") != repo.storage_generation
        || current.get::<_, i64>("pando_generation") != repo.storage_generation
        || current.get::<_, &str>("storage_backend") != "pando"
        || current.get::<_, &str>("transition_state") != "stable"
        || current.get::<_, &str>("state") != "serving"
        || current.get::<_, &str>("object_format") != repo.object_format
        || current.get::<_, &str>("pando_format") != repo.object_format
    {
        return Err(conflict());
    }
    let ref_generation: i64 = current.get("ref_generation");
    let operation_sequence: i64 = current.get("operation_sequence");
    let mut pack_ids: Vec<Uuid> = current.get("pack_ids");
    let next_ref = ref_generation.checked_add(1).ok_or_else(conflict)?;
    let next_operation = operation_sequence.checked_add(1).ok_or_else(conflict)?;
    for change in &prepared.changes {
        let old = tx
            .query_opt(
                "SELECT oid FROM pando_refs WHERE repository_id=$1 AND ref_name=$2 FOR UPDATE",
                &[&repo.id, &change.ref_name],
            )
            .await
            .map_err(Error::internal)?;
        let zero = "0".repeat(change.old_oid.len());
        let actual = old.as_ref().map(|row| row.get::<_, String>(0)).unwrap_or(zero);
        if actual != change.old_oid {
            return Err(conflict());
        }
    }
    let timeout = deadline.saturating_duration_since(Instant::now()).min(Duration::from_secs(120));
    if timeout.is_zero() {
        return Err(Error::timeout());
    }
    guard
        .guard(Box::pin(policy::validate(
            &*tx,
            repo.id,
            &prepared.changes,
            &state.config.git,
            snapshot.path(),
            timeout,
        )))
        .await??;
    guard
        .guard(Box::pin(crate::lfs::publication::validate_new_refs_with_client(
            &*tx,
            snapshot.path(),
            &state.storage.root,
            &state.config.git,
            timeout,
            repo.id,
            tenant_id,
            &prepared.changes,
        )))
        .await??;
    guard
        .guard(Box::pin(crate::lfs::locks::validate_new_refs_with_client(
            &*tx,
            snapshot.path(),
            &state.config.git,
            timeout,
            repo.id,
            actor.id,
            &prepared.changes,
        )))
        .await??;
    if let Some(pack) = &prepared.pack {
        if pack_ids.len() >= MAX_PACKS || pack_ids.contains(&pack.id) {
            return Err(conflict());
        }
        let row = tx
            .query_opt(
                "SELECT manifest FROM pando_pack_manifests WHERE id=$1 AND repository_id=$2
            AND tenant_id=$3 AND storage_generation=$4 AND object_format=$5",
                &[&pack.id, &repo.id, &tenant_id, &repo.storage_generation, &repo.object_format],
            )
            .await
            .map_err(Error::internal)?
            .ok_or_else(conflict)?;
        if row.get::<_, serde_json::Value>(0) != serde_json::to_value(pack).map_err(Error::internal)? {
            return Err(conflict());
        }
        pack_ids.push(pack.id);
    }
    for change in &prepared.changes {
        if change.new_oid.bytes().all(|byte| byte == b'0') {
            tx.execute("DELETE FROM pando_refs WHERE repository_id=$1 AND ref_name=$2", &[&repo.id, &change.ref_name])
                .await
                .map_err(Error::internal)?;
        } else {
            tx.execute(
                "INSERT INTO pando_refs(repository_id,ref_name,oid,updated_generation)
                VALUES($1,$2,$3,$4) ON CONFLICT(repository_id,ref_name) DO UPDATE
                SET oid=EXCLUDED.oid,updated_generation=EXCLUDED.updated_generation",
                &[&repo.id, &change.ref_name, &change.new_oid, &next_ref],
            )
            .await
            .map_err(Error::internal)?;
        }
    }
    tx.execute(
        "UPDATE pando_repository_states SET ref_generation=$2,operation_sequence=$3,
        pack_ids=$4,updated_at=clock_timestamp() WHERE repository_id=$1",
        &[&repo.id, &next_ref, &next_operation, &pack_ids],
    )
    .await
    .map_err(Error::internal)?;
    let record = OperationRecord {
        id: Uuid::new_v4(),
        repository_id: repo.id,
        actor_id: actor.id,
        token_id: actor.token_id,
        service_principal_id: None,
        actor_name: actor.username.clone(),
        sequence: next_operation,
        storage_generation: repo.storage_generation,
        outcome: "recorded".into(),
        evidence: serde_json::json!({"version":1,"kind":"pando_pg_ref_cas",
            "snapshot_ref_generation":snapshot.ref_generation,
            "committed_ref_generation":next_ref,"pack_id":prepared.pack.as_ref().map(|pack|pack.id),
            "changes":prepared.changes}),
    };
    let events: Vec<_> = prepared
        .changes
        .iter()
        .enumerate()
        .map(|(index, change)| RefEventInput {
            transaction_sequence: index as i64 + 1,
            ref_name: change.ref_name.clone(),
            old_oid: change.old_oid.clone(),
            new_oid: change.new_oid.clone(),
        })
        .collect();
    events::publish_in_tx(&tx, &record, &events).await.map_err(Error::internal)?;
    window.ensure_active()?;
    auth::finish_tx(tx, actor, true).await?;
    state.dispatch.committed();
    window.ensure_active()?;
    Ok(next_ref)
}
