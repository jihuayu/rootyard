use super::{
    models::{CheckpointRequest, ForkRequest, RestoreRequest, WS_COLUMNS, Workspace},
    service,
};
use crate::{AppState, Error, auth, members::models::Role, workspace_lab::core};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs, path::Path as FsPath, sync::Arc};
use uuid::Uuid;

fn copy_snapshot(source: &FsPath, dest: &FsPath) -> Result<super::snapshot::Published, Error> {
    let parent = dest.parent().ok_or_else(Error::bad_request)?;
    fs::create_dir_all(parent).map_err(Error::internal)?;
    let staging = parent.join(format!(".restore-{}", Uuid::new_v4()));
    let outcome = core::copy_all(source, &staging)
        .map_err(Error::internal)
        .and_then(|()| super::snapshot::publish(&staging, dest));
    if outcome.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    outcome
}

fn valid_agent(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<CheckpointRequest>,
) -> Result<(StatusCode, Json<Value>), Error> {
    service::authorized(&state, &headers, id, Role::Write, crate::token_scopes::RepoAction::WorkspacesWrite).await?;
    let mutation = super::blocking::lock_mutation(id, super::blocking::io_timeout()).await?;
    super::capture::reconcile_locked(&state, id, &mutation).await?;
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let key = auth::idempotency_key(&headers)?.ok_or_else(Error::bad_request)?.to_owned();
    let hash =
        hex::encode(Sha256::digest(format!("checkpoint:{}:{}", input.expected_workspace_revision, input.lease_epoch)));

    // Phase 1: short pre-check transaction without holding DB locks across snapshot I/O.
    let stored_fp = {
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        let ws =
            service::locked(&tx, &actor, id, Role::Write, crate::token_scopes::RepoAction::WorkspacesWrite).await?;
        if let Some(row) = tx
            .query_opt(
                "SELECT request_sha256,state,result FROM workspace_operations WHERE workspace_id=$1 AND idempotency_key=$2",
                &[&id, &key],
            )
            .await
            .map_err(Error::internal)?
        {
            if row.get::<_, String>(0) != hash {
                return Err(service::conflict());
            }
            if row.get::<_, String>(1) == "committed" {
                let replayed: Value = row.get(2);
                tx.commit().await.map_err(Error::internal)?;
                return Ok((StatusCode::OK, Json(replayed)));
            }
            return Err(service::conflict());
        }
        let lease_ok: bool = tx
            .query_one(
                "SELECT host_id=$2 AND lease_epoch=$3 AND lease_until>clock_timestamp() FROM workspaces WHERE id=$1",
                &[&id, &state.storage.volume_id, &input.lease_epoch],
            )
            .await
            .map_err(Error::internal)?
            .get(0);
        if !lease_ok || ws.revision != input.expected_workspace_revision {
            return Err(service::conflict());
        }
        let stored_fp = tx
            .query_opt("SELECT fingerprint FROM workspace_capture_state WHERE workspace_id=$1", &[&id])
            .await
            .map_err(Error::internal)?
            .map(|row| row.get::<_, String>(0));
        tx.commit().await.map_err(Error::internal)?;
        stored_fp
    };

    // Phase 2: bounded off-thread frozen snapshot copy with zero PostgreSQL locks held.
    let cp = Uuid::new_v4();
    let source = service::workspace_repo(&state, id);
    let dest = service::checkpoint_repo(&state, cp);
    let stable_gate = super::mounts::enabled();
    let state_copy = state.clone();
    let (before, published) = super::blocking::run_mutating(&mutation, move |abandoned, cp_fence| {
        if abandoned.is_abandoned() {
            return Err(Error::timeout());
        }
        super::mounts::with_frozen(id, || {
            let before_raw = super::snapshot::Raw::load(&source)?
                .ok_or_else(|| Error::internal("workspace raw snapshot unavailable"))?;
            let before = before_raw.digest().to_owned();
            if let Some(ref expected_fp) = stored_fp
                && &before != expected_fp
            {
                return Err(service::conflict());
            }
            let before_index = before_raw.raw_file(FsPath::new(".git/index"))?;
            if abandoned.is_abandoned() {
                return Err(Error::timeout());
            }
            let mut published = super::snapshot::copy(&state_copy, &before_raw, &dest)?;
            published.attach_fence(cp_fence);
            if abandoned.is_abandoned() {
                published.cleanup_sync();
                return Err(Error::timeout());
            }
            let captured = super::snapshot::fingerprint(&dest)?;
            if before != captured {
                return Err(service::conflict());
            }
            if !stable_gate {
                let after_raw = super::snapshot::Raw::load(&source)?
                    .ok_or_else(|| Error::internal("workspace raw snapshot unavailable"))?;
                let after = after_raw.digest().to_owned();
                let after_index = after_raw.raw_file(FsPath::new(".git/index"))?;
                if before != after || before_index != after_index {
                    return Err(service::conflict());
                }
            }
            if abandoned.is_abandoned() {
                published.cleanup_sync();
                return Err(Error::timeout());
            }
            Ok((before, published))
        })
    })
    .await?;

    // Phase 3: short FOR UPDATE commit transaction; clean up checkpoint tree on pre-COMMIT exit.
    let mut published_opt = Some(published);
    let phase3: Result<(StatusCode, Value), Error> = async {
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        let ws =
            service::locked(&tx, &actor, id, Role::Write, crate::token_scopes::RepoAction::WorkspacesWrite).await?;
        if let Some(row) = tx
            .query_opt(
                "SELECT request_sha256,state,result FROM workspace_operations WHERE workspace_id=$1 AND idempotency_key=$2",
                &[&id, &key],
            )
            .await
            .map_err(Error::internal)?
        {
            if row.get::<_, String>(0) != hash {
                return Err(service::conflict());
            }
            if row.get::<_, String>(1) == "committed" {
                let replayed: Value = row.get(2);
                tx.commit().await.map_err(Error::internal)?;
                return Ok((StatusCode::OK, replayed));
            }
            return Err(service::conflict());
        }
        let lease_ok: bool = tx
            .query_one(
                "SELECT host_id=$2 AND lease_epoch=$3 AND lease_until>clock_timestamp() FROM workspaces WHERE id=$1",
                &[&id, &state.storage.volume_id, &input.lease_epoch],
            )
            .await
            .map_err(Error::internal)?
            .get(0);
        if !lease_ok || ws.revision != input.expected_workspace_revision {
            return Err(service::conflict());
        }
        let current_fp = tx
            .query_opt("SELECT fingerprint FROM workspace_capture_state WHERE workspace_id=$1 FOR UPDATE", &[&id])
            .await
            .map_err(Error::internal)?
            .map(|row| row.get::<_, String>(0));
        match current_fp {
            Some(ref fp) if fp != &before => return Err(service::conflict()),
            Some(_) => {}
            None => super::capture::record_fingerprint(&tx, id, &before).await?,
        }
        let revision = ws.revision + 1;
        let result = json!({
            "checkpoint_id": cp,
            "workspace_id": id,
            "captured_revision": ws.revision,
            "workspace_revision": revision,
            "state": "local_complete",
            "durability": "local_filesystem_only",
            "excluded_native_state": "none"
        });
        let base_oid: Option<String> = tx
            .query_opt("SELECT base_oid FROM workspaces WHERE id=$1", &[&id])
            .await
            .map_err(Error::internal)?
            .and_then(|row| row.get(0));
        tx.execute(
            "INSERT INTO workspace_checkpoints(id,workspace_id,repository_id,captured_revision,lease_epoch,state,excluded_summary,base_oid) \
             VALUES($1,$2,$3,$4,$5,'local_complete',$6,$7)",
            &[&cp, &id, &ws.repository_id, &ws.revision, &ws.lease_epoch, &json!({"native_entries": "included"}), &base_oid],
        )
        .await
        .map_err(Error::internal)?;
        tx.execute(
            "UPDATE workspaces SET revision=$2,last_checkpoint_id=$3,lease_until=clock_timestamp()+interval '5 minutes' WHERE id=$1",
            &[&id, &revision, &cp],
        )
        .await
        .map_err(Error::internal)?;
        tx.execute(
            "INSERT INTO workspace_events(workspace_id,revision,kind,payload) VALUES($1,$2,'checkpoint',$3)",
            &[&id, &revision, &result],
        )
        .await
        .map_err(Error::internal)?;
        tx.execute(
            "INSERT INTO workspace_operations(id,workspace_id,idempotency_key,request_sha256,kind,state,result) \
             VALUES($1,$2,$3,$4,'checkpoint','committed',$5)",
            &[&Uuid::new_v4(), &id, &key, &hash, &result],
        )
        .await
        .map_err(Error::internal)?;
        if let Some(guard) = published_opt.take() {
            guard.keep();
        }
        tx.commit().await.map_err(Error::internal)?;
        Ok((StatusCode::CREATED, result))
    }
    .await;

    if let Some(guard) = published_opt.take() {
        guard.cleanup().await;
    }
    drop(mutation);
    let (status, result) = phase3?;
    Ok((status, Json(result)))
}

async fn restore_inner(
    state: Arc<AppState>,
    headers: HeaderMap,
    cp: Uuid,
    agent: String,
    kind: &str,
) -> Result<(StatusCode, Json<Workspace>), Error> {
    if !valid_agent(&agent) {
        return Err(Error::bad_request());
    }
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let key = auth::idempotency_key(&headers)?.map(str::to_owned);
    let digest = hex::encode(Sha256::digest(serde_json::to_vec(&(kind, cp, &agent)).map_err(Error::internal)?));

    // Phase 1: short read pre-check and idempotency fast path.
    let (parent, owner_id, cp_state) = {
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        let row = tx
            .query_opt(
                "SELECT w.id,w.repository_id,w.owner_slug,w.repository_name,w.agent_id,w.creator_id,w.state,w.host_id,w.lease_epoch,w.revision,w.git_generation,w.last_checkpoint_id,c.state AS checkpoint_state \
                 FROM workspace_checkpoints c JOIN workspaces w ON w.id=c.workspace_id \
                 WHERE c.id=$1 AND c.state IN ('local_complete','committed')",
                &[&cp],
            )
            .await
            .map_err(Error::internal)?
            .ok_or_else(Error::not_found)?;
        let parent = Workspace::from_row(&row);
        let access = auth::authorize_repo_with_role(
            &tx,
            &actor,
            &parent.owner,
            &parent.repository,
            Role::Write,
            crate::token_scopes::RepoAction::WorkspacesWrite,
        )
        .await?;
        if parent.creator_id != actor.id || access.repo_id != parent.repository_id {
            return Err(Error::not_found());
        }
        if let Some(ref key) = key
            && let Some(saved) = service::lookup_existing_creation(&tx, actor.id, key, &digest, false).await?
        {
            tx.commit().await.map_err(Error::internal)?;
            drop(client);
            super::mounts::ensure_from_database(&state, saved.id).await?;
            return Ok((StatusCode::OK, Json(saved)));
        }
        let cp_state: String = row.get("checkpoint_state");
        tx.commit().await.map_err(Error::internal)?;
        (parent, access.owner_id, cp_state)
    };

    // Phase 2: materialize lower tree and compute initial fingerprint off-thread with zero DB locks held.
    let id = Uuid::new_v4();
    let mutation = super::blocking::lock_mutation(id, super::blocking::io_timeout()).await?;
    let lower = super::mounts::lower_path(&state, id);
    let (mut lazy_guard, mut published, initial_fingerprint) = if super::mounts::enabled() && cp_state == "committed" {
        let lazy_pub = super::lazy::prepare(&state, id, cp, parent.repository_id, owner_id, &mutation).await?;
        let lower_fp = lower.clone();
        let fp = match super::blocking::run_mutating(&mutation, move |abandoned, _fence| {
            if abandoned.is_abandoned() {
                return Err(Error::timeout());
            }
            super::capture::fingerprint(&lower_fp)
        })
        .await
        {
            Ok(fp) => fp,
            Err(error) => {
                lazy_pub.cleanup().await;
                return Err(error);
            }
        };
        (Some(lazy_pub), None, fp)
    } else {
        super::remote::ensure_local(&state, cp, parent.repository_id, owner_id).await?;
        let cp_repo = service::checkpoint_repo(&state, cp);
        let lower_copy = lower.clone();
        let (pub_dir, fp) = super::blocking::run_mutating(&mutation, move |abandoned, fence| {
            if abandoned.is_abandoned() {
                return Err(Error::timeout());
            }
            let mut pub_dir = copy_snapshot(&cp_repo, &lower_copy)?;
            pub_dir.attach_fence(fence);
            if abandoned.is_abandoned() {
                pub_dir.cleanup_sync();
                return Err(Error::timeout());
            }
            let fp = super::capture::fingerprint(&lower_copy)?;
            if abandoned.is_abandoned() {
                pub_dir.cleanup_sync();
                return Err(Error::timeout());
            }
            Ok((pub_dir, fp))
        })
        .await?;
        (None, Some(pub_dir), fp)
    };

    // Phase 3: short commit transaction locking the checkpoint row against concurrent abandon.
    let phase3: Result<(StatusCode, Workspace), Error> = async {
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        let check_row = tx
            .query_opt(
                "SELECT w.creator_id,w.repository_id,w.owner_slug,w.repository_name,c.base_oid \
                 FROM workspace_checkpoints c JOIN workspaces w ON w.id=c.workspace_id \
                 WHERE c.id=$1 AND c.state IN ('local_complete','committed') FOR SHARE OF c",
                &[&cp],
            )
            .await
            .map_err(Error::internal)?
            .ok_or_else(service::conflict)?;
        let owner_slug: String = check_row.get(2);
        let repo_name: String = check_row.get(3);
        let access = auth::authorize_repo_with_role(
            &tx,
            &actor,
            &owner_slug,
            &repo_name,
            Role::Write,
            crate::token_scopes::RepoAction::WorkspacesWrite,
        )
        .await?;
        if check_row.get::<_, Uuid>(0) != actor.id || access.repo_id != check_row.get::<_, Uuid>(1) {
            return Err(Error::not_found());
        }
        if let Some(ref key) = key {
            service::creation_lock(&tx, actor.id, key).await?;
            if let Some(saved) = service::lookup_existing_creation(&tx, actor.id, key, &digest, true).await? {
                tx.commit().await.map_err(Error::internal)?;
                return Ok((StatusCode::OK, saved));
            }
        }
        let base_oid: Option<String> = check_row.get(4);
        tx.execute(
            "INSERT INTO workspaces(id,repository_id,owner_slug,repository_name,agent_id,creator_id,parent_checkpoint_id,state,host_id,lease_until,base_oid) \
             VALUES($1,$2,$3,$4,$5,$6,$7,'ready',$8,clock_timestamp()+interval '5 minutes',$9)",
            &[&id, &parent.repository_id, &owner_slug, &repo_name, &agent, &actor.id, &cp, &state.storage.volume_id, &base_oid],
        )
        .await
        .map_err(Error::internal)?;
        if let Some(ref key) = key {
            tx.execute(
                "INSERT INTO workspace_creations(actor_id,idempotency_key,request_sha256,workspace_id) VALUES($1,$2,$3,$4)",
                &[&actor.id, key, &digest, &id],
            )
            .await
            .map_err(Error::internal)?;
        }
        super::capture::record_fingerprint(&tx, id, &initial_fingerprint).await?;
        let row = tx
            .query_one(&format!("SELECT {WS_COLUMNS} FROM workspaces WHERE id=$1"), &[&id])
            .await
            .map_err(Error::internal)?;
        if let Some(guard) = lazy_guard.take() {
            guard.keep();
        }
        if let Some(guard) = published.take() {
            guard.keep();
        }
        tx.commit().await.map_err(Error::internal)?;
        Ok((StatusCode::CREATED, Workspace::from_row(&row)))
    }
    .await;

    if let Some(guard) = lazy_guard.take() {
        guard.cleanup().await;
    }
    if let Some(guard) = published.take() {
        guard.cleanup().await;
    }
    let (status, saved) = phase3?;
    super::mounts::ensure_from_database(&state, saved.id).await?;
    Ok((status, Json(saved)))
}

pub async fn restore(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<RestoreRequest>,
) -> Result<(StatusCode, Json<Workspace>), Error> {
    restore_inner(state, headers, id, input.agent_id, "restore").await
}

pub async fn fork(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<ForkRequest>,
) -> Result<(StatusCode, Json<Workspace>), Error> {
    let ws = service::authorized(&state, &headers, id, Role::Write, crate::token_scopes::RepoAction::WorkspacesWrite)
        .await?;
    let client = state.pool.get().await.map_err(Error::internal)?;
    let row = client
        .query_opt("SELECT workspace_id FROM workspace_checkpoints WHERE id=$1", &[&input.checkpoint_id])
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    drop(client);
    if row.get::<_, Uuid>(0) != ws.id {
        return Err(Error::not_found());
    }
    restore_inner(state, headers, input.checkpoint_id, input.new_agent_id, "fork").await
}

#[cfg(test)]
#[path = "checkpoints_tests.rs"]
mod tests;
