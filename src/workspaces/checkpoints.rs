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

/// Copy a checkpoint tree into a new workspace lower tree.
///
/// The copy is staged beside the destination and published with a no-replace
/// rename, so a lower tree that already exists is never overwritten or removed;
/// only a staging directory and a directory this call published are cleaned up.
fn copy_snapshot(source: &FsPath, dest: &FsPath) -> Result<(), Error> {
    let parent = dest.parent().ok_or_else(Error::bad_request)?;
    fs::create_dir_all(parent).map_err(Error::internal)?;
    let staging = parent.join(format!(".restore-{}", Uuid::new_v4()));
    core::private_dir(&staging).map_err(Error::internal)?;
    let outcome = core::copy_all(source, &staging)
        .map_err(Error::internal)
        .and_then(|()| super::snapshot::publish(&staging, dest));
    match outcome {
        Ok(published) => {
            published.keep();
            Ok(())
        }
        Err(error) => {
            let _ = fs::remove_dir_all(&staging);
            Err(error)
        }
    }
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
    service::authorized(&state, &headers, id, Role::Write).await?;
    super::capture::reconcile_one(&state, id).await?;
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let key = auth::idempotency_key(&headers)?.ok_or_else(Error::bad_request)?.to_owned();
    let hash =
        hex::encode(Sha256::digest(format!("checkpoint:{}:{}", input.expected_workspace_revision, input.lease_epoch)));
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let ws = service::locked(&tx, &actor, id, Role::Write).await?;
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
            return Ok((StatusCode::OK, Json(row.get(2))));
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
    let cp = Uuid::new_v4();
    let source = service::workspace_repo(&state, id);
    let dest = service::checkpoint_repo(&state, cp);
    // Check the native index and worktree around the immutable copy. A changed
    // source is rejected; external editors are not fenced by this DB lock.
    //
    // Everything inside the freeze reads service-owned raw layers only — the
    // lower tree, the upper tree, the lazy manifest and verified lazy-cache
    // bytes. Reading the FUSE mount here would queue behind the inode lock of a
    // parked write and deadlock the freezer (the process then parks in `D`).
    let (before, before_index, captured, after, after_index, published) = super::mounts::with_frozen(id, || {
        let before_raw = super::snapshot::Raw::load(&source)?
            .ok_or_else(|| Error::internal("workspace raw snapshot unavailable"))?;
        let before_index = before_raw.raw_file(FsPath::new(".git/index"))?;
        // The guard owns the directory this call publishes. Until the database
        // commit succeeds it is dropped on every failure path: a thaw error, a
        // re-read of the raw layers, a failed fingerprint, a SQL error and a
        // failed commit all remove exactly the tree this call created, and a
        // preexisting destination is never removed because publication is
        // no-replace.
        let published = super::snapshot::copy(&state, &before_raw, &dest)?;
        let captured = super::snapshot::fingerprint(&dest)?;
        let after_raw = super::snapshot::Raw::load(&source)?
            .ok_or_else(|| Error::internal("workspace raw snapshot unavailable"))?;
        let after = after_raw.digest().to_owned();
        let after_index = after_raw.raw_file(FsPath::new(".git/index"))?;
        Ok((before_raw.digest().to_owned(), before_index, captured, after, after_index, published))
    })?;
    if before != after || before != captured || before_index != after_index {
        return Err(service::conflict());
    }
    let revision = ws.revision + 1;
    let result = json!({"checkpoint_id":cp,"workspace_id":id,"captured_revision":ws.revision,"workspace_revision":revision,"state":"local_complete","durability":"local_filesystem_only","excluded_native_state":"none"});
    let base_oid: Option<String> = tx
        .query_opt("SELECT base_oid FROM workspaces WHERE id=$1", &[&id])
        .await
        .map_err(Error::internal)?
        .and_then(|row| row.get(0));
    tx.execute("INSERT INTO workspace_checkpoints(id,workspace_id,repository_id,captured_revision,lease_epoch,state,excluded_summary,base_oid) VALUES($1,$2,$3,$4,$5,'local_complete',$6,$7)", &[&cp,&id,&ws.repository_id,&ws.revision,&ws.lease_epoch,&json!({"native_entries":"included"}),&base_oid]).await.map_err(Error::internal)?;
    tx.execute("UPDATE workspaces SET revision=$2,last_checkpoint_id=$3,lease_until=clock_timestamp()+interval '5 minutes' WHERE id=$1", &[&id,&revision,&cp]).await.map_err(Error::internal)?;
    tx.execute(
        "INSERT INTO workspace_events(workspace_id,revision,kind,payload) VALUES($1,$2,'checkpoint',$3)",
        &[&id, &revision, &result],
    )
    .await
    .map_err(Error::internal)?;
    tx.execute("INSERT INTO workspace_operations(id,workspace_id,idempotency_key,request_sha256,kind,state,result) VALUES($1,$2,$3,$4,'checkpoint','committed',$5)", &[&Uuid::new_v4(),&id,&key,&hash,&result]).await.map_err(Error::internal)?;
    tx.commit().await.map_err(Error::internal)?;
    // Only the database commit disarms the guard: the checkpoint tree is now
    // referenced by `workspace_checkpoints`.
    published.keep();
    Ok((StatusCode::CREATED, Json(result)))
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
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let row = tx.query_opt("SELECT w.id,w.repository_id,w.owner_slug,w.repository_name,w.agent_id,w.creator_id,w.state,w.host_id,w.lease_epoch,w.revision,w.git_generation,w.last_checkpoint_id,c.state AS checkpoint_state FROM workspace_checkpoints c JOIN workspaces w ON w.id=c.workspace_id WHERE c.id=$1 AND c.state IN ('local_complete','committed')", &[&cp]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let parent = Workspace::from_row(&row);
    let access = auth::authorize_repo_with_role(&tx, &actor, &parent.owner, &parent.repository, Role::Write).await?;
    if parent.creator_id != actor.id || access.repo_id != parent.repository_id {
        return Err(Error::not_found());
    }
    let key = auth::idempotency_key(&headers)?.map(str::to_owned);
    if let Some(key) = &key {
        service::creation_lock(&tx, actor.id, key).await?;
        let digest = hex::encode(Sha256::digest(serde_json::to_vec(&(kind, cp, &agent)).map_err(Error::internal)?));
        if let Some(old)=tx.query_opt("SELECT request_sha256,workspace_id FROM workspace_creations WHERE actor_id=$1 AND idempotency_key=$2 FOR UPDATE",&[&actor.id,&key]).await.map_err(Error::internal)? {
            if old.get::<_,String>(0)!=digest{return Err(service::conflict());}
            let existing:Uuid=old.get(1);
            let row=tx.query_one(&format!("SELECT {WS_COLUMNS} FROM workspaces WHERE id=$1"),&[&existing]).await.map_err(Error::internal)?;
            let saved=Workspace::from_row(&row);
            tx.commit().await.map_err(Error::internal)?;
            super::mounts::ensure_from_database(&state, existing).await?;
            return Ok((StatusCode::OK,Json(saved)));
        }
    }
    let id = Uuid::new_v4();
    if super::mounts::enabled() && row.get::<_, String>("checkpoint_state") == "committed" {
        super::lazy::prepare(&state, id, cp, parent.repository_id, access.owner_id).await?;
    } else {
        super::remote::ensure_local(&state, cp, parent.repository_id, access.owner_id).await?;
        copy_snapshot(&service::checkpoint_repo(&state, cp), &super::mounts::lower_path(&state, id))?;
    }
    let base_oid: Option<String> = tx
        .query_opt("SELECT base_oid FROM workspace_checkpoints WHERE id=$1", &[&cp])
        .await
        .map_err(Error::internal)?
        .and_then(|row| row.get(0));
    tx.execute("INSERT INTO workspaces(id,repository_id,owner_slug,repository_name,agent_id,creator_id,parent_checkpoint_id,state,host_id,lease_until,base_oid) VALUES($1,$2,$3,$4,$5,$6,$7,'ready',$8,clock_timestamp()+interval '5 minutes',$9)", &[&id,&parent.repository_id,&parent.owner,&parent.repository,&agent,&actor.id,&cp,&state.storage.volume_id,&base_oid]).await.map_err(Error::internal)?;
    if let Some(key) = &key {
        let digest = hex::encode(Sha256::digest(serde_json::to_vec(&(kind, cp, &agent)).map_err(Error::internal)?));
        tx.execute(
            "INSERT INTO workspace_creations(actor_id,idempotency_key,request_sha256,workspace_id) VALUES($1,$2,$3,$4)",
            &[&actor.id, key, &digest, &id],
        )
        .await
        .map_err(Error::internal)?;
    }
    super::capture::record_current_at(&tx, id, &super::mounts::lower_path(&state, id)).await?;
    let row = tx
        .query_one(&format!("SELECT {WS_COLUMNS} FROM workspaces WHERE id=$1"), &[&id])
        .await
        .map_err(Error::internal)?;
    tx.commit().await.map_err(Error::internal)?;
    super::mounts::ensure_from_database(&state, id).await?;
    Ok((StatusCode::CREATED, Json(Workspace::from_row(&row))))
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
    let ws = service::authorized(&state, &headers, id, Role::Write).await?;
    let client = state.pool.get().await.map_err(Error::internal)?;
    let row = client
        .query_opt("SELECT workspace_id FROM workspace_checkpoints WHERE id=$1", &[&input.checkpoint_id])
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    if row.get::<_, Uuid>(0) != ws.id {
        return Err(Error::not_found());
    }
    restore_inner(state, headers, input.checkpoint_id, input.new_agent_id, "fork").await
}
#[cfg(test)]
mod tests {
    use super::copy_snapshot;
    use std::{fs, os::unix::fs::PermissionsExt, path::Path};

    fn write(root: &Path, name: &str, bytes: &[u8]) {
        let path = root.join(name);
        fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        fs::write(&path, bytes).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("mode");
    }

    #[test]
    fn restore_copy_never_replaces_a_preexisting_lower_tree() {
        let root = tempfile::tempdir().expect("temp dir");
        let source = root.path().join("checkpoint");
        fs::create_dir(&source).expect("source");
        write(&source, "a.txt", b"a");

        // An existing lower tree is never overwritten or removed.
        let dest = root.path().join("workspaces/id");
        fs::create_dir_all(&dest).expect("dest");
        fs::write(dest.join("sentinel"), b"sentinel").expect("sentinel");
        assert!(copy_snapshot(&source, &dest).is_err(), "an existing lower tree is never replaced");
        assert_eq!(fs::read(dest.join("sentinel")).expect("sentinel bytes"), b"sentinel");
        assert!(!dest.join("a.txt").exists(), "nothing is copied into the existing tree");
        let staged: Vec<String> = fs::read_dir(root.path().join("workspaces"))
            .expect("workspaces dir")
            .map(|child| child.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        assert!(!staged.iter().any(|name| name.starts_with(".restore-")), "a refused restore leaves no staging tree");

        // A free destination is published with the checkpoint tree.
        let fresh = root.path().join("workspaces/fresh");
        copy_snapshot(&source, &fresh).expect("restore copy");
        assert_eq!(fs::read(fresh.join("a.txt")).expect("copied a.txt"), b"a");
        assert_eq!(fs::read(dest.join("sentinel")).expect("sentinel bytes"), b"sentinel");
    }
}
