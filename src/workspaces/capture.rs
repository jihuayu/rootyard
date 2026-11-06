//! Mandatory full reconciliation for edits made by normal editors and Git.
use super::service;
use crate::{AppState, Error, workspace_lab::core};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub(super) fn fingerprint(repo: &Path) -> Result<String,Error> {
    let entries = core::inventory(repo).map_err(Error::internal)?;
    let raw = serde_json::to_vec(&entries).map_err(Error::internal)?;
    Ok(hex::encode(Sha256::digest(&raw)))
}

pub async fn record_current(tx: &deadpool_postgres::Transaction<'_>, state: &AppState, id: Uuid) -> Result<(),Error> {
    let value=fingerprint(&service::workspace_repo(state,id))?;
    tx.execute("INSERT INTO workspace_capture_state(workspace_id,fingerprint) VALUES($1,$2) ON CONFLICT(workspace_id) DO UPDATE SET fingerprint=$2,scanned_at=clock_timestamp()", &[&id,&value]).await.map_err(Error::internal)?;
    Ok(())
}

pub async fn reconcile_one(state: &AppState, id: Uuid) -> Result<bool,Error> {
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let row = tx.query_opt("SELECT revision,lease_epoch FROM workspaces WHERE id=$1 AND host_id=$2 AND state='ready' AND lease_until>clock_timestamp() FOR UPDATE", &[&id,&state.storage.volume_id]).await.map_err(Error::internal)?;
    let Some(row)=row else { return Ok(false); };
    let revision: i64 = row.get(0);
    let epoch: i64 = row.get(1);
    let repo = service::workspace_repo(state,id);
    let a = fingerprint(&repo)?;
    let b = fingerprint(&repo)?;
    if a!=b { return Err(service::conflict()); }
    let previous = tx.query_opt("SELECT fingerprint FROM workspace_capture_state WHERE workspace_id=$1 FOR UPDATE", &[&id]).await.map_err(Error::internal)?;
    let changed = previous.as_ref().is_some_and(|r|r.get::<_,String>(0)!=b);
    tx.execute("INSERT INTO workspace_capture_state(workspace_id,fingerprint) VALUES($1,$2) ON CONFLICT(workspace_id) DO UPDATE SET fingerprint=$2,scanned_at=clock_timestamp()", &[&id,&b]).await.map_err(Error::internal)?;
    if changed {
        let next=revision+1;
        let payload=json!({"revision":next,"lease_epoch":epoch,"fingerprint":b,"source":"native_scan"});
        tx.execute("UPDATE workspaces SET revision=$2 WHERE id=$1 AND lease_epoch=$3 AND host_id=$4", &[&id,&next,&epoch,&state.storage.volume_id]).await.map_err(Error::internal)?;
        tx.execute("INSERT INTO workspace_events(workspace_id,revision,kind,payload) VALUES($1,$2,'external_capture',$3)", &[&id,&next,&payload]).await.map_err(Error::internal)?;
    }
    tx.commit().await.map_err(Error::internal)?;
    Ok(changed)
}

pub async fn run(state: Arc<AppState>, stop: CancellationToken) {
    tokio::spawn(super::remote_gc::run(state.clone(), stop.child_token()));
    let mut interval = tokio::time::interval(Duration::from_secs(2));
    loop {
        tokio::select! { _=stop.cancelled()=>break, _=interval.tick()=>{} }
        let Ok(client)=state.pool.get().await else { continue; };
        let Ok(rows)=client.query("SELECT id FROM workspaces WHERE host_id=$1 AND state='ready' AND lease_until>clock_timestamp() ORDER BY id LIMIT 100", &[&state.storage.volume_id]).await else { continue; };
        for row in rows {
            if stop.is_cancelled() { return; }
            let id: Uuid=row.get(0);
            let _=reconcile_one(&state,id).await;
        }
    }
}
