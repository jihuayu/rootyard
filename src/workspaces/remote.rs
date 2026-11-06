//! Authenticated, tenant-scoped remote checkpoint closure and recovery.
use super::service;
use crate::{AppState,Error,members::models::Role,storage::remote_objects::{ObjectKey,RemoteObjectStore},workspace_lab::core};
use axum::{Json,extract::{Path,State},http::{HeaderMap,StatusCode}};
use base64::{Engine,engine::general_purpose::STANDARD};
use serde::{Deserialize,Serialize};
use serde_json::{Value,json};
use sha2::{Digest,Sha256};
use std::{collections::BTreeSet,ffi::OsString,fs::{self,OpenOptions},io::Write,os::unix::{ffi::OsStringExt,fs::{OpenOptionsExt,PermissionsExt,symlink}},sync::Arc,time::Duration};
use tokio::time::Instant;
use uuid::Uuid;

#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoteEntry { path_base64:String,kind:String,mode:u32,size:u64,sha256:String,target_base64:Option<String> }
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoteManifest { schema:u32,checkpoint_id:Uuid,repository_id:Uuid,tenant_id:Uuid,captured_revision:i64,entries:Vec<RemoteEntry> }

fn remote_store(state:&AppState)->Result<RemoteObjectStore,Error>{
    let store=RemoteObjectStore::from_env(state.storage.root.join("workspace-service/local-object-cache")).map_err(Error::internal)?;
    if matches!(store,RemoteObjectStore::Local(_)){return Err(Error(StatusCode::SERVICE_UNAVAILABLE,"remote object store is not configured"));}
    Ok(store)
}
fn key(tenant:Uuid,digest:&str)->Result<ObjectKey,Error>{ObjectKey::new(tenant,"workspace",digest).map_err(|_|Error::bad_request())}
fn deadline()->Instant{Instant::now()+Duration::from_secs(120)}
fn bounded_manifest(raw:&[u8])->Result<RemoteManifest,Error>{
    if raw.len()>16*1024*1024{return Err(Error::bad_request());}
    serde_json::from_slice(raw).map_err(|_|Error::bad_request())
}
fn report(cp:Uuid,manifest:&str,size:i64,revision:i64)->Value{json!({"checkpoint_id":cp,"state":"COMMITTED","durability":"remote_verified","manifest_sha256":manifest,"manifest_size":size,"captured_revision":revision})}
async fn stage_key(state:&AppState,cp:Uuid,tenant:Uuid,digest:&str,size:u64,kind:&str)->Result<(),Error>{
    let client=state.pool.get().await.map_err(Error::internal)?;
    client.execute("INSERT INTO workspace_remote_staging_objects(checkpoint_id,tenant_id,digest,size,kind) VALUES($1,$2,$3,$4,$5) ON CONFLICT(checkpoint_id,digest) DO NOTHING", &[&cp,&tenant,&digest,&(size as i64),&kind]).await.map_err(Error::internal)?;
    Ok(())
}

pub async fn publish(State(state):State<Arc<AppState>>,headers:HeaderMap,Path(cp):Path<Uuid>)->Result<(StatusCode,Json<Value>),Error>{
    let client=state.pool.get().await.map_err(Error::internal)?;
    let row=client.query_opt("SELECT c.workspace_id,c.repository_id,c.state,c.lease_epoch,c.captured_revision,c.manifest_digest,c.manifest_size,r.owner_id FROM workspace_checkpoints c JOIN repositories r ON r.id=c.repository_id WHERE c.id=$1", &[&cp]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let ws_id:Uuid=row.get(0);let repo_id:Uuid=row.get(1);let status:String=row.get(2);let epoch:i64=row.get(3);let captured:i64=row.get(4);let digest:Option<String>=row.get(5);let size:Option<i64>=row.get(6);let tenant:Uuid=row.get(7);
    let ws=service::authorized(&state,&headers,ws_id,Role::Write).await?;
    if ws.repository_id!=repo_id{return Err(Error::not_found());}
    if status=="committed" {return Ok((StatusCode::OK,Json(report(cp,&digest.ok_or_else(||Error::internal("missing remote metadata"))?,size.ok_or_else(||Error::internal("missing remote metadata"))?,captured))));}
    if status!="local_complete" || ws.host_id!=state.storage.volume_id || ws.lease_epoch!=epoch {return Err(service::conflict());}
    let valid_lease:bool=client.query_one("SELECT lease_until>clock_timestamp() FROM workspaces WHERE id=$1", &[&ws_id]).await.map_err(Error::internal)?.get(0);
    if !valid_lease{return Err(service::conflict());}
    let store=remote_store(&state)?;
    let root=service::checkpoint_repo(&state,cp);
    let entries=core::inventory(&root).map_err(Error::internal)?;
    let mut remote_entries=Vec::with_capacity(entries.len());
    let mut uploaded=0usize;
    for entry in entries {
        let rel=core::decode_path(&entry.path_base64).map_err(Error::internal)?;
        let file=root.join(rel);
        let target=if entry.kind=="symlink" {
            Some(STANDARD.encode(fs::read_link(&file).map_err(Error::internal)?.into_os_string().into_vec()))
        }else{
            stage_key(&state,cp,tenant,&entry.sha256,entry.size,"file").await?;
            store.put_file(&key(tenant,&entry.sha256)?,&file,entry.size,deadline()).await.map_err(Error::internal)?;
            uploaded+=1;
            if std::env::var("ROOTYARD_WORKSPACE_REMOTE_KILL_AFTER_OBJECTS").ok().and_then(|v|v.parse::<usize>().ok())==Some(uploaded) {
                std::process::exit(77);
            }
            None
        };
        remote_entries.push(RemoteEntry{path_base64:entry.path_base64,kind:entry.kind,mode:entry.mode,size:entry.size,sha256:entry.sha256,target_base64:target});
    }
    let manifest=RemoteManifest{schema:1,checkpoint_id:cp,repository_id:repo_id,tenant_id:tenant,captured_revision:captured,entries:remote_entries};
    let raw=serde_json::to_vec(&manifest).map_err(Error::internal)?;
    bounded_manifest(&raw)?;
    let digest=hex::encode(Sha256::digest(&raw));
    stage_key(&state,cp,tenant,&digest,raw.len() as u64,"manifest").await?;
    let stage=state.storage.root.join("workspace-service/staging");
    fs::create_dir_all(&stage).map_err(Error::internal)?;
    let file=stage.join(format!("manifest-{cp}-{}",Uuid::new_v4()));
    let mut output=OpenOptions::new().write(true).create_new(true).mode(0o600).open(&file).map_err(Error::internal)?;
    output.write_all(&raw).map_err(Error::internal)?;output.sync_all().map_err(Error::internal)?;drop(output);
    let upload=store.put_file(&key(tenant,&digest)?,&file,raw.len() as u64,deadline()).await;
    let _=fs::remove_file(&file);
    upload.map_err(Error::internal)?;
    let mut client=state.pool.get().await.map_err(Error::internal)?;
    let tx=client.transaction().await.map_err(Error::internal)?;
    let changed=tx.execute("UPDATE workspace_checkpoints c SET state='committed',manifest_digest=$2,manifest_size=$3,committed_at=clock_timestamp() FROM workspaces w WHERE c.id=$1 AND c.workspace_id=w.id AND c.state='local_complete' AND c.lease_epoch=w.lease_epoch AND w.host_id=$4 AND w.lease_until>clock_timestamp()", &[&cp,&digest,&(raw.len() as i64),&state.storage.volume_id]).await.map_err(Error::internal)?;
    if changed!=1 {
        let row=tx.query_opt("SELECT state,manifest_digest,manifest_size FROM workspace_checkpoints WHERE id=$1", &[&cp]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
        if row.get::<_,String>(0)!="committed" || row.get::<_,Option<String>>(1).as_deref()!=Some(&digest) {return Err(service::conflict());}
    }
    tx.commit().await.map_err(Error::internal)?;
    Ok((StatusCode::OK,Json(report(cp,&digest,raw.len() as i64,captured))))
}

pub async fn ensure_local(state:&AppState,cp:Uuid,repo:Uuid,tenant:Uuid)->Result<(),Error>{
    let final_path=service::checkpoint_repo(state,cp);
    if final_path.is_dir(){return Ok(());}
    let client=state.pool.get().await.map_err(Error::internal)?;
    let row=client.query_opt("SELECT state,manifest_digest,manifest_size FROM workspace_checkpoints WHERE id=$1 AND repository_id=$2", &[&cp,&repo]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    if row.get::<_,String>(0)!="committed"{return Err(service::conflict());}
    let digest:String=row.get::<_,Option<String>>(1).ok_or_else(||Error::internal("missing remote metadata"))?;
    let size:i64=row.get::<_,Option<i64>>(2).ok_or_else(||Error::internal("missing remote metadata"))?;
    if !(1..=16*1024*1024).contains(&size){return Err(Error::internal("invalid remote manifest size"));}
    let store=remote_store(state)?;
    let stage=state.storage.root.join("workspace-service/staging").join(format!("restore-{cp}-{}",Uuid::new_v4()));
    fs::create_dir_all(&stage).map_err(Error::internal)?;
    let manifest_path=stage.join("manifest.json");
    store.get_to_file(&key(tenant,&digest)?,&manifest_path,size as u64,deadline()).await.map_err(Error::internal)?;
    let raw=fs::read(&manifest_path).map_err(Error::internal)?;
    let manifest=bounded_manifest(&raw)?;
    if manifest.schema!=1 || manifest.checkpoint_id!=cp || manifest.repository_id!=repo || manifest.tenant_id!=tenant {return Err(Error::bad_request());}
    let root=stage.join("repo");fs::create_dir(&root).map_err(Error::internal)?;
    let mut paths=BTreeSet::new();let mut symlinks=BTreeSet::new();let mut total=0u64;
    for entry in &manifest.entries {
        let path=core::decode_path(&entry.path_base64).map_err(|_|Error::bad_request())?;
        if !paths.insert(path.clone()) || entry.mode>0o777 || entry.size>core::MAX_BYTES{return Err(Error::bad_request());}
        total=total.checked_add(entry.size).ok_or_else(Error::bad_request)?;
        if total>core::MAX_BYTES{return Err(Error::bad_request());}
        key(tenant,&entry.sha256)?;
        if entry.kind=="symlink" {symlinks.insert(path);}else if entry.kind!="file" || entry.target_base64.is_some(){return Err(Error::bad_request());}
    }
    for path in &paths {if symlinks.iter().any(|link|path!=link && path.starts_with(link)){return Err(Error::bad_request());}}
    let mut expected=Vec::new();
    for entry in manifest.entries {
        let rel=core::decode_path(&entry.path_base64).map_err(|_|Error::bad_request())?;
        let to=root.join(&rel);let parent=to.parent().ok_or_else(Error::bad_request)?;
        fs::create_dir_all(parent).map_err(Error::internal)?;
        if entry.kind=="file" {
            store.get_to_file(&key(tenant,&entry.sha256)?,&to,entry.size,deadline()).await.map_err(Error::internal)?;
            fs::set_permissions(&to,fs::Permissions::from_mode(entry.mode)).map_err(Error::internal)?;
        }else{
            let target=STANDARD.decode(entry.target_base64.as_deref().ok_or_else(Error::bad_request)?).map_err(|_|Error::bad_request())?;
            if target.len() as u64!=entry.size || hex::encode(Sha256::digest(&target))!=entry.sha256{return Err(Error::bad_request());}
            symlink(OsString::from_vec(target),&to).map_err(Error::internal)?;
        }
        expected.push(core::Entry{path_base64:entry.path_base64,kind:entry.kind,mode:entry.mode,size:entry.size,sha256:entry.sha256});
    }
    let actual=core::inventory(&root).map_err(Error::internal)?;
    if actual!=expected{return Err(Error::internal("remote checkpoint inventory mismatch"));}
    core::sync_tree(&root).map_err(Error::internal)?;
    if let Some(parent)=final_path.parent(){fs::create_dir_all(parent).map_err(Error::internal)?;}
    if fs::rename(&root,&final_path).is_err() && !final_path.is_dir(){return Err(Error::internal("checkpoint restore publication failed"));}
    let _=fs::remove_dir_all(stage);
    Ok(())
}
