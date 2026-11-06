//! Explicit dependency materialization on a mirror using separately authorized sources.
use crate::{AppState, Error, auth, ci_checkouts::{Plan,authority,dependencies}, db, lfs, members::models::Role, mirror};
use axum::{Json,extract::{Path,State},http::{HeaderMap,StatusCode,header},response::{IntoResponse,Response}};
use futures_util::StreamExt;
use sha2::{Digest,Sha256};
use std::{os::unix::fs::OpenOptionsExt,sync::Arc,time::Duration};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

pub async fn prepare(
    State(state):State<Arc<AppState>>,
    Path((owner,name,job_id)):Path<(String,String,Uuid)>,headers:HeaderMap,
) -> Result<Response,Error>{
    let primary=state.mirror_primary.as_ref().ok_or_else(Error::not_found)?.clone();
    let (plan,transport_headers,scope)=if let Ok((_,token))=auth::credentials_for(&headers,"ryj_") {
        let digest=db::digest(&token);
        let client=state.pool.get().await.map_err(Error::internal)?;
        let row=client.query_opt("SELECT plan FROM ci_integration_checkout_jobs WHERE \
            job_id=$1 AND credential_digest=$2",&[&job_id,&digest])
            .await.map_err(Error::internal)?.ok_or_else(Error::unauthorized)?;
        let tentative:Plan=serde_json::from_value(row.get(0)).map_err(Error::internal)?;
        let (principal,_,plan)=authority::authenticate_principal(&state,&headers,&owner,&name,
            &tentative.target_oid).await?;
        if plan.job_id!=job_id || authority::integration_hook_for_plan(&state,&plan).await?.is_none() {
            return Err(Error::unauthorized());
        }
        let operator=std::env::var("ROOTYARD_CI_MIRROR_SOURCE_TOKEN")
            .map_err(|_|Error(StatusCode::SERVICE_UNAVAILABLE,"mirror source credential unavailable"))?;
        if !operator.starts_with("ryt_") || operator.len()!=68 {
            return Err(Error(StatusCode::SERVICE_UNAVAILABLE,"invalid mirror source credential"));
        }
        let mut transport=HeaderMap::new();
        transport.insert(header::AUTHORIZATION,format!("Bearer {operator}").parse().map_err(Error::internal)?);
        let authority::CheckoutPrincipal::Integration{hook_id,token_digest,..}=principal else {
            return Err(Error::unauthorized());
        };
        let scope=authority::IntegrationScope{plan:plan.clone(),hook_id,token_digest};
        scope.validate_source(&state,plan.repository_id).await?;
        (plan,transport,Some(scope))
    } else {
        let actor=auth::authenticate(&state.pool,&headers).await?;
        let mut client=state.pool.get().await.map_err(Error::internal)?;
        let tx=client.transaction().await.map_err(Error::internal)?;
        let access=auth::authorize_repo_with_role(&tx,&actor,&owner,&name,Role::Read).await?;
        let row=tx.query_opt("SELECT plan FROM ci_checkout_jobs WHERE repository_id=$1 AND job_id=$2 \
            AND issuer_token_id=$3 AND NOT cancelled AND NOT revoked \
            AND expires_unix>extract(epoch FROM clock_timestamp())",
            &[&access.repo_id,&job_id,&actor.token_id])
            .await.map_err(Error::internal)?.ok_or_else(Error::unauthorized)?;
        let plan:Plan=serde_json::from_value(row.get(0)).map_err(Error::internal)?;
        for sub in &plan.dependencies.submodules {
            auth::authorize_repo_with_role(&tx,&actor,&sub.owner,&sub.name,Role::Read).await?;
        }
        tx.commit().await.map_err(Error::internal)?;
        (plan,headers.clone(),None)
    };
    if plan.dependencies.version!=1 {return Err(Error(StatusCode::CONFLICT,"dependency manifest missing"));}
    // All transport calls retain the caller's normal token only for the trusted
    // operator-configured primary and separately authorized Rootyard repositories.
    if let Some(scope)=&scope {
        mirror::sync::sync_scoped(state.clone(),owner.clone(),name.clone(),
            transport_headers.clone(),scope.clone()).await?;
    } else {
        mirror::sync::sync(State(state.clone()),Path((owner.clone(),name.clone())),transport_headers.clone()).await?;
    }
    for sub in &plan.dependencies.submodules {
        if let Some(scope)=&scope {
            mirror::sync::sync_scoped(state.clone(),sub.owner.clone(),sub.name.clone(),
                transport_headers.clone(),scope.clone()).await?;
        } else {
            mirror::sync::sync(State(state.clone()),Path((sub.owner.clone(),sub.name.clone())),transport_headers.clone()).await?;
        }
    }
    for dep in &plan.dependencies.lfs {
        let client=state.pool.get().await.map_err(Error::internal)?;
        let row=client.query_one(&format!("{} WHERE r.id=$1",db::REPO_SELECT),&[&dep.repository_id])
            .await.map_err(Error::internal)?;
        let repo=db::Repository::from_row(&row);
        if let Some(scope)=&scope {scope.validate_source(&state,repo.id).await?;}
        fetch_lfs(&state,&primary,&transport_headers,&repo,&dep.oid,dep.size,scope.as_ref()).await?;
    }
    dependencies::verify_on_mirror(&state,&plan).await?;
    Ok((StatusCode::OK,[(header::CACHE_CONTROL,"no-store")],Json(serde_json::json!({
        "job_id":job_id,"target_oid":plan.target_oid,"dependencies_ready":true,
        "lfs_count":plan.dependencies.lfs.len(),"submodule_count":plan.dependencies.submodules.len(),
    }))).into_response())
}

async fn fetch_lfs(state:&AppState,primary:&str,headers:&HeaderMap,repo:&db::Repository,
    oid:&str,size:i64,scope:Option<&authority::IntegrationScope>)->Result<(),Error>{
    if size<0 {return Err(Error::bad_request());}
    let root=state.storage.root.clone();
    let repo_id=repo.id;
    let oid_owned=oid.to_owned();
    let already=tokio::task::spawn_blocking(move||
        lfs::storage::verify_object_integrity(&root,repo_id,&oid_owned,size as u64))
        .await.map_err(Error::internal)?.unwrap_or(false);
    if already {return Ok(());}
    let bearer=headers.get(header::AUTHORIZATION).ok_or_else(Error::unauthorized)?;
    let url=format!("{primary}/git/{}/{}/info/lfs/objects/{oid}",repo.owner,repo.name);
    let http=reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(300)).build().map_err(Error::internal)?;
    let response=http.get(url).header(header::AUTHORIZATION,bearer.to_str().map_err(|_|Error::unauthorized())?)
        .send().await.map_err(Error::internal)?;
    if !response.status().is_success(){return Err(Error(StatusCode::CONFLICT,"LFS source unavailable"));}
    let dir=lfs::storage::ensure_repo_lfs_dir(&state.storage.root,repo.id).map_err(Error::internal)?;
    let target=lfs::storage::object_path(&state.storage.root,repo.id,oid).map_err(Error::internal)?;
    let stage=dir.join(format!(".ci-{}",Uuid::new_v4()));
    let std_file=std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW).open(&stage).map_err(Error::internal)?;
    let mut file=tokio::fs::File::from_std(std_file);
    let mut stream=response.bytes_stream();let mut hash=Sha256::new();let mut count=0u64;
    let result=async {
        while let Some(chunk)=stream.next().await {
            let chunk=chunk.map_err(Error::internal)?;
            count=count.checked_add(chunk.len() as u64).ok_or_else(Error::bad_request)?;
            if count>size as u64 {return Err(Error(StatusCode::CONFLICT,"LFS source exceeded declared size"));}
            hash.update(&chunk);file.write_all(&chunk).await.map_err(Error::internal)?;
        }
        file.sync_all().await.map_err(Error::internal)?;
        if count!=size as u64 || hex::encode(hash.finalize())!=oid {
            return Err(Error(StatusCode::CONFLICT,"LFS source checksum mismatch"));
        }
        Ok(())
    }.await;
    drop(file);
    if let Err(error)=result {let _=std::fs::remove_file(&stage);return Err(error);}
    if let Some(scope)=scope {
        if let Err(error)=scope.validate_source(state,repo.id).await {
            let _=std::fs::remove_file(&stage);return Err(error);
        }
    }
    std::fs::rename(&stage,&target).map_err(Error::internal)?;
    std::fs::File::open(&dir).and_then(|f|f.sync_all()).map_err(Error::internal)?;
    Ok(())
}
