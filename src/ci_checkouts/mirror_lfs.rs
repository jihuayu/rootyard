//! Git LFS Basic download for one immutable, authorized CI checkout manifest.
use crate::{AppState,Error,auth,ci_checkouts::{self,dependencies},db,lfs::{models,storage}};
use axum::{Json,body::Body,extract::{Path,State},http::{HeaderMap,StatusCode,header},response::{IntoResponse,Response}};
use futures_util::StreamExt;
use std::{io,sync::Arc,time::Duration};
use uuid::Uuid;

async fn authorized(state:&AppState,job:Uuid,digest:&[u8],repo:Uuid,generation:i64)->bool{
    matches!(tokio::time::timeout(Duration::from_secs(1),
        ci_checkouts::still_authorized(state,job,digest,repo,generation)).await,Ok(Ok(true)))
}

fn public_url(state:&AppState) -> Result<String,Error> {
    let key=if state.mirror_primary.is_some(){"ROOTYARD_CI_MIRROR_PUBLIC_URL"}
        else {"ROOTYARD_CI_ORIGIN_PUBLIC_URL"};
    let url=std::env::var(key)
        .map_err(|_|Error(StatusCode::SERVICE_UNAVAILABLE,"CI LFS public URL not configured"))?;
    let checked=crate::mirror::sync::primary_origin(&url).map_err(|_|Error::bad_request())?;
    if checked!=url.trim_end_matches('/') {return Err(Error::bad_request());}
    Ok(checked)
}

pub async fn batch(
    State(state):State<Arc<AppState>>,
    Path((target,owner,name)):Path<(String,String,String)>,
    headers:HeaderMap,Json(request):Json<models::BatchRequest>,
) -> Result<Response,Error>{
    if request.operation!="download" || request.objects.is_empty() || request.objects.len()>100 ||
        request.hash_algo.as_deref().is_some_and(|h|h!="sha256") {
        return Err(Error::bad_request());
    }
    let name=name.strip_suffix(".git").ok_or_else(Error::not_found)?.to_owned();
    let (_,repo,plan)=ci_checkouts::authority::authenticate_principal(&state,&headers,&owner,&name,&target).await?;
    if state.mirror_primary.is_some(){dependencies::verify_on_mirror(&state,&plan).await?;}
    else {dependencies::verify_on_origin(&state,&plan).await?;}
    let base=public_url(&state)?;
    let mut objects=Vec::new();
    for spec in request.objects {
        if !models::valid_lfs_oid(&spec.oid) || spec.size<0 ||
            !plan.dependencies.lfs.iter().any(|dep|dep.repository_id==repo.id &&
                dep.oid==spec.oid && dep.size==spec.size) {
            return Err(Error(StatusCode::FORBIDDEN,"LFS object not in checkout plan"));
        }
        let href=format!("{base}/ci/{target}/git/{owner}/{name}.git/info/lfs/objects/{}",spec.oid);
        objects.push(serde_json::json!({"oid":spec.oid,"size":spec.size,
            "authenticated":true,"actions":{"download":{"href":href}}}));
    }
    Ok((StatusCode::OK,[(header::CACHE_CONTROL,"no-store")],Json(serde_json::json!({
        "transfer":"basic","hash_algo":"sha256","objects":objects,
    }))).into_response())
}

pub async fn download(
    State(state):State<Arc<AppState>>,
    Path((target,owner,name,oid)):Path<(String,String,String,String)>,headers:HeaderMap,
) -> Result<Response<Body>,Error>{
    let name=name.strip_suffix(".git").ok_or_else(Error::not_found)?.to_owned();
    let (_,repo,plan)=ci_checkouts::authority::authenticate_principal(&state,&headers,&owner,&name,&target).await?;
    if state.mirror_primary.is_some(){dependencies::verify_on_mirror(&state,&plan).await?;}
    else {dependencies::verify_on_origin(&state,&plan).await?;}
    let dep=plan.dependencies.lfs.iter().find(|dep|dep.repository_id==repo.id && dep.oid==oid)
        .ok_or_else(Error::not_found)?;
    let size=dep.size as u64;
    let (_,token)=auth::credentials_for(&headers,"ryj_")?;
    let digest=db::digest(&token);
    if !authorized(&state,plan.job_id,&digest,repo.id,repo.storage_generation).await {
        return Err(Error::unauthorized());
    }
    let body=storage::open_verified_download_stream(&state,repo.id,&oid,size).await?;
    let (sender,receiver)=tokio::sync::mpsc::channel::<Result<axum::body::Bytes,io::Error>>(8);
    let job=plan.job_id;let repo_id=repo.id;let generation=repo.storage_generation;
    tokio::spawn(async move {
        let mut source=body.into_data_stream();
        let mut tick=tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut pending=None;
        let mut failed=false;
        loop {
            if let Some(bytes)=pending.take() {
                tokio::select! {
                    _=tick.tick()=> {pending=Some(bytes);
                        if !authorized(&state,job,&digest,repo_id,generation).await {failed=true;break;}}
                    permit=sender.reserve()=>match permit {
                        Ok(permit)=>{
                            if !authorized(&state,job,&digest,repo_id,generation).await {failed=true;break;}
                            permit.send(Ok(bytes));
                        },Err(_)=>break,
                    },
                }
            } else {
                tokio::select! {
                    _=tick.tick()=>{
                        if !authorized(&state,job,&digest,repo_id,generation).await {failed=true;break;}}
                    _=sender.closed()=>break,
                    next=source.next()=>match next {
                        Some(Ok(bytes))=>pending=Some(bytes),
                        Some(Err(_))=>{failed=true;break;},
                        None=>break,
                    },
                }
            }
        }
        if failed {
            state.transfer_metrics.record_failure();
            let _=sender.try_send(Err(io::Error::other("CI LFS transfer authorization changed")));
        }
    });
    let stream=futures_util::stream::unfold(receiver,|mut receiver|async move {
        receiver.recv().await.map(|item|(item,receiver))
    });
    Response::builder().status(StatusCode::OK)
        .header(header::CONTENT_TYPE,"application/octet-stream")
        .header(header::CACHE_CONTROL,"no-store")
        .header(header::CONTENT_LENGTH,size.to_string())
        .body(Body::from_stream(stream)).map_err(Error::internal)
}
