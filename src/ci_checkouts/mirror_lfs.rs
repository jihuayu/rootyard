//! Git LFS Basic download for one immutable, authorized CI checkout manifest.
use crate::{AppState,Error,ci_checkouts::{self,dependencies},lfs::{models,storage}};
use axum::{Json,body::Body,extract::{Path,State},http::{HeaderMap,StatusCode,header},response::{IntoResponse,Response}};
use std::sync::Arc;

fn public_url() -> Result<String,Error> {
    let url=std::env::var("ROOTYARD_CI_MIRROR_PUBLIC_URL")
        .map_err(|_|Error(StatusCode::SERVICE_UNAVAILABLE,"mirror public URL not configured"))?;
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
    dependencies::verify_on_mirror(&state,&plan).await?;
    let base=public_url()?;
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
    dependencies::verify_on_mirror(&state,&plan).await?;
    let dep=plan.dependencies.lfs.iter().find(|dep|dep.repository_id==repo.id && dep.oid==oid)
        .ok_or_else(Error::not_found)?;
    let body=storage::open_verified_download_stream(&state,repo.id,&oid,dep.size as u64).await?;
    Ok((StatusCode::OK,[(header::CONTENT_TYPE,"application/octet-stream"),
        (header::CACHE_CONTROL,"no-store")],body).into_response())
}
