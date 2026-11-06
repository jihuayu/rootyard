//! Signed CI-run sandbox execution bound to one claimed candidate and checkout plan.
use super::runner;
use crate::{AppState, Error, ci_checkouts, db, storage::read_leases, webhooks::claimed::{ClaimedRun, authorize_claimed_run}};
use axum::{Json, extract::{Path, Query, State}, http::{HeaderMap, StatusCode}};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{path::PathBuf, sync::Arc};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimTuple {
    runner_id:String, attempt:i64, lease_generation:i64,
    head_oid:String, storage_generation:i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartCi {
    #[serde(flatten)] claim:ClaimTuple,
    argv:Vec<String>, timeout_seconds:Option<u64>,
}
#[derive(Serialize)]
pub struct CiJob {
    pub id:Uuid, pub run_id:Uuid, pub state:String,
    pub exit_code:Option<i32>, pub timeout_seconds:i32,
}
fn job(row:&tokio_postgres::Row)->CiJob {
    CiJob{id:row.get("id"),run_id:row.get("ci_run_id"),state:row.get("state"),
        exit_code:row.get("exit_code"),timeout_seconds:row.get("timeout_seconds")}
}
async fn authorize(state:&AppState,headers:&HeaderMap,owner:&str,name:&str,
    hook:Uuid,run:Uuid,tuple:&ClaimTuple)->Result<ClaimedRun,Error>{
    authorize_claimed_run(state,owner,name,hook,run,&tuple.runner_id,tuple.attempt,
        tuple.lease_generation,&tuple.head_oid,tuple.storage_generation,headers).await
}

pub async fn start(State(state):State<Arc<AppState>>,
    Path((owner,name,hook,run)):Path<(String,String,Uuid,Uuid)>,
    headers:HeaderMap,Json(input):Json<StartCi>,
)->Result<(StatusCode,Json<CiJob>),Error>{
    let claim=authorize(&state,&headers,&owner,&name,hook,run,&input.claim).await?;
    let result=start_ci(state,claim,input.argv,input.timeout_seconds.unwrap_or(60)).await?;
    Ok((StatusCode::CREATED,Json(result)))
}
pub async fn status(State(state):State<Arc<AppState>>,
    Path((owner,name,hook,run,id)):Path<(String,String,Uuid,Uuid,Uuid)>,
    headers:HeaderMap,Query(tuple):Query<ClaimTuple>,
)->Result<Json<CiJob>,Error>{
    let claim=authorize(&state,&headers,&owner,&name,hook,run,&tuple).await?;
    Ok(Json(load_job(&state,&claim,id).await?))
}
pub async fn cancel(State(state):State<Arc<AppState>>,
    Path((owner,name,hook,run,id)):Path<(String,String,Uuid,Uuid,Uuid)>,
    headers:HeaderMap,Query(tuple):Query<ClaimTuple>,
)->Result<Json<CiJob>,Error>{
    let claim=authorize(&state,&headers,&owner,&name,hook,run,&tuple).await?;
    load_job(&state,&claim,id).await?;
    let client=state.pool.get().await.map_err(Error::internal)?;
    client.execute("UPDATE sandbox_jobs SET state='cancelled',finished_at=clock_timestamp() \
        WHERE id=$1 AND ci_run_id=$2 AND ci_attempt=$3 AND ci_lease_generation=$4 \
        AND state IN ('queued','running')",&[&id,&claim.run_id,&claim.attempt,&claim.lease_generation])
        .await.map_err(Error::internal)?;
    Ok(Json(load_job(&state,&claim,id).await?))
}
pub async fn logs(State(state):State<Arc<AppState>>,
    Path((owner,name,hook,run,id)):Path<(String,String,Uuid,Uuid,Uuid)>,
    headers:HeaderMap,Query(tuple):Query<ClaimTuple>,
)->Result<Json<serde_json::Value>,Error>{
    let claim=authorize(&state,&headers,&owner,&name,hook,run,&tuple).await?;
    load_job(&state,&claim,id).await?;
    let root=runner::job_root(&state,id);
    let stdout=read_log(root.join("stdout.log"))?;
    let stderr=read_log(root.join("stderr.log"))?;
    Ok(Json(json!({"job_id":id,"stdout_base64":STANDARD.encode(stdout),
        "stderr_base64":STANDARD.encode(stderr)})))
}
fn read_log(path:PathBuf)->Result<Vec<u8>,Error>{
    use std::{io::Read,os::unix::fs::OpenOptionsExt};
    let file=std::fs::OpenOptions::new().read(true)
        .custom_flags(libc::O_NOFOLLOW|libc::O_NONBLOCK).open(path).map_err(Error::internal)?;
    if !file.metadata().map_err(Error::internal)?.is_file(){return Err(Error::not_found());}
    let mut out=Vec::new();
    file.take(64*1024+1).read_to_end(&mut out).map_err(Error::internal)?;
    if out.len()>64*1024 {return Err(Error(StatusCode::PAYLOAD_TOO_LARGE,"CI log exceeds limit"));}
    Ok(out)
}

pub(crate) async fn start_ci(state:Arc<AppState>,claim:ClaimedRun,
    argv:Vec<String>,timeout_seconds:u64)->Result<CiJob,Error>{
    if claim.source!="origin" {return Err(Error(StatusCode::CONFLICT,
        "in-service CI sandbox requires an origin checkout; mirror jobs use the external runner"));}
    if !(1..=3600).contains(&timeout_seconds) || argv.is_empty() || argv.len()>64 ||
        argv.iter().any(|arg|arg.is_empty() || arg.len()>4096 || arg.contains('\0')) {
        return Err(Error::bad_request());
    }
    if !still_claimed(&state,&claim).await? {return Err(Error(StatusCode::CONFLICT,"CI claim changed"));}
    let client=state.pool.get().await.map_err(Error::internal)?;
    let id=Uuid::new_v4();
    let raw=json!(argv);
    let inserted=client.execute("INSERT INTO sandbox_jobs(id,workspace_id,actor_id,host_id,state,argv,timeout_seconds,lease_epoch,workspace_access,ci_run_id,ci_attempt,ci_lease_generation,ci_hook_id,ci_runner_id,ci_head_oid,ci_storage_generation) \
        VALUES($1,NULL,NULL,$2,'queued',$3,$4,0,'private',$5,$6,$7,$8,$9,$10,$11) ON CONFLICT DO NOTHING",
        &[&id,&state.storage.volume_id,&raw,&(timeout_seconds as i32),&claim.run_id,
          &claim.attempt,&claim.lease_generation,&claim.hook_id,&claim.runner_id,
          &claim.head_oid,&claim.storage_generation]).await.map_err(Error::internal)?;
    if inserted==0 {
        let row=client.query_one("SELECT id,ci_run_id,state,exit_code,timeout_seconds,argv,ci_head_oid,ci_storage_generation,ci_runner_id,ci_hook_id FROM sandbox_jobs \
            WHERE ci_run_id=$1 AND ci_attempt=$2 AND ci_lease_generation=$3",
            &[&claim.run_id,&claim.attempt,&claim.lease_generation]).await.map_err(Error::internal)?;
        if row.get::<_,serde_json::Value>("argv")!=raw || row.get::<_,i32>("timeout_seconds")!=timeout_seconds as i32 ||
            row.get::<_,String>("ci_head_oid")!=claim.head_oid || row.get::<_,i64>("ci_storage_generation")!=claim.storage_generation ||
            row.get::<_,String>("ci_runner_id")!=claim.runner_id || row.get::<_,Uuid>("ci_hook_id")!=claim.hook_id {
            return Err(Error(StatusCode::CONFLICT,"CI sandbox attempt already exists"));
        }
        return Ok(job(&row));
    }
    let checkout=runner::job_root(&state,id).join("checkout");
    let launch=async {
        prepare_checkout(&state,&claim,&checkout).await?;
        runner::launch_ci(state.clone(),id,checkout,claim.clone(),argv,timeout_seconds).await
    }.await;
    if let Err(error)=launch {
        client.execute("UPDATE sandbox_jobs SET state='failed',finished_at=clock_timestamp() WHERE id=$1 AND state='queued'",&[&id]).await.map_err(Error::internal)?;
        return Err(error);
    }
    Ok(load_job(&state,&claim,id).await?)
}

async fn prepare_checkout(state:&AppState,claim:&ClaimedRun,dest:&PathBuf)->Result<(),Error>{
    let lease=read_leases::shared(&state.pool,claim.repository_id,
        tokio::time::Instant::now()+state.config.git_timeout).await?;
    if !still_claimed(state,claim).await? {return Err(Error(StatusCode::CONFLICT,"CI claim changed"));}
    let client=state.pool.get().await.map_err(Error::internal)?;
    let row=client.query_one(&format!("{} WHERE r.id=$1",db::REPO_SELECT),
        &[&claim.repository_id]).await.map_err(Error::internal)?;
    let repo=db::Repository::from_row(&row);
    let owner_id:Uuid=row.get("owner_id");
    if repo.storage_generation!=claim.storage_generation || repo.id!=claim.repository_id ||
        owner_id!=claim.tenant_id || claim.plan.owner_id!=claim.tenant_id ||
        claim.plan.repository_id!=repo.id {
        return Err(Error(StatusCode::CONFLICT,"CI checkout source changed"));
    }
    let source=ci_checkouts::origin_job_path(state,&repo,&claim.plan,&lease).await?;
    if let Some(parent)=dest.parent(){std::fs::create_dir_all(parent).map_err(Error::internal)?;}
    let mut clone=state.storage.git(&state.config);
    clone.args(["-c","core.hooksPath=/dev/null","clone","--no-local","--no-hardlinks","--no-checkout","--"])
        .arg(&source).arg(dest);
    lease.guard(crate::git_http::collect_git_output(clone,4096,state.config.git_timeout))
        .await?.map_err(Error::internal)?;
    lease.ensure_active()?;
    let mut checkout=state.storage.git(&state.config);
    checkout.args(["-c","core.hooksPath=/dev/null","-C"]).arg(dest)
        .args(["checkout","--detach","--force",&claim.head_oid]);
    lease.guard(crate::git_http::collect_git_output(checkout,4096,state.config.git_timeout))
        .await?.map_err(Error::internal)?;
    lease.ensure_active()?;
    if !still_claimed(state,claim).await? {return Err(Error(StatusCode::CONFLICT,"CI claim changed"));}
    let mut verify=state.storage.git(&state.config);
    verify.arg("-C").arg(dest).args(["rev-parse","HEAD"]);
    let actual=lease.guard(crate::git_http::collect_git_output(verify,256,state.config.git_timeout))
        .await?.map_err(Error::internal)?;
    if actual!=format!("{}\n",claim.head_oid).as_bytes(){return Err(Error(StatusCode::CONFLICT,"CI checkout target changed"));}
    Ok(())
}

const AUTHORITY:&str="FROM ci_runs c \
 JOIN forge_webhooks w ON w.id=$2 AND w.repository_id=c.repository_id AND w.active=true \
 JOIN forge_trusted_check_contexts b ON b.repository_id=c.repository_id AND b.context=c.context AND b.webhook_id=w.id AND b.active=true \
 JOIN forge_pulls p ON p.repository_id=c.repository_id AND p.number=c.pull_number AND p.state='open' \
   AND p.version=c.pull_version AND p.head_oid=c.head_oid AND p.base_oid=c.base_oid \
 JOIN repositories r ON r.id=c.repository_id AND r.owner_id=c.tenant_id AND r.state='ready' \
 JOIN ci_integration_checkout_jobs i ON i.run_id=c.id AND i.attempt=c.attempt \
   AND i.lease_generation=c.lease_generation AND i.repository_id=c.repository_id AND i.job_id=c.job_id \
   AND i.issuer_webhook_id=w.id AND i.owner_id=c.tenant_id \
 WHERE c.id=$1 AND c.repository_id=$3 AND c.tenant_id=$9 AND c.job_id=$10 \
   AND i.plan=$11 AND c.runner_id=$4 AND c.attempt=$5 \
   AND c.lease_generation=$6 AND c.head_oid=$7 AND c.storage_generation=$8 \
   AND c.state='leased' AND c.source_url='origin' AND c.lease_expires_unix>extract(epoch FROM clock_timestamp()) \
   AND i.expires_unix>extract(epoch FROM clock_timestamp()) AND i.plan->>'target_oid'=c.head_oid \
   AND i.plan->>'storage_generation'=c.storage_generation::text AND r.storage_generation=c.storage_generation";

async fn still_claimed(state:&AppState,claim:&ClaimedRun)->Result<bool,Error>{
    let client=state.pool.get().await.map_err(Error::internal)?;
    let sql=format!("SELECT 1 {AUTHORITY}");
    let plan=serde_json::to_value(&claim.plan).map_err(Error::internal)?;
    Ok(client.query_opt(&sql,&[&claim.run_id,&claim.hook_id,&claim.repository_id,&claim.runner_id,
        &claim.attempt,&claim.lease_generation,&claim.head_oid,&claim.storage_generation,
        &claim.tenant_id,&claim.job_id,&plan])
        .await.map_err(Error::internal)?.is_some())
}
pub(super) async fn mark_running(state:&AppState,claim:&ClaimedRun,job:Uuid,pid:i32)->Result<(),Error>{
    let client=state.pool.get().await.map_err(Error::internal)?;
    let sql=format!("UPDATE sandbox_jobs j SET state='running',pid=$13,started_at=clock_timestamp() \
        WHERE j.id=$12 AND j.state='queued' AND j.ci_run_id=$1 AND j.ci_attempt=$5 \
        AND j.ci_lease_generation=$6 AND j.ci_hook_id=$2 AND j.ci_runner_id=$4 \
        AND j.ci_head_oid=$7 AND j.ci_storage_generation=$8 AND EXISTS(SELECT 1 {AUTHORITY})");
    let plan=serde_json::to_value(&claim.plan).map_err(Error::internal)?;
    let changed=client.execute(&sql,&[&claim.run_id,&claim.hook_id,&claim.repository_id,&claim.runner_id,
        &claim.attempt,&claim.lease_generation,&claim.head_oid,&claim.storage_generation,
        &claim.tenant_id,&claim.job_id,&plan,&job,&pid])
        .await.map_err(Error::internal)?;
    if changed!=1{return Err(Error(StatusCode::CONFLICT,"CI claim changed before execution"));}
    Ok(())
}
pub(super) async fn still_active(state:&AppState,claim:&ClaimedRun,job:Uuid)->Result<bool,Error>{
    let client=state.pool.get().await.map_err(Error::internal)?;
    let sql=format!("SELECT 1 FROM sandbox_jobs j WHERE j.id=$12 AND j.state='running' \
        AND j.ci_run_id=$1 AND j.ci_attempt=$5 AND j.ci_lease_generation=$6 \
        AND j.ci_hook_id=$2 AND j.ci_runner_id=$4 AND j.ci_head_oid=$7 \
        AND j.ci_storage_generation=$8 AND EXISTS(SELECT 1 {AUTHORITY})");
    let plan=serde_json::to_value(&claim.plan).map_err(Error::internal)?;
    Ok(client.query_opt(&sql,&[&claim.run_id,&claim.hook_id,&claim.repository_id,&claim.runner_id,
        &claim.attempt,&claim.lease_generation,&claim.head_oid,&claim.storage_generation,
        &claim.tenant_id,&claim.job_id,&plan,&job])
        .await.map_err(Error::internal)?.is_some())
}
async fn load_job(state:&AppState,claim:&ClaimedRun,id:Uuid)->Result<CiJob,Error>{
    let client=state.pool.get().await.map_err(Error::internal)?;
    let row=client.query_opt("SELECT id,ci_run_id,state,exit_code,timeout_seconds FROM sandbox_jobs \
        WHERE id=$1 AND ci_run_id=$2 AND ci_attempt=$3 AND ci_lease_generation=$4 AND ci_hook_id=$5 \
        AND ci_runner_id=$6 AND ci_head_oid=$7 AND ci_storage_generation=$8",
        &[&id,&claim.run_id,&claim.attempt,&claim.lease_generation,&claim.hook_id,
            &claim.runner_id,&claim.head_oid,&claim.storage_generation])
        .await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    Ok(job(&row))
}
