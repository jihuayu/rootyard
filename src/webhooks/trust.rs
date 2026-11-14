//! Administrative binding of CI check contexts to signed webhook integrations.
use crate::{AppState, Error, auth, members::models::Role, pulls::models::context_valid};
use axum::{Json, extract::{Path,State}, http::{HeaderMap,StatusCode,header}, response::{IntoResponse,Response}};
use super::models::CiCallbackInput;
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

pub(crate) async fn policy_repo_id(state:&AppState,owner:&str,name:&str)
    ->Result<Uuid,Error>{
    let client=state.pool.get().await.map_err(Error::internal)?;
    let repo:Uuid=client.query_opt(
        "SELECT r.id FROM repositories r JOIN namespaces ns ON ns.id=r.owner_id WHERE ns.slug=$1 AND r.name=$2",
        &[&owner,&name]).await.map_err(Error::internal)?
        .ok_or_else(Error::not_found)?.get(0);
    Ok(repo)
}
/// One repository policy lock domain shared by every authority reader and
/// writer. The prefix is part of the hashed key; do not introduce a second
/// domain for the same repository policy.
const POLICY_LOCK_DOMAIN:&str="rootyard-publication-v1:";
const POLICY_LOCK_EXCLUSIVE:&str=
    "SELECT pg_advisory_xact_lock(hashtextextended($1 || $2::uuid::text, 0))";
const POLICY_LOCK_SHARED:&str=
    "SELECT pg_advisory_xact_lock_shared(hashtextextended($1 || $2::uuid::text, 0))";

async fn policy_lock_tx(tx:&deadpool_postgres::Transaction<'_>,repo:Uuid,sql:&str)
    ->Result<(),Error>{
    // The advisory lock and metadata write share one PostgreSQL transaction,
    // so a lost session cannot publish a policy change after dropping the gate.
    tx.query_one(sql,&[&POLICY_LOCK_DOMAIN,&repo]).await.map_err(Error::internal)?;
    Ok(())
}

/// Exclusive fence for trusted bind/revoke, webhook PATCH, claims, reports and
/// other policy writers. Take it before any binding/webhook/run row lock.
pub(crate) async fn lock_policy_tx(tx:&deadpool_postgres::Transaction<'_>,repo:Uuid)
    ->Result<(),Error>{
    policy_lock_tx(tx,repo,POLICY_LOCK_EXCLUSIVE).await
}

/// Shared fence for readers that must stay stable across several authority
/// rows but never upgrade to a writer. The sandbox start gate uses it before
/// `sandbox_jobs` and the `ci_runs`/binding/webhook row locks.
pub(crate) async fn lock_policy_shared_tx(tx:&deadpool_postgres::Transaction<'_>,repo:Uuid)
    ->Result<(),Error>{
    policy_lock_tx(tx,repo,POLICY_LOCK_SHARED).await
}

/// Revoke bindings owned by one webhook and invalidate the run fencing that
/// produced their evidence. A completed `ci_runs` row records its
/// `lease_generation` in `forge_check_runs`; advancing it here makes an old
/// completion unusable even if an administrator later binds the same context
/// again. Bindings still owned by another webhook keep their evidence.
pub(crate) async fn revoke_owned_contexts(
    tx:&deadpool_postgres::Transaction<'_>,repo:Uuid,webhook_id:Uuid,contexts:&[String],
)->Result<u64,Error>{
    if contexts.is_empty(){return Ok(0);}
    let contexts=contexts.to_vec();
    let changed=tx.execute(
        "UPDATE forge_trusted_check_contexts SET active=false \
         WHERE repository_id=$1 AND webhook_id=$2 AND context=ANY($3)",
        &[&repo,&webhook_id,&contexts]).await.map_err(Error::internal)?;
    tx.execute(
        "UPDATE ci_runs c SET lease_generation=lease_generation+1,updated_at=clock_timestamp() \
         WHERE c.repository_id=$1 AND c.context=ANY($2) \
           AND NOT EXISTS(SELECT 1 FROM forge_trusted_check_contexts b \
             WHERE b.repository_id=c.repository_id AND b.context=c.context \
               AND b.webhook_id IS DISTINCT FROM $3)",
        &[&repo,&contexts,&webhook_id]).await.map_err(Error::internal)?;
    Ok(changed)
}

/// Advance the authority epoch for every run in a context when a binding is
/// created or changes owner. Claims increment the same generation, so old
/// check evidence and old leases cannot be replayed against the new binding.
async fn advance_context_authority(
    tx:&deadpool_postgres::Transaction<'_>,repo:Uuid,context:&str,
)->Result<(),Error>{
    tx.execute(
        "UPDATE ci_runs SET lease_generation=lease_generation+1,updated_at=clock_timestamp() \
         WHERE repository_id=$1 AND context=$2",
        &[&repo,&context]).await.map_err(Error::internal)?;
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextInput { pub context: String }

pub(crate) async fn lock_trusted_callback_run(tx:&tokio_postgres::Transaction<'_>,repo_id:Uuid,
    context:&str,input:&CiCallbackInput,target:&(Uuid,Uuid,String,i64,i64,i64),
)->Result<(),Error>{
    let (run_id,job_id,base_oid,generation,pull_number,attempt)=target;
    let row=tx.query_opt(
        "SELECT c.context,c.state,c.job_id,c.head_oid,c.base_oid,c.pull_number, \
          c.pull_version,c.attempt,c.lease_generation, \
          (c.lease_expires_unix>extract(epoch FROM clock_timestamp())) AS lease_valid, \
          p.state AS live_state,p.head_oid AS live_head,p.base_oid AS live_base, \
          p.version AS live_version \
         FROM ci_runs c JOIN forge_pulls p ON p.repository_id=c.repository_id \
           AND p.number=c.pull_number \
         WHERE c.id=$1 AND c.repository_id=$2 FOR UPDATE OF c",
        &[run_id,&repo_id],
    ).await.map_err(Error::internal)?
        .ok_or_else(||Error(StatusCode::CONFLICT,"CI run attempt or candidate changed"))?;
    let valid=row.get::<_,String>("context").as_str()==context
        && row.get::<_,String>("state").as_str()=="leased"
        && row.get::<_,Uuid>("job_id")==*job_id
        && row.get::<_,String>("head_oid").as_str()==input.commit_oid.as_str()
        && row.get::<_,String>("base_oid").as_str()==base_oid.as_str()
        && row.get::<_,i64>("pull_number")==*pull_number
        && row.get::<_,i64>("attempt")==*attempt
        && row.get::<_,i64>("lease_generation")==*generation
        && row.get::<_,bool>("lease_valid")
        && row.get::<_,String>("live_state").as_str()=="open"
        && row.get::<_,String>("live_head").as_str()==input.commit_oid.as_str()
        && row.get::<_,String>("live_base").as_str()==base_oid.as_str()
        && row.get::<_,i64>("live_version")==row.get::<_,i64>("pull_version");
    if !valid { return Err(Error(StatusCode::CONFLICT,"CI run attempt or candidate changed")); }
    Ok(())
}

/// Shared check policy for merge and direct ref publication. A bound context
/// only passes with an active issuer and completed, current, attempt-fenced run.
pub async fn trusted_check_passed<C: tokio_postgres::GenericClient + Sync>(
    client: &C, repo: Uuid, commit: &str, context: &str, base: Option<&str>,
) -> Result<bool,Error> {
    let binding=client.query_opt(
        "SELECT b.webhook_id,b.active,w.active, \
                COALESCE(w.active AND w.ci_contexts ? b.context,false) AS scope_current \
         FROM forge_trusted_check_contexts b \
         LEFT JOIN forge_webhooks w ON w.id=b.webhook_id AND w.repository_id=b.repository_id \
         WHERE b.repository_id=$1 AND b.context=$2", &[&repo,&context],
    ).await.map_err(Error::internal)?;
    let check=client.query_opt(
        "SELECT c.status,c.conclusion,c.attempt,c.issuer_webhook_id,c.ci_run_id, \
         c.ci_base_oid,c.ci_lease_generation FROM forge_check_runs c \
         WHERE c.repository_id=$1 AND c.commit_oid=$2 AND c.context=$3",
        &[&repo,&commit,&context],
    ).await.map_err(Error::internal)?;
    let Some(check)=check else {return Ok(false);};
    if check.get::<_,String>("status")!="completed" ||
        check.get::<_,Option<String>>("conclusion").as_deref()!=Some("success") {
        return Ok(false);
    }
    let Some(binding)=binding else {return Ok(true);};
    let Some(base)=base else {return Ok(false);};
    let hook:Option<Uuid>=binding.get(0);
    if !binding.get::<_,bool>(1) || binding.get::<_,Option<bool>>(2)!=Some(true) ||
        !binding.get::<_,bool>(3) || hook.is_none() ||
        check.get::<_,Option<Uuid>>("issuer_webhook_id")!=hook ||
        check.get::<_,Option<String>>("ci_base_oid").as_deref()!=Some(base) {
        return Ok(false);
    }
    let (Some(run_id),Some(lease_generation))=(check.get::<_,Option<Uuid>>("ci_run_id"),
        check.get::<_,Option<i64>>("ci_lease_generation")) else {return Ok(false);};
    let valid:bool=client.query_one(
        "SELECT EXISTS(SELECT 1 FROM ci_runs c JOIN forge_pulls p \
         ON p.repository_id=c.repository_id AND p.number=c.pull_number \
         WHERE c.id=$1 AND c.repository_id=$2 AND c.context=$3 \
           AND c.head_oid=$4 AND c.base_oid=$5 AND c.state='completed' \
           AND c.conclusion='success' AND c.attempt=$6 AND c.lease_generation=$7 \
           AND p.state='open' AND p.version=c.pull_version \
           AND p.head_oid=c.head_oid AND p.base_oid=c.base_oid)",
        &[&run_id,&repo,&context,&commit,&base,&check.get::<_,i64>("attempt"),&lease_generation],
    ).await.map_err(Error::internal)?.get(0);
    Ok(valid)
}

pub async fn bind(
    State(state): State<Arc<AppState>>,
    Path((owner,name,hook_id)): Path<(String,String,Uuid)>,
    headers: HeaderMap, Json(input): Json<ContextInput>,
) -> Result<Response,Error> {
    if !context_valid(&input.context) { return Err(Error::bad_request()); }
    let actor = auth::authenticate(&state.pool,&headers).await?;
    let repo_id=policy_repo_id(&state,&owner,&name).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    lock_policy_tx(&tx,repo_id).await?;
    let access = auth::authorize_repo_with_role(&tx,&actor,&owner,&name,Role::Maintain,crate::token_scopes::RepoAction::HooksAdmin).await?;
    if access.repo_id!=repo_id{return Err(Error(StatusCode::CONFLICT,"repository changed"));}
    let hook = tx.query_opt(
        "SELECT active,ci_contexts FROM forge_webhooks WHERE id=$1 AND repository_id=$2",
        &[&hook_id,&access.repo_id],
    ).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let permitted = hook.get::<_,bool>(0) && hook.get::<_,serde_json::Value>(1).as_array()
        .is_some_and(|a| a.iter().any(|v| v.as_str()==Some(input.context.as_str())));
    if !permitted { return Err(Error(StatusCode::CONFLICT,"integration inactive or context not allowed")); }
    let existing = tx.query_opt(
        "SELECT webhook_id,active FROM forge_trusted_check_contexts \
         WHERE repository_id=$1 AND context=$2 FOR UPDATE",
        &[&access.repo_id,&input.context],
    ).await.map_err(Error::internal)?;
    let authority_changed = existing.as_ref().is_none_or(|row| {
        !row.get::<_,bool>("active") ||
        row.get::<_,Option<Uuid>>("webhook_id")!=Some(hook_id)
    });
    if authority_changed {
        advance_context_authority(&tx,access.repo_id,&input.context).await?;
    }
    tx.execute(
        "INSERT INTO forge_trusted_check_contexts(tenant_id,repository_id,context,webhook_id,active) \
         VALUES($1,$2,$3,$4,true) ON CONFLICT(repository_id,context) DO UPDATE \
         SET webhook_id=excluded.webhook_id,active=true",
        &[&access.owner_id,&access.repo_id,&input.context,&hook_id],
    ).await.map_err(Error::internal)?;
    auth::finish_tx(tx,&actor,true).await?;
    Ok((StatusCode::OK,[(header::CACHE_CONTROL,"no-store")],Json(serde_json::json!({"context":input.context,"webhook_id":hook_id,"active":true}))).into_response())
}

pub async fn revoke(
    State(state): State<Arc<AppState>>,
    Path((owner,name,hook_id)): Path<(String,String,Uuid)>,
    headers: HeaderMap, Json(input): Json<ContextInput>,
) -> Result<Response,Error> {
    if !context_valid(&input.context) { return Err(Error::bad_request()); }
    let actor = auth::authenticate(&state.pool,&headers).await?;
    let repo_id=policy_repo_id(&state,&owner,&name).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    lock_policy_tx(&tx,repo_id).await?;
    let access = auth::authorize_repo_with_role(&tx,&actor,&owner,&name,Role::Maintain,crate::token_scopes::RepoAction::HooksAdmin).await?;
    if access.repo_id!=repo_id{return Err(Error(StatusCode::CONFLICT,"repository changed"));}
    let changed = revoke_owned_contexts(&tx,access.repo_id,hook_id,
        std::slice::from_ref(&input.context)).await?;
    if changed==0 { return Err(Error::not_found()); }
    auth::finish_tx(tx,&actor,true).await?;
    Ok((StatusCode::OK,[(header::CACHE_CONTROL,"no-store")],Json(serde_json::json!({"context":input.context,"active":false}))).into_response())
}

/// A source repository administrator separately authorizes one integration to
/// materialize that repository as a pinned submodule dependency.
pub async fn source_grant(
    State(state): State<Arc<AppState>>,
    Path((owner,name,hook_id)): Path<(String,String,Uuid)>, headers: HeaderMap,
) -> Result<Response,Error>{
    source_grant_inner(state,owner,name,hook_id,headers,true).await
}
pub async fn source_revoke(
    State(state): State<Arc<AppState>>,
    Path((owner,name,hook_id)): Path<(String,String,Uuid)>, headers: HeaderMap,
) -> Result<Response,Error>{
    source_grant_inner(state,owner,name,hook_id,headers,false).await
}
async fn source_grant_inner(state:Arc<AppState>,owner:String,name:String,hook_id:Uuid,
    headers:HeaderMap,active:bool)->Result<Response,Error>{
    let actor=auth::authenticate(&state.pool,&headers).await?;
    let mut client=state.pool.get().await.map_err(Error::internal)?;
    let tx=client.transaction().await.map_err(Error::internal)?;
    let access=auth::authorize_repo_with_role(&tx,&actor,&owner,&name,Role::Maintain,crate::token_scopes::RepoAction::HooksAdmin).await?;
    let hook=tx.query_opt("SELECT id FROM forge_webhooks WHERE id=$1 AND active=true",&[&hook_id])
        .await.map_err(Error::internal)?;
    if hook.is_none(){return Err(Error::not_found());}
    tx.execute(
        "INSERT INTO ci_integration_source_grants(issuer_webhook_id,repository_id,active) \
         VALUES($1,$2,$3) ON CONFLICT(issuer_webhook_id,repository_id) DO UPDATE SET active=$3",
        &[&hook_id,&access.repo_id,&active],
    ).await.map_err(Error::internal)?;
    auth::finish_tx(tx,&actor,true).await?;
    Ok((StatusCode::OK,[(header::CACHE_CONTROL,"no-store")],
        Json(serde_json::json!({"repository_id":access.repo_id,"issuer_webhook_id":hook_id,"active":active}))).into_response())
}
