//! Thin external runner adapter for immutable CI candidates and fenced attempts.
use crate::{AppState, Error, ci_checkouts, pulls::models::context_valid, webhooks::signing::{constant_time_eq, sha256_hex}};
use axum::{Json, extract::{Path,State}, http::{HeaderMap,StatusCode,header}, response::{IntoResponse,Response}};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimInput { pub runner_id: String }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportInput { pub attempt: i64, pub lease_generation: i64,
    pub conclusion: String, pub output: String }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatInput { pub attempt:i64, pub lease_generation:i64, pub runner_id:String }

async fn integration(state: &AppState, owner: &str, name: &str, hook_id: Uuid,
    headers: &HeaderMap) -> Result<(Uuid,Uuid),Error> {
    let bearer = headers.get("authorization").and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer ")).ok_or_else(Error::unauthorized)?;
    let client = state.pool.get().await.map_err(Error::internal)?;
    let row = client.query_opt(
        "SELECT r.id,r.owner_id,w.secret,w.active FROM repositories r \
         JOIN namespaces u ON u.id=r.owner_id JOIN forge_webhooks w ON w.repository_id=r.id \
         WHERE u.slug=$1 AND r.name=$2 AND w.id=$3 AND r.state='ready'",
        &[&owner,&name,&hook_id],
    ).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let secret: String = row.get(2);
    if !row.get::<_,bool>(3) || !constant_time_eq(secret.as_bytes(),bearer.as_bytes()) {
        return Err(Error::unauthorized());
    }
    Ok((row.get(0),row.get(1)))
}

pub async fn claim(
    State(state): State<Arc<AppState>>,
    Path((owner,name,hook_id,run_id)): Path<(String,String,Uuid,Uuid)>,
    headers: HeaderMap, Json(input): Json<ClaimInput>,
) -> Result<Response,Error> {
    if input.runner_id.is_empty() || input.runner_id.len()>64 ||
        !input.runner_id.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)) {
        return Err(Error::bad_request());
    }
    let (repo,_) = integration(&state,&owner,&name,hook_id,&headers).await?;
    let snapshot=state.pool.get().await.map_err(Error::internal)?.query_opt(
        "SELECT c.head_oid,c.job_id,c.storage_generation FROM ci_runs c \
         JOIN forge_trusted_check_contexts b ON b.repository_id=c.repository_id \
           AND b.context=c.context AND b.webhook_id=$3 AND b.active=true \
         WHERE c.id=$1 AND c.repository_id=$2 AND c.state IN ('queued','leased')",
        &[&run_id,&repo,&hook_id],
    ).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let prepared=ci_checkouts::integration::prepare(&state,hook_id,repo,snapshot.get("job_id"),
        snapshot.get::<_,String>("head_oid").as_str()).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let row = tx.query_opt(
        "SELECT c.context,c.head_oid,c.base_oid,c.job_id,c.storage_generation,c.state,c.attempt,c.lease_generation \
         FROM ci_runs c JOIN forge_trusted_check_contexts b ON b.repository_id=c.repository_id \
          AND b.context=c.context AND b.webhook_id=$3 AND b.active=true \
         JOIN forge_pulls p ON p.repository_id=c.repository_id AND p.number=c.pull_number \
         WHERE c.id=$1 AND c.repository_id=$2 AND p.state='open' \
           AND p.version=c.pull_version AND p.head_oid=c.head_oid AND p.base_oid=c.base_oid \
         FOR UPDATE OF c",
        &[&run_id,&repo,&hook_id],
    ).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let state_now: String = row.get("state");
    if state_now != "queued" && state_now != "leased" {
        return Err(Error(StatusCode::CONFLICT,"CI run is terminal"));
    }
    if state_now == "leased" {
        let active: bool = tx.query_one(
            "SELECT lease_expires_unix>extract(epoch FROM clock_timestamp()) FROM ci_runs WHERE id=$1",
            &[&run_id],
        ).await.map_err(Error::internal)?.get(0);
        if active { return Err(Error(StatusCode::CONFLICT,"CI run is leased")); }
    }
    let head: String = row.get("head_oid");
    let base: String = row.get("base_oid");
    let generation: i64 = row.get("storage_generation");
    let job_id: Uuid = row.get("job_id");
    if head!=snapshot.get::<_,String>("head_oid") || job_id!=snapshot.get::<_,Uuid>("job_id") ||
        generation!=snapshot.get::<_,i64>("storage_generation") {
        return Err(Error(StatusCode::CONFLICT,"CI candidate changed during checkout preparation"));
    }
    tx.execute("SELECT pg_advisory_xact_lock(1062026)",&[]).await.map_err(Error::internal)?;
    // A mirror is eligible only with a fresh heartbeat and exact target readiness.
    let mirror = tx.query_opt(
        "SELECT m.url FROM ci_mirror_nodes m WHERE m.repository_id=$1 AND m.storage_generation=$2 \
         AND m.active=true AND m.heartbeat_unix>extract(epoch FROM clock_timestamp())-30 \
         AND m.ready_oids ? $3 AND (SELECT count(*) FROM ci_runs c \
             WHERE c.source_url=m.url AND c.state='leased' AND \
             c.lease_expires_unix>extract(epoch FROM clock_timestamp()))<m.capacity \
         ORDER BY m.heartbeat_unix DESC LIMIT 1",
        &[&repo,&generation,&head],
    ).await.map_err(Error::internal)?;
    let source = if let Some(mirror)=mirror { mirror.get::<_,String>(0) } else {
        let global: i64 = std::env::var("ROOTYARD_CI_ORIGIN_FALLBACK_GLOBAL").ok()
            .and_then(|v| v.parse().ok()).unwrap_or(4);
        let per_repo: i64 = std::env::var("ROOTYARD_CI_ORIGIN_FALLBACK_PER_REPO").ok()
            .and_then(|v| v.parse().ok()).unwrap_or(2);
        if global<=0 || per_repo<=0 { return Err(Error(StatusCode::TOO_MANY_REQUESTS,"no ready mirror")); }
        let count = tx.query_one(
            "SELECT count(*) AS global, count(*) FILTER(WHERE repository_id=$1) AS repo \
             FROM ci_runs WHERE state='leased' AND source_url='origin' \
             AND lease_expires_unix>extract(epoch FROM clock_timestamp())", &[&repo],
        ).await.map_err(Error::internal)?;
        if count.get::<_,i64>("global")>=global || count.get::<_,i64>("repo")>=per_repo {
            return Err(Error(StatusCode::TOO_MANY_REQUESTS,"origin fallback budget exhausted"));
        }
        "origin".to_owned()
    };
    let updated = tx.query_one(
        "UPDATE ci_runs SET state='leased',attempt=attempt+1,lease_generation=lease_generation+1, \
         lease_expires_unix=extract(epoch FROM clock_timestamp())::bigint+60,runner_id=$2, \
         source_url=$3,updated_at=clock_timestamp() WHERE id=$1 \
         RETURNING attempt,lease_generation,lease_expires_unix",
        &[&run_id,&input.runner_id,&source],
    ).await.map_err(Error::internal)?;
    let attempt:i64=updated.get(0);
    let lease_generation:i64=updated.get(1);
    let expires_unix:i64=updated.get(2);
    let checkout=ci_checkouts::integration::persist(&tx,prepared,hook_id,run_id,
        attempt,lease_generation,expires_unix+3600).await?;
    tx.commit().await.map_err(Error::internal)?;
    Ok((StatusCode::OK,[(header::CACHE_CONTROL,"no-store")],Json(serde_json::json!({"run_id":run_id,"job_id":job_id,
        "head_oid":head,"base_oid":base,"storage_generation":generation,"source":source,
        "attempt":updated.get::<_,i64>(0),"lease_generation":updated.get::<_,i64>(1),
        "lease_expires_unix":expires_unix,"checkout":checkout}))).into_response())
}

pub async fn heartbeat(
    State(state):State<Arc<AppState>>,
    Path((owner,name,hook_id,run_id)):Path<(String,String,Uuid,Uuid)>,
    headers:HeaderMap,Json(input):Json<HeartbeatInput>,
)->Result<Response,Error>{
    if input.attempt<=0 || input.lease_generation<=0 || input.runner_id.is_empty() ||
        input.runner_id.len()>64 {return Err(Error::bad_request());}
    let (repo,_)=integration(&state,&owner,&name,hook_id,&headers).await?;
    let client=state.pool.get().await.map_err(Error::internal)?;
    let row=client.query_opt(
        "UPDATE ci_runs c SET lease_expires_unix=extract(epoch FROM clock_timestamp())::bigint+60, \
         updated_at=clock_timestamp() FROM forge_trusted_check_contexts b, forge_pulls p \
         WHERE c.id=$1 AND c.repository_id=$2 AND b.repository_id=c.repository_id \
           AND b.context=c.context AND b.webhook_id=$3 AND b.active=true \
           AND p.repository_id=c.repository_id AND p.number=c.pull_number AND p.state='open' \
           AND p.version=c.pull_version AND p.head_oid=c.head_oid AND p.base_oid=c.base_oid \
           AND c.state='leased' AND c.attempt=$4 AND c.lease_generation=$5 \
           AND c.runner_id=$6 AND c.lease_expires_unix>extract(epoch FROM clock_timestamp()) \
         RETURNING c.lease_expires_unix",
        &[&run_id,&repo,&hook_id,&input.attempt,&input.lease_generation,&input.runner_id],
    ).await.map_err(Error::internal)?.ok_or_else(||Error(StatusCode::CONFLICT,"CI run lease changed"))?;
    Ok((StatusCode::OK,[(header::CACHE_CONTROL,"no-store")],Json(serde_json::json!({
        "run_id":run_id,"attempt":input.attempt,"lease_generation":input.lease_generation,
        "lease_expires_unix":row.get::<_,i64>(0)}))).into_response())
}

pub async fn report(
    State(state): State<Arc<AppState>>,
    Path((owner,name,hook_id,run_id)): Path<(String,String,Uuid,Uuid)>,
    headers: HeaderMap, Json(input): Json<ReportInput>,
) -> Result<Response,Error> {
    if input.attempt<=0 || input.lease_generation<=0 || input.output.len()>8192 ||
        !matches!(input.conclusion.as_str(),"success"|"failure"|"cancelled"|"timed_out") {
        return Err(Error::bad_request());
    }
    let (repo,tenant) = integration(&state,&owner,&name,hook_id,&headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let row = tx.query_opt(
        "SELECT c.context,c.head_oid,c.base_oid,c.state,c.attempt,c.lease_generation,c.result_sha256, \
          p.head_oid AS live_head,p.base_oid AS live_base,p.version AS live_version,c.pull_version \
         FROM ci_runs c JOIN forge_trusted_check_contexts b ON b.repository_id=c.repository_id \
          AND b.context=c.context AND b.webhook_id=$3 AND b.active=true \
         JOIN forge_pulls p ON p.repository_id=c.repository_id AND p.number=c.pull_number \
         WHERE c.id=$1 AND c.repository_id=$2 FOR UPDATE OF c",
        &[&run_id,&repo,&hook_id],
    ).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let digest = sha256_hex(format!("{}\0{}",input.conclusion,input.output).as_bytes());
    if row.get::<_,String>("state")=="completed" &&
        row.get::<_,i64>("attempt")==input.attempt &&
        row.get::<_,i64>("lease_generation")==input.lease_generation &&
        row.get::<_,Option<String>>("result_sha256").as_deref()==Some(&digest) {
        tx.commit().await.map_err(Error::internal)?;
        return Ok((StatusCode::OK,[(header::CACHE_CONTROL,"no-store")],Json(serde_json::json!({"run_id":run_id,"replay":true}))).into_response());
    }
    if row.get::<_,String>("state")!="leased" || row.get::<_,i64>("attempt")!=input.attempt ||
        row.get::<_,i64>("lease_generation")!=input.lease_generation ||
        row.get::<_,String>("head_oid")!=row.get::<_,String>("live_head") ||
        row.get::<_,String>("base_oid")!=row.get::<_,String>("live_base") ||
        row.get::<_,i64>("pull_version")!=row.get::<_,i64>("live_version") {
        return Err(Error(StatusCode::CONFLICT,"CI run attempt or candidate changed"));
    }
    let lease_valid: bool = tx.query_one(
        "SELECT lease_expires_unix>extract(epoch FROM clock_timestamp()) FROM ci_runs WHERE id=$1",
        &[&run_id],
    ).await.map_err(Error::internal)?.get(0);
    if !lease_valid { return Err(Error(StatusCode::CONFLICT,"CI run lease expired")); }
    let context: String = row.get("context");
    if !context_valid(&context) { return Err(Error::internal("invalid CI context")); }
    let head: String = row.get("head_oid");
    let base: String = row.get("base_oid");
    tx.execute(
        "INSERT INTO forge_check_runs(tenant_id,repository_id,commit_oid,context,attempt,sequence,status,conclusion,output,issuer_webhook_id,ci_run_id,ci_base_oid,ci_lease_generation) \
         VALUES($1,$2,$3,$4,$5,2,'completed',$6,$7,$8,$9,$10,$11) \
         ON CONFLICT(tenant_id,repository_id,commit_oid,context) DO UPDATE \
         SET attempt=excluded.attempt,sequence=excluded.sequence,status=excluded.status, \
         conclusion=excluded.conclusion,output=excluded.output,issuer_webhook_id=excluded.issuer_webhook_id, \
         ci_run_id=excluded.ci_run_id,ci_base_oid=excluded.ci_base_oid, \
         ci_lease_generation=excluded.ci_lease_generation,updated_at=clock_timestamp()",
        &[&tenant,&repo,&head,&context,&input.attempt,&input.conclusion,&input.output,
          &hook_id,&run_id,&base,&input.lease_generation],
    ).await.map_err(Error::internal)?;
    tx.execute(
        "UPDATE ci_runs SET state='completed',conclusion=$2,result_sha256=$3, \
         lease_expires_unix=0,updated_at=clock_timestamp() WHERE id=$1",
        &[&run_id,&input.conclusion,&digest],
    ).await.map_err(Error::internal)?;
    tx.commit().await.map_err(Error::internal)?;
    Ok((StatusCode::OK,[(header::CACHE_CONTROL,"no-store")],Json(serde_json::json!({"run_id":run_id,"replay":false}))).into_response())
}
