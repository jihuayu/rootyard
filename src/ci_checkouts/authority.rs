//! Authoritative primary-backed job and submodule credential validation.
use super::{Plan,audience};
use crate::{AppState, Error, auth, db, members::{models::Role,rbac}};
use axum::http::HeaderMap;
use uuid::Uuid;

#[derive(Clone)]
pub enum CheckoutPrincipal {
    User(db::Identity),
    Integration { hook_id:Uuid, run_id:Uuid, job_id:Uuid, token_digest:Vec<u8> },
}

#[derive(Clone)]
pub struct IntegrationScope { pub plan:Plan, pub hook_id:Uuid, pub token_digest:Vec<u8> }
impl IntegrationScope {
    pub async fn validate_source(&self,state:&AppState,repo_id:Uuid)->Result<(),Error>{
        if !still_authorized(state,self.plan.job_id,&self.token_digest,
            self.plan.repository_id,self.plan.storage_generation).await? {
            return Err(Error::unauthorized());
        }
        if repo_id==self.plan.repository_id {return Ok(());}
        if !self.plan.dependencies.submodules.iter().any(|sub|sub.repository_id==repo_id){
            return Err(Error::unauthorized());
        }
        let client=state.pool.get().await.map_err(Error::internal)?;
        if client.query_opt("SELECT 1 FROM ci_integration_source_grants g \
            JOIN repositories r ON r.id=g.repository_id \
            WHERE g.issuer_webhook_id=$1 AND g.repository_id=$2 AND g.active=true \
            AND r.state='ready'",&[&self.hook_id,&repo_id])
            .await.map_err(Error::internal)?.is_none(){return Err(Error::unauthorized());}
        Ok(())
    }
}

const INTEGRATION_GRANT: &str = "FROM ci_integration_checkout_jobs i \
 JOIN ci_runs c ON c.id=i.run_id AND c.attempt=i.attempt \
   AND c.lease_generation=i.lease_generation AND c.state='leased' \
   AND c.lease_expires_unix>extract(epoch FROM clock_timestamp()) \
 JOIN forge_webhooks w ON w.id=i.issuer_webhook_id AND w.repository_id=c.repository_id AND w.active=true \
 JOIN forge_trusted_check_contexts b ON b.repository_id=c.repository_id \
   AND b.context=c.context AND b.webhook_id=w.id AND b.active=true \
 JOIN forge_pulls p ON p.repository_id=c.repository_id AND p.number=c.pull_number \
   AND p.state='open' AND p.version=c.pull_version \
   AND p.head_oid=c.head_oid AND p.base_oid=c.base_oid \
 JOIN repositories r ON r.id=i.repository_id AND r.owner_id=i.owner_id \
   AND r.state='ready' AND r.storage_backend='gitfs' \
 WHERE i.expires_unix>extract(epoch FROM clock_timestamp()) \
   AND (i.repository_id=c.repository_id OR EXISTS ( \
      SELECT 1 FROM ci_integration_source_grants g \
      WHERE g.issuer_webhook_id=w.id AND g.repository_id=i.repository_id AND g.active=true))";

pub async fn integration_hook_for_plan(state:&AppState,plan:&Plan)->Result<Option<Uuid>,Error>{
    let client=state.pool.get().await.map_err(Error::internal)?;
    let sql=format!("SELECT i.issuer_webhook_id,i.plan {INTEGRATION_GRANT} \
      AND i.repository_id=$1 AND i.job_id=$2 AND r.storage_generation=$3");
    let row=client.query_opt(&sql,&[&plan.repository_id,&plan.job_id,&plan.storage_generation])
        .await.map_err(Error::internal)?;
    match row {
        Some(row) if row.get::<_,serde_json::Value>(1)==serde_json::to_value(plan).map_err(Error::internal)?
            =>Ok(Some(row.get(0))),
        _=>Ok(None),
    }
}

pub async fn authenticate_principal(state:&AppState,headers:&HeaderMap,owner:&str,
    name:&str,oid:&str)->Result<(CheckoutPrincipal,db::Repository,Plan),Error>{
    if let Ok((identity,repo,plan))=authenticate(state,headers,owner,name,oid).await {
        return Ok((CheckoutPrincipal::User(identity),repo,plan));
    }
    if state.mirror_primary.is_none(){return Err(Error::unauthorized());}
    let (user,token)=auth::credentials_for(headers,"ryj_")?;
    if user.as_ref().is_some_and(|u|u!=owner){return Err(Error::unauthorized());}
    let digest=db::digest(&token);
    let sql=format!("SELECT i.plan,i.job_id,i.owner_id,i.repository_id,i.issuer_webhook_id, \
      i.run_id,i.expires_unix,r.storage_generation {INTEGRATION_GRANT} \
      AND i.credential_digest=$1 AND r.name=$2 AND EXISTS(SELECT 1 FROM users u \
      WHERE u.id=r.owner_id AND u.username=$3)");
    let client=state.pool.get().await.map_err(Error::internal)?;
    let row=client.query_opt(&sql,&[&digest,&name,&owner]).await.map_err(Error::internal)?
        .ok_or_else(Error::unauthorized)?;
    let plan:Plan=serde_json::from_value(row.get(0)).map_err(Error::internal)?;
    let repo_id:Uuid=row.get(3);
    if plan.version!=1 || plan.job_id!=row.get::<_,Uuid>(1) ||
       plan.owner_id!=row.get::<_,Uuid>(2) || plan.repository_id!=repo_id ||
       plan.expires_unix!=row.get::<_,i64>(6) ||
       plan.storage_generation!=row.get::<_,i64>(7) ||
       plan.target_oid!=oid || plan.object_format!=if oid.len()==40 {"sha1"}else{"sha256"} ||
       plan.mirror_audience!=audience()? || plan.dependencies.version!=1 {
        return Err(Error::unauthorized());
    }
    let repo=db::Repository{id:repo_id,name:name.into(),owner:owner.into(),state:"ready".into(),
        clone_path:format!("/git/{owner}/{name}.git"),storage_backend:"gitfs".into(),
        storage_generation:plan.storage_generation};
    Ok((CheckoutPrincipal::Integration{hook_id:row.get(4),run_id:row.get(5),
        job_id:plan.job_id,token_digest:digest},repo,plan))
}

const GRANTS: &str = "WITH grants AS ( \
 SELECT j.plan,j.owner_id,j.repository_id,j.issuer_token_id,j.expires_unix,j.job_id, \
        j.credential_digest,j.cancelled,j.revoked FROM ci_checkout_jobs j \
 UNION ALL \
 SELECT d.plan,d.owner_id,d.repository_id,d.issuer_token_id,d.expires_unix,d.job_id, \
        d.credential_digest,p.cancelled,p.revoked FROM ci_checkout_delegations d \
 JOIN ci_checkout_jobs p ON p.repository_id=d.parent_repository_id AND p.job_id=d.parent_job_id \
 WHERE p.expires_unix>extract(epoch FROM clock_timestamp()) \
 ) ";

/// Each request rechecks the issuing actor's token and current role on the
/// exact repository. Delegated submodule tokens remain tied to the parent job.
pub(crate) async fn authenticate(
    state:&AppState,headers:&HeaderMap,owner:&str,name:&str,oid:&str,
) -> Result<(db::Identity,db::Repository,Plan),Error>{
    if state.mirror_primary.is_none(){return Err(Error::unauthorized());}
    let (user,token)=auth::credentials_for(headers,"ryj_")?;
    if user.as_ref().is_some_and(|u|u!=owner){return Err(Error::unauthorized());}
    let digest=db::digest(&token);
    let mut client=state.pool.get().await.map_err(Error::internal)?;
    let tx=client.transaction().await.map_err(Error::internal)?;
    let sql=format!("{GRANTS} SELECT g.plan,g.owner_id,g.repository_id,g.issuer_token_id, \
        g.expires_unix,r.storage_generation,u.username,g.job_id,t.user_id,ua.username AS actor_name \
        FROM grants g JOIN repositories r ON r.id=g.repository_id AND r.owner_id=g.owner_id \
        JOIN users u ON u.id=g.owner_id JOIN tokens t ON t.id=g.issuer_token_id \
        JOIN users ua ON ua.id=t.user_id \
        WHERE g.credential_digest=$1 AND NOT g.cancelled AND NOT g.revoked \
          AND g.expires_unix>extract(epoch FROM clock_timestamp()) \
          AND NOT t.revoked AND NOT t.read_only \
          AND (t.expires_at IS NULL OR t.expires_at>clock_timestamp()) \
          AND r.state='ready' AND r.storage_backend='gitfs' AND r.name=$2 AND u.username=$3");
    let row=tx.query_opt(&sql,&[&digest,&name,&owner]).await.map_err(Error::internal)?
        .ok_or_else(Error::unauthorized)?;
    let repo_id:Uuid=row.get(2);let owner_id:Uuid=row.get(1);let actor_id:Uuid=row.get(8);
    if rbac::resolve_effective_role_by_id(&tx,repo_id,owner_id,actor_id).await?
        .is_none_or(|r|r<Role::Read){return Err(Error::unauthorized());}
    let plan:Plan=serde_json::from_value(row.get(0)).map_err(Error::internal)?;
    if plan.job_id!=row.get::<_,Uuid>(7) || plan.version!=1 ||
        plan.owner_id!=owner_id || plan.repository_id!=repo_id ||
        plan.expires_unix!=row.get::<_,i64>(4) ||
        plan.storage_generation!=row.get::<_,i64>(5) ||
        plan.object_format!=if oid.len()==40 {"sha1"} else {"sha256"} ||
        plan.target_oid!=oid || plan.mirror_audience!=audience()? ||
        plan.dependencies.version!=1 {return Err(Error::unauthorized());}
    tx.commit().await.map_err(Error::internal)?;
    let identity=db::Identity{id:actor_id,token_id:row.get(3),username:row.get("actor_name"),
        read_only:true,token_digest:digest};
    let repo=db::Repository{id:repo_id,name:name.into(),owner:owner.into(),state:"ready".into(),
        clone_path:format!("/git/{owner}/{name}.git"),storage_backend:"gitfs".into(),
        storage_generation:plan.storage_generation};
    Ok((identity,repo,plan))
}

/// Used during active transfers at a fixed interval. DB errors must end the stream.
pub(crate) async fn still_authorized(
    state:&AppState,job_id:Uuid,credential_digest:&[u8],repository_id:Uuid,
    storage_generation:i64,
) -> Result<bool,Error>{
    let mut client=state.pool.get().await.map_err(Error::internal)?;
    let tx=client.transaction().await.map_err(Error::internal)?;
    let sql=format!("{GRANTS} SELECT r.owner_id,t.user_id FROM grants g \
        JOIN repositories r ON r.id=g.repository_id AND r.owner_id=g.owner_id \
        JOIN tokens t ON t.id=g.issuer_token_id \
        WHERE g.repository_id=$1 AND g.job_id=$2 AND g.credential_digest=$3 \
          AND NOT g.cancelled AND NOT g.revoked \
          AND g.expires_unix>extract(epoch FROM clock_timestamp()) \
          AND NOT t.revoked AND NOT t.read_only \
          AND (t.expires_at IS NULL OR t.expires_at>clock_timestamp()) \
          AND r.state='ready' AND r.storage_generation=$4");
    let row=tx.query_opt(&sql,&[&repository_id,&job_id,&credential_digest,&storage_generation])
        .await.map_err(Error::internal)?;
    let valid=if let Some(row)=row {
        let owner:Uuid=row.get(0);let actor:Uuid=row.get(1);
        rbac::resolve_effective_role_by_id(&tx,repository_id,owner,actor).await?
            .is_some_and(|r|r>=Role::Read)
    } else {false};
    tx.commit().await.map_err(Error::internal)?;
    if valid {return Ok(true);}
    let client=state.pool.get().await.map_err(Error::internal)?;
    let sql=format!("SELECT 1 {INTEGRATION_GRANT} AND i.repository_id=$1 AND i.job_id=$2 \
      AND i.credential_digest=$3 AND r.storage_generation=$4");
    Ok(client.query_opt(&sql,&[&repository_id,&job_id,&credential_digest,&storage_generation])
        .await.map_err(Error::internal)?.is_some())
}
