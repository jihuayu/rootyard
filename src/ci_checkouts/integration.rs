//! One-time checkout capabilities for a signed, fenced CI run attempt.
use super::{Plan, audience, dependencies::{self,Manifest,Principal}};
use crate::{AppState,Error,ci_pins,db};
use axum::http::StatusCode;
use rand::RngCore;
use uuid::Uuid;

pub struct Prepared {
    repo: db::Repository,
    owner_id: Uuid,
    head: String,
    job_id: Uuid,
    receipt: String,
    manifest: Manifest,
    sub_receipts: Vec<(Uuid,String)>,
}

fn intent(repo:&db::Repository,owner_id:Uuid,job_id:Uuid,oid:&str)->ci_pins::Intent {
    ci_pins::Intent{version:1,job_id,owner_id,repository_id:repo.id,
        storage_generation:repo.storage_generation,
        object_format:if oid.len()==40 {"sha1"} else {"sha256"}.into(),
        target_oid:oid.into(),retention_ref:format!("refs/rootyard-ci/jobs/{job_id}")}
}

pub async fn prepare(state:&AppState,hook_id:Uuid,repo_id:Uuid,job_id:Uuid,
    head:&str)->Result<Prepared,Error>{
    let client=state.pool.get().await.map_err(Error::internal)?;
    let row=client.query_one(&format!("{} WHERE r.id=$1",db::REPO_SELECT),&[&repo_id])
        .await.map_err(Error::internal)?;
    let repo=db::Repository::from_row(&row);
    let owner_id:Uuid=row.get("owner_id");
    drop(client);
    let guard=state.storage.write_lock(repo.id).await;
    let receipt=ci_pins::verify_receipt(state,&intent(&repo,owner_id,job_id,head)).await
        .map_err(|_|Error(StatusCode::CONFLICT,"CI source pin missing"))?;
    drop(guard);
    let manifest=dependencies::scan(state,Principal::Integration(hook_id),repo.clone(),
        job_id,head,"full",&[]).await?;
    let mut sub_receipts=Vec::new();
    for sub in &manifest.submodules {
        let client=state.pool.get().await.map_err(Error::internal)?;
        let row=client.query_one(&format!("{} WHERE r.id=$1",db::REPO_SELECT),
            &[&sub.repository_id]).await.map_err(Error::internal)?;
        let sub_repo=db::Repository::from_row(&row);
        let sub_owner:Uuid=row.get("owner_id");
        drop(client);
        let guard=state.storage.write_lock(sub_repo.id).await;
        let receipt=ci_pins::verify_receipt(state,&intent(&sub_repo,sub_owner,
            sub.job_id,&sub.target_oid)).await
            .map_err(|_|Error(StatusCode::CONFLICT,"CI submodule pin missing"))?;
        drop(guard);
        sub_receipts.push((sub.job_id,receipt));
    }
    Ok(Prepared{repo,owner_id,head:head.into(),job_id,receipt,manifest,sub_receipts})
}

fn token()->String {let mut random=[0u8;32];rand::rng().fill_bytes(&mut random);
    format!("ryj_{}",hex::encode(random))}

pub async fn persist(tx:&tokio_postgres::Transaction<'_>,prepared:Prepared,
    hook_id:Uuid,run_id:Uuid,attempt:i64,lease_generation:i64,expires_unix:i64,
) -> Result<serde_json::Value,Error>{
    let audience=audience()?;
    let root=Plan{version:1,job_id:prepared.job_id,owner_id:prepared.owner_id,
        repository_id:prepared.repo.id,storage_generation:prepared.repo.storage_generation,
        object_format:if prepared.head.len()==40 {"sha1"} else {"sha256"}.into(),
        target_oid:prepared.head,source_receipt_sha256:prepared.receipt,
        mirror_audience:audience,expires_unix,dependencies:prepared.manifest.clone()};
    let secret=token();
    tx.execute("INSERT INTO ci_integration_checkout_jobs(run_id,attempt,lease_generation, \
        repository_id,job_id,owner_id,issuer_webhook_id,plan,credential_digest,expires_unix) \
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
        &[&run_id,&attempt,&lease_generation,&root.repository_id,&root.job_id,&root.owner_id,
          &hook_id,&serde_json::to_value(&root).map_err(Error::internal)?,
          &db::digest(&secret),&expires_unix]).await.map_err(Error::internal)?;
    let mut children=Vec::new();
    for sub in &prepared.manifest.submodules {
        let receipt=prepared.sub_receipts.iter().find(|(id,_)|id==&sub.job_id)
            .ok_or_else(||Error::internal("missing prepared submodule receipt"))?.1.clone();
        let row=tx.query_one("SELECT owner_id FROM repositories WHERE id=$1 AND \
            storage_generation=$2 AND state='ready'",&[&sub.repository_id,&sub.storage_generation])
            .await.map_err(Error::internal)?;
        let owner_id:Uuid=row.get(0);
        let plan=Plan{version:1,job_id:sub.job_id,owner_id,
            repository_id:sub.repository_id,storage_generation:sub.storage_generation,
            object_format:if sub.target_oid.len()==40 {"sha1"} else {"sha256"}.into(),
            target_oid:sub.target_oid.clone(),source_receipt_sha256:receipt,
            mirror_audience:audience,expires_unix,
            dependencies:prepared.manifest.for_submodule(sub)};
        let child_secret=token();
        tx.execute("INSERT INTO ci_integration_checkout_jobs(run_id,attempt,lease_generation, \
            repository_id,job_id,owner_id,issuer_webhook_id,plan,credential_digest,expires_unix) \
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
            &[&run_id,&attempt,&lease_generation,&plan.repository_id,&plan.job_id,&owner_id,
              &hook_id,&serde_json::to_value(&plan).map_err(Error::internal)?,
              &db::digest(&child_secret),&expires_unix]).await.map_err(Error::internal)?;
        children.push(serde_json::json!({"path":sub.path,"owner":sub.owner,"name":sub.name,
            "target_oid":sub.target_oid,"job_id":sub.job_id,"token":child_secret}));
    }
    Ok(serde_json::json!({"plan":root,"token":secret,"submodule_credentials":children}))
}
