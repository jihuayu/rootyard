//! Real policy rows (branch rules, open pulls, check runs, trusted contexts,
//! webhooks, LFS locks) from the actual migrations 009/020/040/050/107/121.
//!
//! These are the rows the decision transaction re-reads after its `NOWAIT`
//! dependency locks. The tests mutate them between `select` and `commit` to
//! prove the final commit re-evaluates live policy instead of trusting the
//! persisted decision.
use anyhow::{Result, ensure};
use deadpool_postgres::Pool;
use uuid::Uuid;

pub struct Rule<'a> {
    pub branch_ref: &'a str,
    pub required_approvals: i64,
    pub required_checks: &'a [&'a str],
    pub prevent_deletion: bool,
    pub prevent_force_push: bool,
    pub prevent_self_approval: bool,
}

impl<'a> Rule<'a> {
    pub fn approvals(branch_ref: &'a str, required_approvals: i64) -> Self {
        Self {
            branch_ref,
            required_approvals,
            required_checks: &[],
            prevent_deletion: true,
            prevent_force_push: true,
            prevent_self_approval: true,
        }
    }
}

pub async fn branch_rule(pool: &Pool, tenant: Uuid, repo: Uuid, rule: Rule<'_>) -> Result<()> {
    let checks = serde_json::to_value(rule.required_checks)?;
    pool.get()
        .await?
        .execute(
            "INSERT INTO forge_branch_rules(
                 tenant_id,repository_id,branch_ref,required_approvals,required_checks,
                 require_fast_forward,prevent_deletion,prevent_force_push,prevent_self_approval)
             VALUES($1,$2,$3,$4,$5::jsonb,true,$6,$7,$8)",
            &[
                &tenant,
                &repo,
                &rule.branch_ref,
                &rule.required_approvals,
                &checks,
                &rule.prevent_deletion,
                &rule.prevent_force_push,
                &rule.prevent_self_approval,
            ],
        )
        .await?;
    Ok(())
}

pub async fn webhook(pool: &Pool, tenant: Uuid, repo: Uuid) -> Result<Uuid> {
    let id = Uuid::new_v4();
    pool.get()
        .await?
        .execute(
            "INSERT INTO forge_webhooks(id,tenant_id,repository_id,url,secret,secret_sha256,active)
             VALUES($1,$2,$3,'http://127.0.0.1:9/hook','fixture-secret',$4,true)",
            &[&id, &tenant, &repo, &hex::encode([0x5a; 32])],
        )
        .await?;
    Ok(id)
}

pub async fn trusted_context(pool: &Pool, tenant: Uuid, repo: Uuid, context: &str, hook: Uuid) -> Result<()> {
    pool.get()
        .await?
        .execute(
            "INSERT INTO forge_trusted_check_contexts(tenant_id,repository_id,context,webhook_id,active)
             VALUES($1,$2,$3,$4,true)",
            &[&tenant, &repo, &context, &hook],
        )
        .await?;
    Ok(())
}

pub async fn withdraw_trusted_context(pool: &Pool, repo: Uuid, context: &str) -> Result<()> {
    let updated = pool
        .get()
        .await?
        .execute(
            "UPDATE forge_trusted_check_contexts SET active=false WHERE repository_id=$1 AND context=$2",
            &[&repo, &context],
        )
        .await?;
    ensure!(updated == 1, "trusted check context withdrawal did not hit exactly one row");
    Ok(())
}

pub async fn check_run(
    pool: &Pool,
    tenant: Uuid,
    repo: Uuid,
    commit_oid: &str,
    context: &str,
    hook: Uuid,
) -> Result<()> {
    pool.get()
        .await?
        .execute(
            "INSERT INTO forge_check_runs(
                 tenant_id,repository_id,commit_oid,context,status,conclusion,issuer_webhook_id)
             VALUES($1,$2,$3,$4,'completed','success',$5)",
            &[&tenant, &repo, &commit_oid, &context, &hook],
        )
        .await?;
    Ok(())
}
