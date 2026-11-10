//! Live repository policy facts (branch rules, open pull requests, current reviews, check runs, LFS
//! locks and LFS object metadata) read from the actual schemas.
//!
//! These reads happen inside the decision transaction after the frozen `NOWAIT` dependency locks. A set
//! that exceeds a fixed bound is *unverifiable* (fail closed), never partially evaluated.
use super::contract::DecisionError;
use super::sql_locks;
use crate::ref_store::core::pack_commit::plan::PackCommitPlan;
use tokio_postgres::Transaction;
use uuid::Uuid;

const MAX_OPEN_PULLS: i64 = 64;
const MAX_BRANCH_RULES: i64 = 256;
const MAX_LFS_LOCKS: i64 = 4096;
const MAX_APPROVAL_ROWS: usize = 2048;
const MAX_CHECK_RUN_ROWS: usize = 4096;
const MAX_LFS_POINTER_OBJECTS: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct BranchRuleFacts {
    pub branch_ref: String,
    pub required_approvals: i64,
    pub required_checks: Vec<String>,
    pub require_fast_forward: bool,
    pub prevent_deletion: bool,
    pub prevent_force_push: bool,
    pub prevent_self_approval: bool,
    pub version: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PullFacts {
    pub number: i64,
    pub head_ref: String,
    pub base_ref: String,
    pub head_oid: String,
    pub base_oid: String,
    pub version: i64,
}

/// The latest review per `(pull, author)`, which is what an approval count may use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PullApprovalFacts {
    pub pull_number: i64,
    pub number: i64,
    pub author_id: Uuid,
    pub state: String,
    pub commit_oid: String,
    pub pull_version: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CheckRunFacts {
    pub commit_oid: String,
    pub context: String,
    pub status: String,
    pub conclusion: Option<String>,
    /// A `forge_trusted_check_contexts` row exists for this repo/context.
    pub binding_present: bool,
    pub binding_active: bool,
    pub bound_webhook_id: Option<Uuid>,
    pub webhook_active: bool,
    pub issuer_webhook_id: Option<Uuid>,
    pub ci_base_oid: Option<String>,
    /// Current `ci_runs` attempt/lease matches an open `forge_pulls` version/head/base.
    pub ci_run_valid: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct LfsLockFacts {
    pub path: String,
    pub owner_user_id: Uuid,
    pub version: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct LfsObjectFacts {
    pub oid: String,
    pub ready: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct RepoPolicyFacts {
    pub rules: Vec<BranchRuleFacts>,
    pub pulls: Vec<PullFacts>,
    pub approvals: Vec<PullApprovalFacts>,
    pub checks: Vec<CheckRunFacts>,
    pub lfs_locks: Vec<LfsLockFacts>,
    pub lfs_objects: Vec<LfsObjectFacts>,
}

pub(super) async fn read_policy(tx: &Transaction<'_>, plan: &PackCommitPlan) -> Result<RepoPolicyFacts, DecisionError> {
    let head_oids =
        plan.refs().iter().filter_map(|update| update.target().oid().map(|oid| oid.as_hex())).collect::<Vec<String>>();
    read_policy_repo(tx, plan.repository_id(), plan.tenant_id(), &head_oids).await
}

/// Same live policy reads for a request shape that is not a `PackCommitPlan` (the real metadata
/// `CommitRefsRequest` path). No native facts are assumed.
pub(super) async fn read_policy_repo(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    tenant_id: Uuid,
    head_oids: &[String],
) -> Result<RepoPolicyFacts, DecisionError> {
    let mut rules = tx
        .query(
            "SELECT branch_ref,required_approvals,required_checks::text,require_fast_forward,\
                    prevent_deletion,prevent_force_push,prevent_self_approval,version
             FROM forge_branch_rules
             WHERE repository_id=$1 AND tenant_id=$2
             ORDER BY branch_ref
             LIMIT $3",
            &[&repository_id, &tenant_id, &(MAX_BRANCH_RULES + 1)],
        )
        .await
        .map_err(sql_locks::sql_error)?;
    if rules.len() as i64 > MAX_BRANCH_RULES {
        return Err(DecisionError::Unverifiable("too many branch rules to evaluate"));
    }
    let mut rule_facts = Vec::with_capacity(rules.len());
    for row in rules.drain(..) {
        let required_checks_text: String = row.get(2);
        let required_checks: Vec<String> = serde_json::from_str(&required_checks_text)
            .map_err(|_| DecisionError::Unverifiable("branch rule required_checks is not a string array"))?;
        rule_facts.push(BranchRuleFacts {
            branch_ref: row.get(0),
            required_approvals: row.get(1),
            required_checks,
            require_fast_forward: row.get(3),
            prevent_deletion: row.get(4),
            prevent_force_push: row.get(5),
            prevent_self_approval: row.get(6),
            version: row.get(7),
        });
    }

    let pull_rows = tx
        .query(
            "SELECT number,head_ref,base_ref,head_oid,base_oid,version
             FROM forge_pulls
             WHERE repository_id=$1 AND tenant_id=$2 AND state='open'
             ORDER BY number
             LIMIT $3",
            &[&repository_id, &tenant_id, &(MAX_OPEN_PULLS + 1)],
        )
        .await
        .map_err(sql_locks::sql_error)?;
    if pull_rows.len() as i64 > MAX_OPEN_PULLS {
        return Err(DecisionError::Unverifiable("too many open pull requests to evaluate"));
    }
    let pulls = pull_rows
        .into_iter()
        .map(|row| PullFacts {
            number: row.get(0),
            head_ref: row.get(1),
            base_ref: row.get(2),
            head_oid: row.get(3),
            base_oid: row.get(4),
            version: row.get(5),
        })
        .collect::<Vec<_>>();

    let pull_numbers = pulls.iter().map(|pull| pull.number).collect::<Vec<i64>>();
    let approval_rows = tx
        .query(
            "SELECT DISTINCT ON (pull_number, author_id)
                    pull_number,author_id,state,commit_oid,pull_version,number
             FROM forge_pull_reviews
             WHERE repository_id=$1 AND tenant_id=$2 AND pull_number = ANY($3)
             ORDER BY pull_number, author_id, number DESC
             LIMIT $4",
            &[&repository_id, &tenant_id, &pull_numbers, &((MAX_APPROVAL_ROWS + 1) as i64)],
        )
        .await
        .map_err(sql_locks::sql_error)?;
    if approval_rows.len() > MAX_APPROVAL_ROWS {
        return Err(DecisionError::Unverifiable("too many pull request reviews to evaluate"));
    }
    let approvals = approval_rows
        .into_iter()
        .map(|row| PullApprovalFacts {
            pull_number: row.get(0),
            author_id: row.get(1),
            state: row.get(2),
            commit_oid: row.get(3),
            pull_version: row.get(4),
            number: row.get(5),
        })
        .collect::<Vec<_>>();

    let check_rows = tx
        .query(
            "SELECT fcr.commit_oid,fcr.context,fcr.status,fcr.conclusion,
                    (tc.repository_id IS NOT NULL),
                    COALESCE(tc.active,false),
                    tc.webhook_id,
                    (w.id IS NOT NULL AND w.active AND w.repository_id=fcr.repository_id),
                    fcr.issuer_webhook_id,
                    fcr.ci_base_oid,
                    EXISTS(SELECT 1 FROM ci_runs cr JOIN forge_pulls p
                             ON p.repository_id=cr.repository_id AND p.number=cr.pull_number
                            WHERE cr.id=fcr.ci_run_id AND cr.repository_id=fcr.repository_id
                              AND cr.context=fcr.context AND cr.head_oid=fcr.commit_oid
                              AND cr.base_oid=fcr.ci_base_oid AND cr.state='completed'
                              AND cr.conclusion='success' AND cr.attempt=fcr.attempt
                              AND cr.lease_generation=fcr.ci_lease_generation
                              AND p.state='open' AND p.version=cr.pull_version
                              AND p.head_oid=cr.head_oid AND p.base_oid=cr.base_oid)
             FROM forge_check_runs fcr
             LEFT JOIN forge_trusted_check_contexts tc
                    ON tc.repository_id=fcr.repository_id AND tc.context=fcr.context
             LEFT JOIN forge_webhooks w ON w.id=COALESCE(tc.webhook_id,fcr.issuer_webhook_id)
             WHERE fcr.repository_id=$1 AND fcr.tenant_id=$2 AND fcr.commit_oid = ANY($3)
             ORDER BY fcr.commit_oid, fcr.context LIMIT 4097",
            &[&repository_id, &tenant_id, &head_oids],
        )
        .await
        .map_err(sql_locks::sql_error)?;
    if check_rows.len() > MAX_CHECK_RUN_ROWS {
        return Err(DecisionError::Unverifiable("too many check runs to evaluate"));
    }
    let checks = check_rows
        .into_iter()
        .map(|row| CheckRunFacts {
            commit_oid: row.get(0),
            context: row.get(1),
            status: row.get(2),
            conclusion: row.get(3),
            binding_present: row.get(4),
            binding_active: row.get(5),
            bound_webhook_id: row.get(6),
            webhook_active: row.get(7),
            issuer_webhook_id: row.get(8),
            ci_base_oid: row.get(9),
            ci_run_valid: row.get(10),
        })
        .collect::<Vec<_>>();

    let lock_rows = tx
        .query(
            "SELECT path,owner_user_id,version FROM lfs_locks
             WHERE repository_id=$1 AND tenant_id=$2
             ORDER BY path
             LIMIT $3",
            &[&repository_id, &tenant_id, &(MAX_LFS_LOCKS + 1)],
        )
        .await
        .map_err(sql_locks::sql_error)?;
    if lock_rows.len() as i64 > MAX_LFS_LOCKS {
        return Err(DecisionError::Unverifiable("too many LFS locks to evaluate"));
    }
    let lfs_locks = lock_rows
        .into_iter()
        .map(|row| LfsLockFacts { path: row.get(0), owner_user_id: row.get(1), version: row.get(2) })
        .collect::<Vec<_>>();

    Ok(RepoPolicyFacts { rules: rule_facts, pulls, approvals, checks, lfs_locks, lfs_objects: Vec::new() })
}

/// Read the metadata readiness of the exact LFS objects introduced by the native facts.
pub(super) async fn read_lfs_objects(
    tx: &Transaction<'_>,
    plan: &PackCommitPlan,
    oids: &[String],
) -> Result<Vec<LfsObjectFacts>, DecisionError> {
    if oids.is_empty() {
        return Ok(Vec::new());
    }
    if oids.len() > MAX_LFS_POINTER_OBJECTS {
        return Err(DecisionError::Unverifiable("too many LFS pointer objects to evaluate"));
    }
    let mut sorted = oids.to_vec();
    sorted.sort();
    sorted.dedup();
    let rows = tx
        .query(
            "SELECT oid,state FROM lfs_objects
             WHERE repository_id=$1 AND tenant_id=$2 AND oid = ANY($3)
             ORDER BY oid",
            &[&plan.repository_id(), &plan.tenant_id(), &sorted],
        )
        .await
        .map_err(sql_locks::sql_error)?;
    Ok(rows
        .into_iter()
        .map(|row| {
            let state: String = row.get(1);
            LfsObjectFacts { oid: row.get(0), ready: state == "ready" }
        })
        .collect())
}
