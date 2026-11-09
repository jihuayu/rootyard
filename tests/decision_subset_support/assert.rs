//! Read-only PostgreSQL assertions over the actual migration 138/139/142/144
//! rows. Tests assert durable state here, not a caller-side boolean or an
//! in-memory receipt field.
use anyhow::{Result, ensure};
use deadpool_postgres::Pool;
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq)]
pub struct Operation {
    pub state: String,
    pub request_digest: String,
    pub terminal: Option<serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Decision {
    pub decision_id: Uuid,
    pub operation_id: Uuid,
    pub state: String,
    pub mode: String,
    pub command_digest: String,
    pub refs_digest: String,
    pub selection_digest: String,
    pub selected_refs_digest: String,
    pub base_revision: i64,
    pub actor_id: Uuid,
    pub token_id: Uuid,
    pub consume_receipt_id: Option<Uuid>,
}

pub async fn refs(pool: &Pool, repository_id: Uuid) -> Result<BTreeMap<String, String>> {
    let rows = pool
        .get()
        .await?
        .query("SELECT ref_name,oid FROM ref_store_core_refs WHERE repository_id=$1", &[&repository_id])
        .await?;
    Ok(rows.into_iter().map(|row| (row.get(0), row.get(1))).collect())
}

pub async fn gate_revision(pool: &Pool, repository_id: Uuid) -> Result<i64> {
    Ok(pool
        .get()
        .await?
        .query_one("SELECT revision FROM ref_store_core_gates WHERE repository_id=$1", &[&repository_id])
        .await?
        .get(0))
}

pub async fn membership_count(pool: &Pool, repository_id: Uuid) -> Result<i64> {
    Ok(pool
        .get()
        .await?
        .query_one("SELECT count(*) FROM ref_store_core_pack_memberships WHERE repository_id=$1", &[&repository_id])
        .await?
        .get(0))
}

pub async fn operation(pool: &Pool, repository_id: Uuid, operation_id: Uuid) -> Result<Operation> {
    let row = pool
        .get()
        .await?
        .query_one(
            "SELECT state,request_digest,terminal_result FROM ref_store_operations
             WHERE repository_id=$1 AND operation_id=$2",
            &[&repository_id, &operation_id],
        )
        .await?;
    Ok(Operation { state: row.get(0), request_digest: row.get(1), terminal: row.get(2) })
}

pub async fn operation_opt(pool: &Pool, repository_id: Uuid, operation_id: Uuid) -> Result<Option<Operation>> {
    let row = pool
        .get()
        .await?
        .query_opt(
            "SELECT state,request_digest,terminal_result FROM ref_store_operations
             WHERE repository_id=$1 AND operation_id=$2",
            &[&repository_id, &operation_id],
        )
        .await?;
    Ok(row.map(|row| Operation { state: row.get(0), request_digest: row.get(1), terminal: row.get(2) }))
}

pub async fn decision(pool: &Pool, repository_id: Uuid, operation_id: Uuid) -> Result<Option<Decision>> {
    let row = pool
        .get()
        .await?
        .query_opt(
            "SELECT decision_id,operation_id,state,mode,command_digest,refs_digest,selection_digest,
                    selected_refs_digest,base_revision,actor_id,token_id,consume_receipt_id
             FROM ref_store_publication_decisions
             WHERE repository_id=$1 AND operation_id=$2",
            &[&repository_id, &operation_id],
        )
        .await?;
    Ok(row.map(|row| Decision {
        decision_id: row.get(0),
        operation_id: row.get(1),
        state: row.get(2),
        mode: row.get(3),
        command_digest: row.get(4),
        refs_digest: row.get(5),
        selection_digest: row.get(6),
        selected_refs_digest: row.get(7),
        base_revision: row.get(8),
        actor_id: row.get(9),
        token_id: row.get(10),
        consume_receipt_id: row.get(11),
    }))
}

/// One `(ref_name, verdict, reject_code)` row per original plan ref.
pub async fn verdicts(pool: &Pool, decision_id: Uuid) -> Result<Vec<(String, String, Option<String>)>> {
    let rows = pool
        .get()
        .await?
        .query(
            "SELECT ref_name,verdict,reject_code FROM ref_store_decision_refs
             WHERE decision_id=$1 ORDER BY ref_name",
            &[&decision_id],
        )
        .await?;
    Ok(rows.into_iter().map(|row| (row.get(0), row.get(1), row.get(2))).collect())
}

/// Exact durable rejection protocol: decision REJECTED, 138 Rejected, all ref
/// verdicts rejected and no consume receipt.
pub async fn assert_durable_rejection(pool: &Pool, repository_id: Uuid, operation_id: Uuid) -> Result<Decision> {
    let decision = decision(pool, repository_id, operation_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("rejected decision row missing"))?;
    ensure!(decision.state == "REJECTED", "decision state is {} not REJECTED", decision.state);
    ensure!(decision.consume_receipt_id.is_none(), "rejected decision has a consume receipt");
    let operation = operation(pool, repository_id, operation_id).await?;
    ensure!(operation.state == "rejected", "138 state is {} not rejected", operation.state);
    ensure!(terminal_kind(&operation)? == "rejected", "138 terminal is not rejected");
    let terminal = operation.terminal.as_ref().ok_or_else(|| anyhow::anyhow!("rejected 138 has no body"))?;
    let rows = terminal
        .get("refs")
        .and_then(|value| value.as_array())
        .ok_or_else(|| anyhow::anyhow!("rejected 138 has no ref outcomes"))?;
    ensure!(!rows.is_empty(), "rejected 138 has an empty ref outcome set");
    ensure!(
        rows.iter().all(|row| row.get("outcome").and_then(|value| value.as_str()) == Some("not_applied")),
        "rejected 138 applied at least one ref"
    );
    Ok(decision)
}

/// Exact durable consumption protocol: decision CONSUMED with a consume receipt,
/// 138 Committed and no rejected terminal.
pub async fn assert_durable_consumed(pool: &Pool, repository_id: Uuid, operation_id: Uuid) -> Result<Decision> {
    let decision = decision(pool, repository_id, operation_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("consumed decision row missing"))?;
    ensure!(decision.state == "CONSUMED", "decision state is {} not CONSUMED", decision.state);
    ensure!(decision.consume_receipt_id.is_some(), "consumed decision has no consume receipt");
    let operation = operation(pool, repository_id, operation_id).await?;
    ensure!(operation.state == "committed", "138 state is {} not committed", operation.state);
    ensure!(terminal_kind(&operation)? == "committed", "138 terminal is not committed");
    Ok(decision)
}

pub async fn decision_window(pool: &Pool, decision_id: Uuid) -> Result<(i64, i64)> {
    let row = pool
        .get()
        .await?
        .query_one(
            "SELECT created_db_millis,not_after_millis FROM ref_store_publication_decisions WHERE decision_id=$1",
            &[&decision_id],
        )
        .await?;
    Ok((row.get(0), row.get(1)))
}

pub async fn decision_cancellations(pool: &Pool, repository_id: Uuid, operation_id: Uuid) -> Result<i64> {
    Ok(pool
        .get()
        .await?
        .query_one(
            "SELECT count(*) FROM ref_store_decision_cancellations
             WHERE repository_id=$1 AND operation_id=$2",
            &[&repository_id, &operation_id],
        )
        .await?
        .get(0))
}

pub async fn usage_decisions(pool: &Pool, repository_id: Uuid) -> Result<(i64, i64, i64)> {
    let row = pool
        .get()
        .await?
        .query_one(
            "SELECT decisions,ref_verdicts,logical_bytes FROM ref_store_decision_repo_usage
             WHERE repository_id=$1",
            &[&repository_id],
        )
        .await?;
    Ok((row.get(0), row.get(1), row.get(2)))
}

pub async fn operation_count(pool: &Pool, repository_id: Uuid) -> Result<i64> {
    Ok(pool
        .get()
        .await?
        .query_one("SELECT count(*) FROM ref_store_operations WHERE repository_id=$1", &[&repository_id])
        .await?
        .get(0))
}

/// Assert a durable terminal has the exact immutable body, including whether it
/// is the committed or rejected variant of the unchanged old wire shape.
pub fn terminal_kind(operation: &Operation) -> Result<&str> {
    let terminal = operation.terminal.as_ref().ok_or_else(|| anyhow::anyhow!("operation has no terminal body"))?;
    terminal.get("kind").and_then(|kind| kind.as_str()).ok_or_else(|| anyhow::anyhow!("terminal body has no kind"))
}

pub async fn assert_unchanged(
    pool: &Pool,
    repository_id: Uuid,
    expected_refs: &BTreeMap<String, String>,
    expected_revision: i64,
) -> Result<()> {
    assert_unchanged_with_membership(pool, repository_id, expected_refs, expected_revision, None).await
}

/// No ref, revision or (when supplied) membership change.
pub async fn assert_unchanged_with_membership(
    pool: &Pool,
    repository_id: Uuid,
    expected_refs: &BTreeMap<String, String>,
    expected_revision: i64,
    expected_memberships: Option<i64>,
) -> Result<()> {
    ensure!(refs(pool, repository_id).await? == *expected_refs, "ref rows changed");
    ensure!(gate_revision(pool, repository_id).await? == expected_revision, "gate revision changed");
    if let Some(expected) = expected_memberships {
        ensure!(membership_count(pool, repository_id).await? == expected, "pack membership changed");
    }
    Ok(())
}
