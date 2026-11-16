//! PostgreSQL committed-read decision verifier & signed decision grant minter (`#152`).
//!
//! Separated from HMAC verification so grant cryptographic validation stays offline
//! and every PG read executes inside an independent pooled `READ COMMITTED` read-only
//! snapshot, making it impossible to mint grants from an uncommitted caller `Transaction`.

use std::collections::BTreeSet;

use deadpool_postgres::Pool;
use tokio_postgres::IsolationLevel;
use uuid::Uuid;

use crate::ref_store::core::state_machine::{WireDecisionKind, WireDecisionScopeDep, WireDecisionVerdict};
use crate::ref_store::core::terminal::CommitRejectCode;

use super::remote_authz_grant::{
    DecisionGrantKeyring, GRANT_FORMAT_VERSION, GrantExpectedRealm, RemoteAuthzGrantError, ServiceMtlsIdentity,
    SignedDecisionGrant, SignedDecisionGrantPayload,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PgGrantMintRequest {
    pub decision_id: Uuid,
    pub expected_realm: GrantExpectedRealm,
    pub authz_epoch: i64,
    pub service_identity: ServiceMtlsIdentity,
    pub required_holds: Vec<Uuid>,
    pub not_after_tick: u64,
}

/// Reads a committed `OPEN` PG publication decision from an independent `READ COMMITTED`
/// read-only pooled connection and mints a signed grant only when every indexed dependency
/// scope in `ref_store_decision_scopes` is confirmed `OPEN`.
pub async fn mint_signed_decision_grant_from_pg(
    pool: &Pool,
    signer: &DecisionGrantKeyring,
    req: &PgGrantMintRequest,
) -> Result<SignedDecisionGrant, RemoteAuthzGrantError> {
    req.expected_realm.validate()?;
    req.service_identity.validate()?;
    if req.authz_epoch <= 0 || req.not_after_tick == 0 {
        return Err(RemoteAuthzGrantError::InvalidInput("authz_epoch and not_after_tick must be > 0".into()));
    }
    let mut seen_holds = BTreeSet::new();
    for &hold_id in &req.required_holds {
        if hold_id.is_nil() || !seen_holds.insert(hold_id) {
            return Err(RemoteAuthzGrantError::InvalidInput("mint required_holds must be non-nil and unique".into()));
        }
    }

    let mut client = pool.get().await.map_err(|e| RemoteAuthzGrantError::PgDatabase(e.to_string()))?;
    let tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::ReadCommitted)
        .read_only(true)
        .start()
        .await
        .map_err(|e| RemoteAuthzGrantError::PgDatabase(e.to_string()))?;

    let row = tx
        .query_opt(
            "SELECT repository_id, tenant_id, actor_id, operation_id, mode, state,
                    history_incarnation, authority_epoch, group_epoch, base_revision,
                    base_gate_digest, command_digest, selection_digest, policy_digest,
                    facts_digest, authz_digest, dependencies_digest, packs_digest,
                    hold_receipts_digest, captured_oid_digest
             FROM ref_store_publication_decisions
             WHERE decision_id = $1",
            &[&req.decision_id],
        )
        .await
        .map_err(|e| RemoteAuthzGrantError::PgDatabase(e.to_string()))?
        .ok_or(RemoteAuthzGrantError::DecisionNotCommittedInPg(req.decision_id))?;

    let repository_id: Uuid = row.get(0);
    let tenant_id: Uuid = row.get(1);
    let actor_id: Uuid = row.get(2);
    let operation_id: Uuid = row.get(3);
    let mode: String = row.get(4);
    let state: String = row.get(5);
    let history_incarnation: Uuid = row.get(6);
    let authority_epoch: i64 = row.get(7);
    let group_epoch: i64 = row.get(8);
    let base_revision: i64 = row.get(9);

    if state != "OPEN" {
        return Err(RemoteAuthzGrantError::DecisionNotOpenInPg { decision_id: req.decision_id, state });
    }
    if repository_id != req.expected_realm.repository_id
        || tenant_id != req.expected_realm.tenant_id
        || history_incarnation != req.expected_realm.history_incarnation
        || authority_epoch != req.expected_realm.authority_epoch
        || group_epoch != req.expected_realm.group_epoch
    {
        return Err(RemoteAuthzGrantError::RealmMismatch("PG decision realm differs from mint request"));
    }

    let cancelled = tx
        .query_opt(
            "SELECT 1 FROM ref_store_decision_cancellations WHERE repository_id = $1 AND operation_id = $2",
            &[&repository_id, &operation_id],
        )
        .await
        .map_err(|e| RemoteAuthzGrantError::PgDatabase(e.to_string()))?;
    if cancelled.is_some() {
        return Err(RemoteAuthzGrantError::DecisionCancelledInPg(operation_id));
    }

    let ref_rows = tx
        .query(
            "SELECT ref_name, verdict, reject_code FROM ref_store_decision_refs
             WHERE decision_id = $1 ORDER BY ref_ordinal ASC",
            &[&req.decision_id],
        )
        .await
        .map_err(|e| RemoteAuthzGrantError::PgDatabase(e.to_string()))?;
    let mut verdicts = Vec::with_capacity(ref_rows.len());
    for r in ref_rows {
        let verdict_str: String = r.get(1);
        let code_opt: Option<String> = r.get(2);
        let reject_code = match code_opt {
            Some(code) => Some(
                serde_json::from_value::<CommitRejectCode>(serde_json::Value::String(code))
                    .map_err(|e| RemoteAuthzGrantError::InvalidInput(format!("bad reject_code: {e}")))?,
            ),
            None => None,
        };
        verdicts.push(WireDecisionVerdict { ref_name: r.get(0), accepted: verdict_str == "accept", reject_code });
    }

    let dep_rows = tx
        .query(
            "SELECT scope_kind, scope_id, observed_version, observed_digest
             FROM ref_store_decision_dependencies
             WHERE decision_id = $1 ORDER BY scope_kind ASC, scope_id ASC",
            &[&req.decision_id],
        )
        .await
        .map_err(|e| RemoteAuthzGrantError::PgDatabase(e.to_string()))?;
    let mut scope_dependencies = Vec::with_capacity(dep_rows.len());
    for d in dep_rows {
        let scope_kind: String = d.get(0);
        let scope_id: Uuid = d.get(1);
        let scope_row = tx
            .query_opt(
                "SELECT state FROM ref_store_decision_scopes WHERE scope_kind = $1 AND scope_id = $2",
                &[&scope_kind, &scope_id],
            )
            .await
            .map_err(|e| RemoteAuthzGrantError::PgDatabase(e.to_string()))?;
        let obs_state: Option<String> = scope_row.map(|sr| sr.get(0));
        if obs_state.as_deref() != Some("OPEN") {
            return Err(RemoteAuthzGrantError::ScopeClosingOrMissingInPg {
                scope_kind,
                scope_id,
                observed_state: obs_state,
            });
        }
        scope_dependencies.push(WireDecisionScopeDep {
            scope_kind,
            scope_id,
            observed_version: d.get(2),
            observed_digest: d.get(3),
        });
    }
    let _ = tx.rollback().await;

    let kind = match mode.as_str() {
        "atomic" => WireDecisionKind::Atomic,
        "accepted_subset" => WireDecisionKind::AcceptedSubset,
        other => return Err(RemoteAuthzGrantError::InvalidInput(format!("unknown decision mode {other:?}"))),
    };

    signer.sign(SignedDecisionGrantPayload {
        format_version: GRANT_FORMAT_VERSION,
        key_id: signer.current_key_id(),
        issuer_id: req.service_identity.issuer_id,
        service_mtls_identity: req.service_identity.san_identity.clone(),
        decision_id: req.decision_id,
        tenant_id,
        repository_id,
        actor_id,
        operation_id,
        group_id: req.expected_realm.group_id,
        group_epoch,
        history_incarnation,
        authority_epoch,
        authz_epoch: req.authz_epoch,
        base_revision,
        kind,
        not_after_tick: req.not_after_tick,
        base_gate_digest: row.get(10),
        command_digest: row.get(11),
        selection_digest: row.get(12),
        policy_digest: row.get(13),
        facts_digest: row.get(14),
        authz_digest: row.get(15),
        dependencies_digest: row.get(16),
        packs_digest: row.get(17),
        hold_receipts_digest: row.get(18),
        captured_oid_digest: row.get(19),
        required_holds: req.required_holds.clone(),
        verdicts,
        scope_dependencies,
    })
}
