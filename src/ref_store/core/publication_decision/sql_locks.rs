//! Frozen SQL building blocks: dependency-table lock order, database clock, protocol state and the
//! decision/scope control rows.
//!
//! # Frozen lock order
//!
//! 1. migration-138 operation advisory key -> issuer lane -> repository row (unchanged);
//! 2. `LOCK TABLE ... [IN SHARE MODE | IN SHARE ROW EXCLUSIVE MODE] NOWAIT` for
//!    [`SOURCE_TABLES`] in exactly this order, before any authority read;
//! 3. tenant usage row, then repository usage row (`tenant -> repo`, the frozen global order);
//! 4. the core gate row (`FOR UPDATE` / `FOR SHARE`, never a table lock), then the separate protocol
//!    realm row `ref_store_core_protocol_repos` (`FOR SHARE`);
//! 5. the decision control row (`FOR UPDATE`), then the scope control rows in [`ScopeKind`] order;
//! 6. read the database clock, re-read every fact, then write.
//!
//! `NOWAIT` is deliberate: a blocking `LOCK TABLE` list can deadlock against webhook flows that touch
//! `ci_runs`/`forge_check_runs` in the opposite order. A contended lock aborts this short transaction
//! with [`DecisionError::Contended`]; the caller retries the whole attempt (bounded) under the same
//! operation identity, and nothing was written. Control tables (`ref_store_decision_*`,
//! `ref_store_publication_decisions`, the gate and the protocol row) are **never** table-locked: a
//! table `SHARE` lock followed by an `INSERT`/`UPDATE` into the same table would be a
//! self-conflicting upgrade.
use super::contract::{DecisionError, DecisionKind, DecisionState, DenialCode, PublicationAction, ScopeKind};
use crate::ref_store::contract::RequestDigest;
use tokio_postgres::{Row, Transaction, error::SqlState};
use uuid::Uuid;

/// Complete source set implied by the actual authorization/policy reads (Luna review). Browser
/// decisions are explicitly rejected (`DenialCode::BrowserTokenUnsupported`), so `web_sessions` is
/// deliberately absent. `token_namespace_scopes` is absent because it is never consulted for
/// repository ref publication. No decision/control table is in this list.
pub(crate) const SOURCE_TABLES: [&str; 23] = [
    "tokens",
    "users",
    "repositories",
    "namespaces",
    "organizations",
    "token_repository_scopes",
    "repository_collaborators",
    "repository_teams",
    "repository_team_members",
    "organization_memberships",
    "organization_teams",
    "organization_team_members",
    "forge_pulls",
    "forge_branch_rules",
    "forge_pull_reviews",
    "forge_check_runs",
    "forge_trusted_check_contexts",
    "forge_webhooks",
    "ci_runs",
    "lfs_locks",
    "lfs_objects",
    "pando_repository_states",
    "repository_ref_projection",
];

const DECISION_COLUMNS: &str = "decision_id,repository_id,tenant_id,owner_id,actor_id,token_id,\
token_digest,operation_id,mode,object_format,base_revision,base_gate_digest,command_digest,\
refs_digest,selected_refs_digest,selection_digest,policy_digest,facts_digest,authz_digest,\
dependencies_digest,packs_digest,hold_receipts_digest,captured_oid_digest,not_after_millis,\
created_db_millis,state,consume_receipt_id,proof_facts_digest,closed_code,\naction,merge_pull_number,merge_version,merge_head_oid,merge_base_oid";

/// Map a PostgreSQL error without ever turning a schema/contention problem into an allow.
pub(super) fn sql_error(error: tokio_postgres::Error) -> DecisionError {
    if let Some(code) = error.code() {
        if *code == SqlState::LOCK_NOT_AVAILABLE {
            return DecisionError::Contended("auth dependency share lock unavailable");
        }
        if *code == SqlState::UNDEFINED_COLUMN {
            return DecisionError::Denied(DenialCode::ProtocolStateMissing);
        }
        if *code == SqlState::UNDEFINED_TABLE {
            return DecisionError::Unverifiable("decision/dependency table is not installed");
        }
        if *code == SqlState::QUERY_CANCELED {
            return DecisionError::Timeout;
        }
        if *code == SqlState::UNIQUE_VIOLATION {
            return DecisionError::Ledger("duplicate decision control row");
        }
    }
    DecisionError::Database(error.to_string())
}

pub(super) fn parse_digest(value: &str) -> Result<RequestDigest, DecisionError> {
    value.parse::<RequestDigest>().map_err(|_| DecisionError::Ledger("stored digest is not canonical"))
}

/// Take the coarse, fixed-order source locks for the semantic action. Never upgrades, never waits.
///
/// A `Merge` action needs a write-capable table mode on `forge_pulls` up front because the atomic
/// merge finalizer updates that table in the same transaction; it can never be `SHARE`-locked and then
/// upgraded. `Push` is read-only over `forge_pulls` and uses plain `SHARE`.
pub(crate) async fn lock_source_tables(tx: &Transaction<'_>, action: &PublicationAction) -> Result<(), DecisionError> {
    let merge = action.is_merge();
    let mut sql = String::new();
    for table in SOURCE_TABLES {
        sql.push_str("LOCK TABLE ");
        sql.push_str(table);
        if merge && table == "forge_pulls" {
            sql.push_str(" IN SHARE ROW EXCLUSIVE MODE NOWAIT;");
        } else {
            sql.push_str(" IN SHARE MODE NOWAIT;");
        }
    }
    tx.batch_execute(&sql).await.map_err(sql_error)
}

/// Lock the repository row itself (`FOR SHARE`, after the source table locks and before the usage
/// rows). This is the same row `auth_deps` re-reads; taking it here fixes the global order.
pub(crate) async fn lock_repository_row(tx: &Transaction<'_>, repository_id: Uuid) -> Result<(), DecisionError> {
    let row = tx
        .query_opt("SELECT id FROM repositories WHERE id=$1 FOR SHARE", &[&repository_id])
        .await
        .map_err(sql_error)?
        .ok_or(DecisionError::Denied(DenialCode::RepositoryNotFound))?;
    let _: Uuid = row.get(0);
    Ok(())
}

/// Real database clock in epoch milliseconds, read as its own statement after every lock wait.
pub(super) async fn db_clock(tx: &Transaction<'_>) -> Result<i64, DecisionError> {
    let row =
        tx.query_one("SELECT (extract(epoch FROM clock_timestamp())*1000)::bigint", &[]).await.map_err(sql_error)?;
    Ok(row.get(0))
}

/// The live core gate row plus the separate protocol realm row. The protocol row is the actual
/// decision fence: `ref_store_core_protocol_repos.decision_required` (there is no
/// `core_gates.decision_mode` column). Both rows are read, in gate -> protocol order, and their
/// immutable realm fields must match exactly.
pub(super) struct ProtocolState {
    pub tenant_id: Uuid,
    pub object_format: String,
    pub history_incarnation: Uuid,
    pub authority_epoch: i64,
    pub group_epoch: i64,
    pub head_ref: String,
    pub revision: i64,
    pub decision_required: bool,
}

pub(super) async fn protocol_state(tx: &Transaction<'_>, repository_id: Uuid) -> Result<ProtocolState, DecisionError> {
    // Gate first (Root's existing serialization point); never a table lock.
    let gate = tx
        .query_opt(
            "SELECT tenant_id,object_format,history_incarnation,authority_epoch,group_epoch,\
                    head_ref,revision
             FROM ref_store_core_gates WHERE repository_id=$1 FOR SHARE",
            &[&repository_id],
        )
        .await
        .map_err(sql_error)?
        .ok_or(DecisionError::Denied(DenialCode::GateNotFound))?;
    let gate_tenant: Uuid = gate.get(0);
    let gate_format: String = gate.get(1);
    let gate_history: Uuid = gate.get(2);
    let gate_authority: i64 = gate.get(3);
    let gate_group: i64 = gate.get(4);
    let gate_head: String = gate.get(5);
    let gate_revision: i64 = gate.get(6);

    // Protocol row second. Its realm columns are trigger-immutable; a drift is a refusal, never a
    // silent re-read of a different realm.
    let protocol = tx
        .query_opt(
            "SELECT tenant_id,object_format,history_incarnation,authority_epoch,group_epoch,\
                    decision_required
             FROM ref_store_core_protocol_repos WHERE repository_id=$1 FOR SHARE",
            &[&repository_id],
        )
        .await
        .map_err(sql_error)?
        .ok_or(DecisionError::Denied(DenialCode::ProtocolStateMissing))?;
    let tenant_id: Uuid = protocol.get(0);
    let object_format: String = protocol.get(1);
    let history_incarnation: Uuid = protocol.get(2);
    let authority_epoch: i64 = protocol.get(3);
    let group_epoch: i64 = protocol.get(4);
    let decision_required: bool = protocol.get(5);
    if tenant_id != gate_tenant
        || object_format != gate_format
        || history_incarnation != gate_history
        || authority_epoch != gate_authority
        || group_epoch != gate_group
    {
        return Err(DecisionError::Denied(DenialCode::ProtocolStateMissing));
    }
    Ok(ProtocolState {
        tenant_id,
        object_format,
        history_incarnation,
        authority_epoch,
        group_epoch,
        head_ref: gate_head,
        revision: gate_revision,
        decision_required,
    })
}

/// Lock (or create) the retained usage rows in the frozen global order `tenant -> repository`.
/// Integration calls this BEFORE the gate/protocol row locks. `usage::charge` then only reads and
/// updates rows this transaction already holds, so the order can never invert.
pub(crate) async fn lock_usage(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    tenant_id: Uuid,
) -> Result<(), DecisionError> {
    tx.execute(
        "INSERT INTO ref_store_decision_tenant_usage(tenant_id) VALUES($1)
         ON CONFLICT(tenant_id) DO NOTHING",
        &[&tenant_id],
    )
    .await
    .map_err(sql_error)?;
    tx.query_one("SELECT tenant_id FROM ref_store_decision_tenant_usage WHERE tenant_id=$1 FOR UPDATE", &[&tenant_id])
        .await
        .map_err(sql_error)?;
    tx.execute(
        "INSERT INTO ref_store_decision_repo_usage(repository_id) VALUES($1)
         ON CONFLICT(repository_id) DO NOTHING",
        &[&repository_id],
    )
    .await
    .map_err(sql_error)?;
    tx.query_one(
        "SELECT repository_id FROM ref_store_decision_repo_usage WHERE repository_id=$1 FOR UPDATE",
        &[&repository_id],
    )
    .await
    .map_err(sql_error)?;
    Ok(())
}

fn parse_action(
    action: String,
    pull_number: Option<i64>,
    version: Option<i64>,
    head_oid: Option<String>,
    base_oid: Option<String>,
) -> Result<PublicationAction, DecisionError> {
    match action.as_str() {
        "push" => Ok(PublicationAction::Push),
        "merge" => {
            let binding = super::contract::MergeBinding::new(
                pull_number.ok_or(DecisionError::Ledger("stored merge action has no pull number"))?,
                version.ok_or(DecisionError::Ledger("stored merge action has no version"))?,
                head_oid.ok_or(DecisionError::Ledger("stored merge action has no head oid"))?,
                base_oid.ok_or(DecisionError::Ledger("stored merge action has no base oid"))?,
            )?;
            Ok(PublicationAction::Merge(binding))
        }
        _ => Err(DecisionError::Ledger("unknown stored publication action")),
    }
}

/// Durable decision row, read-only view.
pub(super) struct DecisionRow {
    pub decision_id: Uuid,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
    pub actor_id: Uuid,
    pub token_id: Uuid,
    pub token_digest: String,
    pub operation_id: Uuid,
    pub mode: DecisionKind,
    pub base_revision: i64,
    pub base_gate_digest: RequestDigest,
    pub command_digest: RequestDigest,
    pub refs_digest: RequestDigest,
    pub selected_refs_digest: RequestDigest,
    pub selection_digest: RequestDigest,
    pub policy_digest: RequestDigest,
    pub facts_digest: RequestDigest,
    pub authz_digest: RequestDigest,
    pub dependencies_digest: RequestDigest,
    pub packs_digest: RequestDigest,
    pub hold_receipts_digest: RequestDigest,
    pub captured_oid_digest: RequestDigest,
    pub not_after_millis: i64,
    pub created_db_millis: i64,
    pub state: DecisionState,
    pub consume_receipt_id: Option<Uuid>,
    pub closed_code: Option<String>,
    pub action: PublicationAction,
}

impl DecisionRow {
    fn from_row(row: &Row) -> Result<Self, DecisionError> {
        let proof = row.get::<_, Option<String>>(27);
        let _proof_facts_digest = match proof {
            Some(value) => Some(parse_digest(&value)?),
            None => None,
        };
        Ok(Self {
            decision_id: row.get(0),
            repository_id: row.get(1),
            tenant_id: row.get(2),
            owner_id: row.get(3),
            actor_id: row.get(4),
            token_id: row.get(5),
            token_digest: row.get(6),
            operation_id: row.get(7),
            mode: DecisionKind::parse(row.get::<_, String>(8).as_str())?,
            base_revision: row.get(10),
            base_gate_digest: parse_digest(&row.get::<_, String>(11))?,
            command_digest: parse_digest(&row.get::<_, String>(12))?,
            refs_digest: parse_digest(&row.get::<_, String>(13))?,
            selected_refs_digest: parse_digest(&row.get::<_, String>(14))?,
            selection_digest: parse_digest(&row.get::<_, String>(15))?,
            policy_digest: parse_digest(&row.get::<_, String>(16))?,
            facts_digest: parse_digest(&row.get::<_, String>(17))?,
            authz_digest: parse_digest(&row.get::<_, String>(18))?,
            dependencies_digest: parse_digest(&row.get::<_, String>(19))?,
            packs_digest: parse_digest(&row.get::<_, String>(20))?,
            hold_receipts_digest: parse_digest(&row.get::<_, String>(21))?,
            captured_oid_digest: parse_digest(&row.get::<_, String>(22))?,
            not_after_millis: row.get(23),
            created_db_millis: row.get(24),
            state: DecisionState::parse(row.get::<_, String>(25).as_str())?,
            consume_receipt_id: row.get(26),
            closed_code: row.get(28),
            action: parse_action(row.get(29), row.get(30), row.get(31), row.get(32), row.get(33))?,
        })
    }
}

pub(super) async fn decision_by_operation(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    operation_id: Uuid,
    for_update: bool,
) -> Result<Option<DecisionRow>, DecisionError> {
    let sql = format!(
        "SELECT {DECISION_COLUMNS} FROM ref_store_publication_decisions
         WHERE repository_id=$1 AND operation_id=$2{}",
        if for_update { " FOR UPDATE" } else { "" }
    );
    let row = tx.query_opt(&sql, &[&repository_id, &operation_id]).await.map_err(sql_error)?;
    row.as_ref().map(DecisionRow::from_row).transpose()
}

pub(super) async fn decision_by_id(
    tx: &Transaction<'_>,
    decision_id: Uuid,
    for_update: bool,
) -> Result<Option<DecisionRow>, DecisionError> {
    let sql = format!(
        "SELECT {DECISION_COLUMNS} FROM ref_store_publication_decisions
         WHERE decision_id=$1{}",
        if for_update { " FOR UPDATE" } else { "" }
    );
    let row = tx.query_opt(&sql, &[&decision_id]).await.map_err(sql_error)?;
    row.as_ref().map(DecisionRow::from_row).transpose()
}

/// Lock (or create and then lock) one stable scope control row and advance its observed version.
/// A `CLOSING` scope fails closed: no new decision may be minted under a scope being revoked.
pub(super) async fn observe_scope(
    tx: &Transaction<'_>,
    kind: ScopeKind,
    id: Uuid,
    version: i64,
) -> Result<(), DecisionError> {
    tx.execute(
        "INSERT INTO ref_store_decision_scopes(scope_kind,scope_id,version)
         VALUES($1,$2,$3) ON CONFLICT(scope_kind,scope_id) DO NOTHING",
        &[&kind.as_str(), &id, &version],
    )
    .await
    .map_err(sql_error)?;
    let row = tx
        .query_one(
            "SELECT version,state FROM ref_store_decision_scopes
             WHERE scope_kind=$1 AND scope_id=$2 FOR UPDATE",
            &[&kind.as_str(), &id],
        )
        .await
        .map_err(sql_error)?;
    let state: String = row.get(1);
    if state != "OPEN" {
        return Err(DecisionError::Denied(DenialCode::ScopeClosing));
    }
    let current: i64 = row.get(0);
    if version > current {
        tx.execute(
            "UPDATE ref_store_decision_scopes SET version=$3,updated_at=clock_timestamp()
             WHERE scope_kind=$1 AND scope_id=$2",
            &[&kind.as_str(), &id, &version],
        )
        .await
        .map_err(sql_error)?;
    }
    Ok(())
}
